using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SupertonicVox.Core;

public sealed class VoxCpm2SidecarProvider : IEngineProvider
{
    private const int MaximumRequestBytes = 16 * 1024;
    private const int MaximumWaveBytes = 64 * 1024 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        Converters = { new JsonStringEnumConverter(namingPolicy: null, allowIntegerValues: false) },
    };
    private readonly VerifiedRuntimePack runtimePack;
    private readonly string dataDirectory;
    private readonly ISidecarSessionFactory sessionFactory;
    private readonly SemaphoreSlim operationGate = new(1, 1);
    private readonly object cancellationSync = new();
    private ISidecarClientSession? session;
    private CancellationTokenSource? activeOperationCancellation;
    private long stopGeneration;
    private bool disposed;

    public VoxCpm2SidecarProvider(
        VerifiedRuntimePack runtimePack,
        string dataDirectory,
        ISidecarSessionFactory sessionFactory)
    {
        this.runtimePack = runtimePack ?? throw new ArgumentNullException(nameof(runtimePack));
        this.dataDirectory = Path.GetFullPath(dataDirectory);
        this.sessionFactory = sessionFactory ?? throw new ArgumentNullException(nameof(sessionFactory));
        if (!string.Equals(runtimePack.Manifest.EngineId, "voxcpm2", StringComparison.Ordinal))
            throw new ArgumentException("Runtime pack is not VoxCPM2.", nameof(runtimePack));
    }

    public string EngineId => runtimePack.Manifest.EngineId;
    public string ModelRevision => runtimePack.Manifest.ModelRevision;

    public Task<bool> IsReadyAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(!disposed && Volatile.Read(ref session) is { HasExited: false });
    }

    public async Task EnsureReadyAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        await operationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await EnsureReadyCoreAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            operationGate.Release();
        }
    }

    public async Task<SynthesisResult> SynthesizeAsync(
        SynthesisRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ThrowIfDisposed();
        ValidateRequest(request);
        var operationGeneration = CaptureStopGeneration();
        await operationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        using var operationCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var registered = false;
        try
        {
            RegisterActiveOperation(operationCancellation, operationGeneration);
            registered = true;
            await EnsureReadyCoreAsync(operationCancellation.Token).ConfigureAwait(false);
            var current = Volatile.Read(ref session) ??
                          throw new RuntimePackException("VoxCPM2 sidecar is unavailable.");
            var payload = JsonSerializer.SerializeToUtf8Bytes(new VoxSynthesisRequest
            {
                Text = request.Text,
                Mode = "preset",
                ProfileId = request.VoiceId,
                ReferenceWavPath = null,
                CfgValue = 2.0f,
                InferenceTimesteps = request.QualitySteps,
                Seed = 42,
                ResponseFormat = "wav",
            }, JsonOptions);
            if (payload.Length > MaximumRequestBytes)
                throw new InvalidDataException("VoxCPM2 request exceeded the local request limit.");
            try
            {
                var response = await current.SendAuthenticatedAsync(
                    HttpMethod.Post,
                    "/v1/tts",
                    payload,
                    "application/json",
                    MaximumWaveBytes,
                    TimeSpan.FromMinutes(2),
                    operationCancellation.Token).ConfigureAwait(false);
                if (response.StatusCode != HttpStatusCode.OK ||
                    !string.Equals(response.ContentType, "audio/wav", StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException(
                        $"VoxCPM2 sidecar returned HTTP {(int)response.StatusCode} or an invalid content type.");
                if (!WaveFileInspector.TryReadPcm16(response.Body, out var metadata) ||
                    metadata is null || metadata.SampleRate != 48_000 || metadata.Channels != 1 ||
                    metadata.BitsPerSample != 16 || metadata.Duration <= TimeSpan.Zero ||
                    metadata.Duration > TimeSpan.FromMinutes(5))
                    throw new InvalidDataException("VoxCPM2 returned an invalid WAV response.");
                return new SynthesisResult
                {
                    WavBytes = response.Body,
                    SampleRate = metadata.SampleRate,
                    Channels = metadata.Channels,
                    BitsPerSample = metadata.BitsPerSample,
                    Duration = metadata.Duration,
                    EngineId = EngineId,
                    ModelRevision = ModelRevision,
                    VoiceId = request.VoiceId,
                };
            }
            catch
            {
                await StopCoreAsync(CancellationToken.None).ConfigureAwait(false);
                throw;
            }
        }
        finally
        {
            if (registered) ClearActiveOperation(operationCancellation);
            operationGate.Release();
        }
    }

    public async Task StopAsync(CancellationToken cancellationToken = default)
    {
        RequestStop();
        await StopDetachedAsync(Interlocked.Exchange(ref session, null)).ConfigureAwait(false);
        await operationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await StopCoreAsync(CancellationToken.None).ConfigureAwait(false);
        }
        finally
        {
            operationGate.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (disposed) return;
        disposed = true;
        RequestStop();
        await StopDetachedAsync(Interlocked.Exchange(ref session, null)).ConfigureAwait(false);
        await operationGate.WaitAsync().ConfigureAwait(false);
        try
        {
            await StopCoreAsync(CancellationToken.None).ConfigureAwait(false);
        }
        finally
        {
            operationGate.Release();
            operationGate.Dispose();
        }
    }

    private async Task EnsureReadyCoreAsync(CancellationToken cancellationToken)
    {
        if (Volatile.Read(ref session) is { HasExited: false }) return;
        await StopCoreAsync(CancellationToken.None).ConfigureAwait(false);
        var candidate = await sessionFactory.StartAsync(
            new SidecarLaunchOptions
            {
                RuntimePack = runtimePack,
                DataDirectory = dataDirectory,
                StartupTimeout = TimeSpan.FromSeconds(30),
            },
            cancellationToken).ConfigureAwait(false);
        try
        {
            await VerifyHealthAsync(candidate, cancellationToken).ConfigureAwait(false);
            Interlocked.Exchange(ref session, candidate);
        }
        catch
        {
            await candidate.StopAsync(CancellationToken.None).ConfigureAwait(false);
            await candidate.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private async Task VerifyHealthAsync(
        ISidecarClientSession candidate,
        CancellationToken cancellationToken)
    {
        var response = await candidate.SendAuthenticatedAsync(
            HttpMethod.Get,
            "/v1/health",
            ReadOnlyMemory<byte>.Empty,
            null,
            64 * 1024,
            TimeSpan.FromSeconds(10),
            cancellationToken).ConfigureAwait(false);
        if (response.StatusCode != HttpStatusCode.OK ||
            !string.Equals(response.ContentType, "application/json", StringComparison.OrdinalIgnoreCase))
            throw new RuntimePackException("VoxCPM2 health endpoint is unavailable.");
        VoxHealthDocument health;
        try
        {
            health = JsonSerializer.Deserialize<VoxHealthDocument>(response.Body, JsonOptions)
                     ?? throw new RuntimePackException("VoxCPM2 health response is empty.");
        }
        catch (JsonException exception)
        {
            throw new RuntimePackException($"VoxCPM2 health response is invalid: {exception.Message}");
        }
        var handshake = candidate.Handshake;
        if (health.SchemaVersion != 1 || !health.Ready ||
            !string.Equals(health.EngineId, runtimePack.Manifest.EngineId, StringComparison.Ordinal) ||
            !string.Equals(health.EngineVersion, runtimePack.Manifest.EngineVersion, StringComparison.Ordinal) ||
            !string.Equals(health.ModelRevision, runtimePack.Manifest.ModelRevision, StringComparison.Ordinal) ||
            health.Backend != runtimePack.Manifest.Backend ||
            !string.Equals(health.SessionId, candidate.SessionId, StringComparison.Ordinal) ||
            health.ProcessId != candidate.ProcessId ||
            health.ProcessId != handshake.ProcessId)
            throw new RuntimePackException("VoxCPM2 health identity does not match the owned sidecar.");
    }

    private async Task StopCoreAsync(CancellationToken cancellationToken)
    {
        var current = Interlocked.Exchange(ref session, null);
        await StopDetachedAsync(current, cancellationToken).ConfigureAwait(false);
    }

    private static async Task StopDetachedAsync(
        ISidecarClientSession? current,
        CancellationToken cancellationToken = default)
    {
        if (current is null) return;
        try { await current.StopAsync(cancellationToken).ConfigureAwait(false); }
        finally { await current.DisposeAsync().ConfigureAwait(false); }
    }

    private long CaptureStopGeneration()
    {
        lock (cancellationSync)
        {
            return stopGeneration;
        }
    }

    private void RegisterActiveOperation(CancellationTokenSource source, long expectedGeneration)
    {
        lock (cancellationSync)
        {
            if (stopGeneration != expectedGeneration)
                throw new OperationCanceledException("VoxCPM2 synthesis was superseded by stop.");
            if (activeOperationCancellation is not null)
                throw new InvalidOperationException("A VoxCPM2 synthesis operation is already active.");
            activeOperationCancellation = source;
        }
    }

    private void ClearActiveOperation(CancellationTokenSource source)
    {
        lock (cancellationSync)
        {
            if (ReferenceEquals(activeOperationCancellation, source)) activeOperationCancellation = null;
        }
    }

    private void RequestStop()
    {
        lock (cancellationSync)
        {
            stopGeneration = checked(stopGeneration + 1);
            try { activeOperationCancellation?.Cancel(); }
            catch (ObjectDisposedException) { }
        }
    }

    private static void ValidateRequest(SynthesisRequest request)
    {
        if (request.ReferenceAudio is not null || request.ReferenceTranscript is not null)
            throw new NotSupportedException(
                "VoxCPM2 reference audio is disabled until owner-controlled private-state handling is released.");
        if (string.IsNullOrWhiteSpace(request.Text) || request.Text.Length > 220 ||
            !string.Equals(request.Language, "ko", StringComparison.OrdinalIgnoreCase) ||
            request.VoiceId.Length is < 1 or > 64 ||
            !request.VoiceId.All(character =>
                character is >= 'a' and <= 'z' or >= '0' and <= '9' or '_') ||
            request.QualitySteps is not (6 or 8 or 10))
            throw new ArgumentException("VoxCPM2 synthesis request is invalid.", nameof(request));
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
    }

    private sealed record VoxHealthDocument
    {
        public required int SchemaVersion { get; init; }
        public required string EngineId { get; init; }
        public required string EngineVersion { get; init; }
        public required string ModelRevision { get; init; }
        public required AccelerationBackend Backend { get; init; }
        public required string SessionId { get; init; }
        public required int ProcessId { get; init; }
        public required bool Ready { get; init; }
    }

    private sealed record VoxSynthesisRequest
    {
        public required string Text { get; init; }
        public required string Mode { get; init; }
        [JsonPropertyName("profile_id")]
        public required string ProfileId { get; init; }
        [JsonPropertyName("reference_wav_path")]
        public required string? ReferenceWavPath { get; init; }
        [JsonPropertyName("cfg_value")]
        public required float CfgValue { get; init; }
        [JsonPropertyName("inference_timesteps")]
        public required int InferenceTimesteps { get; init; }
        public required int Seed { get; init; }
        [JsonPropertyName("response_format")]
        public required string ResponseFormat { get; init; }
    }
}
