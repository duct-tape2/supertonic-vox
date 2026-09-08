using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using Supertonic;

namespace SupertonicVox.Core;

public sealed record SupertonicProviderOptions
{
    public required string OnnxDirectory { get; init; }
    public required string VoiceStyleDirectory { get; init; }
    public int MaximumTextCharacters { get; init; } = 2_000;
    public float MaximumDurationSeconds { get; init; } = 120f;
    public int MaximumWavBytes { get; init; } = 24 * 1024 * 1024;
}

public static class SupertonicModelManifest
{
    public const string EngineId = "supertonic-3";
    public const string UpstreamCodeRevision = "5379cc4e4297cec249a8a71283fc44d55ec327f1";
    public const string ModelRevision = "3cadd1ee6394adea1bd021217a0e650ede09a323";

    public static IReadOnlyDictionary<string, ModelFileIdentity> RequiredOnnxFiles { get; } =
        new Dictionary<string, ModelFileIdentity>(StringComparer.Ordinal)
        {
            ["duration_predictor.onnx"] = new(
                3_700_147,
                "c3eb91414d5ff8a7a239b7fe9e34e7e2bf8a8140d8375ffb14718b1c639325db"),
            ["text_encoder.onnx"] = new(
                36_416_150,
                "c7befd5ea8c3119769e8a6c1486c4edc6a3bc8365c67621c881bbb774b9902ff"),
            ["vector_estimator.onnx"] = new(
                256_534_781,
                "883ac868ea0275ef0e991524dc64f16b3c0376efd7c320af6b53f5b780d7c61c"),
            ["vocoder.onnx"] = new(
                101_424_195,
                "085de76dd8e8d5836d6ca66826601f615939218f90e519f70ee8a36ed2a4c4ba"),
            ["tts.json"] = new(
                8_253,
                "42078d3aef1cd43ab43021f3c54f47d2d75ceb4e75f627f118890128b06a0d09"),
            ["unicode_indexer.json"] = new(
                277_676,
                "9bf7346e43883a81f8645c81224f786d43c5b57f3641f6e7671a7d6c493cb24f"),
        };

    public static IReadOnlyDictionary<string, ModelFileIdentity> RequiredVoiceFiles { get; } =
        new Dictionary<string, ModelFileIdentity>(StringComparer.OrdinalIgnoreCase)
        {
            ["M1.json"] = new(
                291_748,
                "e35604687f5d23694b8e91593a93eec0e4eca6c0b02bb8ed69139ab2ea6b0a5b"),
        };
}

public sealed record ModelFileIdentity(long SizeBytes, string Sha256);

public sealed class SupertonicEngineProvider : IEngineProvider
{
    private readonly SupertonicProviderOptions options;
    private readonly SemaphoreSlim initializationGate = new(1, 1);
    private readonly SemaphoreSlim synthesisGate = new(1, 1);
    private readonly object operationSync = new();
    private TextToSpeech? textToSpeech;
    private CancellationTokenSource? currentOperation;
    private bool disposed;

    public SupertonicEngineProvider(SupertonicProviderOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        this.options = options with
        {
            OnnxDirectory = Path.GetFullPath(options.OnnxDirectory),
            VoiceStyleDirectory = Path.GetFullPath(options.VoiceStyleDirectory),
        };
        if (options.MaximumTextCharacters is < 1 or > 20_000)
            throw new ArgumentOutOfRangeException(nameof(options.MaximumTextCharacters));
        if (!float.IsFinite(options.MaximumDurationSeconds) || options.MaximumDurationSeconds is < 1 or > 600)
            throw new ArgumentOutOfRangeException(nameof(options.MaximumDurationSeconds));
        if (options.MaximumWavBytes is < 44 or > 128 * 1024 * 1024)
            throw new ArgumentOutOfRangeException(nameof(options.MaximumWavBytes));
    }

    public string EngineId => SupertonicModelManifest.EngineId;
    public string ModelRevision => SupertonicModelManifest.ModelRevision;

    public async Task<bool> IsReadyAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        try
        {
            await ValidateAssetsAsync(cancellationToken).ConfigureAwait(false);
            return true;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or CryptographicException)
        {
            return false;
        }
    }

    public async Task EnsureReadyAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        if (textToSpeech is not null) return;
        await initializationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            if (textToSpeech is not null) return;
            await ValidateAssetsAsync(cancellationToken).ConfigureAwait(false);
            textToSpeech = await Task.Run(
                () => Helper.LoadTextToSpeech(options.OnnxDirectory),
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            initializationGate.Release();
        }
    }

    public async Task<SynthesisResult> SynthesizeAsync(
        SynthesisRequest request,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ValidateRequest(request);
        await EnsureReadyAsync(cancellationToken).ConfigureAwait(false);
        await synthesisGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        CancellationTokenSource? operation = null;
        try
        {
            operation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            lock (operationSync)
            {
                ThrowIfDisposed();
                currentOperation = operation;
            }

            var stylePath = ResolveVoicePath(request.VoiceId);
            var style = await Task.Run(
                () => Helper.LoadVoiceStyle([stylePath]),
                operation.Token).ConfigureAwait(false);
            var inference = textToSpeech ?? throw new InvalidOperationException("Supertonic is not initialized.");
            var result = await Task.Run(
                () => inference.Call(
                    request.Text,
                    request.Language,
                    style,
                    request.QualitySteps,
                    request.Speed,
                    maxDurationSeconds: options.MaximumDurationSeconds,
                    cancellationToken: operation.Token),
                operation.Token).ConfigureAwait(false);

            operation.Token.ThrowIfCancellationRequested();
            var durationSeconds = result.duration.Single();
            if (!float.IsFinite(durationSeconds) || durationSeconds <= 0 ||
                durationSeconds > options.MaximumDurationSeconds)
                throw new InvalidDataException("Supertonic returned an invalid duration.");
            var expectedSamples = checked((int)Math.Ceiling(durationSeconds * inference.SampleRate));
            var sampleCount = Math.Min(expectedSamples, result.wav.Length);
            if (sampleCount <= 0) throw new InvalidDataException("Supertonic returned no audio samples.");
            var wav = CreateMonoPcm16Wave(result.wav.AsSpan(0, sampleCount), inference.SampleRate);
            if (wav.Length > options.MaximumWavBytes)
                throw new InvalidDataException("Generated WAV exceeds the configured response limit.");

            return new SynthesisResult
            {
                WavBytes = wav,
                SampleRate = inference.SampleRate,
                Channels = 1,
                BitsPerSample = 16,
                Duration = TimeSpan.FromSeconds(sampleCount / (double)inference.SampleRate),
                EngineId = EngineId,
                ModelRevision = ModelRevision,
                VoiceId = request.VoiceId.ToUpperInvariant(),
            };
        }
        finally
        {
            lock (operationSync)
            {
                if (ReferenceEquals(currentOperation, operation)) currentOperation = null;
            }
            operation?.Dispose();
            synthesisGate.Release();
        }
    }

    public Task StopAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (operationSync) currentOperation?.Cancel();
        return Task.CompletedTask;
    }

    public async ValueTask DisposeAsync()
    {
        if (disposed) return;
        disposed = true;
        lock (operationSync) currentOperation?.Cancel();
        await initializationGate.WaitAsync().ConfigureAwait(false);
        try
        {
            await synthesisGate.WaitAsync().ConfigureAwait(false);
            try
            {
                textToSpeech?.Dispose();
                textToSpeech = null;
            }
            finally
            {
                synthesisGate.Release();
            }
        }
        finally
        {
            initializationGate.Release();
        }
    }

    private async Task ValidateAssetsAsync(CancellationToken cancellationToken)
    {
        await ValidateDirectoryAsync(
            options.OnnxDirectory,
            SupertonicModelManifest.RequiredOnnxFiles,
            cancellationToken).ConfigureAwait(false);
        await ValidateDirectoryAsync(
            options.VoiceStyleDirectory,
            SupertonicModelManifest.RequiredVoiceFiles,
            cancellationToken).ConfigureAwait(false);
    }

    private static async Task ValidateDirectoryAsync(
        string directory,
        IReadOnlyDictionary<string, ModelFileIdentity> expected,
        CancellationToken cancellationToken)
    {
        if (!Directory.Exists(directory)) throw new DirectoryNotFoundException(directory);
        foreach (var pair in expected)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var path = Path.GetFullPath(Path.Combine(directory, pair.Key));
            if (!Path.GetDirectoryName(path)!.Equals(directory, StringComparison.Ordinal))
                throw new InvalidDataException("Model manifest contains an unsafe filename.");
            var info = new FileInfo(path);
            if (!info.Exists || info.Length != pair.Value.SizeBytes)
                throw new InvalidDataException($"Supertonic asset size mismatch: {pair.Key}");
            var actual = await ComputeSha256Async(path, cancellationToken).ConfigureAwait(false);
            if (!actual.Equals(pair.Value.Sha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException($"Supertonic asset hash mismatch: {pair.Key}");
        }
    }

    private static async Task<string> ComputeSha256Async(string path, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            1024 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        var hash = await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false);
        return Convert.ToHexStringLower(hash);
    }

    private string ResolveVoicePath(string voiceId)
    {
        var fileName = $"{voiceId.ToUpperInvariant()}.json";
        if (!SupertonicModelManifest.RequiredVoiceFiles.ContainsKey(fileName))
            throw new ArgumentException("The requested Supertonic voice is not in the verified manifest.", nameof(voiceId));
        var path = Path.GetFullPath(Path.Combine(options.VoiceStyleDirectory, fileName));
        if (!Path.GetDirectoryName(path)!.Equals(options.VoiceStyleDirectory, StringComparison.Ordinal))
            throw new InvalidDataException("Voice path escaped the verified model directory.");
        return path;
    }

    private void ValidateRequest(SynthesisRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (string.IsNullOrWhiteSpace(request.Text)) throw new ArgumentException("Text is required.", nameof(request));
        if (request.Text.Length > options.MaximumTextCharacters)
            throw new ArgumentException("Text exceeds the configured local synthesis limit.", nameof(request));
        if (!string.Equals(request.Language, "ko", StringComparison.Ordinal))
            throw new ArgumentException("The first release enables Korean synthesis only.", nameof(request));
        if (!float.IsFinite(request.Speed) || request.Speed is < 0.5f or > 2f)
            throw new ArgumentOutOfRangeException(nameof(request), "Speed must be between 0.5 and 2.0.");
        if (request.QualitySteps is < 1 or > 16)
            throw new ArgumentOutOfRangeException(nameof(request), "Quality steps must be between 1 and 16.");
        if (request.ReferenceAudio is not null || !string.IsNullOrWhiteSpace(request.ReferenceTranscript))
            throw new NotSupportedException("Supertonic fixed voices do not accept reference audio.");
        _ = ResolveVoicePath(request.VoiceId);
    }

    private static byte[] CreateMonoPcm16Wave(ReadOnlySpan<float> samples, int sampleRate)
    {
        if (sampleRate is < 8_000 or > 192_000) throw new InvalidDataException("Invalid sample rate.");
        var dataBytes = checked(samples.Length * sizeof(short));
        var output = new byte[checked(44 + dataBytes)];
        using var stream = new MemoryStream(output, writable: true);
        using var writer = new BinaryWriter(stream, Encoding.ASCII, leaveOpen: true);
        writer.Write(Encoding.ASCII.GetBytes("RIFF"));
        writer.Write(checked(36 + dataBytes));
        writer.Write(Encoding.ASCII.GetBytes("WAVEfmt "));
        writer.Write(16);
        writer.Write((short)1);
        writer.Write((short)1);
        writer.Write(sampleRate);
        writer.Write(checked(sampleRate * sizeof(short)));
        writer.Write((short)sizeof(short));
        writer.Write((short)16);
        writer.Write(Encoding.ASCII.GetBytes("data"));
        writer.Write(dataBytes);
        foreach (var sample in samples)
        {
            if (!float.IsFinite(sample)) throw new InvalidDataException("Supertonic returned non-finite audio.");
            var clamped = Math.Clamp(sample, -1f, 1f);
            writer.Write((short)Math.Round(clamped * short.MaxValue));
        }
        return output;
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(disposed, this);
}
