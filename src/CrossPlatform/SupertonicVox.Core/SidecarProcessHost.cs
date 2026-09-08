using System.Buffers.Binary;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SupertonicVox.Core;

public sealed record SidecarHandshakeDocument
{
    public required int SchemaVersion { get; init; }
    public required int ProtocolVersion { get; init; }
    public required string EngineId { get; init; }
    public required string EngineVersion { get; init; }
    public required string ModelRevision { get; init; }
    public required AccelerationBackend Backend { get; init; }
    public required int ParentProcessId { get; init; }
    public required long ParentStartUtcTicks { get; init; }
    public required string SessionId { get; init; }
    public required string ListenerAddress { get; init; }
    public required int ProcessId { get; init; }
    public required int Port { get; init; }
    public required string Nonce { get; init; }
    public required string Proof { get; init; }
}

internal sealed record SidecarBootstrapRequest
{
    public required string Challenge { get; init; }
}

internal sealed record SidecarBootstrapResponse
{
    public required string Challenge { get; init; }
    public required string Proof { get; init; }
}

public sealed record SidecarLaunchOptions
{
    public required VerifiedRuntimePack RuntimePack { get; init; }
    public required string DataDirectory { get; init; }
    public TimeSpan StartupTimeout { get; init; } = TimeSpan.FromSeconds(30);
}

public sealed record SidecarHttpResponse(
    HttpStatusCode StatusCode,
    string? ContentType,
    byte[] Body,
    IReadOnlyDictionary<string, string> Headers);

public interface ISidecarClientSession : IAsyncDisposable
{
    SidecarHandshakeDocument Handshake { get; }
    string SessionId { get; }
    int ProcessId { get; }
    bool HasExited { get; }
    Task<SidecarHttpResponse> SendAuthenticatedAsync(
        HttpMethod method,
        string path,
        ReadOnlyMemory<byte> body,
        string? contentType,
        int maximumResponseBytes,
        TimeSpan timeout,
        CancellationToken cancellationToken = default);
    Task StopAsync(CancellationToken cancellationToken = default);
}

public interface ISidecarSessionFactory
{
    Task<ISidecarClientSession> StartAsync(
        SidecarLaunchOptions options,
        CancellationToken cancellationToken = default);
}

public static class SidecarHandshakeProof
{
    private const string HandshakeDomain = "svx-handshake-v2";
    private const string BootstrapDomain = "svx-listener-bootstrap-v2";

    public static string Compute(
        ReadOnlySpan<byte> sessionSecret,
        int schemaVersion,
        int protocolVersion,
        string engineId,
        string engineVersion,
        string modelRevision,
        AccelerationBackend backend,
        int parentProcessId,
        long parentStartUtcTicks,
        string sessionId,
        string listenerAddress,
        int processId,
        int port,
        string nonce)
    {
        using var hmac = new HMACSHA256(sessionSecret.ToArray());
        Append(hmac, HandshakeDomain);
        Append(hmac, schemaVersion.ToString(CultureInfo.InvariantCulture));
        Append(hmac, protocolVersion.ToString(CultureInfo.InvariantCulture));
        Append(hmac, engineId);
        Append(hmac, engineVersion);
        Append(hmac, modelRevision);
        Append(hmac, backend.ToString());
        Append(hmac, parentProcessId.ToString(CultureInfo.InvariantCulture));
        Append(hmac, parentStartUtcTicks.ToString(CultureInfo.InvariantCulture));
        Append(hmac, sessionId);
        Append(hmac, listenerAddress);
        Append(hmac, processId.ToString(CultureInfo.InvariantCulture));
        Append(hmac, port.ToString(CultureInfo.InvariantCulture));
        Append(hmac, nonce);
        hmac.TransformFinalBlock([], 0, 0);
        return Convert.ToHexStringLower(hmac.Hash!);
    }

    public static string ComputeBootstrap(
        ReadOnlySpan<byte> sessionSecret,
        SidecarHandshakeDocument handshake,
        string challenge)
    {
        using var hmac = new HMACSHA256(sessionSecret.ToArray());
        Append(hmac, BootstrapDomain);
        Append(hmac, handshake.SchemaVersion.ToString(CultureInfo.InvariantCulture));
        Append(hmac, handshake.ProtocolVersion.ToString(CultureInfo.InvariantCulture));
        Append(hmac, handshake.EngineId);
        Append(hmac, handshake.EngineVersion);
        Append(hmac, handshake.ModelRevision);
        Append(hmac, handshake.Backend.ToString());
        Append(hmac, handshake.ParentProcessId.ToString(CultureInfo.InvariantCulture));
        Append(hmac, handshake.ParentStartUtcTicks.ToString(CultureInfo.InvariantCulture));
        Append(hmac, handshake.SessionId);
        Append(hmac, handshake.ListenerAddress);
        Append(hmac, handshake.ProcessId.ToString(CultureInfo.InvariantCulture));
        Append(hmac, handshake.Port.ToString(CultureInfo.InvariantCulture));
        Append(hmac, handshake.Nonce);
        Append(hmac, challenge);
        hmac.TransformFinalBlock([], 0, 0);
        return Convert.ToHexStringLower(hmac.Hash!);
    }

    private static void Append(HMAC hmac, string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(length, bytes.Length);
        var lengthBytes = length.ToArray();
        hmac.TransformBlock(lengthBytes, 0, lengthBytes.Length, null, 0);
        hmac.TransformBlock(bytes, 0, bytes.Length, null, 0);
    }
}

public sealed class OwnedSidecarProcessHost : ISidecarSessionFactory
{
    private const int MaximumHandshakeBytes = 16 * 1024;
    private const int MaximumLogCharacters = 2 * 1024 * 1024;
    private static readonly JsonSerializerOptions HandshakeOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        Converters = { new JsonStringEnumConverter(namingPolicy: null, allowIntegerValues: false) },
    };
    private readonly RuntimePackVerifier packVerifier;
    private readonly ILoopbackListenerOwnerVerifier listenerOwnerVerifier;
    private readonly IReadOnlyDictionary<string, string> fixtureEnvironment;

    public OwnedSidecarProcessHost(RuntimePackVerifier packVerifier)
        : this(
            packVerifier,
            LoopbackListenerOwnerVerifier.CreateDefault(),
            new Dictionary<string, string>(StringComparer.Ordinal))
    {
    }

    internal OwnedSidecarProcessHost(
        RuntimePackVerifier packVerifier,
        IReadOnlyDictionary<string, string> fixtureEnvironment)
        : this(packVerifier, LoopbackListenerOwnerVerifier.CreateDefault(), fixtureEnvironment)
    {
    }

    internal OwnedSidecarProcessHost(
        RuntimePackVerifier packVerifier,
        ILoopbackListenerOwnerVerifier listenerOwnerVerifier,
        IReadOnlyDictionary<string, string> fixtureEnvironment)
    {
        this.packVerifier = packVerifier;
        this.listenerOwnerVerifier = listenerOwnerVerifier;
        this.fixtureEnvironment = fixtureEnvironment.ToDictionary(
            pair => pair.Key,
            pair => pair.Value,
            StringComparer.Ordinal);
    }

    public async Task<ISidecarClientSession> StartAsync(
        SidecarLaunchOptions options,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(options.RuntimePack);
        if (options.StartupTimeout <= TimeSpan.Zero || options.StartupTimeout > TimeSpan.FromMinutes(5))
            throw new ArgumentOutOfRangeException(nameof(options), "Sidecar startup timeout is invalid.");
        var pack = options.RuntimePack;
        var currentPack = await packVerifier.VerifyAsync(pack.RootPath, cancellationToken).ConfigureAwait(false);
        if (!string.Equals(currentPack.ManifestSha256, pack.ManifestSha256, StringComparison.Ordinal) ||
            !string.Equals(currentPack.PackFingerprint, pack.PackFingerprint, StringComparison.Ordinal))
            throw new RuntimePackException("Runtime pack identity changed before launch.");
        pack = currentPack;
        await packVerifier.VerifyPrelaunchAsync(pack, cancellationToken).ConfigureAwait(false);
        var entrypoint = ResolvePackPath(pack, pack.Manifest.EntryPoint);
        var dataDirectory = PrepareOwnerDataDirectory(options.DataDirectory);
        var statePath = Path.Combine(dataDirectory, "sidecar-process-state.json");
        await SidecarStaleProcessSweeper.SweepAsync(
            statePath,
            entrypoint,
            pack.PackFingerprint,
            cancellationToken).ConfigureAwait(false);

        var bearerToken = RandomNumberGenerator.GetBytes(32);
        var sessionSecret = RandomNumberGenerator.GetBytes(32);
        var nonce = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));
        var sessionId = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));
        var parent = Process.GetCurrentProcess();
        var parentStartUtcTicks = parent.StartTime.ToUniversalTime().Ticks;
        var startInfo = new ProcessStartInfo
        {
            FileName = entrypoint,
            WorkingDirectory = pack.RootPath,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var argument in pack.Manifest.LaunchArguments) startInfo.ArgumentList.Add(argument);
        SetEnvironment(startInfo, "SVX_LOCAL_AUTH_TOKEN", Convert.ToBase64String(bearerToken));
        SetEnvironment(startInfo, "SVX_SESSION_SECRET", Convert.ToBase64String(sessionSecret));
        SetEnvironment(startInfo, "SVX_SESSION_NONCE", nonce);
        SetEnvironment(startInfo, "SVX_SESSION_ID", sessionId);
        SetEnvironment(startInfo, "SVX_PARENT_PID", parent.Id.ToString(CultureInfo.InvariantCulture));
        SetEnvironment(
            startInfo,
            "SVX_PARENT_START_UTC_TICKS",
            parentStartUtcTicks.ToString(CultureInfo.InvariantCulture));
        SetEnvironment(startInfo, "SVX_DATA_DIRECTORY", dataDirectory);
        SetEnvironment(startInfo, "SVX_ENGINE_BACKEND", pack.Manifest.Backend.ToString());
        SetEnvironment(startInfo, "HF_HUB_OFFLINE", "1");
        SetEnvironment(startInfo, "TRANSFORMERS_OFFLINE", "1");
        SetEnvironment(startInfo, "HF_DATASETS_OFFLINE", "1");
        SetEnvironment(startInfo, "MODELSCOPE_OFFLINE", "1");
        foreach (var name in new[]
                 {
                     "ALL_PROXY", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
                     "all_proxy", "http_proxy", "https_proxy", "no_proxy",
                 })
            SetEnvironment(startInfo, name, string.Empty);
        foreach (var pair in fixtureEnvironment) SetEnvironment(startInfo, pair.Key, pair.Value);

        var process = new Process { StartInfo = startInfo, EnableRaisingEvents = true };
        try
        {
            if (!process.Start()) throw new RuntimePackException("Could not start the verified sidecar process.");
        }
        catch
        {
            process.Dispose();
            CryptographicOperations.ZeroMemory(bearerToken);
            CryptographicOperations.ZeroMemory(sessionSecret);
            throw;
        }
        finally
        {
            startInfo.Environment.Remove("SVX_LOCAL_AUTH_TOKEN");
            startInfo.Environment.Remove("SVX_SESSION_SECRET");
        }
        var stderrTask = DrainBoundedAsync(process.StandardError, MaximumLogCharacters);
        try
        {
            using var startupSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            startupSource.CancelAfter(options.StartupTimeout);
            var line = await ReadBoundedLineAsync(
                process.StandardOutput,
                MaximumHandshakeBytes,
                startupSource.Token).ConfigureAwait(false);
            if (process.HasExited)
                throw new RuntimePackException("Sidecar exited before its handshake was accepted.");
            var handshake = ParseAndVerifyHandshake(
                line,
                process.Id,
                pack,
                nonce,
                sessionId,
                parent.Id,
                parentStartUtcTicks,
                sessionSecret);
            if (process.HasExited)
                throw new RuntimePackException("Sidecar exited after handshake and before authentication.");
            await listenerOwnerVerifier.VerifyOwnedAsync(
                process.Id,
                handshake.Port,
                startupSource.Token).ConfigureAwait(false);
            await VerifyListenerBootstrapAsync(
                handshake,
                sessionSecret,
                startupSource.Token).ConfigureAwait(false);
            if (process.HasExited)
                throw new RuntimePackException("Sidecar exited after listener bootstrap.");
            var stdoutTask = DrainBoundedAsync(process.StandardOutput, MaximumLogCharacters);
            await SidecarStaleProcessSweeper.WriteStateAsync(
                statePath,
                new SidecarProcessState
                {
                    SchemaVersion = 1,
                    ProcessId = process.Id,
                    ProcessStartUtcTicks = process.StartTime.ToUniversalTime().Ticks,
                    ExecutablePath = Path.GetFullPath(entrypoint),
                    PackFingerprint = pack.PackFingerprint,
                },
                cancellationToken).ConfigureAwait(false);
            return new OwnedSidecarClientSession(
                process,
                handshake,
                sessionId,
                bearerToken,
                listenerOwnerVerifier,
                statePath,
                stdoutTask,
                stderrTask);
        }
        catch
        {
            TryKill(process);
            process.Dispose();
            CryptographicOperations.ZeroMemory(bearerToken);
            CryptographicOperations.ZeroMemory(sessionSecret);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sessionSecret);
        }
    }

    private static SidecarHandshakeDocument ParseAndVerifyHandshake(
        string line,
        int ownedProcessId,
        VerifiedRuntimePack pack,
        string expectedNonce,
        string expectedSessionId,
        int expectedParentProcessId,
        long expectedParentStartUtcTicks,
        byte[] sessionSecret)
    {
        SidecarHandshakeDocument handshake;
        try
        {
            handshake = JsonSerializer.Deserialize<SidecarHandshakeDocument>(line, HandshakeOptions)
                        ?? throw new RuntimePackException("Sidecar handshake is empty.");
        }
        catch (JsonException exception)
        {
            throw new RuntimePackException($"Sidecar handshake is invalid: {exception.Message}");
        }
        if (handshake.SchemaVersion != 1 ||
            handshake.ProtocolVersion != pack.Manifest.ProtocolVersion ||
            handshake.ParentProcessId != expectedParentProcessId ||
            handshake.ParentStartUtcTicks != expectedParentStartUtcTicks ||
            !string.Equals(handshake.SessionId, expectedSessionId, StringComparison.Ordinal) ||
            !string.Equals(handshake.ListenerAddress, "127.0.0.1", StringComparison.Ordinal) ||
            handshake.ProcessId != ownedProcessId ||
            handshake.Port is < 1024 or > 65535 ||
            !string.Equals(handshake.EngineId, pack.Manifest.EngineId, StringComparison.Ordinal) ||
            !string.Equals(handshake.EngineVersion, pack.Manifest.EngineVersion, StringComparison.Ordinal) ||
            !string.Equals(handshake.ModelRevision, pack.Manifest.ModelRevision, StringComparison.Ordinal) ||
            handshake.Backend != pack.Manifest.Backend ||
            !string.Equals(handshake.Nonce, expectedNonce, StringComparison.Ordinal) ||
            !IsLowerHex(handshake.SessionId, 32) ||
            !IsLowerHex(handshake.Nonce, 64) ||
            handshake.Proof.Length != 64 ||
            !handshake.Proof.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f'))
            throw new RuntimePackException("Sidecar handshake identity does not match the verified pack.");
        var expectedProof = SidecarHandshakeProof.Compute(
            sessionSecret,
            handshake.SchemaVersion,
            handshake.ProtocolVersion,
            handshake.EngineId,
            handshake.EngineVersion,
            handshake.ModelRevision,
            handshake.Backend,
            handshake.ParentProcessId,
            handshake.ParentStartUtcTicks,
            handshake.SessionId,
            handshake.ListenerAddress,
            handshake.ProcessId,
            handshake.Port,
            handshake.Nonce);
        if (!CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(expectedProof),
                Encoding.ASCII.GetBytes(handshake.Proof)))
            throw new RuntimePackException("Sidecar handshake proof is invalid.");
        return handshake;
    }

    private static async Task VerifyListenerBootstrapAsync(
        SidecarHandshakeDocument handshake,
        byte[] sessionSecret,
        CancellationToken cancellationToken)
    {
        var challenge = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        var payload = JsonSerializer.SerializeToUtf8Bytes(
            new SidecarBootstrapRequest { Challenge = challenge },
            HandshakeOptions);
        using var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseProxy = false,
            AutomaticDecompression = DecompressionMethods.None,
            ConnectTimeout = TimeSpan.FromSeconds(2),
        };
        using var client = new HttpClient(handler)
        {
            BaseAddress = new Uri($"http://127.0.0.1:{handshake.Port}/", UriKind.Absolute),
            Timeout = Timeout.InfiniteTimeSpan,
        };
        using var request = new HttpRequestMessage(HttpMethod.Post, "v1/bootstrap-challenge")
        {
            Content = new ByteArrayContent(payload),
        };
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(5));
        using var response = await client.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            timeout.Token).ConfigureAwait(false);
        if (response.StatusCode != HttpStatusCode.OK ||
            !string.Equals(
                response.Content.Headers.ContentType?.MediaType,
                "application/json",
                StringComparison.OrdinalIgnoreCase) ||
            response.Content.Headers.ContentLength is > 4096)
            throw new RuntimePackException("Sidecar listener bootstrap response is invalid.");
        await using var stream = await response.Content.ReadAsStreamAsync(timeout.Token).ConfigureAwait(false);
        var body = await ReadBoundedBytesAsync(stream, 4096, timeout.Token).ConfigureAwait(false);
        SidecarBootstrapResponse bootstrap;
        try
        {
            bootstrap = JsonSerializer.Deserialize<SidecarBootstrapResponse>(body, HandshakeOptions)
                        ?? throw new RuntimePackException("Sidecar listener bootstrap response is empty.");
        }
        catch (JsonException exception)
        {
            throw new RuntimePackException($"Sidecar listener bootstrap response is invalid: {exception.Message}");
        }
        var expectedProof = SidecarHandshakeProof.ComputeBootstrap(sessionSecret, handshake, challenge);
        if (!string.Equals(bootstrap.Challenge, challenge, StringComparison.Ordinal) ||
            !IsLowerHex(bootstrap.Proof, 64) ||
            !CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(expectedProof),
                Encoding.ASCII.GetBytes(bootstrap.Proof)))
            throw new RuntimePackException("Sidecar listener bootstrap proof is invalid.");
    }

    private static async Task<byte[]> ReadBoundedBytesAsync(
        Stream stream,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        using var output = new MemoryStream(Math.Min(maximumBytes, 4096));
        var buffer = new byte[4096];
        while (true)
        {
            var read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0) return output.ToArray();
            if (output.Length + read > maximumBytes)
                throw new RuntimePackException("Sidecar listener bootstrap response exceeded its limit.");
            await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
        }
    }

    private static bool IsLowerHex(string value, int length) =>
        value.Length == length &&
        value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static async Task<string> ReadBoundedLineAsync(
        StreamReader reader,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        var output = new StringBuilder();
        var buffer = new char[256];
        while (true)
        {
            var read = await reader.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false);
            if (read == 0) throw new RuntimePackException("Sidecar closed stdout before handshake.");
            for (var index = 0; index < read; index++)
            {
                var character = buffer[index];
                if (character == '\n')
                {
                    if (Encoding.UTF8.GetByteCount(output.ToString()) > maximumBytes)
                        throw new RuntimePackException("Sidecar handshake exceeded its size limit.");
                    return output.ToString().TrimEnd('\r');
                }
                output.Append(character);
                if (output.Length > maximumBytes)
                    throw new RuntimePackException("Sidecar handshake exceeded its size limit.");
            }
        }
    }

    private static async Task DrainBoundedAsync(StreamReader reader, int maximumCharacters)
    {
        var buffer = new char[4096];
        var total = 0;
        while (true)
        {
            var read = await reader.ReadAsync(buffer).ConfigureAwait(false);
            if (read == 0) return;
            total = checked(total + read);
            if (total > maximumCharacters)
                throw new RuntimePackException("Sidecar diagnostic output exceeded its limit.");
        }
    }

    private static string PrepareOwnerDataDirectory(string value)
    {
        var path = Path.GetFullPath(value);
        Directory.CreateDirectory(path);
        var info = new DirectoryInfo(path);
        if (info.LinkTarget is not null || (info.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new RuntimePackException("Sidecar data directory cannot be linked.");
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        return path;
    }

    private static string ResolvePackPath(VerifiedRuntimePack pack, string relative)
    {
        var root = Path.GetFullPath(pack.RootPath);
        var path = Path.GetFullPath(Path.Combine(root, relative.Replace('/', Path.DirectorySeparatorChar)));
        var comparison = OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;
        if (!path.StartsWith(root + Path.DirectorySeparatorChar, comparison))
            throw new RuntimePackException("Sidecar entrypoint escaped the verified pack.");
        return path;
    }

    private static void SetEnvironment(ProcessStartInfo startInfo, string name, string value) =>
        startInfo.Environment[name] = value;

    internal static void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
        }
        catch
        {
        }
    }
}

internal sealed class OwnedSidecarClientSession : ISidecarClientSession
{
    private readonly Process process;
    private readonly byte[] bearerToken;
    private readonly ILoopbackListenerOwnerVerifier listenerOwnerVerifier;
    private readonly string statePath;
    private readonly Task stdoutTask;
    private readonly Task stderrTask;
    private readonly HttpClient client;
    private readonly SemaphoreSlim requestGate = new(1, 1);
    private int firstAuthenticatedRequestCompleted;
    private int tokenZeroed;
    private int stopped;

    public OwnedSidecarClientSession(
        Process process,
        SidecarHandshakeDocument handshake,
        string sessionId,
        byte[] bearerToken,
        ILoopbackListenerOwnerVerifier listenerOwnerVerifier,
        string statePath,
        Task stdoutTask,
        Task stderrTask)
    {
        this.process = process;
        Handshake = handshake;
        SessionId = sessionId;
        this.bearerToken = bearerToken;
        this.listenerOwnerVerifier = listenerOwnerVerifier;
        this.statePath = statePath;
        this.stdoutTask = stdoutTask;
        this.stderrTask = stderrTask;
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseProxy = false,
            AutomaticDecompression = DecompressionMethods.None,
            ConnectTimeout = TimeSpan.FromSeconds(5),
        };
        client = new HttpClient(handler, disposeHandler: true)
        {
            BaseAddress = new Uri($"http://127.0.0.1:{handshake.Port}/", UriKind.Absolute),
            Timeout = Timeout.InfiniteTimeSpan,
        };
    }

    public SidecarHandshakeDocument Handshake { get; }
    public string SessionId { get; }
    public int ProcessId => process.Id;
    public bool HasExited => process.HasExited;
    internal bool RetainsLaunchSecrets =>
        process.StartInfo.Environment.ContainsKey("SVX_LOCAL_AUTH_TOKEN") ||
        process.StartInfo.Environment.ContainsKey("SVX_SESSION_SECRET");

    public async Task<SidecarHttpResponse> SendAuthenticatedAsync(
        HttpMethod method,
        string path,
        ReadOnlyMemory<byte> body,
        string? contentType,
        int maximumResponseBytes,
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        if (method is not { Method: "GET" or "POST" } ||
            string.IsNullOrEmpty(path) || !path.StartsWith("/v1/", StringComparison.Ordinal) ||
            path.Contains('?', StringComparison.Ordinal) || path.Contains('#', StringComparison.Ordinal) ||
            maximumResponseBytes is < 1 or > 256 * 1024 * 1024 ||
            timeout <= TimeSpan.Zero || timeout > TimeSpan.FromMinutes(10))
            throw new ArgumentException("Sidecar HTTP request contract is invalid.");
        await requestGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        var isFirstRequest = Volatile.Read(ref firstAuthenticatedRequestCompleted) == 0;
        try
        {
            if (Volatile.Read(ref stopped) != 0 || process.HasExited)
                throw new RuntimePackException("Owned sidecar process is not running.");
            if (isFirstRequest)
                await listenerOwnerVerifier.VerifyOwnedAsync(
                    process.Id,
                    Handshake.Port,
                    cancellationToken).ConfigureAwait(false);

            using var request = new HttpRequestMessage(method, path[1..]);
            request.Headers.Authorization = new AuthenticationHeaderValue(
                "Bearer",
                Convert.ToBase64String(bearerToken));
            if (!body.IsEmpty)
            {
                var content = new ByteArrayContent(body.ToArray());
                if (contentType is not null)
                    content.Headers.ContentType = MediaTypeHeaderValue.Parse(contentType);
                request.Content = content;
            }
            using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutSource.CancelAfter(timeout);
            using var response = await client.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                timeoutSource.Token).ConfigureAwait(false);
            if (response.Content.Headers.ContentLength is > 0 and var declaredLength &&
                declaredLength > maximumResponseBytes)
                throw new RuntimePackException("Sidecar response exceeded its declared size limit.");
            await using var stream = await response.Content.ReadAsStreamAsync(timeoutSource.Token)
                .ConfigureAwait(false);
            var bytes = await ReadResponseBoundedAsync(
                stream,
                maximumResponseBytes,
                timeoutSource.Token).ConfigureAwait(false);
            if (isFirstRequest)
            {
                await listenerOwnerVerifier.VerifyOwnedAsync(
                    process.Id,
                    Handshake.Port,
                    timeoutSource.Token).ConfigureAwait(false);
                Volatile.Write(ref firstAuthenticatedRequestCompleted, 1);
            }
            var headers = response.Headers.Concat(response.Content.Headers)
                .ToDictionary(
                    pair => pair.Key,
                    pair => string.Join(",", pair.Value),
                    StringComparer.OrdinalIgnoreCase);
            return new SidecarHttpResponse(
                response.StatusCode,
                response.Content.Headers.ContentType?.MediaType,
                bytes,
                headers);
        }
        catch
        {
            if (isFirstRequest) await FailClosedAsync().ConfigureAwait(false);
            throw;
        }
        finally
        {
            requestGate.Release();
        }
    }

    public async Task StopAsync(CancellationToken cancellationToken = default)
    {
        if (Interlocked.Exchange(ref stopped, 1) != 0) return;
        client.Dispose();
        OwnedSidecarProcessHost.TryKill(process);
        try
        {
            await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            OwnedSidecarProcessHost.TryKill(process);
            throw;
        }
        finally
        {
            TryDeleteState(statePath);
            ZeroBearerToken();
            process.Dispose();
        }
        try { await Task.WhenAll(stdoutTask, stderrTask).WaitAsync(TimeSpan.FromSeconds(2), cancellationToken); }
        catch (Exception exception) when (exception is TimeoutException or RuntimePackException or IOException)
        {
        }
    }

    public async ValueTask DisposeAsync() => await StopAsync().ConfigureAwait(false);

    private async Task FailClosedAsync()
    {
        if (Interlocked.Exchange(ref stopped, 1) != 0)
        {
            ZeroBearerToken();
            return;
        }
        client.Dispose();
        OwnedSidecarProcessHost.TryKill(process);
        try
        {
            if (!process.HasExited)
                await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is InvalidOperationException or TimeoutException)
        {
            OwnedSidecarProcessHost.TryKill(process);
        }
        finally
        {
            TryDeleteState(statePath);
            ZeroBearerToken();
            process.Dispose();
        }
    }

    private void ZeroBearerToken()
    {
        if (Interlocked.Exchange(ref tokenZeroed, 1) == 0)
            CryptographicOperations.ZeroMemory(bearerToken);
    }

    private static async Task<byte[]> ReadResponseBoundedAsync(
        Stream stream,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        using var memory = new MemoryStream(Math.Min(maximumBytes, 64 * 1024));
        var buffer = new byte[64 * 1024];
        while (true)
        {
            var read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0) return memory.ToArray();
            if (memory.Length + read > maximumBytes)
                throw new RuntimePackException("Sidecar response exceeded its size limit.");
            await memory.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
        }
    }

    private static void TryDeleteState(string path)
    {
        try { File.Delete(path); }
        catch { }
    }
}

internal sealed record SidecarProcessState
{
    public required int SchemaVersion { get; init; }
    public required int ProcessId { get; init; }
    public required long ProcessStartUtcTicks { get; init; }
    public required string ExecutablePath { get; init; }
    public required string PackFingerprint { get; init; }
}

internal static class SidecarStaleProcessSweeper
{
    private const int MaximumStateBytes = 64 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    public static async Task SweepAsync(
        string statePath,
        string expectedExecutable,
        string expectedPackFingerprint,
        CancellationToken cancellationToken)
    {
        if (!File.Exists(statePath)) return;
        SidecarProcessState? state = null;
        try
        {
            var info = new FileInfo(statePath);
            if (info.LinkTarget is not null || info.Length is < 1 or > MaximumStateBytes)
                throw new RuntimePackException("Sidecar process state is invalid.");
            var bytes = await File.ReadAllBytesAsync(statePath, cancellationToken).ConfigureAwait(false);
            state = JsonSerializer.Deserialize<SidecarProcessState>(bytes, JsonOptions);
            if (state is null || state.SchemaVersion != 1 || state.ProcessId <= 0 ||
                state.ProcessStartUtcTicks <= 0 || state.PackFingerprint.Length != 64 ||
                !string.Equals(
                    CanonicalExecutablePath(state.ExecutablePath),
                    CanonicalExecutablePath(expectedExecutable),
                    PathComparison) ||
                !string.Equals(state.PackFingerprint, expectedPackFingerprint, StringComparison.Ordinal))
                throw new RuntimePackException("Sidecar process state identity is invalid.");
            using var process = Process.GetProcessById(state.ProcessId);
            var actualStart = process.StartTime.ToUniversalTime().Ticks;
            var actualExecutable = process.MainModule?.FileName;
            if (actualStart == state.ProcessStartUtcTicks && actualExecutable is not null &&
                string.Equals(
                    CanonicalExecutablePath(actualExecutable),
                    CanonicalExecutablePath(expectedExecutable),
                    PathComparison))
            {
                process.Kill(entireProcessTree: true);
                await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
            }
        }
        catch (Exception exception) when (exception is
               IOException or UnauthorizedAccessException or ArgumentException or
               InvalidOperationException or JsonException or RuntimePackException)
        {
        }
        finally
        {
            try { File.Delete(statePath); }
            catch { }
        }
    }

    public static async Task WriteStateAsync(
        string statePath,
        SidecarProcessState state,
        CancellationToken cancellationToken)
    {
        var directory = Path.GetDirectoryName(statePath)
                        ?? throw new RuntimePackException("Sidecar state directory is unavailable.");
        Directory.CreateDirectory(directory);
        var temporary = Path.Combine(
            directory,
            $".{Path.GetFileName(statePath)}.{Guid.NewGuid():N}.tmp");
        try
        {
            var bytes = JsonSerializer.SerializeToUtf8Bytes(state, JsonOptions);
            await using (var stream = new FileStream(
                             temporary,
                             FileMode.CreateNew,
                             FileAccess.Write,
                             FileShare.None,
                             4096,
                             FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
            }
            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(temporary, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            File.Move(temporary, statePath, true);
        }
        finally
        {
            try { File.Delete(temporary); }
            catch { }
        }
    }

    private static StringComparison PathComparison =>
        OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

    private static string CanonicalExecutablePath(string path)
    {
        var fullPath = Path.GetFullPath(path);
        if (OperatingSystem.IsWindows()) return fullPath;

        var canonical = RealPath(fullPath, nint.Zero);
        if (canonical == nint.Zero) return fullPath;
        try
        {
            return Marshal.PtrToStringUTF8(canonical) ?? fullPath;
        }
        finally
        {
            Free(canonical);
        }
    }

    [DllImport("libc", EntryPoint = "realpath", SetLastError = true)]
    private static extern nint RealPath(string path, nint resolvedPath);

    [DllImport("libc", EntryPoint = "free")]
    private static extern void Free(nint pointer);
}
