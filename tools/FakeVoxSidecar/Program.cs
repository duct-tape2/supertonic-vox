using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using SupertonicVox.Core;

var mode = Environment.GetEnvironmentVariable("SVX_FIXTURE_MODE") ?? "normal";
if (mode == "exit-before-handshake") return 17;

var token = RequireSecret("SVX_LOCAL_AUTH_TOKEN");
var sessionSecret = RequireSecret("SVX_SESSION_SECRET");
var nonce = RequireText("SVX_SESSION_NONCE");
var sessionId = RequireText("SVX_SESSION_ID");
var requestCountPath = Environment.GetEnvironmentVariable("SVX_FIXTURE_REQUEST_COUNT_PATH");
var processIdPath = Environment.GetEnvironmentVariable("SVX_FIXTURE_PROCESS_ID_PATH");
if (!string.IsNullOrEmpty(processIdPath))
    await File.WriteAllTextAsync(processIdPath, Environment.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture));
if (mode == "hang-before-handshake")
{
    await Task.Delay(TimeSpan.FromMinutes(5));
    return 0;
}
var parentPid = int.Parse(RequireText("SVX_PARENT_PID"), System.Globalization.CultureInfo.InvariantCulture);
var parentStartTicks = long.Parse(
    RequireText("SVX_PARENT_START_UTC_TICKS"),
    System.Globalization.CultureInfo.InvariantCulture);
if (!Enum.TryParse<AccelerationBackend>(RequireText("SVX_ENGINE_BACKEND"), false, out var launchedBackend) ||
    launchedBackend is not (AccelerationBackend.Cpu or AccelerationBackend.Cuda or AccelerationBackend.Mps))
    throw new InvalidOperationException("SVX_ENGINE_BACKEND is invalid.");
var engineId = mode == "bad-engine" ? "attacker" : "voxcpm2";
var engineVersion = "2.0.3";
var modelRevision = mode == "bad-model" ? "wrong-revision" : "bffb3df5a2944062";
var backend = mode == "bad-backend" ? AccelerationBackend.Cuda : launchedBackend;

var builder = WebApplication.CreateSlimBuilder([]);
builder.Logging.ClearProviders();
builder.WebHost.ConfigureKestrel(options =>
{
    options.Listen(IPAddress.Loopback, 0);
    options.Limits.MaxRequestBodySize = 16 * 1024;
});
var app = builder.Build();
var bootstrapAttempts = mode == "bootstrap-budget-exhausted" ? 3 : 0;
var bootstrapCompleted = 0;
var bearerSeen = 0;
SidecarHandshakeDocument? bootstrapHandshake = null;

app.Use(async (context, next) =>
{
    if (context.Request.Path == "/v1/bootstrap-challenge")
    {
        if (Volatile.Read(ref bearerSeen) != 0 || Volatile.Read(ref bootstrapCompleted) != 0)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }
        await next(context);
        return;
    }
    if (Volatile.Read(ref bootstrapCompleted) != 2)
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        return;
    }
    var authorization = context.Request.Headers.Authorization.ToString();
    var expected = "Bearer " + Convert.ToBase64String(token);
    var providedBytes = Encoding.ASCII.GetBytes(authorization);
    var expectedBytes = Encoding.ASCII.GetBytes(expected);
    if (providedBytes.Length != expectedBytes.Length ||
        !CryptographicOperations.FixedTimeEquals(providedBytes, expectedBytes))
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        await context.Response.WriteAsJsonAsync(new { error = new { code = "unauthorized" } });
        return;
    }
    Interlocked.Exchange(ref bearerSeen, 1);
    if (!string.IsNullOrEmpty(requestCountPath))
        await File.AppendAllTextAsync(requestCountPath, "1\n", context.RequestAborted);
    await next(context);
});

app.MapPost("/v1/bootstrap-challenge", async (HttpContext context) =>
{
    if (Interlocked.Increment(ref bootstrapAttempts) > 3)
        return Results.StatusCode(StatusCodes.Status429TooManyRequests);
    if (Interlocked.CompareExchange(ref bootstrapCompleted, 1, 0) != 0)
        return Results.NotFound();
    var succeeded = false;
    try
    {
        if (!string.Equals(context.Request.ContentType, "application/json", StringComparison.Ordinal))
            return Results.BadRequest(new { error = new { code = "invalid_content_type" } });
        if (mode == "hang-bootstrap")
            await Task.Delay(TimeSpan.FromMinutes(5), context.RequestAborted);
        if (mode == "delay-bootstrap-success")
            await Task.Delay(250, context.RequestAborted);
        FixtureBootstrapRequest? request;
        try
        {
            request = await JsonSerializer.DeserializeAsync<FixtureBootstrapRequest>(
                context.Request.Body,
                FixtureJson.Options,
                context.RequestAborted);
        }
        catch (JsonException)
        {
            return Results.BadRequest(new { error = new { code = "invalid_json" } });
        }
        if (request is null || !TryDecodeChallenge(request.Challenge, out var challengeBytes))
            return Results.BadRequest(new { error = new { code = "invalid_challenge" } });
        CryptographicOperations.ZeroMemory(challengeBytes);
        var handshake = bootstrapHandshake
                        ?? throw new InvalidOperationException("Fixture handshake is unavailable.");
        var challenge = mode == "bad-bootstrap-challenge"
            ? Convert.ToBase64String(new byte[32])
            : request.Challenge;
        var proof = SidecarHandshakeProof.ComputeBootstrap(sessionSecret, handshake, request.Challenge);
        if (mode == "bad-bootstrap-proof") proof = new string('0', 64);
        if (mode == "oversized-bootstrap")
            return Results.Json(new { challenge, proof, padding = new string('x', 8 * 1024) });
        Interlocked.Exchange(ref bootstrapCompleted, 2);
        succeeded = true;
        return Results.Json(new FixtureBootstrapResponse { Challenge = challenge, Proof = proof }, FixtureJson.Options);
    }
    finally
    {
        if (!succeeded) Interlocked.CompareExchange(ref bootstrapCompleted, 0, 1);
    }
});

app.MapGet("/v1/health", () => Results.Json(new
{
    schemaVersion = 1,
    engineId = "voxcpm2",
    engineVersion,
    modelRevision = "bffb3df5a2944062",
    backend = launchedBackend,
    sessionId = mode == "bad-health-session" ? new string('f', 32) : sessionId,
    processId = Environment.ProcessId,
    ready = true,
}, FixtureJson.Options));

app.MapPost("/v1/tts", async (HttpContext context) =>
{
    if (mode == "hang")
        await Task.Delay(TimeSpan.FromMinutes(5), context.RequestAborted);
    if (mode == "oversized-response")
        return Results.Bytes(new byte[65 * 1024 * 1024], "audio/wav");
    if (mode == "malformed-wav")
        return Results.Bytes("not-wave"u8.ToArray(), "audio/wav");
    using var document = await JsonDocument.ParseAsync(context.Request.Body, cancellationToken: context.RequestAborted);
    if (!document.RootElement.TryGetProperty("text", out var text) ||
        text.ValueKind != JsonValueKind.String || text.GetString() is not { Length: > 0 and <= 220 })
        return Results.BadRequest(new { error = new { code = "validation_error" } });
    return Results.Bytes(CreateWave(), "audio/wav", lastModified: null, entityTag: null, enableRangeProcessing: false);
});
app.MapFallback(() => Results.NotFound(new { error = new { code = "not_found" } }));

await app.StartAsync();
var addresses = app.Services.GetRequiredService<IServer>()
    .Features.Get<IServerAddressesFeature>()?.Addresses
    ?? throw new InvalidOperationException("Fixture server address is unavailable.");
var address = addresses.Single();
var port = new Uri(address).Port;
var handshakeNonce = mode == "bad-nonce" ? new string('0', 64) : nonce;
var processId = mode == "bad-pid" ? Environment.ProcessId + 1 : Environment.ProcessId;
var handshakeParentPid = mode == "bad-parent-pid" ? parentPid + 1 : parentPid;
var handshakeParentStartTicks = mode == "bad-parent-start" ? parentStartTicks + 1 : parentStartTicks;
var handshakeSessionId = mode == "bad-session" ? new string('f', 32) : sessionId;
var listenerAddress = mode == "bad-listener-address" ? "0.0.0.0" : "127.0.0.1";
var proof = SidecarHandshakeProof.Compute(
    sessionSecret,
    1,
    2,
    engineId,
    engineVersion,
    modelRevision,
    backend,
    handshakeParentPid,
    handshakeParentStartTicks,
    handshakeSessionId,
    listenerAddress,
    processId,
    port,
    handshakeNonce);
if (mode == "bad-proof") proof = new string('0', 64);
var handshake = new SidecarHandshakeDocument
{
    SchemaVersion = 1,
    ProtocolVersion = 2,
    EngineId = engineId,
    EngineVersion = engineVersion,
    ModelRevision = modelRevision,
    Backend = backend,
    ParentProcessId = handshakeParentPid,
    ParentStartUtcTicks = handshakeParentStartTicks,
    SessionId = handshakeSessionId,
    ListenerAddress = listenerAddress,
    ProcessId = processId,
    Port = port,
    Nonce = handshakeNonce,
    Proof = proof,
};
bootstrapHandshake = handshake;
if (mode == "huge-handshake")
{
    Console.Out.WriteLine(new string('x', 32 * 1024));
}
else
{
    Console.Out.WriteLine(JsonSerializer.Serialize(handshake, FixtureJson.Options));
}
Console.Out.Flush();
if (mode == "exit-after-handshake") return 19;

_ = Task.Run(async () =>
{
    while (true)
    {
        await Task.Delay(250);
        try
        {
            using var parent = Process.GetProcessById(parentPid);
            if (parent.StartTime.ToUniversalTime().Ticks != parentStartTicks) Environment.Exit(0);
        }
        catch (ArgumentException)
        {
            Environment.Exit(0);
        }
    }
});

await app.WaitForShutdownAsync();
CryptographicOperations.ZeroMemory(token);
CryptographicOperations.ZeroMemory(sessionSecret);
return 0;

static byte[] RequireSecret(string name)
{
    var value = RequireText(name);
    var bytes = Convert.FromBase64String(value);
    if (bytes.Length != 32) throw new InvalidOperationException($"Fixture secret length is invalid: {name}");
    return bytes;
}

static string RequireText(string name) =>
    Environment.GetEnvironmentVariable(name)
    ?? throw new InvalidOperationException($"Fixture environment is missing: {name}");

static bool TryDecodeChallenge(string value, out byte[] bytes)
{
    try
    {
        bytes = Convert.FromBase64String(value);
        if (bytes.Length == 32) return true;
        CryptographicOperations.ZeroMemory(bytes);
    }
    catch (FormatException)
    {
    }
    bytes = [];
    return false;
}

static byte[] CreateWave()
{
    const int sampleRate = 48_000;
    const int sampleCount = 4_800;
    var bytes = new byte[44 + sampleCount * 2];
    "RIFF"u8.CopyTo(bytes);
    BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(4, 4), bytes.Length - 8);
    "WAVEfmt "u8.CopyTo(bytes.AsSpan(8));
    BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(16, 4), 16);
    BinaryPrimitives.WriteInt16LittleEndian(bytes.AsSpan(20, 2), 1);
    BinaryPrimitives.WriteInt16LittleEndian(bytes.AsSpan(22, 2), 1);
    BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(24, 4), sampleRate);
    BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(28, 4), sampleRate * 2);
    BinaryPrimitives.WriteInt16LittleEndian(bytes.AsSpan(32, 2), 2);
    BinaryPrimitives.WriteInt16LittleEndian(bytes.AsSpan(34, 2), 16);
    "data"u8.CopyTo(bytes.AsSpan(36));
    BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(40, 4), sampleCount * 2);
    for (var index = 0; index < sampleCount; index++)
    {
        var sample = (short)(Math.Sin(2 * Math.PI * 220 * index / sampleRate) * 2000);
        BinaryPrimitives.WriteInt16LittleEndian(bytes.AsSpan(44 + index * 2, 2), sample);
    }
    return bytes;
}

internal static class FixtureJson
{
    internal static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        Converters = { new JsonStringEnumConverter(namingPolicy: null, allowIntegerValues: false) },
    };
}

internal sealed record FixtureBootstrapRequest
{
    public required string Challenge { get; init; }
}

internal sealed record FixtureBootstrapResponse
{
    public required string Challenge { get; init; }
    public required string Proof { get; init; }
}
