using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using SupertonicVox.Core;

namespace SupertonicVox.Core.Tests;

public sealed class SidecarProcessHostTests
{
    [Fact]
    public async Task NonCriticalRuntimeMutationIsRejectedBeforeProcessStart()
    {
        using var temporary = new TemporaryDirectory();
        var pack = await SidecarTestFixture.CreateRuntimePackAsync(temporary.Path);
        var relative = pack.Files.Keys.First(path =>
            !pack.Manifest.PrelaunchVerifyPaths.Contains(path, StringComparer.Ordinal));
        var path = Path.Combine(pack.RootPath, relative.Replace('/', Path.DirectorySeparatorChar));
        if (OperatingSystem.IsWindows())
            File.SetAttributes(path, File.GetAttributes(path) & ~FileAttributes.ReadOnly);
        else
            File.SetUnixFileMode(path, File.GetUnixFileMode(path) | UnixFileMode.UserWrite);
        await File.AppendAllTextAsync(path, "tamper");
        var host = SidecarTestFixture.CreateHost();

        await Assert.ThrowsAsync<RuntimePackException>(() =>
            host.StartAsync(SidecarTestFixture.Launch(pack, Path.Combine(temporary.Path, "data"))));
    }

    [Fact]
    public void ProtocolProofKnownVectorMatchesPythonImplementation()
    {
        var secret = Enumerable.Range(32, 32).Select(value => (byte)value).ToArray();
        const long ticks = 621_355_968_000_000_000L + 1_700_000_000L * TimeSpan.TicksPerSecond + 9_999_999L;
        var proof = SidecarHandshakeProof.Compute(
            secret,
            1,
            2,
            "voxcpm2",
            "2.0.3",
            "bffb3df5a29440629464e5e839f4d214c8714c3d",
            AccelerationBackend.Cpu,
            1234,
            ticks,
            new string('2', 32),
            "127.0.0.1",
            4567,
            32123,
            new string('1', 64));
        Assert.Equal("4b05c9db2c53c9f247cb2201f66f3e3885533530c2b1185aa03ed7b0fcd71f25", proof);

        var handshake = new SidecarHandshakeDocument
        {
            SchemaVersion = 1,
            ProtocolVersion = 2,
            EngineId = "voxcpm2",
            EngineVersion = "2.0.3",
            ModelRevision = "bffb3df5a29440629464e5e839f4d214c8714c3d",
            Backend = AccelerationBackend.Cpu,
            ParentProcessId = 1234,
            ParentStartUtcTicks = ticks,
            SessionId = new string('2', 32),
            ListenerAddress = "127.0.0.1",
            ProcessId = 4567,
            Port = 32123,
            Nonce = new string('1', 64),
            Proof = proof,
        };
        var challenge = Convert.ToBase64String(Enumerable.Range(64, 32).Select(value => (byte)value).ToArray());
        Assert.Equal(
            "791d561f2379273b05c5c07d9e6a6dfcab76888d988fb9e79bea0668b1ff6f34",
            SidecarHandshakeProof.ComputeBootstrap(secret, handshake, challenge));
    }

    [Fact]
    public void ParentStartIdentityHasDocumentedWholeSecondBoundary()
    {
        using var parent = Process.GetCurrentProcess();
        var ticks = parent.StartTime.ToUniversalTime().Ticks;
        var fromTicks = (ticks - DateTime.UnixEpoch.Ticks) / TimeSpan.TicksPerSecond;
        var fromDateTime = new DateTimeOffset(parent.StartTime.ToUniversalTime()).ToUnixTimeSeconds();
        Assert.Equal(fromDateTime, fromTicks);
    }

    [Fact]
    public async Task VerifiedFakeRuntimePackCompletesHandshakeHealthAndWaveThenRemovesState()
    {
        using var temporary = new TemporaryDirectory();
        var pack = await SidecarTestFixture.CreateRuntimePackAsync(temporary.Path);
        var dataDirectory = Path.Combine(temporary.Path, "sidecar-data");
        var host = SidecarTestFixture.CreateHost();
        var session = await host.StartAsync(SidecarTestFixture.Launch(pack, dataDirectory));
        var processId = session.ProcessId;
        var statePath = Path.Combine(dataDirectory, "sidecar-process-state.json");
        try
        {
            Assert.Equal("voxcpm2", session.Handshake.EngineId);
            using var parent = Process.GetCurrentProcess();
            Assert.Equal(parent.Id, session.Handshake.ParentProcessId);
            Assert.Equal(parent.StartTime.ToUniversalTime().Ticks, session.Handshake.ParentStartUtcTicks);
            Assert.Equal(session.SessionId, session.Handshake.SessionId);
            Assert.Equal("127.0.0.1", session.Handshake.ListenerAddress);
            Assert.False(Assert.IsType<OwnedSidecarClientSession>(session).RetainsLaunchSecrets);
            Assert.True(File.Exists(statePath));

            var health = await session.SendAuthenticatedAsync(
                HttpMethod.Get,
                "/v1/health",
                ReadOnlyMemory<byte>.Empty,
                null,
                64 * 1024,
                TimeSpan.FromSeconds(5));
            Assert.Equal(System.Net.HttpStatusCode.OK, health.StatusCode);
            Assert.Equal("application/json", health.ContentType);

            using var unauthenticated = new HttpClient(new SocketsHttpHandler
            {
                UseProxy = false,
                AllowAutoRedirect = false,
            });
            using var replay = await unauthenticated.PostAsync(
                $"http://127.0.0.1:{session.Handshake.Port}/v1/bootstrap-challenge",
                new StringContent("{\"challenge\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"}"));
            Assert.Equal(System.Net.HttpStatusCode.NotFound, replay.StatusCode);

            var wave = await session.SendAuthenticatedAsync(
                HttpMethod.Post,
                "/v1/tts",
                "{\"text\":\"테스트\"}"u8.ToArray(),
                "application/json",
                128 * 1024,
                TimeSpan.FromSeconds(5));
            Assert.Equal(System.Net.HttpStatusCode.OK, wave.StatusCode);
            Assert.Equal("audio/wav", wave.ContentType);
            Assert.True(WaveFileInspector.TryReadPcm16(wave.Body, out var metadata));
            Assert.Equal(48_000, metadata!.SampleRate);
        }
        finally
        {
            await session.DisposeAsync();
        }

        Assert.False(File.Exists(statePath));
        await SidecarTestFixture.AssertProcessExitedAsync(processId);
    }

    [Theory]
    [InlineData("bad-proof")]
    [InlineData("bad-nonce")]
    [InlineData("bad-pid")]
    [InlineData("bad-engine")]
    [InlineData("bad-model")]
    [InlineData("bad-backend")]
    [InlineData("bad-parent-pid")]
    [InlineData("bad-parent-start")]
    [InlineData("bad-session")]
    [InlineData("bad-listener-address")]
    public async Task RejectedHandshakeMakesNoHttpRequestAndCleansUpOwnedProcess(string mode)
    {
        using var temporary = new TemporaryDirectory();
        var pack = await SidecarTestFixture.CreateRuntimePackAsync(temporary.Path);
        var requestCountPath = Path.Combine(temporary.Path, "request-count");
        var processIdPath = Path.Combine(temporary.Path, "fixture-pid");
        var host = SidecarTestFixture.CreateHost(mode, requestCountPath, processIdPath);

        var exception = await Record.ExceptionAsync(async () =>
            await host.StartAsync(SidecarTestFixture.Launch(pack, Path.Combine(temporary.Path, "data"))));

        Assert.NotNull(exception);
        Assert.IsType<RuntimePackException>(exception);
        Assert.Equal(0, SidecarTestFixture.ReadRequestCount(requestCountPath));
        await SidecarTestFixture.AssertFixtureProcessExitedAsync(processIdPath);
    }

    [Theory]
    [InlineData("bad-bootstrap-proof")]
    [InlineData("bad-bootstrap-challenge")]
    [InlineData("oversized-bootstrap")]
    [InlineData("bootstrap-budget-exhausted")]
    public async Task RejectedBootstrapSendsNoBearerRequestAndCleansUpOwnedProcess(string mode)
    {
        using var temporary = new TemporaryDirectory();
        var pack = await SidecarTestFixture.CreateRuntimePackAsync(temporary.Path);
        var requestCountPath = Path.Combine(temporary.Path, "authenticated-request-count");
        var processIdPath = Path.Combine(temporary.Path, "fixture-pid");
        var host = SidecarTestFixture.CreateHost(mode, requestCountPath, processIdPath);

        await Assert.ThrowsAsync<RuntimePackException>(async () =>
            await host.StartAsync(SidecarTestFixture.Launch(pack, Path.Combine(temporary.Path, "data"))));

        Assert.Equal(0, SidecarTestFixture.ReadRequestCount(requestCountPath));
        await SidecarTestFixture.AssertFixtureProcessExitedAsync(processIdPath);
    }

    [Fact]
    public async Task BootstrapDeadlineSendsNoBearerRequestAndCleansUpOwnedProcess()
    {
        using var temporary = new TemporaryDirectory();
        var pack = await SidecarTestFixture.CreateRuntimePackAsync(temporary.Path);
        var requestCountPath = Path.Combine(temporary.Path, "authenticated-request-count");
        var processIdPath = Path.Combine(temporary.Path, "fixture-pid");
        var host = SidecarTestFixture.CreateHost("hang-bootstrap", requestCountPath, processIdPath);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await host.StartAsync(SidecarTestFixture.Launch(
                pack,
                Path.Combine(temporary.Path, "data"),
                TimeSpan.FromSeconds(1))));

        Assert.Equal(0, SidecarTestFixture.ReadRequestCount(requestCountPath));
        await SidecarTestFixture.AssertFixtureProcessExitedAsync(processIdPath);
    }

    [Fact]
    public async Task BootstrapEndpointAllowsExactlyOneConcurrentSuccess()
    {
        using var temporary = new TemporaryDirectory();
        var pack = await SidecarTestFixture.CreateRuntimePackAsync(temporary.Path);
        using var parent = Process.GetCurrentProcess();
        var endpoint = await SidecarTestFixture.StartDirectFakeEndpointAsync(
            pack,
            parent.Id,
            parent.StartTime.ToUniversalTime().Ticks,
            "delay-bootstrap-success");
        try
        {
            using var client = new HttpClient(new SocketsHttpHandler
            {
                UseProxy = false,
                AllowAutoRedirect = false,
            });
            var challenge = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
            var payload = JsonSerializer.SerializeToUtf8Bytes(new { challenge });
            async Task<HttpResponseMessage> SendAsync()
            {
                using var request = new HttpRequestMessage(
                    HttpMethod.Post,
                    $"http://127.0.0.1:{endpoint.Port}/v1/bootstrap-challenge")
                {
                    Content = new ByteArrayContent(payload),
                };
                request.Content.Headers.ContentType =
                    new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
                return await client.SendAsync(request);
            }

            var responses = await Task.WhenAll(SendAsync(), SendAsync(), SendAsync());
            try
            {
                Assert.Single(responses, response => response.StatusCode == System.Net.HttpStatusCode.OK);
                Assert.Equal(
                    2,
                    responses.Count(response => response.StatusCode == System.Net.HttpStatusCode.NotFound));
            }
            finally
            {
                foreach (var response in responses) response.Dispose();
            }
        }
        finally
        {
            await SidecarTestFixture.StopDirectProcessAsync(endpoint.Process);
        }
    }

    [Theory]
    [InlineData(1, 0)]
    [InlineData(2, 0)]
    [InlineData(3, 1)]
    public async Task ListenerOwnerMismatchFailsClosedAtEveryRequiredCheckpoint(
        int failingCall,
        int expectedAuthenticatedRequests)
    {
        using var temporary = new TemporaryDirectory();
        var pack = await SidecarTestFixture.CreateRuntimePackAsync(temporary.Path);
        var requestCountPath = Path.Combine(temporary.Path, "authenticated-request-count");
        var processIdPath = Path.Combine(temporary.Path, "fixture-pid");
        var verifier = new ScriptedListenerOwnerVerifier(failingCall);
        var host = SidecarTestFixture.CreateHost(
            "normal",
            requestCountPath,
            processIdPath,
            verifier);

        if (failingCall == 1)
        {
            await Assert.ThrowsAsync<RuntimePackException>(async () =>
                await host.StartAsync(SidecarTestFixture.Launch(
                    pack,
                    Path.Combine(temporary.Path, "data"))));
        }
        else
        {
            var session = await host.StartAsync(SidecarTestFixture.Launch(
                pack,
                Path.Combine(temporary.Path, "data")));
            await Assert.ThrowsAsync<RuntimePackException>(async () =>
                await session.SendAuthenticatedAsync(
                    HttpMethod.Get,
                    "/v1/health",
                    ReadOnlyMemory<byte>.Empty,
                    null,
                    64 * 1024,
                    TimeSpan.FromSeconds(5)));
            await session.DisposeAsync();
        }

        Assert.Equal(failingCall, verifier.CallCount);
        Assert.Equal(expectedAuthenticatedRequests, SidecarTestFixture.ReadRequestCount(requestCountPath));
        await SidecarTestFixture.AssertFixtureProcessExitedAsync(processIdPath);
    }

    [Fact]
    public void PlatformListenerOwnerParsersAreStrict()
    {
        Assert.True(MacOsLoopbackListenerOwnerVerifier.OutputMatches(
            "p123\0\nf9\0\nn127.0.0.1:50001\0\n",
            123,
            50_001));
        Assert.False(MacOsLoopbackListenerOwnerVerifier.OutputMatches(
            "p124\0\nf9\0\nn127.0.0.1:50001\0\n",
            123,
            50_001));
        Assert.False(MacOsLoopbackListenerOwnerVerifier.OutputMatches(
            "p123\0\nf9\0\nn0.0.0.0:50001\0\n",
            123,
            50_001));

        var networkOrderPort = unchecked((uint)(ushort)System.Net.IPAddress.HostToNetworkOrder((short)50_001));
        Assert.Equal(50_001, WindowsLoopbackListenerOwnerVerifier.DecodePort(networkOrderPort));
    }

    [Theory]
    [InlineData("exit-before-handshake")]
    [InlineData("huge-handshake")]
    public async Task StartupExitAndOversizedHandshakeFailClosed(string mode)
    {
        using var temporary = new TemporaryDirectory();
        var pack = await SidecarTestFixture.CreateRuntimePackAsync(temporary.Path);
        var processIdPath = Path.Combine(temporary.Path, "fixture-pid");
        var host = SidecarTestFixture.CreateHost(mode, null, processIdPath);

        var exception = await Record.ExceptionAsync(async () =>
            await host.StartAsync(SidecarTestFixture.Launch(pack, Path.Combine(temporary.Path, "data"))));

        Assert.NotNull(exception);
        Assert.IsType<RuntimePackException>(exception);
        await SidecarTestFixture.AssertFixtureProcessExitedAsync(processIdPath);
    }

    [Fact]
    public async Task HandshakeDeadlineKillsOwnedProcessWithoutMakingHttpRequest()
    {
        using var temporary = new TemporaryDirectory();
        var pack = await SidecarTestFixture.CreateRuntimePackAsync(temporary.Path);
        var requestCountPath = Path.Combine(temporary.Path, "request-count");
        var processIdPath = Path.Combine(temporary.Path, "fixture-pid");
        var host = SidecarTestFixture.CreateHost("hang-before-handshake", requestCountPath, processIdPath);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await host.StartAsync(SidecarTestFixture.Launch(
                pack,
                Path.Combine(temporary.Path, "data"),
                TimeSpan.FromSeconds(1))));

        Assert.Equal(0, SidecarTestFixture.ReadRequestCount(requestCountPath));
        await SidecarTestFixture.AssertFixtureProcessExitedAsync(processIdPath);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task DirectFakeSidecarExitsAfterHandshakeWhenParentIdentityIsInvalid(bool nonexistentParent)
    {
        using var temporary = new TemporaryDirectory();
        var pack = await SidecarTestFixture.CreateRuntimePackAsync(temporary.Path);
        using var current = Process.GetCurrentProcess();
        var parentProcessId = nonexistentParent ? int.MaxValue : current.Id;
        var parentStartUtcTicks = nonexistentParent
            ? 1L
            : checked(current.StartTime.ToUniversalTime().Ticks + 1);
        var sidecar = await SidecarTestFixture.StartDirectFakeAsync(
            pack,
            parentProcessId,
            parentStartUtcTicks);
        try
        {
            await SidecarTestFixture.AssertProcessExitedAsync(sidecar.Id);
        }
        finally
        {
            await SidecarTestFixture.StopDirectProcessAsync(sidecar);
        }
    }

    [Fact]
    public async Task ExactStaleStateIsSweptBeforeNewSessionAndMismatchedStateDoesNotKillCurrentProcess()
    {
        using var temporary = new TemporaryDirectory();
        var pack = await SidecarTestFixture.CreateRuntimePackAsync(temporary.Path);
        var dataDirectory = Path.Combine(temporary.Path, "data");
        var statePath = Path.Combine(dataDirectory, "sidecar-process-state.json");
        Directory.CreateDirectory(dataDirectory);
        using var current = Process.GetCurrentProcess();
        var entrypoint = SidecarTestFixture.ResolveEntrypoint(pack);
        var stale = await SidecarTestFixture.StartDirectFakeAsync(
            pack,
            current.Id,
            current.StartTime.ToUniversalTime().Ticks);
        try
        {
            await SidecarStaleProcessSweeper.WriteStateAsync(statePath, new SidecarProcessState
            {
                SchemaVersion = 1,
                ProcessId = stale.Id,
                ProcessStartUtcTicks = stale.StartTime.ToUniversalTime().Ticks,
                ExecutablePath = entrypoint,
                PackFingerprint = pack.PackFingerprint,
            }, CancellationToken.None);
            SidecarTestFixture.AssertOwnerOnlyStateFile(statePath);

            var host = SidecarTestFixture.CreateHost();
            var session = await host.StartAsync(SidecarTestFixture.Launch(pack, dataDirectory));
            try
            {
                Assert.NotEqual(stale.Id, session.ProcessId);
                await SidecarTestFixture.AssertProcessExitedAsync(stale.Id);
                var health = await session.SendAuthenticatedAsync(
                    HttpMethod.Get,
                    "/v1/health",
                    ReadOnlyMemory<byte>.Empty,
                    null,
                    64 * 1024,
                    TimeSpan.FromSeconds(5));
                Assert.Equal(System.Net.HttpStatusCode.OK, health.StatusCode);
            }
            finally
            {
                await session.DisposeAsync();
            }

            current.Refresh();
            await SidecarStaleProcessSweeper.WriteStateAsync(statePath, new SidecarProcessState
            {
                SchemaVersion = 1,
                ProcessId = current.Id,
                ProcessStartUtcTicks = current.StartTime.ToUniversalTime().Ticks,
                ExecutablePath = entrypoint,
                PackFingerprint = pack.PackFingerprint,
            }, CancellationToken.None);
            SidecarTestFixture.AssertOwnerOnlyStateFile(statePath);

            var safeSession = await host.StartAsync(SidecarTestFixture.Launch(pack, dataDirectory));
            try
            {
                current.Refresh();
                Assert.False(current.HasExited);
            }
            finally
            {
                await safeSession.DisposeAsync();
            }
        }
        finally
        {
            await SidecarTestFixture.StopDirectProcessAsync(stale);
        }
    }
}

internal sealed class ScriptedListenerOwnerVerifier(int failingCall) : ILoopbackListenerOwnerVerifier
{
    public int CallCount { get; private set; }

    public Task VerifyOwnedAsync(int processId, int port, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        CallCount++;
        if (CallCount == failingCall)
            throw new RuntimePackException("Injected listener ownership mismatch.");
        return Task.CompletedTask;
    }
}

internal static class SidecarTestFixture
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter(namingPolicy: null, allowIntegerValues: false) },
    };

    public static async Task<VerifiedRuntimePack> CreateRuntimePackAsync(string parentDirectory)
    {
        var source = LocateFakeSidecarOutput();
        var partial = Path.Combine(parentDirectory, "fake-runtime.partial");
        var final = Path.Combine(parentDirectory, "fake-runtime");
        var binaryDirectory = Path.Combine(partial, "bin");
        Directory.CreateDirectory(binaryDirectory);

        foreach (var sourceFile in Directory.EnumerateFiles(source, "*", SearchOption.AllDirectories))
        {
            var relative = Path.GetRelativePath(source, sourceFile);
            var destination = Path.Combine(binaryDirectory, relative);
            Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
            File.Copy(sourceFile, destination);
        }

        var entrypointName = OperatingSystem.IsWindows() ? "FakeVoxSidecar.exe" : "FakeVoxSidecar";
        var sourceEntrypoint = Path.Combine(source, entrypointName);
        var entrypoint = Path.Combine(binaryDirectory, entrypointName);
        if (!File.Exists(entrypoint))
            throw new FileNotFoundException("Fake Vox sidecar apphost was not built.", entrypoint);
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(entrypoint, File.GetUnixFileMode(sourceEntrypoint));

        var files = Directory.EnumerateFiles(partial, "*", SearchOption.AllDirectories)
            .Select(path => new RuntimePackFile
            {
                Path = Normalize(Path.GetRelativePath(partial, path)),
                SizeBytes = new FileInfo(path).Length,
                Sha256 = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path))),
            })
            .OrderBy(file => file.Path.ToUpperInvariant(), StringComparer.Ordinal)
            .ToArray();
        var manifest = new RuntimePackManifest
        {
            SchemaVersion = 1,
            ProtocolVersion = 2,
            EngineId = "voxcpm2",
            EngineVersion = "2.0.3",
            ModelRevision = "bffb3df5a2944062",
            Platform = OperatingSystem.IsWindows() ? PlatformKind.Windows : PlatformKind.MacOS,
            Architecture = System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture ==
                           System.Runtime.InteropServices.Architecture.Arm64
                ? CpuArchitectureKind.Arm64
                : CpuArchitectureKind.X64,
            Backend = AccelerationBackend.Cpu,
            EntryPoint = $"bin/{entrypointName}",
            LaunchArguments = [],
            PrelaunchVerifyPaths = [$"bin/{entrypointName}"],
            Files = files,
        };
        await File.WriteAllBytesAsync(
            Path.Combine(partial, RuntimePackVerifier.ManifestFileName),
            JsonSerializer.SerializeToUtf8Bytes(manifest, JsonOptions));

        return await new RuntimePackVerifier().VerifyAndActivateAsync(partial, final);
    }

    public static OwnedSidecarProcessHost CreateHost(
        string? mode = null,
        string? requestCountPath = null,
        string? processIdPath = null,
        ILoopbackListenerOwnerVerifier? listenerOwnerVerifier = null)
    {
        var environment = new Dictionary<string, string>(StringComparer.Ordinal);
        if (mode is not null) environment.Add("SVX_FIXTURE_MODE", mode);
        if (requestCountPath is not null) environment.Add("SVX_FIXTURE_REQUEST_COUNT_PATH", requestCountPath);
        if (processIdPath is not null) environment.Add("SVX_FIXTURE_PROCESS_ID_PATH", processIdPath);
        return listenerOwnerVerifier is null
            ? new OwnedSidecarProcessHost(new RuntimePackVerifier(), environment)
            : new OwnedSidecarProcessHost(
                new RuntimePackVerifier(),
                listenerOwnerVerifier,
                environment);
    }

    public static SidecarLaunchOptions Launch(
        VerifiedRuntimePack pack,
        string dataDirectory,
        TimeSpan? startupTimeout = null) => new()
        {
            RuntimePack = pack,
            DataDirectory = dataDirectory,
            StartupTimeout = startupTimeout ?? TimeSpan.FromSeconds(8),
        };

    public static int ReadRequestCount(string path) =>
        File.Exists(path) ? File.ReadLines(path).Count() : 0;

    public static async Task AssertFixtureProcessExitedAsync(string processIdPath)
    {
        if (!File.Exists(processIdPath)) return;
        var value = await File.ReadAllTextAsync(processIdPath);
        Assert.True(int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var processId));
        await AssertProcessExitedAsync(processId);
    }

    public static async Task AssertProcessExitedAsync(int processId)
    {
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(5);
        while (DateTime.UtcNow < deadline)
        {
            try
            {
                using var process = Process.GetProcessById(processId);
                if (process.HasExited) return;
            }
            catch (ArgumentException)
            {
                return;
            }
            await Task.Delay(25);
        }
        Assert.Fail($"Fixture sidecar process {processId} remained running after cleanup.");
    }

    public static async Task<Process> StartDirectFakeAsync(
        VerifiedRuntimePack pack,
        int parentProcessId,
        long parentStartUtcTicks) =>
        (await StartDirectFakeEndpointAsync(pack, parentProcessId, parentStartUtcTicks)).Process;

    public static async Task<DirectFakeEndpoint> StartDirectFakeEndpointAsync(
        VerifiedRuntimePack pack,
        int parentProcessId,
        long parentStartUtcTicks,
        string mode = "normal")
    {
        var bearerToken = RandomNumberGenerator.GetBytes(32);
        var sessionSecret = RandomNumberGenerator.GetBytes(32);
        var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = ResolveEntrypoint(pack),
                WorkingDirectory = pack.RootPath,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            },
        };
        try
        {
            process.StartInfo.Environment["SVX_FIXTURE_MODE"] = mode;
            process.StartInfo.Environment["SVX_FIXTURE_REQUEST_COUNT_PATH"] = string.Empty;
            process.StartInfo.Environment["SVX_FIXTURE_PROCESS_ID_PATH"] = string.Empty;
            process.StartInfo.Environment["SVX_LOCAL_AUTH_TOKEN"] = Convert.ToBase64String(bearerToken);
            process.StartInfo.Environment["SVX_SESSION_SECRET"] = Convert.ToBase64String(sessionSecret);
            process.StartInfo.Environment["SVX_SESSION_NONCE"] = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));
            process.StartInfo.Environment["SVX_SESSION_ID"] = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));
            process.StartInfo.Environment["SVX_PARENT_PID"] = parentProcessId.ToString(CultureInfo.InvariantCulture);
            process.StartInfo.Environment["SVX_PARENT_START_UTC_TICKS"] =
                parentStartUtcTicks.ToString(CultureInfo.InvariantCulture);
            process.StartInfo.Environment["SVX_ENGINE_BACKEND"] = pack.Manifest.Backend.ToString();
            if (!process.Start()) throw new InvalidOperationException("Could not start the direct fake sidecar.");
            using var handshakeTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var handshake = await process.StandardOutput.ReadLineAsync(handshakeTimeout.Token);
            Assert.False(string.IsNullOrWhiteSpace(handshake));
            using var document = JsonDocument.Parse(handshake);
            Assert.Equal("voxcpm2", document.RootElement.GetProperty("engineId").GetString());
            var port = document.RootElement.GetProperty("port").GetInt32();
            return new DirectFakeEndpoint(process, port);
        }
        catch
        {
            await StopDirectProcessAsync(process);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bearerToken);
            CryptographicOperations.ZeroMemory(sessionSecret);
        }
    }

    public static async Task StopDirectProcessAsync(Process process)
    {
        try
        {
            OwnedSidecarProcessHost.TryKill(process);
            if (!process.HasExited)
                await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));
        }
        catch (InvalidOperationException)
        {
        }
        finally
        {
            process.Dispose();
        }
    }

    public static string ResolveEntrypoint(VerifiedRuntimePack pack) =>
        Path.GetFullPath(Path.Combine(pack.RootPath, pack.Manifest.EntryPoint.Replace('/', Path.DirectorySeparatorChar)));

    public static void AssertOwnerOnlyStateFile(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            Assert.True((File.GetAttributes(path) & FileAttributes.ReadOnly) == 0);
            return;
        }
        Assert.Equal(
            UnixFileMode.UserRead | UnixFileMode.UserWrite,
            File.GetUnixFileMode(path));
    }

    public static VerifiedRuntimePack ProviderPack() => new()
    {
        RootPath = Path.GetTempPath(),
        Manifest = new RuntimePackManifest
        {
            SchemaVersion = 1,
            ProtocolVersion = 2,
            EngineId = "voxcpm2",
            EngineVersion = "2.0.3",
            ModelRevision = "bffb3df5a2944062",
            Platform = PlatformKind.MacOS,
            Architecture = CpuArchitectureKind.Arm64,
            Backend = AccelerationBackend.Cpu,
            EntryPoint = "bin/FakeVoxSidecar",
            LaunchArguments = [],
            PrelaunchVerifyPaths = ["bin/FakeVoxSidecar"],
            Files =
            [
                new RuntimePackFile
                {
                    Path = "bin/FakeVoxSidecar",
                    SizeBytes = 1,
                    Sha256 = new string('0', 64),
                },
            ],
        },
        ManifestSha256 = new string('0', 64),
        PackFingerprint = new string('0', 64),
        Files = new Dictionary<string, RuntimePackFile>(StringComparer.Ordinal)
        {
            ["bin/FakeVoxSidecar"] = new RuntimePackFile
            {
                Path = "bin/FakeVoxSidecar",
                SizeBytes = 1,
                Sha256 = new string('0', 64),
            },
        },
    };

    private static string LocateFakeSidecarOutput()
    {
        var root = FindRepositoryRoot();
        var binaryRoot = Path.Combine(root, "tools", "FakeVoxSidecar", "bin");
        var apphostName = OperatingSystem.IsWindows() ? "FakeVoxSidecar.exe" : "FakeVoxSidecar";
        var candidates = Directory.EnumerateFiles(binaryRoot, apphostName, SearchOption.AllDirectories)
            .Where(path => File.Exists(Path.Combine(Path.GetDirectoryName(path)!, "FakeVoxSidecar.runtimeconfig.json")))
            .OrderByDescending(File.GetLastWriteTimeUtc)
            .ToArray();
        return candidates.FirstOrDefault() is { } apphost
            ? Path.GetDirectoryName(apphost)!
            : throw new FileNotFoundException("Fake Vox sidecar build output is unavailable.", binaryRoot);
    }

    private static string FindRepositoryRoot()
    {
        foreach (var start in new[] { Directory.GetCurrentDirectory(), AppContext.BaseDirectory })
        {
            for (var directory = new DirectoryInfo(start); directory is not null; directory = directory.Parent)
            {
                if (File.Exists(Path.Combine(directory.FullName, "SupertonicVox.CrossPlatform.slnx")))
                    return directory.FullName;
            }
        }
        throw new DirectoryNotFoundException("Could not locate the solution root for the Fake Vox sidecar.");
    }

    private static string Normalize(string value) => value.Replace(Path.DirectorySeparatorChar, '/');
}

internal sealed record DirectFakeEndpoint(Process Process, int Port);
