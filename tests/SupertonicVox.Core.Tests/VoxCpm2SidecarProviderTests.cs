using System.Buffers.Binary;
using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;
using SupertonicVox.Core;

namespace SupertonicVox.Core.Tests;

public sealed class VoxCpm2SidecarProviderTests
{
    [Fact]
    public async Task ReferenceAudioIsDisabledBeforeAnySidecarIsStarted()
    {
        var factory = new ScriptedSessionFactory(new ScriptedSession());
        await using var provider = new VoxCpm2SidecarProvider(
            SidecarTestFixture.ProviderPack(),
            Path.GetTempPath(),
            factory);

        await Assert.ThrowsAsync<NotSupportedException>(() => provider.SynthesizeAsync(new SynthesisRequest
        {
            Text = "참조 음성은 차단되어야 합니다.",
            VoiceId = "m1",
            ReferenceAudio = [1, 2, 3],
        }));

        Assert.Equal(0, factory.StartCount);
    }

    [Fact]
    public async Task InvalidWaveStopsAndDisposesInjectedSession()
    {
        var session = new ScriptedSession
        {
            TtsResponse = new SidecarHttpResponse(
                HttpStatusCode.OK,
                "audio/wav",
                "not-a-wave"u8.ToArray(),
                new Dictionary<string, string>()),
        };
        var factory = new ScriptedSessionFactory(session);
        await using var provider = new VoxCpm2SidecarProvider(
            SidecarTestFixture.ProviderPack(),
            Path.GetTempPath(),
            factory);

        await Assert.ThrowsAsync<InvalidDataException>(() => provider.SynthesizeAsync(Request()));

        Assert.Equal(1, factory.StartCount);
        Assert.Equal(new[] { "/v1/health", "/v1/tts" }, session.Paths);
        Assert.Equal(1, session.StopCount);
        Assert.Equal(1, session.DisposeCount);
        Assert.False(await provider.IsReadyAsync());
    }

    [Fact]
    public async Task ValidResponseUsesPresetOnlyPayloadAndPreservesWaveMetadata()
    {
        var wave = CreateWave();
        var session = new ScriptedSession
        {
            TtsResponse = new SidecarHttpResponse(
                HttpStatusCode.OK,
                "audio/wav",
                wave,
                new Dictionary<string, string>()),
        };
        var factory = new ScriptedSessionFactory(session);
        var provider = new VoxCpm2SidecarProvider(
            SidecarTestFixture.ProviderPack(),
            Path.GetTempPath(),
            factory);
        try
        {
            var result = await provider.SynthesizeAsync(Request());

            Assert.Equal(wave, result.WavBytes);
            Assert.Equal(48_000, result.SampleRate);
            Assert.Equal(1, result.Channels);
            Assert.Equal(16, result.BitsPerSample);
            Assert.True(await provider.IsReadyAsync());
            using var body = JsonDocument.Parse(session.TtsBody);
            Assert.Equal("preset", body.RootElement.GetProperty("mode").GetString());
            Assert.Equal("m1", body.RootElement.GetProperty("profile_id").GetString());
            Assert.Equal(JsonValueKind.Null, body.RootElement.GetProperty("reference_wav_path").ValueKind);
            Assert.Equal("wav", body.RootElement.GetProperty("response_format").GetString());
        }
        finally
        {
            await provider.DisposeAsync();
        }

        Assert.Equal(1, session.StopCount);
        Assert.Equal(1, session.DisposeCount);
    }

    [Fact]
    public async Task RealFakeRuntimePackCompletesProviderHealthAndWavLifecycle()
    {
        using var temporary = new TemporaryDirectory();
        var pack = await SidecarTestFixture.CreateRuntimePackAsync(temporary.Path);
        var processIdPath = Path.Combine(temporary.Path, "fixture-pid");
        var dataDirectory = Path.Combine(temporary.Path, "data");
        var provider = new VoxCpm2SidecarProvider(
            pack,
            dataDirectory,
            SidecarTestFixture.CreateHost(null, null, processIdPath));
        try
        {
            var result = await provider.SynthesizeAsync(Request());

            Assert.Equal("voxcpm2", result.EngineId);
            Assert.Equal("bffb3df5a2944062", result.ModelRevision);
            Assert.Equal(48_000, result.SampleRate);
            Assert.Equal(1, result.Channels);
            Assert.Equal(16, result.BitsPerSample);
            Assert.True(result.WavBytes.Length > 44);
            Assert.True(await provider.IsReadyAsync());
            Assert.True(File.Exists(Path.Combine(dataDirectory, "sidecar-process-state.json")));
        }
        finally
        {
            await provider.DisposeAsync();
        }

        Assert.False(File.Exists(Path.Combine(dataDirectory, "sidecar-process-state.json")));
        await SidecarTestFixture.AssertFixtureProcessExitedAsync(processIdPath);
    }

    [Fact]
    public async Task HealthSessionMismatchStopsOwnedFakeSidecarAndDeletesState()
    {
        using var temporary = new TemporaryDirectory();
        var pack = await SidecarTestFixture.CreateRuntimePackAsync(temporary.Path);
        var processIdPath = Path.Combine(temporary.Path, "fixture-pid");
        var dataDirectory = Path.Combine(temporary.Path, "data");
        await using var provider = new VoxCpm2SidecarProvider(
            pack,
            dataDirectory,
            SidecarTestFixture.CreateHost("bad-health-session", null, processIdPath));

        await Assert.ThrowsAsync<RuntimePackException>(() => provider.EnsureReadyAsync());

        Assert.False(File.Exists(Path.Combine(dataDirectory, "sidecar-process-state.json")));
        await SidecarTestFixture.AssertFixtureProcessExitedAsync(processIdPath);
    }

    [Theory]
    [InlineData("malformed-wav")]
    [InlineData("oversized-response")]
    public async Task InvalidOrOversizedResponseStopsOwnedFakeSidecarAndDeletesState(string mode)
    {
        using var temporary = new TemporaryDirectory();
        var pack = await SidecarTestFixture.CreateRuntimePackAsync(temporary.Path);
        var processIdPath = Path.Combine(temporary.Path, "fixture-pid");
        var dataDirectory = Path.Combine(temporary.Path, "data");
        await using var provider = new VoxCpm2SidecarProvider(
            pack,
            dataDirectory,
            SidecarTestFixture.CreateHost(mode, null, processIdPath));

        var exception = await Record.ExceptionAsync(() => provider.SynthesizeAsync(Request()));

        Assert.NotNull(exception);
        Assert.True(exception is InvalidDataException or RuntimePackException);
        Assert.False(File.Exists(Path.Combine(dataDirectory, "sidecar-process-state.json")));
        await SidecarTestFixture.AssertFixtureProcessExitedAsync(processIdPath);
    }

    [Fact]
    public async Task TimedOutTtsCancellationStopsOwnedFakeSidecarAndDeletesState()
    {
        using var temporary = new TemporaryDirectory();
        var pack = await SidecarTestFixture.CreateRuntimePackAsync(temporary.Path);
        var processIdPath = Path.Combine(temporary.Path, "fixture-pid");
        var dataDirectory = Path.Combine(temporary.Path, "data");
        await using var provider = new VoxCpm2SidecarProvider(
            pack,
            dataDirectory,
            SidecarTestFixture.CreateHost("hang", null, processIdPath));
        await provider.EnsureReadyAsync();
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(250));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            provider.SynthesizeAsync(Request(), cancellation.Token));

        Assert.False(File.Exists(Path.Combine(dataDirectory, "sidecar-process-state.json")));
        await SidecarTestFixture.AssertFixtureProcessExitedAsync(processIdPath);
    }

    [Fact]
    public async Task StopInterruptsInFlightSynthesisBeforeTheOperationGateIsReleased()
    {
        var session = new StopReleasedSession();
        var factory = new StopReleasedSessionFactory(session);
        await using var provider = new VoxCpm2SidecarProvider(
            SidecarTestFixture.ProviderPack(),
            Path.GetTempPath(),
            factory);
        var synthesis = provider.SynthesizeAsync(Request());
        await session.TtsEntered.Task.WaitAsync(TimeSpan.FromSeconds(2));

        await provider.StopAsync().WaitAsync(TimeSpan.FromSeconds(2));
        await Assert.ThrowsAsync<IOException>(() => synthesis);

        Assert.Equal(1, session.StopCount);
        Assert.Equal(1, session.DisposeCount);
        Assert.Equal(1, factory.StartCount);
        Assert.False(await provider.IsReadyAsync());
    }

    [Fact]
    public async Task StopRejectsSynthesisQueuedBeforeTheStopGeneration()
    {
        var session = new StopReleasedSession();
        var factory = new StopReleasedSessionFactory(session);
        await using var provider = new VoxCpm2SidecarProvider(
            SidecarTestFixture.ProviderPack(),
            Path.GetTempPath(),
            factory);
        var first = provider.SynthesizeAsync(Request());
        await session.TtsEntered.Task.WaitAsync(TimeSpan.FromSeconds(2));
        var queued = provider.SynthesizeAsync(Request());

        await provider.StopAsync().WaitAsync(TimeSpan.FromSeconds(2));
        await Assert.ThrowsAsync<IOException>(() => first);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => queued);

        Assert.Equal(1, factory.StartCount);
    }

    private static SynthesisRequest Request() => new()
    {
        Text = "안녕하세요.",
        VoiceId = "m1",
        QualitySteps = 8,
    };

    private static byte[] CreateWave()
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
        return bytes;
    }

    private sealed class ScriptedSessionFactory(ScriptedSession session) : ISidecarSessionFactory
    {
        public int StartCount { get; private set; }

        public Task<ISidecarClientSession> StartAsync(
            SidecarLaunchOptions options,
            CancellationToken cancellationToken = default)
        {
            StartCount++;
            return Task.FromResult<ISidecarClientSession>(session);
        }
    }

    private sealed class ScriptedSession : ISidecarClientSession
    {
        private static readonly JsonSerializerOptions HealthJsonOptions = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            Converters = { new JsonStringEnumConverter(namingPolicy: null, allowIntegerValues: false) },
        };

        public SidecarHandshakeDocument Handshake { get; } = new()
        {
            SchemaVersion = 1,
            ProtocolVersion = 2,
            EngineId = "voxcpm2",
            EngineVersion = "2.0.3",
            ModelRevision = "bffb3df5a2944062",
            Backend = AccelerationBackend.Cpu,
            ParentProcessId = 12_344,
            ParentStartUtcTicks = 638_000_000_000_000_000,
            SessionId = new string('c', 32),
            ListenerAddress = "127.0.0.1",
            ProcessId = 12_345,
            Port = 50_001,
            Nonce = new string('a', 64),
            Proof = new string('b', 64),
        };

        public string SessionId { get; } = new string('c', 32);
        public int ProcessId => Handshake.ProcessId;
        public bool HasExited { get; private set; }
        public int StopCount { get; private set; }
        public int DisposeCount { get; private set; }
        public List<string> Paths { get; } = [];
        public byte[] TtsBody { get; private set; } = [];
        public SidecarHttpResponse TtsResponse { get; init; } = new(
            HttpStatusCode.OK,
            "audio/wav",
            VoxCpm2SidecarProviderTests.CreateWave(),
            new Dictionary<string, string>());

        public Task<SidecarHttpResponse> SendAuthenticatedAsync(
            HttpMethod method,
            string path,
            ReadOnlyMemory<byte> body,
            string? contentType,
            int maximumResponseBytes,
            TimeSpan timeout,
            CancellationToken cancellationToken = default)
        {
            Paths.Add(path);
            if (path == "/v1/health")
            {
                var bytes = JsonSerializer.SerializeToUtf8Bytes(new
                {
                    schemaVersion = 1,
                    engineId = "voxcpm2",
                    engineVersion = "2.0.3",
                    modelRevision = "bffb3df5a2944062",
                    backend = AccelerationBackend.Cpu,
                    sessionId = SessionId,
                    processId = ProcessId,
                    ready = true,
                }, HealthJsonOptions);
                return Task.FromResult(new SidecarHttpResponse(
                    HttpStatusCode.OK,
                    "application/json",
                    bytes,
                    new Dictionary<string, string>()));
            }
            TtsBody = body.ToArray();
            return Task.FromResult(TtsResponse);
        }

        public Task StopAsync(CancellationToken cancellationToken = default)
        {
            StopCount++;
            HasExited = true;
            return Task.CompletedTask;
        }

        public ValueTask DisposeAsync()
        {
            DisposeCount++;
            return ValueTask.CompletedTask;
        }
    }

    private sealed class StopReleasedSessionFactory(StopReleasedSession session) : ISidecarSessionFactory
    {
        public int StartCount { get; private set; }

        public Task<ISidecarClientSession> StartAsync(
            SidecarLaunchOptions options,
            CancellationToken cancellationToken = default)
        {
            StartCount++;
            return Task.FromResult<ISidecarClientSession>(session);
        }
    }

    private sealed class StopReleasedSession : ISidecarClientSession
    {
        private readonly TaskCompletionSource<SidecarHttpResponse> stopped =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public SidecarHandshakeDocument Handshake { get; } = new()
        {
            SchemaVersion = 1,
            ProtocolVersion = 2,
            EngineId = "voxcpm2",
            EngineVersion = "2.0.3",
            ModelRevision = "bffb3df5a2944062",
            Backend = AccelerationBackend.Cpu,
            ParentProcessId = 12_344,
            ParentStartUtcTicks = 638_000_000_000_000_000,
            SessionId = new string('c', 32),
            ListenerAddress = "127.0.0.1",
            ProcessId = 12_345,
            Port = 50_001,
            Nonce = new string('a', 64),
            Proof = new string('b', 64),
        };

        public TaskCompletionSource TtsEntered { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        public string SessionId => Handshake.SessionId;
        public int ProcessId => Handshake.ProcessId;
        public bool HasExited { get; private set; }
        public int StopCount { get; private set; }
        public int DisposeCount { get; private set; }

        public Task<SidecarHttpResponse> SendAuthenticatedAsync(
            HttpMethod method,
            string path,
            ReadOnlyMemory<byte> body,
            string? contentType,
            int maximumResponseBytes,
            TimeSpan timeout,
            CancellationToken cancellationToken = default)
        {
            if (path == "/v1/health")
            {
                var bytes = JsonSerializer.SerializeToUtf8Bytes(new
                {
                    schemaVersion = 1,
                    engineId = "voxcpm2",
                    engineVersion = "2.0.3",
                    modelRevision = "bffb3df5a2944062",
                    backend = AccelerationBackend.Cpu,
                    sessionId = SessionId,
                    processId = ProcessId,
                    ready = true,
                }, new JsonSerializerOptions
                {
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                    Converters = { new JsonStringEnumConverter(namingPolicy: null, allowIntegerValues: false) },
                });
                return Task.FromResult(new SidecarHttpResponse(
                    HttpStatusCode.OK,
                    "application/json",
                    bytes,
                    new Dictionary<string, string>()));
            }
            TtsEntered.TrySetResult();
            return stopped.Task;
        }

        public Task StopAsync(CancellationToken cancellationToken = default)
        {
            StopCount++;
            HasExited = true;
            stopped.TrySetException(new IOException("owned sidecar stopped"));
            return Task.CompletedTask;
        }

        public ValueTask DisposeAsync()
        {
            DisposeCount++;
            return ValueTask.CompletedTask;
        }
    }
}
