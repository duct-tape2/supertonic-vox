using System.Buffers.Binary;
using SupertonicVox.Core;

namespace SupertonicVox.Core.Tests;

public sealed class EngineBenchmarkTests
{
    [Fact]
    public async Task SuccessfulRunWritesCurrentValidatedBenchmark()
    {
        using var temporary = new TemporaryDirectory();
        var cache = new JsonBenchmarkCache(Path.Combine(temporary.Path, "benchmark.json"));
        await using var provider = new FakeProvider(CreateWave());
        var hardware = TestFixtures.Hardware(
            PlatformKind.MacOS,
            CpuArchitectureKind.Arm64,
            16 * TestFixtures.GiB);

        var result = await new EngineBenchmarkService().RunAsync(
            provider,
            hardware,
            "1.0.0",
            cache,
            executionFingerprint: new string('a', 64));

        Assert.True(result.Success);
        Assert.True(result.WavValid);
        Assert.True(double.IsFinite(result.RealTimeFactor));
        Assert.True(result.RealTimeFactor >= 0);
        Assert.Equal(new string('a', 64), result.ExecutionFingerprint);
        Assert.NotNull(await cache.GetAsync("1.0.0", provider.EngineId, provider.ModelRevision, hardware.Fingerprint));
    }

    [Fact]
    public void WaveInspectorRejectsTruncationAndLengthMismatch()
    {
        var wav = CreateWave();
        Assert.True(WaveFileInspector.TryReadPcm16(wav, out var metadata));
        Assert.Equal(44_100, metadata!.SampleRate);

        Assert.False(WaveFileInspector.TryReadPcm16(wav.AsSpan(0, 40), out _));
        wav[4] = 0;
        Assert.False(WaveFileInspector.TryReadPcm16(wav, out _));

        wav = CreateWave();
        BinaryPrimitives.WriteInt32LittleEndian(wav.AsSpan(28), 44_100);
        Assert.False(WaveFileInspector.TryReadPcm16(wav, out _));

        wav = CreateWave();
        BinaryPrimitives.WriteInt16LittleEndian(wav.AsSpan(32), 1);
        Assert.False(WaveFileInspector.TryReadPcm16(wav, out _));
    }

    [Fact]
    public async Task BenchmarkRejectsProviderDurationMismatch()
    {
        using var temporary = new TemporaryDirectory();
        var cache = new JsonBenchmarkCache(Path.Combine(temporary.Path, "benchmark.json"));
        await using var provider = new FakeProvider(CreateWave(), TimeSpan.FromSeconds(10));
        var hardware = TestFixtures.Hardware(
            PlatformKind.MacOS,
            CpuArchitectureKind.Arm64,
            16 * TestFixtures.GiB);

        var result = await new EngineBenchmarkService().RunAsync(provider, hardware, "1.0.0", cache);

        Assert.False(result.Success);
        Assert.False(result.WavValid);
    }

    private static byte[] CreateWave()
    {
        const int samples = 4_410;
        var bytes = new byte[44 + (samples * 2)];
        "RIFF"u8.CopyTo(bytes);
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(4), bytes.Length - 8);
        "WAVEfmt "u8.CopyTo(bytes.AsSpan(8));
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(16), 16);
        BinaryPrimitives.WriteInt16LittleEndian(bytes.AsSpan(20), 1);
        BinaryPrimitives.WriteInt16LittleEndian(bytes.AsSpan(22), 1);
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(24), 44_100);
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(28), 88_200);
        BinaryPrimitives.WriteInt16LittleEndian(bytes.AsSpan(32), 2);
        BinaryPrimitives.WriteInt16LittleEndian(bytes.AsSpan(34), 16);
        "data"u8.CopyTo(bytes.AsSpan(36));
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(40), samples * 2);
        return bytes;
    }

    private sealed class FakeProvider(byte[] wave, TimeSpan? reportedDuration = null) : IEngineProvider
    {
        public string EngineId => "supertonic-3";
        public string ModelRevision => "revision";

        public Task<bool> IsReadyAsync(CancellationToken cancellationToken = default) => Task.FromResult(true);
        public Task EnsureReadyAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task StopAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;

        public Task<SynthesisResult> SynthesizeAsync(
            SynthesisRequest request,
            CancellationToken cancellationToken = default) => Task.FromResult(new SynthesisResult
            {
                WavBytes = wave,
                SampleRate = 44_100,
                Channels = 1,
                BitsPerSample = 16,
                Duration = reportedDuration ?? TimeSpan.FromMilliseconds(100),
                EngineId = EngineId,
                ModelRevision = ModelRevision,
                VoiceId = request.VoiceId,
            });
    }
}
