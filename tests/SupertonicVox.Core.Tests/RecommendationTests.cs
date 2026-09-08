using SupertonicVox.Core;

namespace SupertonicVox.Core.Tests;

public sealed class RecommendationTests
{
    [Fact]
    public void UnknownCapacityRejectsDownloadEnginesButKeepsBundledFallback()
    {
        var hardware = TestFixtures.Hardware(
            PlatformKind.Windows,
            CpuArchitectureKind.X64,
            0) with
        {
            FreeDiskBytes = 0,
        };

        var result = service.Recommend(Request(hardware));

        Assert.Equal("supertonic-3", result.SelectedEngine.Id);
        Assert.All(
            result.Candidates.Where(candidate => !candidate.Engine.IsBundled),
            candidate => Assert.False(candidate.Eligible));
        Assert.Contains(
            result.Candidates.Single(candidate => candidate.Engine.Id == "voxcpm2").Reasons,
            reason => reason.Contains("could not be verified", StringComparison.Ordinal));
    }

    private readonly EngineRecommendationService service = new();

    [Fact]
    public void EightGibCpu_SelectsBundledSupertonicWithoutInventingLatency()
    {
        var hardware = TestFixtures.Hardware(PlatformKind.Windows, CpuArchitectureKind.X64, 8 * TestFixtures.GiB);
        var recommendation = service.Recommend(Request(hardware));
        Assert.Equal("supertonic-3", recommendation.SelectedEngine.Id);
        Assert.True(recommendation.LatencyPending);
        Assert.Contains(recommendation.Reasons, reason => reason.Contains("pending", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void NvidiaEightGib_SelectsVoxForVoiceDesign()
    {
        var hardware = TestFixtures.Hardware(
            PlatformKind.Windows,
            CpuArchitectureKind.X64,
            16 * TestFixtures.GiB,
            new GpuDevice("NVIDIA Fixture", AccelerationBackend.Cuda, 8 * TestFixtures.GiB, false));
        var recommendation = service.Recommend(Request(hardware, EngineFeatures.VoiceDesign));
        Assert.Equal("voxcpm2", recommendation.SelectedEngine.Id);
        Assert.Equal(AccelerationBackend.Cuda, recommendation.SelectedBackend);
    }

    [Fact]
    public void AppleSiliconEightGib_RejectsVox()
    {
        var hardware = TestFixtures.Hardware(PlatformKind.MacOS, CpuArchitectureKind.Arm64, 8 * TestFixtures.GiB);
        var recommendation = service.Recommend(Request(hardware));
        var vox = Assert.Single(recommendation.Candidates, candidate => candidate.Engine.Id == "voxcpm2");
        Assert.False(vox.Eligible);
    }

    [Fact]
    public void AppleSiliconSixteenGib_AllowsVoxMpsOnlyAfterCurrentBenchmark()
    {
        var hardware = TestFixtures.Hardware(
            PlatformKind.MacOS,
            CpuArchitectureKind.Arm64,
            16 * TestFixtures.GiB,
            new GpuDevice("Apple M1", AccelerationBackend.Metal, 16 * TestFixtures.GiB, true));
        var benchmark = SuccessfulBenchmark("voxcpm2", "vox-rev", hardware);
        var recommendation = service.Recommend(Request(
            hardware,
            EngineFeatures.VoiceDesign,
            benchmarks: new Dictionary<string, BenchmarkResult> { [benchmark.EngineId] = benchmark }));
        Assert.Equal("voxcpm2", recommendation.SelectedEngine.Id);
        Assert.Equal(AccelerationBackend.Mps, recommendation.SelectedBackend);
    }

    [Fact]
    public void AppleSiliconSixteenGib_RejectsVoxMpsWithoutCurrentBenchmark()
    {
        var hardware = TestFixtures.Hardware(
            PlatformKind.MacOS,
            CpuArchitectureKind.Arm64,
            16 * TestFixtures.GiB,
            new GpuDevice("Apple M1", AccelerationBackend.Metal, 16 * TestFixtures.GiB, true));

        Assert.Throws<InvalidOperationException>(() =>
            service.Recommend(Request(hardware, EngineFeatures.VoiceDesign)));
    }

    [Fact]
    public void VoxBenchmarkFromDifferentRuntimePackIsRejected()
    {
        var hardware = TestFixtures.Hardware(
            PlatformKind.MacOS,
            CpuArchitectureKind.Arm64,
            16 * TestFixtures.GiB,
            new GpuDevice("Apple M1", AccelerationBackend.Metal, 16 * TestFixtures.GiB, true));
        var benchmark = SuccessfulBenchmark("voxcpm2", "vox-rev", hardware) with
        {
            ExecutionFingerprint = new string('a', 64),
        };

        Assert.Throws<InvalidOperationException>(() => service.Recommend(Request(
            hardware,
            EngineFeatures.VoiceDesign,
            benchmarks: new Dictionary<string, BenchmarkResult> { [benchmark.EngineId] = benchmark },
            executionFingerprints: new Dictionary<string, string>
            {
                ["voxcpm2"] = new string('b', 64),
            })));
    }

    [Fact]
    public void CurrentBenchmark_ActivatesWarmWeights()
    {
        var hardware = TestFixtures.Hardware(PlatformKind.Windows, CpuArchitectureKind.X64, 8 * TestFixtures.GiB);
        var benchmark = new BenchmarkResult
        {
            EngineId = "supertonic-3",
            ModelRevision = "super-rev",
            HardwareFingerprint = hardware.Fingerprint,
            AppVersion = "0.1.0",
            Success = true,
            WavValid = true,
            ColdStartMilliseconds = 500,
            RealTimeFactor = 0.25,
            PeakMemoryBytes = 512 * 1024 * 1024,
            CreatedUtc = DateTimeOffset.UtcNow,
        };
        var recommendation = service.Recommend(Request(
            hardware,
            benchmarks: new Dictionary<string, BenchmarkResult> { [benchmark.EngineId] = benchmark }));
        Assert.False(recommendation.LatencyPending);
        Assert.Contains(recommendation.Reasons, reason => reason.Contains("0.25", StringComparison.Ordinal));
    }

    [Fact]
    public void StaleBenchmark_IsIgnored()
    {
        var hardware = TestFixtures.Hardware(PlatformKind.Windows, CpuArchitectureKind.X64, 8 * TestFixtures.GiB);
        var stale = new BenchmarkResult
        {
            EngineId = "supertonic-3",
            ModelRevision = "old-revision",
            HardwareFingerprint = hardware.Fingerprint,
            AppVersion = "0.1.0",
            Success = true,
            WavValid = true,
            ColdStartMilliseconds = 1,
            RealTimeFactor = 0.01,
            PeakMemoryBytes = 1,
            CreatedUtc = DateTimeOffset.UtcNow,
        };
        var recommendation = service.Recommend(Request(
            hardware,
            benchmarks: new Dictionary<string, BenchmarkResult> { [stale.EngineId] = stale }));
        Assert.True(recommendation.LatencyPending);
    }

    [Fact]
    public void InvalidWavBenchmark_IsIgnored()
    {
        var hardware = TestFixtures.Hardware(PlatformKind.Windows, CpuArchitectureKind.X64, 8 * TestFixtures.GiB);
        var invalid = new BenchmarkResult
        {
            EngineId = "supertonic-3",
            ModelRevision = "super-rev",
            HardwareFingerprint = hardware.Fingerprint,
            AppVersion = "0.1.0",
            Success = true,
            WavValid = false,
            ColdStartMilliseconds = 100,
            RealTimeFactor = 0.1,
            PeakMemoryBytes = 1,
            CreatedUtc = DateTimeOffset.UtcNow,
        };

        var recommendation = service.Recommend(Request(
            hardware,
            benchmarks: new Dictionary<string, BenchmarkResult> { [invalid.EngineId] = invalid }));

        Assert.True(recommendation.LatencyPending);
    }

    [Fact]
    public void EligibleManualOverrideWins()
    {
        var hardware = TestFixtures.Hardware(PlatformKind.Windows, CpuArchitectureKind.X64, 8 * TestFixtures.GiB);
        var recommendation = service.Recommend(Request(hardware, manualEngineId: "melotts-ko"));
        Assert.Equal("melotts-ko", recommendation.SelectedEngine.Id);
        Assert.True(recommendation.IsManualOverride);
    }

    [Fact]
    public void IneligibleManualOverrideIsRevalidatedAndRejected()
    {
        var hardware = TestFixtures.Hardware(PlatformKind.MacOS, CpuArchitectureKind.Arm64, 8 * TestFixtures.GiB);
        Assert.Throws<InvalidOperationException>(() => service.Recommend(Request(hardware, manualEngineId: "voxcpm2")));
    }

    private static RecommendationRequest Request(
        HardwareProfile hardware,
        EngineFeatures features = EngineFeatures.GeneralTts,
        string? manualEngineId = null,
        IReadOnlyDictionary<string, BenchmarkResult>? benchmarks = null,
        IReadOnlyDictionary<string, string>? executionFingerprints = null) => new()
        {
            Hardware = hardware,
            Engines = [TestFixtures.Supertonic(), TestFixtures.Vox(), TestFixtures.Melo()],
            Benchmarks = benchmarks ?? new Dictionary<string, BenchmarkResult>(),
            AppVersion = "0.1.0",
            InstallStates = new Dictionary<string, EngineInstallState>(StringComparer.Ordinal)
            {
                ["supertonic-3"] = EngineInstallState.Bundled,
                ["voxcpm2"] = EngineInstallState.Installed,
                ["melotts-ko"] = EngineInstallState.Installed,
            },
            ExecutionFingerprints = executionFingerprints ?? new Dictionary<string, string>(),
            RequiredFeatures = features,
            ManualEngineId = manualEngineId,
        };

    private static BenchmarkResult SuccessfulBenchmark(
        string engineId,
        string modelRevision,
        HardwareProfile hardware) => new()
        {
            EngineId = engineId,
            ModelRevision = modelRevision,
            HardwareFingerprint = hardware.Fingerprint,
            AppVersion = "0.1.0",
            Success = true,
            WavValid = true,
            ColdStartMilliseconds = 500,
            RealTimeFactor = 0.8,
            PeakMemoryBytes = 1024,
            CreatedUtc = DateTimeOffset.UtcNow,
        };
}
