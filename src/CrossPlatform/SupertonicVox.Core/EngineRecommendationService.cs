namespace SupertonicVox.Core;

public sealed class EngineRecommendationService
{
    private const string SupertonicId = "supertonic-3";
    private const string VoxId = "voxcpm2";

    public EngineRecommendation Recommend(RecommendationRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.Engines.Count == 0)
        {
            throw new InvalidOperationException("The verified engine catalog is empty.");
        }

        var candidates = request.Engines
            .Select(engine => Score(engine, request))
            .OrderByDescending(candidate => candidate.Score)
            .ThenBy(candidate => candidate.Engine.Id, StringComparer.Ordinal)
            .ToList();

        EngineCandidateScore selected;
        var isManual = false;
        if (!string.IsNullOrWhiteSpace(request.ManualEngineId))
        {
            selected = candidates.FirstOrDefault(candidate =>
                string.Equals(candidate.Engine.Id, request.ManualEngineId, StringComparison.Ordinal))
                ?? throw new InvalidOperationException("The manually selected engine is not in the verified catalog.");
            if (!selected.Eligible)
            {
                throw new InvalidOperationException(
                    $"The manually selected engine is no longer eligible: {string.Join(" ", selected.Reasons)}");
            }
            isManual = true;
        }
        else
        {
            selected = candidates.FirstOrDefault(candidate => candidate.Eligible)
                ?? throw new InvalidOperationException("No engine is eligible for this hardware profile.");
        }

        return new EngineRecommendation
        {
            SelectedEngine = selected.Engine,
            Score = selected.Score,
            IsManualOverride = isManual,
            LatencyPending = selected.LatencyPending,
            SelectedBackend = selected.SelectedBackend ?? AccelerationBackend.Cpu,
            Reasons = selected.Reasons,
            Candidates = candidates,
        };
    }

    private static EngineCandidateScore Score(EngineDescriptor engine, RecommendationRequest request)
    {
        var reasons = new List<string>();
        var hardware = request.Hardware;
        if (!engine.Platforms.Contains(hardware.Platform)) reasons.Add("This operating system is not supported.");
        if (!engine.Architectures.Contains(hardware.Architecture)) reasons.Add("This CPU architecture is not supported.");
        if (!engine.IsBundled && hardware.TotalMemoryBytes == 0 && engine.MinimumMemoryBytes > 0)
            reasons.Add("System memory capacity could not be verified.");
        if (!engine.IsBundled && hardware.FreeDiskBytes == 0 && engine.MinimumFreeDiskBytes > 0)
            reasons.Add("Free disk space could not be verified.");
        if (hardware.TotalMemoryBytes > 0 && hardware.TotalMemoryBytes < engine.MinimumMemoryBytes)
            reasons.Add("Not enough system memory.");
        if (hardware.FreeDiskBytes > 0 && hardware.FreeDiskBytes < engine.MinimumFreeDiskBytes)
            reasons.Add("Not enough free disk space.");
        if ((engine.Features & request.RequiredFeatures) != request.RequiredFeatures)
            reasons.Add("The engine does not provide the requested features.");
        var installState = request.InstallStates.TryGetValue(engine.Id, out var declaredState)
            ? declaredState
            : engine.IsBundled ? EngineInstallState.Bundled : EngineInstallState.NotInstalled;
        if (installState is not (EngineInstallState.Bundled or EngineInstallState.Installed))
            reasons.Add("The verified engine runtime is not installed and ready.");

        var backend = SelectBackend(engine, hardware, reasons);
        var benchmark = GetCurrentBenchmark(engine, request);
        if (string.Equals(engine.Id, VoxId, StringComparison.Ordinal) &&
            backend == AccelerationBackend.Mps && benchmark is null)
            reasons.Add("VoxCPM2 on Apple Silicon requires a successful current MPS benchmark.");
        var eligible = reasons.Count == 0 && backend is not null;
        if (!eligible)
        {
            return new EngineCandidateScore
            {
                Engine = engine,
                Eligible = false,
                Score = 0,
                LatencyPending = true,
                SelectedBackend = backend,
                Reasons = reasons,
            };
        }

        var quality = Math.Clamp(engine.KoreanQualityScore / 100d, 0, 1);
        var resource = ResourceHeadroom(engine, hardware, backend!.Value);
        var feature = FeatureFit(engine, request.RequiredFeatures);
        var latencyPending = benchmark is null;
        double score;
        if (benchmark is null)
        {
            score = 100d * ((quality * 50d) + (resource * 15d) + (feature * 10d)) / 75d;
            reasons.Add("Speed is pending a local benchmark; quality and resource fit were used.");
        }
        else
        {
            var latency = Math.Clamp(1d - (benchmark.RealTimeFactor / 2d), 0, 1);
            score = 100d * ((quality * 50d) + (latency * 25d) + (resource * 15d) + (feature * 10d)) / 100d;
            reasons.Add($"Measured local RTF: {benchmark.RealTimeFactor:0.00}.");
        }
        reasons.Insert(0, $"Selected backend: {backend}.");
        if (engine.IsBundled) reasons.Add("Bundled and ready without an additional engine download.");

        return new EngineCandidateScore
        {
            Engine = engine,
            Eligible = true,
            Score = Math.Round(score, 2),
            LatencyPending = latencyPending,
            SelectedBackend = backend,
            Reasons = reasons,
        };
    }

    private static BenchmarkResult? GetCurrentBenchmark(
        EngineDescriptor engine,
        RecommendationRequest request)
    {
        if (!request.Benchmarks.TryGetValue(engine.Id, out var benchmark)) return null;
        if (request.ExecutionFingerprints.TryGetValue(engine.Id, out var expectedExecutionFingerprint) &&
            !string.Equals(
                benchmark.ExecutionFingerprint,
                expectedExecutionFingerprint,
                StringComparison.Ordinal))
            return null;
        return benchmark.Success &&
               benchmark.WavValid &&
               benchmark.EngineId == engine.Id &&
               benchmark.ModelRevision == engine.ModelRevision &&
               benchmark.HardwareFingerprint == request.Hardware.Fingerprint &&
               benchmark.AppVersion == request.AppVersion
            ? benchmark
            : null;
    }

    private static AccelerationBackend? SelectBackend(
        EngineDescriptor engine,
        HardwareProfile hardware,
        ICollection<string> reasons)
    {
        if (string.Equals(engine.Id, VoxId, StringComparison.Ordinal))
        {
            var minimumGpuMemory = engine.MinimumGpuMemoryBytes == 0
                ? 8UL * 1024 * 1024 * 1024
                : engine.MinimumGpuMemoryBytes;
            var cuda = hardware.Gpus.FirstOrDefault(gpu =>
                gpu.Backend == AccelerationBackend.Cuda && gpu.MemoryBytes >= minimumGpuMemory);
            if (cuda is not null && engine.Backends.Contains(AccelerationBackend.Cuda)) return AccelerationBackend.Cuda;
            if (hardware.IsAppleSilicon && hardware.TotalMemoryBytes >= 16UL * 1024 * 1024 * 1024 &&
                engine.Backends.Contains(AccelerationBackend.Mps)) return AccelerationBackend.Mps;
            if (hardware.Platform == PlatformKind.Windows && hardware.TotalMemoryBytes >= 32UL * 1024 * 1024 * 1024 &&
                engine.Backends.Contains(AccelerationBackend.Cpu)) return AccelerationBackend.Cpu;
            reasons.Add("VoxCPM2 requires NVIDIA 8 GiB VRAM, Apple Silicon 16 GiB, or Windows 32 GiB RAM.");
            return null;
        }

        if (string.Equals(engine.Id, SupertonicId, StringComparison.Ordinal) &&
            engine.Backends.Contains(AccelerationBackend.OnnxCpu)) return AccelerationBackend.OnnxCpu;
        if (hardware.IsAppleSilicon && engine.Backends.Contains(AccelerationBackend.Mps)) return AccelerationBackend.Mps;
        if (engine.Backends.Contains(AccelerationBackend.Cpu)) return AccelerationBackend.Cpu;
        if (engine.Backends.Contains(AccelerationBackend.OnnxCpu)) return AccelerationBackend.OnnxCpu;
        reasons.Add("No compatible execution backend is available.");
        return null;
    }

    private static double ResourceHeadroom(
        EngineDescriptor engine,
        HardwareProfile hardware,
        AccelerationBackend backend)
    {
        static double Ratio(ulong available, ulong minimum)
        {
            if (minimum == 0) return 1;
            if (available == 0) return 0;
            return Math.Clamp(available / (double)(minimum * 2), 0, 1);
        }

        var memory = Ratio(hardware.TotalMemoryBytes, engine.MinimumMemoryBytes);
        var disk = Ratio(hardware.FreeDiskBytes, engine.MinimumFreeDiskBytes);
        var gpu = 1d;
        if (backend == AccelerationBackend.Cuda && engine.MinimumGpuMemoryBytes > 0)
        {
            var available = hardware.Gpus
                .Where(device => device.Backend == AccelerationBackend.Cuda)
                .Select(device => device.MemoryBytes)
                .DefaultIfEmpty(0UL)
                .Max();
            gpu = Ratio(available, engine.MinimumGpuMemoryBytes);
        }
        return Math.Min(memory, Math.Min(disk, gpu));
    }

    private static double FeatureFit(EngineDescriptor engine, EngineFeatures requested)
    {
        if (requested == EngineFeatures.None) return 1;
        var requestedCount = CountFlags(requested);
        var matchedCount = CountFlags(engine.Features & requested);
        return requestedCount == 0 ? 1 : matchedCount / (double)requestedCount;
    }

    private static int CountFlags(EngineFeatures features)
    {
        var count = 0;
        foreach (var flag in new[]
                 {
                     EngineFeatures.GeneralTts,
                     EngineFeatures.VoiceDesign,
                     EngineFeatures.VoiceCloning,
                     EngineFeatures.ReferenceAudio,
                 })
        {
            if (features.HasFlag(flag)) count++;
        }
        return count;
    }
}
