using SupertonicVox.Core;

namespace SupertonicVox.Core.Tests;

public sealed class BenchmarkCacheTests
{
    [Fact]
    public async Task RoundTripAndInvalidationUseAllKeyFields()
    {
        using var temporary = new TemporaryDirectory();
        var cache = new JsonBenchmarkCache(Path.Combine(temporary.Path, "benchmarks.json"));
        var result = Result();
        await cache.PutAsync(result);
        Assert.NotNull(await cache.GetAsync("0.1.0", "supertonic-3", "revision", "hardware"));
        Assert.Null(await cache.GetAsync("0.2.0", "supertonic-3", "revision", "hardware"));
        Assert.Null(await cache.GetAsync("0.1.0", "supertonic-3", "other", "hardware"));
        Assert.Null(await cache.GetAsync("0.1.0", "supertonic-3", "revision", "other"));
    }

    [Fact]
    public async Task CorruptCacheIsIgnored()
    {
        using var temporary = new TemporaryDirectory();
        var path = Path.Combine(temporary.Path, "benchmarks.json");
        await File.WriteAllTextAsync(path, "not-json");
        var cache = new JsonBenchmarkCache(path);
        Assert.Null(await cache.GetAsync("0.1.0", "supertonic-3", "revision", "hardware"));
    }

    private static BenchmarkResult Result() => new()
    {
        EngineId = "supertonic-3",
        ModelRevision = "revision",
        HardwareFingerprint = "hardware",
        AppVersion = "0.1.0",
        Success = true,
        WavValid = true,
        ColdStartMilliseconds = 100,
        RealTimeFactor = 0.5,
        PeakMemoryBytes = 1000,
        CreatedUtc = DateTimeOffset.UtcNow,
    };
}

internal sealed class TemporaryDirectory : IDisposable
{
    public TemporaryDirectory()
    {
        Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "svx-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path);
    }

    public string Path { get; }

    public void Dispose()
    {
        try { Directory.Delete(Path, true); }
        catch { }
    }
}
