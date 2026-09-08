using System.Diagnostics;

namespace SupertonicVox.Core;

public sealed class EngineBenchmarkService
{
    private static readonly string[] KoreanCorpus =
    [
        "오늘은 맑은 하늘 아래에서 천천히 산책했습니다.",
        "로컬 음성 합성은 원고를 외부로 보내지 않습니다.",
    ];

    public async Task<BenchmarkResult> RunAsync(
        IEngineProvider provider,
        HardwareProfile hardware,
        string appVersion,
        IBenchmarkCache cache,
        CancellationToken cancellationToken = default,
        string voiceId = "M1",
        string executionFingerprint = "")
    {
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(hardware);
        ArgumentException.ThrowIfNullOrWhiteSpace(appVersion);
        ArgumentNullException.ThrowIfNull(cache);
        if (string.IsNullOrWhiteSpace(voiceId) || voiceId.Length > 64)
            throw new ArgumentOutOfRangeException(nameof(voiceId));
        if (executionFingerprint.Length > 128 || executionFingerprint.Any(character =>
                character is not (>= '0' and <= '9' or >= 'a' and <= 'f')))
            throw new ArgumentOutOfRangeException(nameof(executionFingerprint));

        var stopwatch = Stopwatch.StartNew();
        var coldStartMilliseconds = 0d;
        var totalAudioSeconds = 0d;
        var wavValid = true;
        var success = false;
        ulong peakMemoryBytes = 0;
        try
        {
            for (var index = 0; index < KoreanCorpus.Length; index++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var before = stopwatch.Elapsed;
                var result = await provider.SynthesizeAsync(new SynthesisRequest
                {
                    Text = KoreanCorpus[index],
                    Language = "ko",
                    VoiceId = voiceId,
                    Speed = 1.05f,
                    QualitySteps = 8,
                }, cancellationToken).ConfigureAwait(false);
                if (index == 0) coldStartMilliseconds = (stopwatch.Elapsed - before).TotalMilliseconds;
                wavValid &= WaveFileInspector.TryReadPcm16(result.WavBytes, out var metadata) &&
                            metadata is not null &&
                            metadata.SampleRate == result.SampleRate &&
                            metadata.Duration > TimeSpan.Zero &&
                            Math.Abs((metadata.Duration - result.Duration).TotalMilliseconds) <= 20;
                if (metadata is not null) totalAudioSeconds += metadata.Duration.TotalSeconds;
                using var process = Process.GetCurrentProcess();
                process.Refresh();
                peakMemoryBytes = Math.Max(peakMemoryBytes, checked((ulong)Math.Max(0, process.PeakWorkingSet64)));
            }
            success = wavValid && totalAudioSeconds > 0;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            success = false;
            wavValid = false;
        }

        stopwatch.Stop();
        var realTimeFactor = totalAudioSeconds > 0
            ? stopwatch.Elapsed.TotalSeconds / totalAudioSeconds
            : double.MaxValue;
        var benchmark = new BenchmarkResult
        {
            EngineId = provider.EngineId,
            ModelRevision = provider.ModelRevision,
            HardwareFingerprint = hardware.Fingerprint,
            AppVersion = appVersion,
            Success = success,
            WavValid = wavValid,
            ColdStartMilliseconds = coldStartMilliseconds,
            RealTimeFactor = realTimeFactor,
            PeakMemoryBytes = peakMemoryBytes,
            CreatedUtc = DateTimeOffset.UtcNow,
            ExecutionFingerprint = executionFingerprint,
        };
        await cache.PutAsync(benchmark, cancellationToken).ConfigureAwait(false);
        return benchmark;
    }
}
