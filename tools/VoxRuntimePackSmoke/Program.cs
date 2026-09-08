using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using SupertonicVox.Core;

if (args.Length != 4)
{
    Console.Error.WriteLine(
        "Usage: VoxRuntimePackSmoke <staged-pack.partial> <new-final-pack> <data-directory> <output.wav>");
    return 2;
}

var stagedPack = Path.GetFullPath(args[0]);
var finalPack = Path.GetFullPath(args[1]);
var dataDirectory = Path.GetFullPath(args[2]);
var outputPath = Path.GetFullPath(args[3]);
if (!Path.GetFileName(stagedPack).EndsWith(".partial", StringComparison.Ordinal) ||
    File.Exists(outputPath) || Directory.Exists(outputPath))
{
    Console.Error.WriteLine("Inputs must use a .partial staging pack and a new output WAV path.");
    return 2;
}

Directory.CreateDirectory(dataDirectory);
var verifier = new RuntimePackVerifier();
var pack = await verifier.VerifyAndActivateAsync(stagedPack, finalPack);
var stopwatch = Stopwatch.StartNew();
await using var provider = new VoxCpm2SidecarProvider(
    pack,
    dataDirectory,
    new OwnedSidecarProcessHost(verifier));
try
{
    await provider.EnsureReadyAsync();
    var coldStartMilliseconds = stopwatch.Elapsed.TotalMilliseconds;
    stopwatch.Restart();
    var result = await provider.SynthesizeAsync(new SynthesisRequest
    {
        Text = "안녕하세요. 로컬 음성 합성 검증 문장입니다.",
        Language = "ko",
        VoiceId = "vox_news_f",
        QualitySteps = 8,
    });
    var synthesisMilliseconds = stopwatch.Elapsed.TotalMilliseconds;
    var temporaryOutput = outputPath + $".{Environment.ProcessId}.partial";
    try
    {
        await File.WriteAllBytesAsync(temporaryOutput, result.WavBytes);
        File.Move(temporaryOutput, outputPath, overwrite: false);
    }
    finally
    {
        if (File.Exists(temporaryOutput)) File.Delete(temporaryOutput);
    }
    var evidence = new
    {
        schemaVersion = 1,
        releaseEligible = false,
        engineId = result.EngineId,
        engineVersion = pack.Manifest.EngineVersion,
        modelRevision = result.ModelRevision,
        backend = pack.Manifest.Backend,
        platform = pack.Manifest.Platform,
        architecture = pack.Manifest.Architecture,
        packFingerprint = pack.PackFingerprint,
        manifestSha256 = pack.ManifestSha256,
        coldStartMilliseconds,
        synthesisMilliseconds,
        durationMilliseconds = result.Duration.TotalMilliseconds,
        realTimeFactor = synthesisMilliseconds / result.Duration.TotalMilliseconds,
        sampleRate = result.SampleRate,
        channels = result.Channels,
        bitsPerSample = result.BitsPerSample,
        wavBytes = result.WavBytes.Length,
        wavSha256 = Convert.ToHexStringLower(SHA256.HashData(result.WavBytes)),
    };
    Console.WriteLine(JsonSerializer.Serialize(evidence));
    return 0;
}
finally
{
    await provider.StopAsync();
}
