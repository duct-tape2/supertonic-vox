using SupertonicVox.Core;

if (args.Length is < 3 or > 4)
{
    Console.Error.WriteLine("Usage: SupertonicSmoke <onnx-directory> <voice-style-directory> <output.wav> [text]");
    return 2;
}

var outputPath = Path.GetFullPath(args[2]);
var outputDirectory = Path.GetDirectoryName(outputPath)
                      ?? throw new InvalidOperationException("Output directory is unavailable.");
Directory.CreateDirectory(outputDirectory);

await using var provider = new SupertonicEngineProvider(new SupertonicProviderOptions
{
    OnnxDirectory = args[0],
    VoiceStyleDirectory = args[1],
});

var text = args.Length == 4 ? args[3] : "안녕하세요. 슈퍼토닉 로컬 음성 합성 검증입니다.";
var result = await provider.SynthesizeAsync(new SynthesisRequest
{
    Text = text,
    Language = "ko",
    VoiceId = "M1",
    Speed = 1.05f,
    QualitySteps = 8,
});

var temporaryPath = Path.Combine(outputDirectory, $".{Path.GetFileName(outputPath)}.{Guid.NewGuid():N}.tmp");
try
{
    await File.WriteAllBytesAsync(temporaryPath, result.WavBytes);
    File.Move(temporaryPath, outputPath, true);
}
finally
{
    if (File.Exists(temporaryPath)) File.Delete(temporaryPath);
}

Console.WriteLine($"engine={result.EngineId}");
Console.WriteLine($"model_revision={result.ModelRevision}");
Console.WriteLine($"sample_rate={result.SampleRate}");
Console.WriteLine($"duration_seconds={result.Duration.TotalSeconds:F3}");
Console.WriteLine($"wav_bytes={result.WavBytes.Length}");
Console.WriteLine($"output={outputPath}");
return 0;
