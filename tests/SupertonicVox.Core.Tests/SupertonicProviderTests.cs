using SupertonicVox.Core;

namespace SupertonicVox.Core.Tests;

public sealed class SupertonicProviderTests
{
    [Fact]
    public async Task MissingAssetsFailClosed()
    {
        using var temporary = new TemporaryDirectory();
        await using var provider = Provider(temporary.Path);

        Assert.False(await provider.IsReadyAsync());
        await Assert.ThrowsAsync<DirectoryNotFoundException>(() => provider.EnsureReadyAsync());
    }

    [Fact]
    public async Task ReferenceAudioIsRejectedBeforeModelLoading()
    {
        using var temporary = new TemporaryDirectory();
        Directory.CreateDirectory(Path.Combine(temporary.Path, "voice_styles"));
        await using var provider = Provider(temporary.Path);

        await Assert.ThrowsAsync<NotSupportedException>(() => provider.SynthesizeAsync(new SynthesisRequest
        {
            Text = "안녕하세요.",
            ReferenceAudio = [0, 1, 2],
        }));
    }

    [Fact]
    public async Task TextAndQualityLimitsAreEnforcedBeforeModelLoading()
    {
        using var temporary = new TemporaryDirectory();
        Directory.CreateDirectory(Path.Combine(temporary.Path, "voice_styles"));
        await using var provider = new SupertonicEngineProvider(new SupertonicProviderOptions
        {
            OnnxDirectory = Path.Combine(temporary.Path, "onnx"),
            VoiceStyleDirectory = Path.Combine(temporary.Path, "voice_styles"),
            MaximumTextCharacters = 8,
        });

        await Assert.ThrowsAsync<ArgumentException>(() => provider.SynthesizeAsync(new SynthesisRequest
        {
            Text = "123456789",
        }));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => provider.SynthesizeAsync(new SynthesisRequest
        {
            Text = "안녕",
            QualitySteps = 17,
        }));
    }

    [Fact]
    public void ManifestPinsOfficialImmutableRevisions()
    {
        Assert.Equal("5379cc4e4297cec249a8a71283fc44d55ec327f1", SupertonicModelManifest.UpstreamCodeRevision);
        Assert.Equal("3cadd1ee6394adea1bd021217a0e650ede09a323", SupertonicModelManifest.ModelRevision);
        Assert.Equal(6, SupertonicModelManifest.RequiredOnnxFiles.Count);
        Assert.All(
            SupertonicModelManifest.RequiredOnnxFiles.Values,
            file => Assert.Matches("^[0-9a-f]{64}$", file.Sha256));
    }

    private static SupertonicEngineProvider Provider(string root) => new(new SupertonicProviderOptions
    {
        OnnxDirectory = Path.Combine(root, "onnx"),
        VoiceStyleDirectory = Path.Combine(root, "voice_styles"),
    });
}
