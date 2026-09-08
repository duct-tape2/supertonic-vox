using SupertonicVox.Core;

namespace SupertonicVox.Core.Tests;

public sealed class SupertonicModelLocatorTests
{
    [Fact]
    public void AbsoluteEnvironmentOverrideWins()
    {
        using var temporary = new TemporaryDirectory();
        var configured = Path.Combine(temporary.Path, "custom-model");

        var resolved = SupertonicModelLocator.TryResolve(temporary.Path, configured, out var modelRoot);

        Assert.True(resolved);
        Assert.Equal(Path.GetFullPath(configured), modelRoot);
    }

    [Fact]
    public void RelativeEnvironmentOverrideFailsClosed()
    {
        using var temporary = new TemporaryDirectory();

        var resolved = SupertonicModelLocator.TryResolve(temporary.Path, "relative/model", out var modelRoot);

        Assert.False(resolved);
        Assert.Empty(modelRoot);
    }

    [Fact]
    public void ResolvesWindowsStyleAdjacentBundledModel()
    {
        using var temporary = new TemporaryDirectory();
        var root = Path.Combine(temporary.Path, "Models", "Supertonic3");
        CreateLayout(root);

        var resolved = SupertonicModelLocator.TryResolve(temporary.Path, null, out var modelRoot);

        Assert.True(resolved);
        Assert.Equal(Path.GetFullPath(root), modelRoot);
    }

    [Fact]
    public void ResolvesMacAppResourcesBundledModel()
    {
        using var temporary = new TemporaryDirectory();
        var executableDirectory = Path.Combine(temporary.Path, "SupertonicVox.app", "Contents", "MacOS");
        Directory.CreateDirectory(executableDirectory);
        var root = Path.Combine(temporary.Path, "SupertonicVox.app", "Contents", "Resources", "Models", "Supertonic3");
        CreateLayout(root);

        var resolved = SupertonicModelLocator.TryResolve(executableDirectory, null, out var modelRoot);

        Assert.True(resolved);
        Assert.Equal(Path.GetFullPath(root), modelRoot);
    }

    private static void CreateLayout(string root)
    {
        Directory.CreateDirectory(Path.Combine(root, "onnx"));
        Directory.CreateDirectory(Path.Combine(root, "voice_styles"));
    }
}
