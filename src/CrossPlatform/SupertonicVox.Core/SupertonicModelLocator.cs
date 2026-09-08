namespace SupertonicVox.Core;

public static class SupertonicModelLocator
{
    public const string EnvironmentVariable = "SVX_SUPERTONIC_MODEL_ROOT";

    public static bool TryResolve(
        string baseDirectory,
        string? configuredRoot,
        out string modelRoot)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(baseDirectory);
        if (!Path.IsPathFullyQualified(baseDirectory))
            throw new ArgumentException("The application base directory must be absolute.", nameof(baseDirectory));

        if (!string.IsNullOrWhiteSpace(configuredRoot))
        {
            if (!Path.IsPathFullyQualified(configuredRoot))
            {
                modelRoot = string.Empty;
                return false;
            }

            modelRoot = Path.GetFullPath(configuredRoot);
            return true;
        }

        var candidates = new[]
        {
            Path.Combine(baseDirectory, "Models", "Supertonic3"),
            Path.Combine(baseDirectory, "Models", "supertonic-3"),
            Path.Combine(baseDirectory, "..", "Resources", "Models", "Supertonic3"),
            Path.Combine(baseDirectory, "..", "Resources", "Models", "supertonic-3"),
        }.Select(Path.GetFullPath).Distinct(StringComparer.Ordinal).ToArray();

        modelRoot = candidates.FirstOrDefault(HasExpectedLayout) ?? candidates[0];
        return true;
    }

    private static bool HasExpectedLayout(string root) =>
        Directory.Exists(Path.Combine(root, "onnx")) &&
        Directory.Exists(Path.Combine(root, "voice_styles"));
}
