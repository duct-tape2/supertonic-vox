using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using SupertonicVox.Core;

namespace SupertonicVox.Core.Tests;

public sealed class RuntimePackTests
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter(namingPolicy: null, allowIntegerValues: false) },
    };

    [Fact]
    public async Task ValidPackIsVerifiedSealedActivatedAndRechecked()
    {
        using var temporary = new TemporaryDirectory();
        var staged = CreatePack(temporary.Path, "vox.partial");
        var final = Path.Combine(temporary.Path, "vox-active");
        var verifier = new RuntimePackVerifier();

        var pack = await verifier.VerifyAndActivateAsync(staged, final);

        Assert.False(Directory.Exists(staged));
        Assert.True(Directory.Exists(final));
        Assert.Equal("voxcpm2", pack.Manifest.EngineId);
        Assert.Equal(final, pack.RootPath);
        Assert.Equal(64, pack.PackFingerprint.Length);
        await verifier.VerifyPrelaunchAsync(pack);
        if (!OperatingSystem.IsWindows())
        {
            var entrypoint = Path.Combine(final, "bin", "fake-sidecar");
            var mode = File.GetUnixFileMode(entrypoint);
            Assert.True((mode & UnixFileMode.UserExecute) != 0);
            Assert.True((mode & UnixFileMode.UserWrite) == 0);
        }
    }

    [Fact]
    public async Task PackRejectsTamperMissingUnlistedAndLinkedFiles()
    {
        using var temporary = new TemporaryDirectory();
        var verifier = new RuntimePackVerifier();

        var tampered = CreatePack(temporary.Path, "tampered.partial");
        await File.AppendAllTextAsync(Path.Combine(tampered, "config", "engine.json"), "tamper");
        await Assert.ThrowsAsync<RuntimePackException>(() => verifier.VerifyAsync(tampered));

        var missing = CreatePack(temporary.Path, "missing.partial");
        File.Delete(Path.Combine(missing, "config", "engine.json"));
        await Assert.ThrowsAsync<RuntimePackException>(() => verifier.VerifyAsync(missing));

        var unlisted = CreatePack(temporary.Path, "unlisted.partial");
        await File.WriteAllTextAsync(Path.Combine(unlisted, "unexpected.bin"), "unexpected");
        await Assert.ThrowsAsync<RuntimePackException>(() => verifier.VerifyAsync(unlisted));

        var linked = CreatePack(temporary.Path, "linked.partial");
        var config = Path.Combine(linked, "config", "engine.json");
        File.Delete(config);
        File.CreateSymbolicLink(config, Path.Combine(linked, "bin", "fake-sidecar"));
        await Assert.ThrowsAsync<RuntimePackException>(() => verifier.VerifyAsync(linked));

        var hardLinked = CreatePack(temporary.Path, "hardlink.partial");
        var hardTarget = Path.Combine(hardLinked, "config", "engine.json");
        var replacement = Path.Combine(hardLinked, "config", "hardlink-source.json");
        File.Move(hardTarget, replacement);
        CreateHardLink(hardTarget, replacement);
        var manifest = LoadManifest(hardLinked);
        manifest = manifest with
        {
            Files = manifest.Files
                .Where(value => value.Path != "config/engine.json")
                .Append(FileRecord(hardTarget, "config/engine.json"))
                .Append(FileRecord(replacement, "config/hardlink-source.json"))
                .OrderBy(value => value.Path, StringComparer.Ordinal)
                .ToArray(),
            PrelaunchVerifyPaths =
            ["bin/fake-sidecar", "config/engine.json", "config/hardlink-source.json"],
        };
        WriteManifest(hardLinked, manifest);
        await Assert.ThrowsAsync<RuntimePackException>(() => verifier.VerifyAsync(hardLinked));
    }

    [Fact]
    public async Task PackRejectsHardLinkedManifest()
    {
        using var temporary = new TemporaryDirectory();
        var pack = CreatePack(temporary.Path, "manifest-hardlink.partial");
        var manifest = Path.Combine(pack, RuntimePackVerifier.ManifestFileName);
        var external = Path.Combine(temporary.Path, "manifest-source.json");
        File.Move(manifest, external);
        CreateHardLink(manifest, external);

        await Assert.ThrowsAsync<RuntimePackException>(
            () => new RuntimePackVerifier().VerifyAsync(pack));
    }

    [Fact]
    public async Task PrelaunchRejectsManifestHardLinkedAfterActivation()
    {
        using var temporary = new TemporaryDirectory();
        var staged = CreatePack(temporary.Path, "manifest-race.partial");
        var final = Path.Combine(temporary.Path, "manifest-race-active");
        var verifier = new RuntimePackVerifier();
        var pack = await verifier.VerifyAndActivateAsync(staged, final);
        var manifest = Path.Combine(final, RuntimePackVerifier.ManifestFileName);
        var external = Path.Combine(temporary.Path, "manifest-race-source.json");
        MakeWritable(manifest);
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(final, File.GetUnixFileMode(final) | UnixFileMode.UserWrite);
        File.Move(manifest, external);
        CreateHardLink(manifest, external);

        await Assert.ThrowsAsync<RuntimePackException>(
            () => verifier.VerifyPrelaunchAsync(pack));
    }

    [Fact]
    public async Task ManifestRejectsUnknownFieldsUnsafePathsAndCaseCollisions()
    {
        using var temporary = new TemporaryDirectory();
        var verifier = new RuntimePackVerifier();

        var unknown = CreatePack(temporary.Path, "unknown.partial");
        var node = JsonNode.Parse(await File.ReadAllTextAsync(
            Path.Combine(unknown, RuntimePackVerifier.ManifestFileName)))!.AsObject();
        node["unexpected"] = true;
        await File.WriteAllTextAsync(
            Path.Combine(unknown, RuntimePackVerifier.ManifestFileName),
            node.ToJsonString());
        await Assert.ThrowsAsync<RuntimePackException>(() => verifier.VerifyAsync(unknown));

        var unsafePack = CreatePack(temporary.Path, "unsafe.partial");
        var unsafeManifest = LoadManifest(unsafePack);
        unsafeManifest = unsafeManifest with
        {
            Files =
            [
                unsafeManifest.Files[0],
                unsafeManifest.Files[1] with { Path = "../escape" },
            ],
        };
        WriteManifest(unsafePack, unsafeManifest);
        await Assert.ThrowsAsync<RuntimePackException>(() => verifier.VerifyAsync(unsafePack));

        var duplicatePack = CreatePack(temporary.Path, "duplicate.partial");
        var duplicateManifest = LoadManifest(duplicatePack);
        duplicateManifest = duplicateManifest with
        {
            Files =
            [
                duplicateManifest.Files[0],
                duplicateManifest.Files[1],
                duplicateManifest.Files[1] with { Path = "CONFIG/ENGINE.JSON" },
            ],
        };
        WriteManifest(duplicatePack, duplicateManifest);
        await Assert.ThrowsAsync<RuntimePackException>(() => verifier.VerifyAsync(duplicatePack));
    }

    [Fact]
    public async Task PrelaunchVerificationRejectsPostActivationMutation()
    {
        using var temporary = new TemporaryDirectory();
        var staged = CreatePack(temporary.Path, "mutation.partial");
        var final = Path.Combine(temporary.Path, "mutation-active");
        var verifier = new RuntimePackVerifier();
        var pack = await verifier.VerifyAndActivateAsync(staged, final);
        var entrypoint = Path.Combine(final, "bin", "fake-sidecar");
        MakeWritable(entrypoint);
        await File.WriteAllTextAsync(entrypoint, "changed");

        await Assert.ThrowsAsync<RuntimePackException>(() => verifier.VerifyPrelaunchAsync(pack));
    }

    [Fact]
    public async Task ActivationRequiresSiblingPartialAndNewFinalDirectory()
    {
        using var temporary = new TemporaryDirectory();
        var verifier = new RuntimePackVerifier();
        var notPartial = CreatePack(temporary.Path, "pack-staging");
        await Assert.ThrowsAsync<RuntimePackException>(() => verifier.VerifyAndActivateAsync(
            notPartial,
            Path.Combine(temporary.Path, "final")));

        var staged = CreatePack(temporary.Path, "existing.partial");
        var final = Path.Combine(temporary.Path, "existing-final");
        Directory.CreateDirectory(final);
        await Assert.ThrowsAsync<RuntimePackException>(() => verifier.VerifyAndActivateAsync(staged, final));
    }

    [Fact]
    public async Task LegacySidecarProtocolFailsClosed()
    {
        using var temporary = new TemporaryDirectory();
        var root = CreatePack(temporary.Path, "legacy.partial");
        var manifest = LoadManifest(root) with { ProtocolVersion = 1 };
        WriteManifest(root, manifest);

        await Assert.ThrowsAsync<RuntimePackException>(() => new RuntimePackVerifier().VerifyAsync(root));
    }

    [Fact]
    public async Task StrictManifestAboveOneMiBAndBelowEightMiBIsAccepted()
    {
        using var temporary = new TemporaryDirectory();
        var root = CreatePack(temporary.Path, "large-valid.partial");
        var common = Path.Combine(
            root,
            "payload",
            new string('a', 96),
            new string('b', 96),
            new string('c', 96),
            new string('d', 96),
            new string('e', 96),
            new string('f', 96),
            new string('g', 96));
        Directory.CreateDirectory(common);
        var files = LoadManifest(root).Files.ToList();
        for (var index = 0; index < 1_600; index++)
        {
            var name = $"fixture-{index:D4}.bin";
            var path = Path.Combine(common, name);
            await File.WriteAllTextAsync(path, "x");
            files.Add(FileRecord(path, Path.GetRelativePath(root, path).Replace('\\', '/')));
        }
        var manifest = LoadManifest(root) with
        {
            Files = files.OrderBy(value => value.Path.ToUpperInvariant(), StringComparer.Ordinal).ToArray(),
        };
        WriteManifest(root, manifest);
        var manifestLength = new FileInfo(Path.Combine(root, RuntimePackVerifier.ManifestFileName)).Length;
        Assert.InRange(manifestLength, 1024 * 1024 + 1L, 8L * 1024 * 1024);

        var verified = await new RuntimePackVerifier().VerifyAsync(root);

        Assert.Equal(files.Count, verified.Files.Count);
    }

    [Fact]
    public async Task ManifestAboveEightMiBIsRejectedBeforeParsing()
    {
        using var temporary = new TemporaryDirectory();
        var root = Path.Combine(temporary.Path, "too-large.partial");
        Directory.CreateDirectory(root);
        var manifest = Path.Combine(root, RuntimePackVerifier.ManifestFileName);
        await using (var stream = new FileStream(manifest, FileMode.CreateNew, FileAccess.Write))
        {
            stream.SetLength(8L * 1024 * 1024 + 1);
        }

        var exception = await Assert.ThrowsAsync<RuntimePackException>(
            () => new RuntimePackVerifier().VerifyAsync(root));

        Assert.Contains("input size is invalid", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ListedZeroByteRegularFileIsHashBoundAndAccepted()
    {
        using var temporary = new TemporaryDirectory();
        var root = CreatePack(temporary.Path, "empty-file.partial");
        var empty = Path.Combine(root, "config", "package-marker.txt");
        await File.WriteAllBytesAsync(empty, []);
        var manifest = LoadManifest(root);
        manifest = manifest with
        {
            Files = manifest.Files
                .Append(FileRecord(empty, "config/package-marker.txt"))
                .OrderBy(value => value.Path.ToUpperInvariant(), StringComparer.Ordinal)
                .ToArray(),
        };
        WriteManifest(root, manifest);

        var verified = await new RuntimePackVerifier().VerifyAsync(root);

        var declaration = verified.Files["config/package-marker.txt"];
        Assert.Equal(0, declaration.SizeBytes);
        Assert.Equal("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", declaration.Sha256);
    }

    private static string CreatePack(string parent, string name)
    {
        var root = Path.Combine(parent, name);
        Directory.CreateDirectory(Path.Combine(root, "bin"));
        Directory.CreateDirectory(Path.Combine(root, "config"));
        var entrypoint = Path.Combine(root, "bin", "fake-sidecar");
        var config = Path.Combine(root, "config", "engine.json");
        File.WriteAllText(entrypoint, "fixture entrypoint");
        File.WriteAllText(config, "{\"fixture\":true}");
        var manifest = new RuntimePackManifest
        {
            SchemaVersion = 1,
            ProtocolVersion = 2,
            EngineId = "voxcpm2",
            EngineVersion = "2.0.3",
            ModelRevision = "bffb3df5a2944062",
            Platform = OperatingSystem.IsWindows() ? PlatformKind.Windows : PlatformKind.MacOS,
            Architecture = OperatingSystem.IsWindows()
                ? CpuArchitectureKind.X64
                : CpuArchitectureKind.Arm64,
            Backend = AccelerationBackend.Cpu,
            EntryPoint = "bin/fake-sidecar",
            LaunchArguments = ["--fixture"],
            PrelaunchVerifyPaths = ["bin/fake-sidecar", "config/engine.json"],
            Files =
            [
                FileRecord(entrypoint, "bin/fake-sidecar"),
                FileRecord(config, "config/engine.json"),
            ],
        };
        WriteManifest(root, manifest);
        return root;
    }

    private static RuntimePackManifest LoadManifest(string root) =>
        JsonSerializer.Deserialize<RuntimePackManifest>(
            File.ReadAllBytes(Path.Combine(root, RuntimePackVerifier.ManifestFileName)),
            JsonOptions)!;

    private static void WriteManifest(string root, RuntimePackManifest manifest) =>
        File.WriteAllBytes(
            Path.Combine(root, RuntimePackVerifier.ManifestFileName),
            JsonSerializer.SerializeToUtf8Bytes(manifest, JsonOptions));

    private static RuntimePackFile FileRecord(string path, string relative) => new()
    {
        Path = relative,
        SizeBytes = new FileInfo(path).Length,
        Sha256 = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path))),
    };

    private static void MakeWritable(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            File.SetAttributes(path, File.GetAttributes(path) & ~FileAttributes.ReadOnly);
        }
        else
        {
            File.SetUnixFileMode(path, File.GetUnixFileMode(path) | UnixFileMode.UserWrite);
        }
    }

    private static void CreateHardLink(string linkPath, string existingPath)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = OperatingSystem.IsWindows() ? "cmd.exe" : "/bin/ln",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        if (OperatingSystem.IsWindows())
        {
            startInfo.ArgumentList.Add("/c");
            startInfo.ArgumentList.Add("mklink");
            startInfo.ArgumentList.Add("/H");
            startInfo.ArgumentList.Add(linkPath);
            startInfo.ArgumentList.Add(existingPath);
        }
        else
        {
            startInfo.ArgumentList.Add(existingPath);
            startInfo.ArgumentList.Add(linkPath);
        }
        using var process = Process.Start(startInfo)!;
        process.WaitForExit();
        if (process.ExitCode != 0)
            throw new InvalidOperationException(process.StandardError.ReadToEnd());
    }
}
