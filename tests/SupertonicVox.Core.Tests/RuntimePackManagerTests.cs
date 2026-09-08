using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using SupertonicVox.Core;

namespace SupertonicVox.Core.Tests;

public sealed class RuntimePackManagerTests
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter(namingPolicy: null, allowIntegerValues: false) },
    };

    [Fact]
    public async Task InstallPersistsAndReverifiesActivePackAcrossManagerInstances()
    {
        using var temporary = new TemporaryDirectory();
        var fixture = await CreateFixtureAsync(temporary.Path, "first", "first.svxpack.tar");
        var root = Path.Combine(temporary.Path, "managed");
        var installer = new CopyingArtifactInstaller([fixture]);
        var manager = new RuntimePackManager(root, installer);
        var consent = Consent(fixture, manager.DownloadDirectory);

        var result = await manager.InstallAsync(fixture.Engine, fixture.Artifact, consent);
        var inventory = await manager.GetInventoryAsync();
        var reopened = new RuntimePackManager(root, installer);
        var active = await reopened.GetActiveAsync("voxcpm2");

        Assert.False(result.ReusedExistingPack);
        Assert.Equal(fixture.Verified.PackFingerprint, result.Pack.PackFingerprint);
        Assert.Single(inventory.Installed);
        Assert.Empty(inventory.Invalid);
        Assert.Equal(fixture.Verified.PackFingerprint, active!.PackFingerprint);
        Assert.False(File.Exists(Path.Combine(manager.DownloadDirectory, fixture.Artifact.Name)));
    }

    [Fact]
    public async Task SideBySideUpdateCanRollbackAndStopsBeforeActiveUninstall()
    {
        using var temporary = new TemporaryDirectory();
        var first = await CreateFixtureAsync(temporary.Path, "first", "first.svxpack.tar");
        var second = await CreateFixtureAsync(temporary.Path, "second", "second.svxpack.tar");
        var engine = first.Engine with { Artifacts = [first.Artifact, second.Artifact] };
        first = first with { Engine = engine };
        second = second with { Engine = engine };
        var manager = new RuntimePackManager(
            Path.Combine(temporary.Path, "managed"),
            new CopyingArtifactInstaller([first, second]));
        await manager.InstallAsync(engine, first.Artifact, Consent(first, manager.DownloadDirectory));
        await manager.InstallAsync(engine, second.Artifact, Consent(second, manager.DownloadDirectory));
        Assert.Equal(second.Verified.PackFingerprint,
            (await manager.GetActiveAsync("voxcpm2"))!.PackFingerprint);
        var secondRoot = Path.Combine(
            temporary.Path,
            "managed",
            "packs",
            "voxcpm2",
            second.Verified.PackFingerprint);
        var stoppedBeforeMove = false;

        await manager.UninstallAsync(
            "voxcpm2",
            second.Verified.PackFingerprint,
            _ =>
            {
                stoppedBeforeMove = Directory.Exists(secondRoot);
                return Task.CompletedTask;
            });

        Assert.True(stoppedBeforeMove);
        Assert.False(Directory.Exists(secondRoot));
        Assert.Equal(first.Verified.PackFingerprint,
            (await manager.GetActiveAsync("voxcpm2"))!.PackFingerprint);
    }

    [Fact]
    public async Task TamperedInstalledPackIsInvalidAndCannotRemainActive()
    {
        using var temporary = new TemporaryDirectory();
        var fixture = await CreateFixtureAsync(temporary.Path, "first", "pack.svxpack.tar");
        var manager = new RuntimePackManager(
            Path.Combine(temporary.Path, "managed"),
            new CopyingArtifactInstaller([fixture]));
        var installed = await manager.InstallAsync(
            fixture.Engine,
            fixture.Artifact,
            Consent(fixture, manager.DownloadDirectory));
        var config = Path.Combine(installed.Pack.RootPath, "config", "engine.json");
        MakeWritable(config);
        await File.AppendAllTextAsync(config, "tamper");

        var inventory = await manager.GetInventoryAsync();

        Assert.Empty(inventory.Installed);
        Assert.Single(inventory.Invalid);
        Assert.Empty(inventory.ActivePackFingerprints);
        Assert.Null(await manager.GetActiveAsync("voxcpm2"));
    }

    [Fact]
    public async Task SignedIdentityMismatchNeverActivatesTheExtractedPack()
    {
        using var temporary = new TemporaryDirectory();
        var fixture = await CreateFixtureAsync(temporary.Path, "first", "pack.svxpack.tar");
        var forgedMetadata = fixture.Artifact.RuntimePack! with { PackFingerprint = new string('f', 64) };
        var forgedArtifact = fixture.Artifact with { RuntimePack = forgedMetadata };
        var engine = fixture.Engine with { Artifacts = [forgedArtifact] };
        fixture = fixture with { Engine = engine, Artifact = forgedArtifact };
        var root = Path.Combine(temporary.Path, "managed");
        var manager = new RuntimePackManager(root, new CopyingArtifactInstaller([fixture]));

        await Assert.ThrowsAsync<RuntimePackException>(() => manager.InstallAsync(
            engine,
            forgedArtifact,
            Consent(fixture, manager.DownloadDirectory)));

        Assert.False(Directory.Exists(Path.Combine(root, "packs", "voxcpm2", new string('f', 64))));
        Assert.Empty((await manager.GetInventoryAsync()).Installed);
    }

    [Fact]
    public async Task InvalidPackCanBeUninstalledAndReinstalledWithoutLeavingState()
    {
        using var temporary = new TemporaryDirectory();
        var fixture = await CreateFixtureAsync(temporary.Path, "first", "pack.svxpack.tar");
        var root = Path.Combine(temporary.Path, "managed");
        var manager = new RuntimePackManager(root, new CopyingArtifactInstaller([fixture]));
        var installed = await manager.InstallAsync(
            fixture.Engine,
            fixture.Artifact,
            Consent(fixture, manager.DownloadDirectory));
        var config = Path.Combine(installed.Pack.RootPath, "config", "engine.json");
        MakeWritable(config);
        await File.AppendAllTextAsync(config, "tamper");

        await manager.UninstallAsync("voxcpm2", installed.Pack.PackFingerprint, _ => Task.CompletedTask);
        Assert.Empty((await manager.GetInventoryAsync()).Installed);
        var reinstalled = await manager.InstallAsync(
            fixture.Engine,
            fixture.Artifact,
            Consent(fixture, manager.DownloadDirectory));
        config = Path.Combine(reinstalled.Pack.RootPath, "config", "engine.json");
        MakeWritable(config);
        await File.AppendAllTextAsync(config, "tamper-again");
        var stopped = false;

        var repaired = await manager.InstallAsync(
            fixture.Engine,
            fixture.Artifact,
            Consent(fixture, manager.DownloadDirectory),
            stopExistingProvider: _ =>
            {
                stopped = true;
                return Task.CompletedTask;
            });

        Assert.True(stopped);
        Assert.Equal(fixture.Verified.PackFingerprint, repaired.Pack.PackFingerprint);
        Assert.Single((await manager.GetInventoryAsync()).Installed);
    }

    [Fact]
    public async Task MalformedArchiveFailureCleansStagingAndRetrySucceeds()
    {
        using var temporary = new TemporaryDirectory();
        var fixture = await CreateFixtureAsync(temporary.Path, "first", "pack.svxpack.tar");
        var validArchive = await File.ReadAllBytesAsync(fixture.ArchivePath);
        await File.WriteAllBytesAsync(fixture.ArchivePath, [.. validArchive, 1]);
        var root = Path.Combine(temporary.Path, "managed");
        var manager = new RuntimePackManager(root, new CopyingArtifactInstaller([fixture]));
        var consent = Consent(fixture, manager.DownloadDirectory);

        await Assert.ThrowsAsync<RuntimePackException>(() => manager.InstallAsync(
            fixture.Engine,
            fixture.Artifact,
            consent));
        var staged = Path.Combine(
            root,
            "packs",
            "voxcpm2",
            fixture.Verified.PackFingerprint + ".partial");
        Assert.False(Directory.Exists(staged));
        await File.WriteAllBytesAsync(fixture.ArchivePath, validArchive);

        var installed = await manager.InstallAsync(fixture.Engine, fixture.Artifact, consent);

        Assert.Equal(fixture.Verified.PackFingerprint, installed.Pack.PackFingerprint);
    }

    [Fact]
    public async Task RegularFileAtPackRootCanBePurgedAndReinstalled()
    {
        using var temporary = new TemporaryDirectory();
        var fixture = await CreateFixtureAsync(temporary.Path, "first", "pack.svxpack.tar");
        var manager = new RuntimePackManager(
            Path.Combine(temporary.Path, "managed"),
            new CopyingArtifactInstaller([fixture]));
        var installed = await manager.InstallAsync(
            fixture.Engine,
            fixture.Artifact,
            Consent(fixture, manager.DownloadDirectory));
        DeletePackDirectoryForTamper(installed.Pack.RootPath);
        await File.WriteAllTextAsync(installed.Pack.RootPath, "invalid root file");
        Assert.Single((await manager.GetInventoryAsync()).Invalid);

        var repaired = await manager.InstallAsync(
            fixture.Engine,
            fixture.Artifact,
            Consent(fixture, manager.DownloadDirectory),
            stopExistingProvider: _ => Task.CompletedTask);

        Assert.True(Directory.Exists(repaired.Pack.RootPath));
        Assert.False(File.Exists(repaired.Pack.RootPath));
        Assert.Single((await manager.GetInventoryAsync()).Installed);
    }

    [Fact]
    public async Task UninstallDoesNotActivateCorruptRollbackCandidate()
    {
        using var temporary = new TemporaryDirectory();
        var first = await CreateFixtureAsync(temporary.Path, "first", "first.svxpack.tar");
        var second = await CreateFixtureAsync(temporary.Path, "second", "second.svxpack.tar");
        var engine = first.Engine with { Artifacts = [first.Artifact, second.Artifact] };
        first = first with { Engine = engine };
        second = second with { Engine = engine };
        var manager = new RuntimePackManager(
            Path.Combine(temporary.Path, "managed"),
            new CopyingArtifactInstaller([first, second]));
        var firstInstalled = await manager.InstallAsync(
            engine,
            first.Artifact,
            Consent(first, manager.DownloadDirectory));
        var secondInstalled = await manager.InstallAsync(
            engine,
            second.Artifact,
            Consent(second, manager.DownloadDirectory));
        var firstConfig = Path.Combine(firstInstalled.Pack.RootPath, "config", "engine.json");
        MakeWritable(firstConfig);
        await File.AppendAllTextAsync(firstConfig, "tamper");

        await manager.UninstallAsync(
            "voxcpm2",
            secondInstalled.Pack.PackFingerprint,
            _ => Task.CompletedTask);

        var inventory = await manager.GetInventoryAsync();
        Assert.Empty(inventory.ActivePackFingerprints);
        Assert.Single(inventory.Invalid);
        Assert.Null(await manager.GetActiveAsync("voxcpm2"));
    }

    private static ArtifactInstallConsent Consent(PackFixture fixture, string destination) => new(
        fixture.Engine.Id,
        fixture.Artifact.Name,
        fixture.Artifact.SizeBytes,
        fixture.Engine.ModelLicense,
        destination,
        true);

    private static async Task<PackFixture> CreateFixtureAsync(
        string parent,
        string configValue,
        string archiveName)
    {
        var sourceRoot = Path.Combine(parent, $"source-{configValue}");
        Directory.CreateDirectory(Path.Combine(sourceRoot, "bin"));
        Directory.CreateDirectory(Path.Combine(sourceRoot, "config"));
        var entrypoint = Path.Combine(sourceRoot, "bin", "fake-sidecar");
        var config = Path.Combine(sourceRoot, "config", "engine.json");
        await File.WriteAllTextAsync(entrypoint, "fixture entrypoint");
        await File.WriteAllTextAsync(config, $"{{\"fixture\":\"{configValue}\"}}");
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
        var manifestBytes = JsonSerializer.SerializeToUtf8Bytes(manifest, JsonOptions);
        await File.WriteAllBytesAsync(Path.Combine(sourceRoot, RuntimePackVerifier.ManifestFileName), manifestBytes);
        var verified = await new RuntimePackVerifier().VerifyAsync(sourceRoot);
        var entries = new List<(string Path, byte[] Bytes)>
        {
            (RuntimePackVerifier.ManifestFileName, manifestBytes),
        };
        entries.AddRange(manifest.Files.Select(value =>
            (value.Path, File.ReadAllBytes(Path.Combine(
                sourceRoot,
                value.Path.Replace('/', Path.DirectorySeparatorChar))))));
        var archive = Path.Combine(parent, archiveName);
        WriteArchive(archive, entries);
        var archiveBytes = await File.ReadAllBytesAsync(archive);
        var metadata = new RuntimePackArtifactMetadata
        {
            ArchiveProfile = RuntimePackArchiveProfile.UstarV1,
            ProtocolVersion = manifest.ProtocolVersion,
            EngineVersion = manifest.EngineVersion,
            ModelRevision = manifest.ModelRevision,
            Platform = manifest.Platform,
            Architecture = manifest.Architecture,
            Backend = manifest.Backend,
            ManifestSha256 = verified.ManifestSha256,
            PackFingerprint = verified.PackFingerprint,
            ExtractedFileCount = entries.Count,
            ExtractedBytes = entries.Sum(value => (long)value.Bytes.Length),
        };
        var artifact = new EngineArtifact
        {
            Name = archiveName,
            DownloadUri = new Uri($"https://github.com/example/{archiveName}"),
            SizeBytes = archiveBytes.LongLength,
            Sha256 = Convert.ToHexStringLower(SHA256.HashData(archiveBytes)),
            Platforms = [metadata.Platform],
            Architectures = [metadata.Architecture],
            Backends = [metadata.Backend],
            Kind = EngineArtifactKind.RuntimePackTar,
            RuntimePack = metadata,
        };
        var engine = TestFixtures.Vox() with
        {
            Version = manifest.EngineVersion,
            ModelRevision = manifest.ModelRevision,
            DownloadBytes = artifact.SizeBytes,
            Artifacts = [artifact],
        };
        return new PackFixture(engine, artifact, archive, verified);
    }

    private static RuntimePackFile FileRecord(string path, string relative) => new()
    {
        Path = relative,
        SizeBytes = new FileInfo(path).Length,
        Sha256 = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path))),
    };

    private static void WriteArchive(string path, IReadOnlyList<(string Path, byte[] Bytes)> entries)
    {
        using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        foreach (var entry in entries)
        {
            var header = Header(entry.Path, entry.Bytes.LongLength);
            stream.Write(header);
            stream.Write(entry.Bytes);
            var padding = (int)((512 - entry.Bytes.LongLength % 512) % 512);
            if (padding > 0) stream.Write(new byte[padding]);
        }
        stream.Write(new byte[1024]);
        stream.Flush(flushToDisk: true);
    }

    private static byte[] Header(string path, long size)
    {
        var header = new byte[512];
        Encoding.ASCII.GetBytes(path).CopyTo(header, 0);
        WriteOctal(header.AsSpan(100, 8), 420);
        WriteOctal(header.AsSpan(108, 8), 0);
        WriteOctal(header.AsSpan(116, 8), 0);
        WriteOctal(header.AsSpan(124, 12), size);
        WriteOctal(header.AsSpan(136, 12), 0);
        header.AsSpan(148, 8).Fill(0x20);
        header[156] = (byte)'0';
        "ustar\0"u8.CopyTo(header.AsSpan(257, 6));
        "00"u8.CopyTo(header.AsSpan(263, 2));
        var checksum = header.Sum(value => (long)value);
        Encoding.ASCII.GetBytes(Convert.ToString(checksum, 8)!.PadLeft(6, '0')).CopyTo(header, 148);
        header[154] = 0;
        header[155] = 0x20;
        return header;
    }

    private static void WriteOctal(Span<byte> field, long value)
    {
        Encoding.ASCII.GetBytes(Convert.ToString(value, 8)!.PadLeft(field.Length - 1, '0')).CopyTo(field);
        field[^1] = 0;
    }

    private static void MakeWritable(string path)
    {
        if (OperatingSystem.IsWindows())
            File.SetAttributes(path, File.GetAttributes(path) & ~FileAttributes.ReadOnly);
        else
            File.SetUnixFileMode(path, File.GetUnixFileMode(path) | UnixFileMode.UserWrite);
    }

    private static void DeletePackDirectoryForTamper(string root)
    {
        foreach (var file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
        {
            if (OperatingSystem.IsWindows())
                File.SetAttributes(file, File.GetAttributes(file) & ~FileAttributes.ReadOnly);
            else
                File.SetUnixFileMode(file, File.GetUnixFileMode(file) | UnixFileMode.UserWrite);
        }
        if (!OperatingSystem.IsWindows())
        {
            foreach (var directory in Directory.EnumerateDirectories(root, "*", SearchOption.AllDirectories)
                         .OrderByDescending(value => value.Length))
                File.SetUnixFileMode(
                    directory,
                    File.GetUnixFileMode(directory) |
                    UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            File.SetUnixFileMode(
                root,
                File.GetUnixFileMode(root) | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
        Directory.Delete(root, recursive: true);
    }

    private sealed record PackFixture(
        EngineDescriptor Engine,
        EngineArtifact Artifact,
        string ArchivePath,
        VerifiedRuntimePack Verified);

    private sealed class CopyingArtifactInstaller(IReadOnlyList<PackFixture> fixtures) : IArtifactInstaller
    {
        public Task<ArtifactInstallResult> InstallAsync(
            EngineDescriptor engine,
            EngineArtifact artifact,
            ArtifactInstallConsent consent,
            string destinationDirectory,
            CancellationToken cancellationToken = default)
        {
            var fixture = fixtures.Single(value => value.Artifact.Name == artifact.Name);
            Directory.CreateDirectory(destinationDirectory);
            var destination = Path.Combine(destinationDirectory, artifact.Name);
            File.Copy(fixture.ArchivePath, destination, overwrite: true);
            return Task.FromResult(new ArtifactInstallResult(
                destination,
                artifact.SizeBytes,
                artifact.Sha256,
                false));
        }
    }
}
