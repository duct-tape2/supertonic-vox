using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using SupertonicVox.Core;

namespace SupertonicVox.Core.Tests;

public sealed class RuntimePackArchiveTests
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter(namingPolicy: null, allowIntegerValues: false) },
    };

    [Fact]
    public async Task StrictArchiveExtractsAndMatchesRuntimePackVerifier()
    {
        using var temporary = new TemporaryDirectory();
        var fixture = CreateFixture();
        var archive = Path.Combine(temporary.Path, "pack.svxpack.tar");
        WriteArchive(archive, fixture.Entries);
        var staged = Path.Combine(temporary.Path, "pack.partial");

        var extracted = await new RuntimePackArchiveExtractor().ExtractAsync(
            archive,
            staged,
            fixture.Metadata);
        var verified = await new RuntimePackVerifier().VerifyAsync(staged);

        Assert.Equal(fixture.Metadata.ManifestSha256, extracted.ManifestSha256);
        Assert.Equal(fixture.Metadata.ExtractedFileCount, extracted.ExtractedFileCount);
        Assert.Equal("voxcpm2", verified.Manifest.EngineId);
        Assert.Equal(2, verified.Files.Count);
    }

    [Fact]
    public async Task ArchiveRejectsLinksTraversalAndTrailerBytes()
    {
        using var temporary = new TemporaryDirectory();
        var fixture = CreateFixture();

        var linkedArchive = Path.Combine(temporary.Path, "linked.tar");
        WriteArchive(linkedArchive, fixture.Entries, firstTypeFlag: (byte)'2');
        await Assert.ThrowsAsync<RuntimePackException>(() => new RuntimePackArchiveExtractor().ExtractAsync(
            linkedArchive,
            Path.Combine(temporary.Path, "linked.partial"),
            fixture.Metadata));

        var traversalEntries = fixture.Entries.ToArray();
        traversalEntries[1] = ("../escape", traversalEntries[1].Bytes);
        var traversalArchive = Path.Combine(temporary.Path, "traversal.tar");
        WriteArchive(traversalArchive, traversalEntries);
        await Assert.ThrowsAsync<RuntimePackException>(() => new RuntimePackArchiveExtractor().ExtractAsync(
            traversalArchive,
            Path.Combine(temporary.Path, "traversal.partial"),
            fixture.Metadata));

        var trailerArchive = Path.Combine(temporary.Path, "trailer.tar");
        WriteArchive(trailerArchive, fixture.Entries, trailer: [1]);
        await Assert.ThrowsAsync<RuntimePackException>(() => new RuntimePackArchiveExtractor().ExtractAsync(
            trailerArchive,
            Path.Combine(temporary.Path, "trailer.partial"),
            fixture.Metadata));
    }

    [Fact]
    public async Task ArchiveRejectsWrongManifestOrderIdentityAndExtractionTotals()
    {
        using var temporary = new TemporaryDirectory();
        var fixture = CreateFixture();
        var reordered = fixture.Entries.Skip(1).Append(fixture.Entries[0]).ToArray();
        var reorderedArchive = Path.Combine(temporary.Path, "reordered.tar");
        WriteArchive(reorderedArchive, reordered);
        await Assert.ThrowsAsync<RuntimePackException>(() => new RuntimePackArchiveExtractor().ExtractAsync(
            reorderedArchive,
            Path.Combine(temporary.Path, "reordered.partial"),
            fixture.Metadata));

        var validArchive = Path.Combine(temporary.Path, "valid.tar");
        WriteArchive(validArchive, fixture.Entries);
        await Assert.ThrowsAsync<RuntimePackException>(() => new RuntimePackArchiveExtractor().ExtractAsync(
            validArchive,
            Path.Combine(temporary.Path, "identity.partial"),
            fixture.Metadata with { ManifestSha256 = new string('0', 64) }));
        await Assert.ThrowsAsync<RuntimePackException>(() => new RuntimePackArchiveExtractor().ExtractAsync(
            validArchive,
            Path.Combine(temporary.Path, "totals.partial"),
            fixture.Metadata with { ExtractedBytes = fixture.Metadata.ExtractedBytes + 1 }));
    }

    private static ArchiveFixture CreateFixture()
    {
        var entrypoint = "fixture entrypoint"u8.ToArray();
        var config = "{\"fixture\":true}"u8.ToArray();
        var files = new[]
        {
            FileRecord("bin/fake-sidecar", entrypoint),
            FileRecord("config/engine.json", config),
        };
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
            Files = files,
        };
        var manifestBytes = JsonSerializer.SerializeToUtf8Bytes(manifest, JsonOptions);
        var entries = new (string Path, byte[] Bytes)[]
        {
            (RuntimePackVerifier.ManifestFileName, manifestBytes),
            ("bin/fake-sidecar", entrypoint),
            ("config/engine.json", config),
        };
        return new ArchiveFixture(
            entries,
            new RuntimePackArtifactMetadata
            {
                ArchiveProfile = RuntimePackArchiveProfile.UstarV1,
                ProtocolVersion = 2,
                EngineVersion = manifest.EngineVersion,
                ModelRevision = manifest.ModelRevision,
                Platform = manifest.Platform,
                Architecture = manifest.Architecture,
                Backend = manifest.Backend,
                ManifestSha256 = Sha256(manifestBytes),
                PackFingerprint = new string('a', 64),
                ExtractedFileCount = entries.Length,
                ExtractedBytes = entries.Sum(value => (long)value.Bytes.Length),
            });
    }

    private static RuntimePackFile FileRecord(string path, byte[] bytes) => new()
    {
        Path = path,
        SizeBytes = bytes.LongLength,
        Sha256 = Sha256(bytes),
    };

    private static string Sha256(byte[] bytes) =>
        Convert.ToHexStringLower(SHA256.HashData(bytes));

    private static void WriteArchive(
        string path,
        IReadOnlyList<(string Path, byte[] Bytes)> entries,
        byte firstTypeFlag = (byte)'0',
        byte[]? trailer = null)
    {
        using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        for (var index = 0; index < entries.Count; index++)
        {
            var entry = entries[index];
            var header = Header(entry.Path, entry.Bytes.LongLength, index == 0 ? firstTypeFlag : (byte)'0');
            stream.Write(header);
            stream.Write(entry.Bytes);
            var padding = (int)((512 - entry.Bytes.LongLength % 512) % 512);
            if (padding > 0) stream.Write(new byte[padding]);
        }
        stream.Write(new byte[1024]);
        if (trailer is not null) stream.Write(trailer);
        stream.Flush(flushToDisk: true);
    }

    private static byte[] Header(string path, long size, byte typeFlag)
    {
        if (Encoding.ASCII.GetByteCount(path) > 100)
            throw new ArgumentOutOfRangeException(nameof(path));
        var header = new byte[512];
        Encoding.ASCII.GetBytes(path).CopyTo(header, 0);
        WriteOctal(header.AsSpan(100, 8), 420);
        WriteOctal(header.AsSpan(108, 8), 0);
        WriteOctal(header.AsSpan(116, 8), 0);
        WriteOctal(header.AsSpan(124, 12), size);
        WriteOctal(header.AsSpan(136, 12), 0);
        header.AsSpan(148, 8).Fill(0x20);
        header[156] = typeFlag;
        "ustar\0"u8.CopyTo(header.AsSpan(257, 6));
        "00"u8.CopyTo(header.AsSpan(263, 2));
        long checksum = header.Sum(value => (long)value);
        var checksumText = Convert.ToString(checksum, 8)!.PadLeft(6, '0');
        Encoding.ASCII.GetBytes(checksumText).CopyTo(header, 148);
        header[154] = 0;
        header[155] = 0x20;
        return header;
    }

    private static void WriteOctal(Span<byte> field, long value)
    {
        var text = Convert.ToString(value, 8)!.PadLeft(field.Length - 1, '0');
        Encoding.ASCII.GetBytes(text).CopyTo(field);
        field[^1] = 0;
    }

    private sealed record ArchiveFixture(
        IReadOnlyList<(string Path, byte[] Bytes)> Entries,
        RuntimePackArtifactMetadata Metadata);
}
