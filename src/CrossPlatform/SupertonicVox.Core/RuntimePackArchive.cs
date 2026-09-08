using System.Security.Cryptography;
using System.Text;

namespace SupertonicVox.Core;

public sealed record RuntimePackArchiveExtractionResult(
    string StagedRoot,
    string ManifestSha256,
    int ExtractedFileCount,
    long ExtractedBytes);

/// <summary>
/// Extracts the deliberately small SVX USTAR profile. The profile permits only
/// sorted regular files, requires runtime-pack.json first, validates every header
/// and padding byte, and rejects links, extensions and trailing data.
/// </summary>
public sealed class RuntimePackArchiveExtractor
{
    private const int TarBlockBytes = 512;
    private const int BufferBytes = 1024 * 1024;
    private const int MaximumManifestBytes = 8 * 1024 * 1024;
    private const long MaximumSingleFileBytes = 8L * 1024 * 1024 * 1024;
    private const long MaximumTotalBytes = 16L * 1024 * 1024 * 1024;

    public async Task<RuntimePackArchiveExtractionResult> ExtractAsync(
        string archivePath,
        string stagedRoot,
        RuntimePackArtifactMetadata metadata,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(metadata);
        if (metadata.ArchiveProfile != RuntimePackArchiveProfile.UstarV1)
            throw new RuntimePackException("Runtime-pack archive profile is unsupported.");
        if (metadata.ExtractedFileCount is < 2 or > 50_001 ||
            metadata.ExtractedBytes is < 1 or > MaximumTotalBytes ||
            !IsLowerSha256(metadata.ManifestSha256))
            throw new RuntimePackException("Runtime-pack archive limits are invalid.");

        var archive = Path.GetFullPath(archivePath);
        var archiveInfo = new FileInfo(archive);
        if (!archiveInfo.Exists || archiveInfo.LinkTarget is not null ||
            (archiveInfo.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new RuntimePackException("Runtime-pack archive is missing or linked.");
        if (await FileLinkInspector.GetLinkCountAsync(archive, cancellationToken).ConfigureAwait(false) != 1)
            throw new RuntimePackException("Runtime-pack archive is hard-linked.");

        var staged = Path.GetFullPath(stagedRoot);
        if (!Path.GetFileName(staged).EndsWith(".partial", StringComparison.Ordinal) ||
            File.Exists(staged) || Directory.Exists(staged))
            throw new RuntimePackException("Runtime-pack extraction target must be a new .partial directory.");
        var parent = Path.GetDirectoryName(staged)
                     ?? throw new RuntimePackException("Runtime-pack extraction parent is unavailable.");
        EnsureUnlinkedDirectory(parent, mustExist: true);
        Directory.CreateDirectory(staged);
        EnsureUnlinkedDirectory(staged, mustExist: true);

        await using var input = new FileStream(
            archive,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            BufferBytes,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        var header = new byte[TarBlockBytes];
        var buffer = new byte[BufferBytes];
        var normalizedKeys = new HashSet<string>(StringComparer.Ordinal);
        string? previousKey = null;
        string? manifestSha256 = null;
        long extractedBytes = 0;
        var extractedFiles = 0;

        while (true)
        {
            await ReadExactlyAsync(input, header, cancellationToken).ConfigureAwait(false);
            if (header.All(value => value == 0))
            {
                await ReadExactlyAsync(input, header, cancellationToken).ConfigureAwait(false);
                if (header.Any(value => value != 0) || input.Position != input.Length)
                    throw new RuntimePackException("Runtime-pack archive has an invalid trailer.");
                break;
            }

            var entry = ParseHeader(header);
            var stableKey = StablePathKey(entry.Path);
            var isFirstEntry = extractedFiles == 0;
            if (!normalizedKeys.Add(stableKey) ||
                !isFirstEntry && previousKey is not null &&
                string.CompareOrdinal(previousKey, stableKey) >= 0)
                throw new RuntimePackException("Runtime-pack archive paths are duplicated or unsorted.");
            if (!isFirstEntry) previousKey = stableKey;
            extractedFiles = checked(extractedFiles + 1);
            extractedBytes = checked(extractedBytes + entry.SizeBytes);
            if (extractedFiles > metadata.ExtractedFileCount ||
                extractedBytes > metadata.ExtractedBytes ||
                entry.SizeBytes > MaximumSingleFileBytes)
                throw new RuntimePackException("Runtime-pack archive exceeded its signed extraction limits.");
            if (extractedFiles == 1 &&
                !string.Equals(entry.Path, RuntimePackVerifier.ManifestFileName, StringComparison.Ordinal))
                throw new RuntimePackException("Runtime-pack manifest must be the first archive entry.");
            if (extractedFiles > 1 &&
                string.Equals(entry.Path, RuntimePackVerifier.ManifestFileName, StringComparison.Ordinal))
                throw new RuntimePackException("Runtime-pack archive contains a duplicate manifest.");
            if (extractedFiles == 1 && entry.SizeBytes > MaximumManifestBytes)
                throw new RuntimePackException("Runtime-pack manifest exceeds the archive profile limit.");

            var target = ResolveContainedPath(staged, entry.Path);
            var targetParent = Path.GetDirectoryName(target)
                               ?? throw new RuntimePackException("Runtime-pack archive target is invalid.");
            CreateUnlinkedDirectories(staged, targetParent);
            await using (var output = new FileStream(
                             target,
                             FileMode.CreateNew,
                             FileAccess.Write,
                             FileShare.None,
                             BufferBytes,
                             FileOptions.Asynchronous | FileOptions.SequentialScan))
            {
                using var hash = extractedFiles == 1 ? IncrementalHash.CreateHash(HashAlgorithmName.SHA256) : null;
                var remaining = entry.SizeBytes;
                while (remaining > 0)
                {
                    var count = checked((int)Math.Min(remaining, buffer.Length));
                    await ReadExactlyAsync(input, buffer.AsMemory(0, count), cancellationToken).ConfigureAwait(false);
                    await output.WriteAsync(buffer.AsMemory(0, count), cancellationToken).ConfigureAwait(false);
                    hash?.AppendData(buffer, 0, count);
                    remaining -= count;
                }
                await output.FlushAsync(cancellationToken).ConfigureAwait(false);
                output.Flush(flushToDisk: true);
                if (hash is not null) manifestSha256 = Convert.ToHexStringLower(hash.GetHashAndReset());
            }
            await ReadAndValidatePaddingAsync(input, entry.SizeBytes, buffer, cancellationToken)
                .ConfigureAwait(false);
        }

        if (extractedFiles != metadata.ExtractedFileCount || extractedBytes != metadata.ExtractedBytes ||
            !string.Equals(manifestSha256, metadata.ManifestSha256, StringComparison.Ordinal))
            throw new RuntimePackException("Runtime-pack archive does not match its signed extracted identity.");
        return new RuntimePackArchiveExtractionResult(
            staged,
            manifestSha256!,
            extractedFiles,
            extractedBytes);
    }

    private static TarFileEntry ParseHeader(ReadOnlySpan<byte> header)
    {
        if (!header.Slice(257, 6).SequenceEqual("ustar\0"u8) ||
            !header.Slice(263, 2).SequenceEqual("00"u8) ||
            header[156] != (byte)'0' ||
            ContainsNonzero(header.Slice(157, 100)) ||
            ContainsNonzero(header.Slice(329, 16)))
            throw new RuntimePackException("Runtime-pack archive contains an unsupported USTAR header.");
        if (ParseOctal(header.Slice(100, 8), "mode") != 420 ||
            ParseOctal(header.Slice(108, 8), "uid") != 0 ||
            ParseOctal(header.Slice(116, 8), "gid") != 0 ||
            ParseOctal(header.Slice(136, 12), "mtime") != 0)
            throw new RuntimePackException("Runtime-pack archive header metadata is not deterministic.");
        if (ReadString(header.Slice(265, 32), "owner").Length != 0 ||
            ReadString(header.Slice(297, 32), "group").Length != 0)
            throw new RuntimePackException("Runtime-pack archive owner metadata is not empty.");

        var declaredChecksum = ParseChecksum(header.Slice(148, 8));
        long actualChecksum = 0;
        for (var index = 0; index < header.Length; index++)
            actualChecksum += index is >= 148 and < 156 ? 0x20 : header[index];
        if (declaredChecksum != actualChecksum)
            throw new RuntimePackException("Runtime-pack archive header checksum is invalid.");

        var name = ReadString(header.Slice(0, 100), "name");
        var prefix = ReadString(header.Slice(345, 155), "prefix");
        var path = prefix.Length == 0 ? name : $"{prefix}/{name}";
        path = NormalizeRelativePath(path);
        var size = ParseOctal(header.Slice(124, 12), "size");
        return new TarFileEntry(path, size);
    }

    private static long ParseOctal(ReadOnlySpan<byte> field, string label)
    {
        if (field.Length < 2 || field[^1] != 0 || !IsOctal(field[..^1]))
            throw new RuntimePackException($"Runtime-pack archive {label} field is invalid.");
        long value = 0;
        foreach (var character in field[..^1]) value = checked(value * 8 + character - (byte)'0');
        return value;
    }

    private static long ParseChecksum(ReadOnlySpan<byte> field)
    {
        if (field.Length != 8 || field[6] != 0 || field[7] != 0x20 ||
            !IsOctal(field[..6]))
            throw new RuntimePackException("Runtime-pack archive checksum field is invalid.");
        long value = 0;
        foreach (var character in field[..6]) value = checked(value * 8 + character - (byte)'0');
        return value;
    }

    private static string ReadString(ReadOnlySpan<byte> field, string label)
    {
        var terminator = field.IndexOf((byte)0);
        if (terminator < 0) terminator = field.Length;
        if (ContainsNonzero(field[terminator..]) || !IsPrintableAscii(field[..terminator]))
            throw new RuntimePackException($"Runtime-pack archive {label} field is invalid.");
        return Encoding.ASCII.GetString(field[..terminator]);
    }

    private static async Task ReadExactlyAsync(
        Stream stream,
        Memory<byte> buffer,
        CancellationToken cancellationToken)
    {
        try
        {
            await stream.ReadExactlyAsync(buffer, cancellationToken).ConfigureAwait(false);
        }
        catch (EndOfStreamException)
        {
            throw new RuntimePackException("Runtime-pack archive is truncated.");
        }
    }

    private static async Task ReadAndValidatePaddingAsync(
        Stream stream,
        long size,
        byte[] buffer,
        CancellationToken cancellationToken)
    {
        var padding = checked((int)((TarBlockBytes - size % TarBlockBytes) % TarBlockBytes));
        if (padding == 0) return;
        await ReadExactlyAsync(stream, buffer.AsMemory(0, padding), cancellationToken).ConfigureAwait(false);
        if (buffer.AsSpan(0, padding).ContainsAnyExcept((byte)0))
            throw new RuntimePackException("Runtime-pack archive contains nonzero file padding.");
    }

    private static string NormalizeRelativePath(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 255 || value.IndexOf('\0') >= 0 ||
            value.Any(character => char.IsControl(character) || character > 0x7f) ||
            value.Contains(':', StringComparison.Ordinal) || value.Contains('\\', StringComparison.Ordinal) ||
            Path.IsPathRooted(value))
            throw new RuntimePackException("Runtime-pack archive path is unsafe.");
        var parts = value.Split('/');
        if (parts.Any(part => part.Length == 0 || part is "." or ".." ||
                              part.EndsWith(' ') || part.EndsWith('.')))
            throw new RuntimePackException("Runtime-pack archive path is unsafe.");
        return string.Join('/', parts);
    }

    private static string StablePathKey(string value) => value.ToUpperInvariant();

    private static string ResolveContainedPath(string root, string relative)
    {
        var fullRoot = Path.GetFullPath(root);
        var full = Path.GetFullPath(Path.Combine(root, relative.Replace('/', Path.DirectorySeparatorChar)));
        if (!full.StartsWith(fullRoot + Path.DirectorySeparatorChar, PathComparison))
            throw new RuntimePackException("Runtime-pack archive path escaped its root.");
        return full;
    }

    private static void CreateUnlinkedDirectories(string root, string targetParent)
    {
        var relative = Path.GetRelativePath(root, targetParent);
        var current = root;
        foreach (var part in relative.Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, part);
            if (!Directory.Exists(current)) Directory.CreateDirectory(current);
            EnsureUnlinkedDirectory(current, mustExist: true);
        }
    }

    private static void EnsureUnlinkedDirectory(string path, bool mustExist)
    {
        var info = new DirectoryInfo(path);
        if ((mustExist && !info.Exists) || info.LinkTarget is not null ||
            (info.Exists && (info.Attributes & FileAttributes.ReparsePoint) != 0))
            throw new RuntimePackException("Runtime-pack archive directory is missing or linked.");
    }

    private static bool IsLowerSha256(string value) =>
        value.Length == 64 && value.All(character =>
            character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static bool ContainsNonzero(ReadOnlySpan<byte> value)
    {
        foreach (var character in value)
            if (character != 0) return true;
        return false;
    }

    private static bool IsOctal(ReadOnlySpan<byte> value)
    {
        foreach (var character in value)
            if (character is < (byte)'0' or > (byte)'7') return false;
        return true;
    }

    private static bool IsPrintableAscii(ReadOnlySpan<byte> value)
    {
        foreach (var character in value)
            if (character is < 0x20 or > 0x7e) return false;
        return true;
    }

    private static StringComparison PathComparison =>
        OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

    private sealed record TarFileEntry(string Path, long SizeBytes);
}
