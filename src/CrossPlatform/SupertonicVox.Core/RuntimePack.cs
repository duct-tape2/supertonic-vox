using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32.SafeHandles;

namespace SupertonicVox.Core;

public sealed record RuntimePackFile
{
    public required string Path { get; init; }
    public required long SizeBytes { get; init; }
    public required string Sha256 { get; init; }
}

public sealed record RuntimePackManifest
{
    public required int SchemaVersion { get; init; }
    public required int ProtocolVersion { get; init; }
    public required string EngineId { get; init; }
    public required string EngineVersion { get; init; }
    public required string ModelRevision { get; init; }
    public required PlatformKind Platform { get; init; }
    public required CpuArchitectureKind Architecture { get; init; }
    public required AccelerationBackend Backend { get; init; }
    public required string EntryPoint { get; init; }
    public required IReadOnlyList<string> LaunchArguments { get; init; }
    public required IReadOnlyList<string> PrelaunchVerifyPaths { get; init; }
    public required IReadOnlyList<RuntimePackFile> Files { get; init; }
}

public sealed record VerifiedRuntimePack
{
    public required string RootPath { get; init; }
    public required RuntimePackManifest Manifest { get; init; }
    public required string ManifestSha256 { get; init; }
    public required string PackFingerprint { get; init; }
    public required IReadOnlyDictionary<string, RuntimePackFile> Files { get; init; }
}

public sealed class RuntimePackException(string message) : IOException(message);

public sealed class RuntimePackVerifier
{
    public const string ManifestFileName = "runtime-pack.json";
    private const int MaximumManifestBytes = 8 * 1024 * 1024;
    private const int MaximumFileCount = 50_000;
    private const long MaximumFileBytes = 8L * 1024 * 1024 * 1024;
    private const long MaximumTotalBytes = 16L * 1024 * 1024 * 1024;
    private const int BufferBytes = 1024 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        Converters = { new JsonStringEnumConverter(namingPolicy: null, allowIntegerValues: false) },
    };
    private static readonly string[] ForbiddenPathParts =
    [
        "cache",
        "generatedaudio",
        "logs",
        "savedtext",
        "settings",
        "user",
        "voiceprofiles",
        "voicesamples",
    ];

    public async Task<VerifiedRuntimePack> VerifyAndActivateAsync(
        string stagedRoot,
        string finalRoot,
        CancellationToken cancellationToken = default)
    {
        var staged = Path.GetFullPath(stagedRoot);
        var final = Path.GetFullPath(finalRoot);
        if (!string.Equals(
                Path.GetDirectoryName(staged),
                Path.GetDirectoryName(final),
                PathComparison))
            throw new RuntimePackException("Runtime-pack staging and final directories must be siblings.");
        if (!Path.GetFileName(staged).EndsWith(".partial", StringComparison.Ordinal))
            throw new RuntimePackException("Runtime-pack staging directory must use the .partial suffix.");
        if (File.Exists(final) || Directory.Exists(final))
            throw new RuntimePackException("Runtime-pack final directory already exists.");

        var verified = await VerifyAsync(staged, cancellationToken).ConfigureAwait(false);
        EnsureHostCompatibility(verified.Manifest);
        // Move first, then lock the tree: renaming a directory whose entries were already made
        // read-only fails with EACCES on some macOS hosts (seen on GitHub macos runners), and the
        // hashes were verified above, so locking the final location is equivalent.
        Directory.Move(staged, final);
        var activated = verified with { RootPath = final };
        MakeTreeReadOnly(final, verified.Manifest.EntryPoint);
        await VerifyPrelaunchAsync(activated, cancellationToken).ConfigureAwait(false);
        return activated;
    }

    public async Task<VerifiedRuntimePack> VerifyAsync(
        string rootPath,
        CancellationToken cancellationToken = default)
    {
        var root = Path.GetFullPath(rootPath);
        var rootInfo = new DirectoryInfo(root);
        if (!rootInfo.Exists || rootInfo.LinkTarget is not null ||
            (rootInfo.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new RuntimePackException("Runtime-pack root is missing or linked.");

        var manifestPath = Path.Combine(root, ManifestFileName);
        RequireRegularFile(manifestPath, "runtime-pack manifest");
        if (await FileLinkInspector.GetLinkCountAsync(manifestPath, cancellationToken)
                .ConfigureAwait(false) != 1)
            throw new RuntimePackException("Runtime-pack manifest is hard-linked.");
        var manifestBytes = await ReadBoundedAsync(
            manifestPath,
            MaximumManifestBytes,
            cancellationToken).ConfigureAwait(false);
        RequireRegularFile(manifestPath, "runtime-pack manifest");
        if (await FileLinkInspector.GetLinkCountAsync(manifestPath, cancellationToken)
                .ConfigureAwait(false) != 1)
            throw new RuntimePackException("Runtime-pack manifest changed link identity during verification.");
        RuntimePackManifest manifest;
        try
        {
            manifest = JsonSerializer.Deserialize<RuntimePackManifest>(manifestBytes, JsonOptions)
                       ?? throw new RuntimePackException("Runtime-pack manifest is empty.");
        }
        catch (JsonException exception)
        {
            throw new RuntimePackException($"Runtime-pack manifest is invalid: {exception.Message}");
        }
        ValidateManifest(manifest);

        var expected = manifest.Files.ToDictionary(value => value.Path, StringComparer.Ordinal);
        var actual = new HashSet<string>(StringComparer.Ordinal);
        foreach (var directory in rootInfo.EnumerateDirectories("*", SearchOption.AllDirectories))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (directory.LinkTarget is not null ||
                (directory.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new RuntimePackException(
                    $"Runtime-pack directory is linked: {Path.GetRelativePath(root, directory.FullName)}");
        }
        var files = rootInfo.EnumerateFiles("*", SearchOption.AllDirectories)
            .OrderBy(value => StablePathKey(RelativeUnixPath(root, value.FullName)), StringComparer.Ordinal)
            .ToArray();
        if (files.Length != expected.Count + 1)
            throw new RuntimePackException("Runtime-pack file inventory count does not match the manifest.");
        var linkCounts = await FileLinkInspector.GetLinkCountsAsync(
            files.Select(file => file.FullName).ToArray(),
            cancellationToken).ConfigureAwait(false);

        long totalBytes = 0;
        foreach (var file in files)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var relative = NormalizeRelativePath(RelativeUnixPath(root, file.FullName));
            if (string.Equals(relative, ManifestFileName, StringComparison.Ordinal)) continue;
            if (!expected.TryGetValue(relative, out var declared) || !actual.Add(relative))
                throw new RuntimePackException($"Runtime-pack contains an unlisted file: {relative}");
            RequireRegularFile(file.FullName, relative);
            if (linkCounts[file.FullName] != 1)
                throw new RuntimePackException($"Runtime-pack file is hard-linked: {relative}");
            if (file.Length != declared.SizeBytes)
                throw new RuntimePackException($"Runtime-pack file size mismatch: {relative}");
            var beforeWrite = file.LastWriteTimeUtc;
            var digest = await ComputeSha256Async(file.FullName, cancellationToken).ConfigureAwait(false);
            file.Refresh();
            if (file.Length != declared.SizeBytes || file.LastWriteTimeUtc != beforeWrite)
                throw new RuntimePackException($"Runtime-pack file changed during verification: {relative}");
            if (!CryptographicOperations.FixedTimeEquals(
                    Encoding.ASCII.GetBytes(digest),
                    Encoding.ASCII.GetBytes(declared.Sha256)))
                throw new RuntimePackException($"Runtime-pack file SHA-256 mismatch: {relative}");
            totalBytes = checked(totalBytes + declared.SizeBytes);
        }
        if (actual.Count != expected.Count || totalBytes > MaximumTotalBytes)
            throw new RuntimePackException("Runtime-pack inventory is incomplete or oversized.");

        var manifestSha = Convert.ToHexStringLower(SHA256.HashData(manifestBytes));
        var fingerprint = ComputePackFingerprint(manifestSha, manifest.Files);
        return new VerifiedRuntimePack
        {
            RootPath = root,
            Manifest = manifest,
            ManifestSha256 = manifestSha,
            PackFingerprint = fingerprint,
            Files = expected,
        };
    }

    public async Task VerifyPrelaunchAsync(
        VerifiedRuntimePack pack,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pack);
        var manifestPath = Path.Combine(pack.RootPath, ManifestFileName);
        RequireRegularFile(manifestPath, "runtime-pack manifest");
        if (await FileLinkInspector.GetLinkCountAsync(manifestPath, cancellationToken)
                .ConfigureAwait(false) != 1)
            throw new RuntimePackException("Runtime-pack manifest is hard-linked before launch.");
        if (!IsReadOnly(manifestPath))
            throw new RuntimePackException("Runtime-pack manifest is writable before launch.");
        var manifestBytes = await ReadBoundedAsync(
            manifestPath,
            MaximumManifestBytes,
            cancellationToken).ConfigureAwait(false);
        var manifestSha = Convert.ToHexStringLower(SHA256.HashData(manifestBytes));
        if (!CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(manifestSha),
                Encoding.ASCII.GetBytes(pack.ManifestSha256)))
            throw new RuntimePackException("Runtime-pack manifest SHA-256 mismatch before launch.");
        RequireRegularFile(manifestPath, "runtime-pack manifest");
        if (await FileLinkInspector.GetLinkCountAsync(manifestPath, cancellationToken)
                .ConfigureAwait(false) != 1)
            throw new RuntimePackException("Runtime-pack manifest changed link identity before launch.");
        foreach (var relative in pack.Files.Keys)
        {
            var path = ResolveContainedPath(pack.RootPath, relative);
            RequireRegularFile(path, relative);
            if (!IsReadOnly(path))
                throw new RuntimePackException($"Runtime-pack file is writable before launch: {relative}");
        }
        foreach (var relative in pack.Manifest.PrelaunchVerifyPaths)
        {
            if (!pack.Files.TryGetValue(relative, out var declared))
                throw new RuntimePackException($"Prelaunch verification path is not declared: {relative}");
            var path = ResolveContainedPath(pack.RootPath, relative);
            RequireRegularFile(path, relative);
            if (!IsReadOnly(path))
                throw new RuntimePackException($"Runtime-pack file is writable before launch: {relative}");
            var digest = await ComputeSha256Async(path, cancellationToken).ConfigureAwait(false);
            if (!CryptographicOperations.FixedTimeEquals(
                    Encoding.ASCII.GetBytes(digest),
                    Encoding.ASCII.GetBytes(declared.Sha256)))
                throw new RuntimePackException($"Runtime-pack prelaunch SHA-256 mismatch: {relative}");
        }
    }

    private static void ValidateManifest(RuntimePackManifest manifest)
    {
        if (manifest.SchemaVersion != 1 || manifest.ProtocolVersion != 2)
            throw new RuntimePackException("Runtime-pack schema or protocol version is unsupported.");
        if (!IsIdentifier(manifest.EngineId) || !IsVersion(manifest.EngineVersion) ||
            !IsRevision(manifest.ModelRevision) ||
            manifest.Platform == PlatformKind.Unknown || !Enum.IsDefined(manifest.Platform) ||
            manifest.Architecture == CpuArchitectureKind.Unknown || !Enum.IsDefined(manifest.Architecture) ||
            !Enum.IsDefined(manifest.Backend))
            throw new RuntimePackException("Runtime-pack identity metadata is invalid.");
        if (manifest.Files.Count is < 1 or > MaximumFileCount)
            throw new RuntimePackException("Runtime-pack file count is invalid.");
        if (manifest.LaunchArguments.Count > 32)
            throw new RuntimePackException("Runtime-pack launch arguments are invalid.");

        var normalizedKeys = new HashSet<string>(StringComparer.Ordinal);
        var paths = new HashSet<string>(StringComparer.Ordinal);
        long total = 0;
        foreach (var file in manifest.Files)
        {
            var normalized = NormalizeRelativePath(file.Path);
            if (!string.Equals(normalized, file.Path, StringComparison.Ordinal) ||
                string.Equals(normalized, ManifestFileName, StringComparison.Ordinal) ||
                !paths.Add(normalized) ||
                !normalizedKeys.Add(StablePathKey(normalized)) ||
                IsForbiddenPrivatePath(normalized) ||
                file.SizeBytes is < 0 or > MaximumFileBytes ||
                !IsLowerSha256(file.Sha256))
                throw new RuntimePackException($"Runtime-pack file declaration is invalid: {file.Path}");
            total = checked(total + file.SizeBytes);
        }
        if (total > MaximumTotalBytes)
            throw new RuntimePackException("Runtime-pack declared size exceeds the limit.");
        foreach (var argument in manifest.LaunchArguments)
        {
            if (argument.Length is < 1 or > 1024 || argument.IndexOf('\0') >= 0 ||
                argument.Contains(':', StringComparison.Ordinal) ||
                argument.Contains('\\', StringComparison.Ordinal) ||
                Path.IsPathRooted(argument) || ContainsSecretPlaceholder(argument) ||
                argument.Any(character => char.IsWhiteSpace(character) || character > 0x7f))
                throw new RuntimePackException("Runtime-pack launch arguments are invalid.");
            if (argument.Contains('/', StringComparison.Ordinal))
            {
                var argumentPath = NormalizeRelativePath(argument);
                if (!paths.Contains(argumentPath) ||
                    !manifest.PrelaunchVerifyPaths.Contains(argumentPath, StringComparer.Ordinal))
                    throw new RuntimePackException(
                        "Runtime-pack file arguments must be declared for prelaunch verification.");
            }
        }
        if (!paths.Contains(manifest.EntryPoint) || IsForbiddenPrivatePath(manifest.EntryPoint))
            throw new RuntimePackException("Runtime-pack entrypoint is not declared.");
        if (manifest.PrelaunchVerifyPaths.Count is < 1 or > 64 ||
            !manifest.PrelaunchVerifyPaths.Contains(manifest.EntryPoint, StringComparer.Ordinal) ||
            manifest.PrelaunchVerifyPaths.Any(value =>
                !string.Equals(NormalizeRelativePath(value), value, StringComparison.Ordinal) ||
                !paths.Contains(value)) ||
            manifest.PrelaunchVerifyPaths.Distinct(StringComparer.Ordinal).Count() !=
            manifest.PrelaunchVerifyPaths.Count)
            throw new RuntimePackException("Runtime-pack prelaunch verification paths are invalid.");
        var sorted = manifest.Files.Select(value => value.Path)
            .OrderBy(StablePathKey, StringComparer.Ordinal).ToArray();
        if (!manifest.Files.Select(value => value.Path).SequenceEqual(sorted, StringComparer.Ordinal))
            throw new RuntimePackException("Runtime-pack file inventory must be stably sorted.");
    }

    private static void EnsureHostCompatibility(RuntimePackManifest manifest)
    {
        var platform = OperatingSystem.IsWindows()
            ? PlatformKind.Windows
            : OperatingSystem.IsMacOS()
                ? PlatformKind.MacOS
                : PlatformKind.Unknown;
        var architecture = System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture switch
        {
            System.Runtime.InteropServices.Architecture.X64 => CpuArchitectureKind.X64,
            System.Runtime.InteropServices.Architecture.Arm64 => CpuArchitectureKind.Arm64,
            _ => CpuArchitectureKind.Unknown,
        };
        var backendAllowed = platform switch
        {
            PlatformKind.Windows => manifest.Backend is
                AccelerationBackend.Cpu or AccelerationBackend.Cuda,
            PlatformKind.MacOS => manifest.Backend is
                AccelerationBackend.Cpu or AccelerationBackend.Mps or AccelerationBackend.Metal,
            _ => false,
        };
        if (manifest.Platform != platform || manifest.Architecture != architecture || !backendAllowed)
            throw new RuntimePackException("Runtime pack is not compatible with this host.");
    }

    private static async Task<byte[]> ReadBoundedAsync(
        string path,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        if (stream.Length < 1 || stream.Length > maximumBytes)
            throw new RuntimePackException($"Runtime-pack input size is invalid: {Path.GetFileName(path)}");
        var bytes = new byte[checked((int)stream.Length)];
        await stream.ReadExactlyAsync(bytes, cancellationToken).ConfigureAwait(false);
        if (stream.Length != bytes.Length)
            throw new RuntimePackException($"Runtime-pack input changed while reading: {Path.GetFileName(path)}");
        return bytes;
    }

    private static async Task<string> ComputeSha256Async(
        string path,
        CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            BufferBytes,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        var digest = await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false);
        return Convert.ToHexStringLower(digest);
    }

    private static string ComputePackFingerprint(
        string manifestSha256,
        IReadOnlyList<RuntimePackFile> files)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        AppendField(hash, manifestSha256);
        foreach (var file in files)
        {
            AppendField(hash, file.Path);
            AppendField(hash, file.SizeBytes.ToString(CultureInfo.InvariantCulture));
            AppendField(hash, file.Sha256);
        }
        return Convert.ToHexStringLower(hash.GetHashAndReset());
    }

    private static void AppendField(IncrementalHash hash, string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        Span<byte> length = stackalloc byte[4];
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(length, bytes.Length);
        hash.AppendData(length);
        hash.AppendData(bytes);
    }

    // Manifest paths are always "/"-separated; on Windows Path.GetRelativePath yields "\", which the
    // safety check below rejects on purpose. Convert the on-disk relative path to the manifest form first.
    private static string RelativeUnixPath(string root, string fullPath) =>
        Path.GetRelativePath(root, fullPath).Replace(Path.DirectorySeparatorChar, '/').Replace(Path.AltDirectorySeparatorChar, '/');

    private static string NormalizeRelativePath(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.IndexOf('\0') >= 0 ||
            value.Any(char.IsControl) ||
            value.Contains(':', StringComparison.Ordinal) ||
            Path.IsPathRooted(value) || value.Contains('\\', StringComparison.Ordinal))
            throw new RuntimePackException($"Unsafe runtime-pack path: {value}");
        var normalized = value.Normalize(NormalizationForm.FormC);
        var parts = normalized.Split('/');
        if (parts.Any(part => part.Length == 0 || part is "." or ".." ||
                              part.EndsWith(' ') || part.EndsWith('.')))
            throw new RuntimePackException($"Unsafe runtime-pack path: {value}");
        return string.Join('/', parts);
    }

    private static string StablePathKey(string value) =>
        value.Normalize(NormalizationForm.FormC).ToUpperInvariant();

    private static bool IsForbiddenPrivatePath(string value)
    {
        var parts = value.Split('/');
        return parts.Any(part => ForbiddenPathParts.Contains(
            part.Normalize(NormalizationForm.FormC),
            StringComparer.OrdinalIgnoreCase));
    }

    private static bool IsIdentifier(string value) =>
        value.Length is >= 1 and <= 64 && value.All(character =>
            character is >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '_');

    private static bool IsVersion(string value) =>
        value.Length is >= 1 and <= 64 && value.All(character =>
            char.IsAsciiLetterOrDigit(character) || character is '.' or '-' or '+');

    private static bool IsRevision(string value) =>
        value.Length is >= 8 and <= 128 && value.All(character =>
            char.IsAsciiLetterOrDigit(character) || character is '.' or '-' or '_');

    private static bool IsLowerSha256(string value) =>
        value.Length == 64 && value.All(character =>
            character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static bool ContainsSecretPlaceholder(string value) =>
        value.Contains("token", StringComparison.OrdinalIgnoreCase) ||
        value.Contains("secret", StringComparison.OrdinalIgnoreCase) ||
        value.Contains("session", StringComparison.OrdinalIgnoreCase);

    private static string ResolveContainedPath(string root, string relative)
    {
        var full = Path.GetFullPath(Path.Combine(root, relative.Replace('/', Path.DirectorySeparatorChar)));
        if (!full.StartsWith(Path.GetFullPath(root) + Path.DirectorySeparatorChar, PathComparison))
            throw new RuntimePackException($"Runtime-pack path escaped its root: {relative}");
        return full;
    }

    private static void RequireRegularFile(string path, string label)
    {
        var info = new FileInfo(path);
        if (!info.Exists || info.LinkTarget is not null ||
            (info.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new RuntimePackException($"Runtime-pack file is missing or linked: {label}");
    }

    private static void MakeTreeReadOnly(string root, string entryPoint)
    {
        foreach (var file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
        {
            if (OperatingSystem.IsWindows())
            {
                File.SetAttributes(file, File.GetAttributes(file) | FileAttributes.ReadOnly);
            }
            else
            {
                var relative = NormalizeRelativePath(Path.GetRelativePath(root, file));
                File.SetUnixFileMode(
                    file,
                    string.Equals(relative, entryPoint, StringComparison.Ordinal)
                        ? UnixFileMode.UserRead | UnixFileMode.UserExecute |
                          UnixFileMode.GroupRead | UnixFileMode.GroupExecute |
                          UnixFileMode.OtherRead | UnixFileMode.OtherExecute
                        : UnixFileMode.UserRead | UnixFileMode.GroupRead | UnixFileMode.OtherRead);
            }
        }
        if (!OperatingSystem.IsWindows())
        {
            foreach (var directory in Directory.EnumerateDirectories(root, "*", SearchOption.AllDirectories)
                         .OrderByDescending(value => value.Length))
                File.SetUnixFileMode(
                    directory,
                    UnixFileMode.UserRead | UnixFileMode.UserExecute |
                    UnixFileMode.GroupRead | UnixFileMode.GroupExecute |
                    UnixFileMode.OtherRead | UnixFileMode.OtherExecute);
            File.SetUnixFileMode(
                root,
                UnixFileMode.UserRead | UnixFileMode.UserExecute |
                UnixFileMode.GroupRead | UnixFileMode.GroupExecute |
                UnixFileMode.OtherRead | UnixFileMode.OtherExecute);
        }
    }

    private static bool IsReadOnly(string path)
    {
        if (OperatingSystem.IsWindows())
            return (File.GetAttributes(path) & FileAttributes.ReadOnly) != 0;
        return (File.GetUnixFileMode(path) & UnixFileMode.UserWrite) == 0;
    }

    private static StringComparison PathComparison =>
        OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
}

internal static partial class FileLinkInspector
{
    private const int MaximumBatchPathCount = 256;
    private const int MaximumBatchArgumentCharacters = 96 * 1024;

    public static async Task<uint> GetLinkCountAsync(
        string path,
        CancellationToken cancellationToken) =>
        (await GetLinkCountsAsync([path], cancellationToken).ConfigureAwait(false))[path];

    public static async Task<IReadOnlyDictionary<string, uint>> GetLinkCountsAsync(
        IReadOnlyList<string> paths,
        CancellationToken cancellationToken)
    {
        if (paths.Count == 0)
            return new Dictionary<string, uint>(StringComparer.Ordinal);
        if (paths.Distinct(StringComparer.Ordinal).Count() != paths.Count)
            throw new RuntimePackException("Runtime-pack link inspection paths are duplicated.");
        if (OperatingSystem.IsWindows())
        {
            var windowsResults = new Dictionary<string, uint>(paths.Count, StringComparer.Ordinal);
            foreach (var path in paths)
            {
                cancellationToken.ThrowIfCancellationRequested();
                windowsResults.Add(path, GetWindowsLinkCount(path));
            }
            return windowsResults;
        }
        var statPath = "/usr/bin/stat";
        if (!File.Exists(statPath))
            throw new RuntimePackException("The platform link-count inspector is unavailable.");
        var results = new Dictionary<string, uint>(paths.Count, StringComparer.Ordinal);
        var index = 0;
        while (index < paths.Count)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var batch = new List<string>(MaximumBatchPathCount);
            var characters = 0;
            while (index < paths.Count && batch.Count < MaximumBatchPathCount)
            {
                var path = paths[index];
                if (path.Any(char.IsControl))
                    throw new RuntimePackException("Runtime-pack link inspection path contains control characters.");
                if (batch.Count > 0 && characters + path.Length > MaximumBatchArgumentCharacters) break;
                batch.Add(path);
                characters += path.Length;
                index++;
            }
            var counts = await GetUnixLinkCountsBatchAsync(statPath, batch, cancellationToken)
                .ConfigureAwait(false);
            for (var batchIndex = 0; batchIndex < batch.Count; batchIndex++)
                results.Add(batch[batchIndex], counts[batchIndex]);
        }
        return results;
    }

    private static async Task<IReadOnlyList<uint>> GetUnixLinkCountsBatchAsync(
        string statPath,
        IReadOnlyList<string> paths,
        CancellationToken cancellationToken)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = statPath,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        startInfo.ArgumentList.Add(OperatingSystem.IsMacOS() ? "-f" : "-c");
        startInfo.ArgumentList.Add(OperatingSystem.IsMacOS() ? "%l" : "%h");
        foreach (var path in paths) startInfo.ArgumentList.Add(path);
        using var process = new Process { StartInfo = startInfo };
        if (!process.Start()) throw new RuntimePackException("Could not inspect runtime-pack links.");
        var outputTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var errorTask = process.StandardError.ReadToEndAsync(cancellationToken);
        await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
        var output = await outputTask.ConfigureAwait(false);
        var error = await errorTask.ConfigureAwait(false);
        if (process.ExitCode != 0 || error.Length > 4096 || output.Length > paths.Count * 32)
            throw new RuntimePackException("Could not inspect runtime-pack link count.");
        var lines = output.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries);
        if (lines.Length != paths.Count)
            throw new RuntimePackException("Could not inspect runtime-pack link count.");
        var counts = new uint[lines.Length];
        for (var index = 0; index < lines.Length; index++)
            if (!uint.TryParse(lines[index].Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out counts[index]))
                throw new RuntimePackException("Could not inspect runtime-pack link count.");
        return counts;
    }

    private static uint GetWindowsLinkCount(string path)
    {
        using var handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (NativeMethods.GetFileInformationByHandle(handle, out var information) == 0)
            throw new RuntimePackException("Could not inspect runtime-pack link count.");
        return information.NumberOfLinks;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public uint CreationTimeLow;
        public uint CreationTimeHigh;
        public uint LastAccessTimeLow;
        public uint LastAccessTimeHigh;
        public uint LastWriteTimeLow;
        public uint LastWriteTimeHigh;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    private static partial class NativeMethods
    {
        [LibraryImport("kernel32.dll", SetLastError = true)]
        internal static partial int GetFileInformationByHandle(
            SafeFileHandle hFile,
            out ByHandleFileInformation fileInformation);
    }
}
