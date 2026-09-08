using System.Text.Json;
using System.Text.Json.Serialization;

namespace SupertonicVox.Core;

public sealed record InstalledRuntimePackRecord
{
    public required string EngineId { get; init; }
    public required string EngineVersion { get; init; }
    public required string ModelRevision { get; init; }
    public required int ProtocolVersion { get; init; }
    public required PlatformKind Platform { get; init; }
    public required CpuArchitectureKind Architecture { get; init; }
    public required AccelerationBackend Backend { get; init; }
    public required string RelativeRoot { get; init; }
    public required string ManifestSha256 { get; init; }
    public required string PackFingerprint { get; init; }
    public required string SourceArtifactSha256 { get; init; }
    public required DateTimeOffset InstalledUtc { get; init; }
}

public sealed record RuntimePackInventory
{
    public required IReadOnlyList<InstalledRuntimePackRecord> Installed { get; init; }
    public required IReadOnlyList<InstalledRuntimePackRecord> Invalid { get; init; }
    public required IReadOnlyDictionary<string, string> ActivePackFingerprints { get; init; }
}

public sealed record RuntimePackInstallResult(
    VerifiedRuntimePack Pack,
    InstalledRuntimePackRecord Record,
    bool ReusedExistingPack);

internal sealed record RuntimePackStateDocument
{
    public required int SchemaVersion { get; init; }
    public required IReadOnlyList<InstalledRuntimePackRecord> Packs { get; init; }
    public required IReadOnlyDictionary<string, string> ActivePackFingerprints { get; init; }
}

public sealed class RuntimePackManager
{
    private const int MaximumStateBytes = 1024 * 1024;
    private const int MaximumPackRecords = 128;
    private static readonly TimeSpan StateLockTimeout = TimeSpan.FromSeconds(30);
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter(namingPolicy: null, allowIntegerValues: false) },
    };

    private readonly string rootDirectory;
    private readonly string packsDirectory;
    private readonly string statePath;
    private readonly string stateLockPath;
    private readonly IArtifactInstaller artifactInstaller;
    private readonly RuntimePackArchiveExtractor archiveExtractor;
    private readonly RuntimePackVerifier packVerifier;
    private readonly IFileSpaceProbe fileSpaceProbe;
    private readonly SemaphoreSlim operationGate = new(1, 1);

    public RuntimePackManager(
        string rootDirectory,
        IArtifactInstaller artifactInstaller,
        RuntimePackArchiveExtractor? archiveExtractor = null,
        RuntimePackVerifier? packVerifier = null,
        IFileSpaceProbe? fileSpaceProbe = null)
    {
        this.rootDirectory = Path.GetFullPath(rootDirectory);
        packsDirectory = Path.Combine(this.rootDirectory, "packs");
        DownloadDirectory = Path.Combine(this.rootDirectory, "downloads");
        statePath = Path.Combine(this.rootDirectory, "runtime-packs.json");
        stateLockPath = Path.Combine(this.rootDirectory, "runtime-packs.lock");
        this.artifactInstaller = artifactInstaller ?? throw new ArgumentNullException(nameof(artifactInstaller));
        this.archiveExtractor = archiveExtractor ?? new RuntimePackArchiveExtractor();
        this.packVerifier = packVerifier ?? new RuntimePackVerifier();
        this.fileSpaceProbe = fileSpaceProbe ?? new DriveFileSpaceProbe();
    }

    public string DownloadDirectory { get; }

    public async Task<RuntimePackInventory> GetInventoryAsync(
        CancellationToken cancellationToken = default)
    {
        await operationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            PrepareControlledDirectories();
            await using var stateLock = await AcquireStateLockAsync(cancellationToken).ConfigureAwait(false);
            await RecoverTransientDirectoriesAsync(cancellationToken).ConfigureAwait(false);
            var state = await ReadStateAsync(cancellationToken).ConfigureAwait(false);
            return await VerifyInventoryAsync(state, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            operationGate.Release();
        }
    }

    public async Task<VerifiedRuntimePack?> GetActiveAsync(
        string engineId,
        CancellationToken cancellationToken = default)
    {
        ValidateIdentifier(engineId, nameof(engineId));
        await operationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            PrepareControlledDirectories();
            await using var stateLock = await AcquireStateLockAsync(cancellationToken).ConfigureAwait(false);
            var state = await ReadStateAsync(cancellationToken).ConfigureAwait(false);
            if (!state.ActivePackFingerprints.TryGetValue(engineId, out var fingerprint)) return null;
            var record = state.Packs.SingleOrDefault(value =>
                string.Equals(value.EngineId, engineId, StringComparison.Ordinal) &&
                string.Equals(value.PackFingerprint, fingerprint, StringComparison.Ordinal));
            if (record is null) return null;
            try
            {
                return await VerifyRecordAsync(record, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                return null;
            }
        }
        finally
        {
            operationGate.Release();
        }
    }

    public async Task<RuntimePackInstallResult> InstallAsync(
        EngineDescriptor engine,
        EngineArtifact artifact,
        ArtifactInstallConsent consent,
        CancellationToken cancellationToken = default,
        Func<CancellationToken, Task>? stopExistingProvider = null)
    {
        ArgumentNullException.ThrowIfNull(engine);
        ArgumentNullException.ThrowIfNull(artifact);
        ValidateRuntimeArtifact(engine, artifact);
        var metadata = artifact.RuntimePack!;
        EnsureHostTarget(metadata);

        await operationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            PrepareControlledDirectories();
            await using var stateLock = await AcquireStateLockAsync(cancellationToken).ConfigureAwait(false);
            await RecoverTransientDirectoriesAsync(cancellationToken).ConfigureAwait(false);
            var state = await ReadStateAsync(cancellationToken).ConfigureAwait(false);
            var engineDirectory = Path.Combine(packsDirectory, engine.Id);
            Directory.CreateDirectory(engineDirectory);
            EnsureUnlinkedDirectory(engineDirectory);
            var finalRoot = Path.Combine(engineDirectory, metadata.PackFingerprint);

            if (PathEntryExists(finalRoot))
            {
                try
                {
                    var existing = await packVerifier.VerifyAsync(finalRoot, cancellationToken).ConfigureAwait(false);
                    MatchSignedIdentity(engine, artifact, existing);
                    var existingRecord = CreateRecord(engine, artifact, existing, DateTimeOffset.UtcNow);
                    state = AddAndActivate(state, existingRecord);
                    await WriteStateAsync(state, cancellationToken).ConfigureAwait(false);
                    return new RuntimePackInstallResult(existing, existingRecord, true);
                }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
                {
                    if (stopExistingProvider is null)
                        throw new RuntimePackException(
                            "The existing runtime pack is invalid and must be stopped before replacement.");
                    await stopExistingProvider(cancellationToken).ConfigureAwait(false);
                    var invalidRoot = MoveToDeletingPath(finalRoot);
                    try
                    {
                        state = await RemovePackStateAsync(
                            state,
                            engine.Id,
                            metadata.PackFingerprint,
                            cancellationToken).ConfigureAwait(false);
                        await WriteStateAsync(state, cancellationToken).ConfigureAwait(false);
                    }
                    catch
                    {
                        if (invalidRoot is not null) RestoreDeletingPath(invalidRoot, finalRoot);
                        throw;
                    }
                    if (invalidRoot is not null)
                        await DeleteTreeNoFollowAsync(invalidRoot, cancellationToken).ConfigureAwait(false);
                }
            }

            var requiredDiskBytes = checked(
                (ulong)artifact.SizeBytes +
                (ulong)metadata.ExtractedBytes +
                512UL * 1024 * 1024);
            requiredDiskBytes = Math.Max(requiredDiskBytes, engine.MinimumFreeDiskBytes);
            if (fileSpaceProbe.GetAvailableBytes(rootDirectory) < requiredDiskBytes)
                throw new IOException("There is not enough free space to download and activate the runtime pack.");

            var downloaded = await artifactInstaller.InstallAsync(
                engine,
                artifact,
                consent,
                DownloadDirectory,
                cancellationToken).ConfigureAwait(false);
            var stagedRoot = finalRoot + ".partial";
            if (PathEntryExists(stagedRoot))
                await DeleteTreeNoFollowAsync(stagedRoot, cancellationToken).ConfigureAwait(false);
            try
            {
                await archiveExtractor.ExtractAsync(
                    downloaded.FinalPath,
                    stagedRoot,
                    metadata,
                    cancellationToken).ConfigureAwait(false);
                var stagedPack = await packVerifier.VerifyAsync(stagedRoot, cancellationToken)
                    .ConfigureAwait(false);
                MatchSignedIdentity(engine, artifact, stagedPack);
                var verified = await packVerifier.VerifyAndActivateAsync(
                    stagedRoot,
                    finalRoot,
                    cancellationToken).ConfigureAwait(false);
                MatchSignedIdentity(engine, artifact, verified);
                var record = CreateRecord(engine, artifact, verified, DateTimeOffset.UtcNow);
                state = AddAndActivate(state, record);
                await WriteStateAsync(state, cancellationToken).ConfigureAwait(false);
                DeleteDownloadedArchive(downloaded.FinalPath);
                return new RuntimePackInstallResult(verified, record, false);
            }
            catch
            {
                DeleteDownloadedArchive(downloaded.FinalPath);
                if (PathEntryExists(stagedRoot))
                    await DeleteTreeNoFollowAsync(stagedRoot, CancellationToken.None).ConfigureAwait(false);
                throw;
            }
        }
        finally
        {
            operationGate.Release();
        }
    }

    public async Task<VerifiedRuntimePack> ActivateAsync(
        string engineId,
        string packFingerprint,
        CancellationToken cancellationToken = default)
    {
        ValidateIdentifier(engineId, nameof(engineId));
        ValidateSha256(packFingerprint, nameof(packFingerprint));
        await operationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            PrepareControlledDirectories();
            await using var stateLock = await AcquireStateLockAsync(cancellationToken).ConfigureAwait(false);
            var state = await ReadStateAsync(cancellationToken).ConfigureAwait(false);
            var record = state.Packs.SingleOrDefault(value =>
                string.Equals(value.EngineId, engineId, StringComparison.Ordinal) &&
                string.Equals(value.PackFingerprint, packFingerprint, StringComparison.Ordinal))
                         ?? throw new RuntimePackException("The requested runtime pack is not installed.");
            var verified = await VerifyRecordAsync(record, cancellationToken).ConfigureAwait(false);
            var active = state.ActivePackFingerprints.ToDictionary(pair => pair.Key, pair => pair.Value,
                StringComparer.Ordinal);
            active[engineId] = packFingerprint;
            await WriteStateAsync(state with { ActivePackFingerprints = active }, cancellationToken)
                .ConfigureAwait(false);
            return verified;
        }
        finally
        {
            operationGate.Release();
        }
    }

    public async Task UninstallAsync(
        string engineId,
        string packFingerprint,
        Func<CancellationToken, Task> stopActiveProvider,
        CancellationToken cancellationToken = default)
    {
        ValidateIdentifier(engineId, nameof(engineId));
        ValidateSha256(packFingerprint, nameof(packFingerprint));
        ArgumentNullException.ThrowIfNull(stopActiveProvider);
        await operationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            PrepareControlledDirectories();
            await using var stateLock = await AcquireStateLockAsync(cancellationToken).ConfigureAwait(false);
            var state = await ReadStateAsync(cancellationToken).ConfigureAwait(false);
            var record = state.Packs.SingleOrDefault(value =>
                string.Equals(value.EngineId, engineId, StringComparison.Ordinal) &&
                string.Equals(value.PackFingerprint, packFingerprint, StringComparison.Ordinal))
                         ?? throw new RuntimePackException("The requested runtime pack is not installed.");
            var isActive = state.ActivePackFingerprints.TryGetValue(engineId, out var activeFingerprint) &&
                           string.Equals(activeFingerprint, packFingerprint, StringComparison.Ordinal);
            if (isActive) await stopActiveProvider(cancellationToken).ConfigureAwait(false);
            var originalRoot = ResolveRecordRoot(record);
            try
            {
                await VerifyRecordAsync(record, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                // Invalid packs still have to be recoverable. The state record
                // constrains the path to the controlled engine/fingerprint root.
            }
            var deletingRoot = MoveToDeletingPath(originalRoot);
            try
            {
                await WriteStateAsync(
                    await RemovePackStateAsync(
                        state,
                        engineId,
                        packFingerprint,
                        cancellationToken).ConfigureAwait(false),
                    cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                if (deletingRoot is not null) RestoreDeletingPath(deletingRoot, originalRoot);
                throw;
            }
            if (deletingRoot is not null)
                await DeleteTreeNoFollowAsync(deletingRoot, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            operationGate.Release();
        }
    }

    private async Task<RuntimePackInventory> VerifyInventoryAsync(
        RuntimePackStateDocument state,
        CancellationToken cancellationToken)
    {
        var installed = new List<InstalledRuntimePackRecord>();
        var invalid = new List<InstalledRuntimePackRecord>();
        foreach (var record in state.Packs)
        {
            try
            {
                await VerifyRecordAsync(record, cancellationToken).ConfigureAwait(false);
                installed.Add(record);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                invalid.Add(record);
            }
        }
        var installedFingerprints = installed.ToDictionary(
            value => $"{value.EngineId}\n{value.PackFingerprint}",
            value => value,
            StringComparer.Ordinal);
        var active = state.ActivePackFingerprints
            .Where(pair => installedFingerprints.ContainsKey($"{pair.Key}\n{pair.Value}"))
            .ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal);
        return new RuntimePackInventory
        {
            Installed = installed,
            Invalid = invalid,
            ActivePackFingerprints = active,
        };
    }

    private async Task<VerifiedRuntimePack> VerifyRecordAsync(
        InstalledRuntimePackRecord record,
        CancellationToken cancellationToken)
    {
        ValidateRecord(record);
        var verified = await packVerifier.VerifyAsync(ResolveRecordRoot(record), cancellationToken)
            .ConfigureAwait(false);
        if (!string.Equals(verified.Manifest.EngineId, record.EngineId, StringComparison.Ordinal) ||
            !string.Equals(verified.Manifest.EngineVersion, record.EngineVersion, StringComparison.Ordinal) ||
            !string.Equals(verified.Manifest.ModelRevision, record.ModelRevision, StringComparison.Ordinal) ||
            verified.Manifest.ProtocolVersion != record.ProtocolVersion ||
            verified.Manifest.Platform != record.Platform ||
            verified.Manifest.Architecture != record.Architecture ||
            verified.Manifest.Backend != record.Backend ||
            !string.Equals(verified.ManifestSha256, record.ManifestSha256, StringComparison.Ordinal) ||
            !string.Equals(verified.PackFingerprint, record.PackFingerprint, StringComparison.Ordinal))
            throw new RuntimePackException("Persisted runtime-pack identity does not match the verified pack.");
        return verified;
    }

    private static RuntimePackStateDocument AddAndActivate(
        RuntimePackStateDocument state,
        InstalledRuntimePackRecord record)
    {
        var packs = state.Packs.Where(value =>
                !(string.Equals(value.EngineId, record.EngineId, StringComparison.Ordinal) &&
                  string.Equals(value.PackFingerprint, record.PackFingerprint, StringComparison.Ordinal)))
            .Append(record)
            .OrderBy(value => value.EngineId, StringComparer.Ordinal)
            .ThenBy(value => value.PackFingerprint, StringComparer.Ordinal)
            .ToArray();
        var active = state.ActivePackFingerprints.ToDictionary(pair => pair.Key, pair => pair.Value,
            StringComparer.Ordinal);
        active[record.EngineId] = record.PackFingerprint;
        return state with { Packs = packs, ActivePackFingerprints = active };
    }

    private async Task<RuntimePackStateDocument> RemovePackStateAsync(
        RuntimePackStateDocument state,
        string engineId,
        string packFingerprint,
        CancellationToken cancellationToken)
    {
        var remaining = state.Packs.Where(value =>
                !(string.Equals(value.EngineId, engineId, StringComparison.Ordinal) &&
                  string.Equals(value.PackFingerprint, packFingerprint, StringComparison.Ordinal)))
            .ToArray();
        var active = state.ActivePackFingerprints.ToDictionary(pair => pair.Key, pair => pair.Value,
            StringComparer.Ordinal);
        if (active.TryGetValue(engineId, out var current) &&
            string.Equals(current, packFingerprint, StringComparison.Ordinal))
        {
            InstalledRuntimePackRecord? fallback = null;
            foreach (var candidate in remaining
                .Where(value => string.Equals(value.EngineId, engineId, StringComparison.Ordinal))
                .OrderByDescending(value => value.InstalledUtc)
                .ThenBy(value => value.PackFingerprint, StringComparer.Ordinal))
            {
                try
                {
                    await VerifyRecordAsync(candidate, cancellationToken).ConfigureAwait(false);
                    fallback = candidate;
                    break;
                }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
                {
                }
            }
            if (fallback is null) active.Remove(engineId);
            else active[engineId] = fallback.PackFingerprint;
        }
        return state with { Packs = remaining, ActivePackFingerprints = active };
    }

    private static InstalledRuntimePackRecord CreateRecord(
        EngineDescriptor engine,
        EngineArtifact artifact,
        VerifiedRuntimePack pack,
        DateTimeOffset installedUtc) => new()
        {
            EngineId = pack.Manifest.EngineId,
            EngineVersion = pack.Manifest.EngineVersion,
            ModelRevision = pack.Manifest.ModelRevision,
            ProtocolVersion = pack.Manifest.ProtocolVersion,
            Platform = pack.Manifest.Platform,
            Architecture = pack.Manifest.Architecture,
            Backend = pack.Manifest.Backend,
            RelativeRoot = $"{engine.Id}/{pack.PackFingerprint}",
            ManifestSha256 = pack.ManifestSha256,
            PackFingerprint = pack.PackFingerprint,
            SourceArtifactSha256 = artifact.Sha256.ToLowerInvariant(),
            InstalledUtc = installedUtc.ToUniversalTime(),
        };

    private static void ValidateRuntimeArtifact(EngineDescriptor engine, EngineArtifact artifact)
    {
        if (!string.Equals(engine.Id, "voxcpm2", StringComparison.Ordinal) || engine.IsBundled ||
            artifact.Kind != EngineArtifactKind.RuntimePackTar || artifact.RuntimePack is null ||
            !engine.Artifacts.Contains(artifact))
            throw new RuntimePackException("The selected artifact is not a signed VoxCPM2 runtime pack.");
        var metadata = artifact.RuntimePack;
        if (!string.Equals(metadata.EngineVersion, engine.Version, StringComparison.Ordinal) ||
            !string.Equals(metadata.ModelRevision, engine.ModelRevision, StringComparison.Ordinal) ||
            artifact.Platforms.Count != 1 || artifact.Platforms[0] != metadata.Platform ||
            artifact.Architectures.Count != 1 || artifact.Architectures[0] != metadata.Architecture ||
            artifact.Backends.Count != 1 || artifact.Backends[0] != metadata.Backend)
            throw new RuntimePackException("Runtime-pack catalog identity is inconsistent.");
    }

    private static void MatchSignedIdentity(
        EngineDescriptor engine,
        EngineArtifact artifact,
        VerifiedRuntimePack pack)
    {
        var metadata = artifact.RuntimePack!;
        if (!string.Equals(pack.Manifest.EngineId, engine.Id, StringComparison.Ordinal) ||
            !string.Equals(pack.Manifest.EngineVersion, metadata.EngineVersion, StringComparison.Ordinal) ||
            !string.Equals(pack.Manifest.ModelRevision, metadata.ModelRevision, StringComparison.Ordinal) ||
            pack.Manifest.ProtocolVersion != metadata.ProtocolVersion ||
            pack.Manifest.Platform != metadata.Platform ||
            pack.Manifest.Architecture != metadata.Architecture ||
            pack.Manifest.Backend != metadata.Backend ||
            !string.Equals(pack.ManifestSha256, metadata.ManifestSha256, StringComparison.Ordinal) ||
            !string.Equals(pack.PackFingerprint, metadata.PackFingerprint, StringComparison.Ordinal))
            throw new RuntimePackException("Verified runtime pack does not match the signed catalog identity.");
    }

    private static void EnsureHostTarget(RuntimePackArtifactMetadata metadata)
    {
        var platform = OperatingSystem.IsWindows() ? PlatformKind.Windows :
            OperatingSystem.IsMacOS() ? PlatformKind.MacOS : PlatformKind.Unknown;
        var architecture = System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture switch
        {
            System.Runtime.InteropServices.Architecture.X64 => CpuArchitectureKind.X64,
            System.Runtime.InteropServices.Architecture.Arm64 => CpuArchitectureKind.Arm64,
            _ => CpuArchitectureKind.Unknown,
        };
        if (metadata.Platform != platform || metadata.Architecture != architecture)
            throw new RuntimePackException("Runtime-pack artifact does not target this host.");
    }

    private async Task<RuntimePackStateDocument> ReadStateAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(statePath)) return EmptyState();
        RequireRegularStateFile(statePath);
        await using var stream = new FileStream(
            statePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        if (stream.Length is < 1 or > MaximumStateBytes)
            throw new RuntimePackException("Runtime-pack state size is invalid.");
        var bytes = new byte[checked((int)stream.Length)];
        await stream.ReadExactlyAsync(bytes, cancellationToken).ConfigureAwait(false);
        RuntimePackStateDocument state;
        try
        {
            state = JsonSerializer.Deserialize<RuntimePackStateDocument>(bytes, JsonOptions)
                    ?? throw new RuntimePackException("Runtime-pack state is empty.");
        }
        catch (JsonException exception)
        {
            throw new RuntimePackException($"Runtime-pack state is invalid: {exception.Message}");
        }
        ValidateState(state);
        return state;
    }

    private async Task WriteStateAsync(
        RuntimePackStateDocument state,
        CancellationToken cancellationToken)
    {
        ValidateState(state);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(state, JsonOptions);
        if (bytes.Length > MaximumStateBytes)
            throw new RuntimePackException("Runtime-pack state exceeds its limit.");
        var partial = statePath + $".partial-{Guid.NewGuid():N}";
        try
        {
            await using (var stream = new FileStream(
                             partial,
                             FileMode.CreateNew,
                             FileAccess.Write,
                             FileShare.None,
                             64 * 1024,
                             FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
            }
            File.Move(partial, statePath, overwrite: true);
        }
        finally
        {
            if (File.Exists(partial)) File.Delete(partial);
        }
    }

    private static void ValidateState(RuntimePackStateDocument state)
    {
        if (state.SchemaVersion != 1 || state.Packs.Count > MaximumPackRecords)
            throw new RuntimePackException("Runtime-pack state schema or record count is invalid.");
        var identities = new HashSet<string>(StringComparer.Ordinal);
        var roots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var record in state.Packs)
        {
            ValidateRecord(record);
            if (!identities.Add($"{record.EngineId}\n{record.PackFingerprint}") ||
                !roots.Add(record.RelativeRoot))
                throw new RuntimePackException("Runtime-pack state contains duplicate records.");
        }
        foreach (var pair in state.ActivePackFingerprints)
        {
            ValidateIdentifier(pair.Key, "active engine ID");
            ValidateSha256(pair.Value, "active pack fingerprint");
            if (!identities.Contains($"{pair.Key}\n{pair.Value}"))
                throw new RuntimePackException("Runtime-pack active state references a missing pack.");
        }
    }

    private static void ValidateRecord(InstalledRuntimePackRecord record)
    {
        ValidateIdentifier(record.EngineId, nameof(record.EngineId));
        ValidateSha256(record.ManifestSha256, nameof(record.ManifestSha256));
        ValidateSha256(record.PackFingerprint, nameof(record.PackFingerprint));
        ValidateSha256(record.SourceArtifactSha256, nameof(record.SourceArtifactSha256));
        if (record.ProtocolVersion != 2 || string.IsNullOrWhiteSpace(record.EngineVersion) ||
            string.IsNullOrWhiteSpace(record.ModelRevision) ||
            record.Platform == PlatformKind.Unknown || !Enum.IsDefined(record.Platform) ||
            record.Architecture == CpuArchitectureKind.Unknown || !Enum.IsDefined(record.Architecture) ||
            !Enum.IsDefined(record.Backend) || record.InstalledUtc == default ||
            !string.Equals(
                record.RelativeRoot,
                $"{record.EngineId}/{record.PackFingerprint}",
                StringComparison.Ordinal))
            throw new RuntimePackException("Runtime-pack state record is invalid.");
    }

    private string ResolveRecordRoot(InstalledRuntimePackRecord record)
    {
        var full = Path.GetFullPath(Path.Combine(
            packsDirectory,
            record.RelativeRoot.Replace('/', Path.DirectorySeparatorChar)));
        if (!full.StartsWith(Path.GetFullPath(packsDirectory) + Path.DirectorySeparatorChar, PathComparison))
            throw new RuntimePackException("Runtime-pack state path escaped its controlled root.");
        return full;
    }

    private void PrepareControlledDirectories()
    {
        Directory.CreateDirectory(rootDirectory);
        EnsureUnlinkedDirectory(rootDirectory);
        Directory.CreateDirectory(packsDirectory);
        EnsureUnlinkedDirectory(packsDirectory);
        Directory.CreateDirectory(DownloadDirectory);
        EnsureUnlinkedDirectory(DownloadDirectory);
    }

    private async Task<FileStream> AcquireStateLockAsync(CancellationToken cancellationToken)
    {
        var deadline = DateTimeOffset.UtcNow + StateLockTimeout;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                return new FileStream(
                    stateLockPath,
                    FileMode.OpenOrCreate,
                    FileAccess.ReadWrite,
                    FileShare.None,
                    1,
                    FileOptions.WriteThrough);
            }
            catch (IOException) when (DateTimeOffset.UtcNow < deadline)
            {
                await Task.Delay(50, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private static RuntimePackStateDocument EmptyState() => new()
    {
        SchemaVersion = 1,
        Packs = [],
        ActivePackFingerprints = new Dictionary<string, string>(StringComparer.Ordinal),
    };

    private static void DeleteDownloadedArchive(string path)
    {
        try
        {
            var info = new FileInfo(path);
            if (info.Exists && info.LinkTarget is null &&
                (info.Attributes & FileAttributes.ReparsePoint) == 0)
                File.Delete(path);
        }
        catch
        {
        }
    }

    private async Task RecoverTransientDirectoriesAsync(CancellationToken cancellationToken)
    {
        foreach (var engineDirectory in new DirectoryInfo(packsDirectory).EnumerateDirectories())
        {
            if (engineDirectory.LinkTarget is not null ||
                (engineDirectory.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new RuntimePackException("Runtime-pack engine directory is linked.");
            foreach (var entry in engineDirectory.EnumerateFileSystemInfos())
            {
                if (entry.Name.EndsWith(".partial", StringComparison.Ordinal) ||
                    entry.Name.Contains(".deleting-", StringComparison.Ordinal))
                    await DeleteTreeNoFollowAsync(entry.FullName, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private static string? MoveToDeletingPath(string path)
    {
        FileAttributes attributes;
        try { attributes = File.GetAttributes(path); }
        catch (Exception exception) when (exception is FileNotFoundException or DirectoryNotFoundException)
        {
            return null;
        }
        var deleting = path + $".deleting-{Guid.NewGuid():N}";
        if ((attributes & FileAttributes.Directory) != 0) Directory.Move(path, deleting);
        else File.Move(path, deleting);
        return deleting;
    }

    private static void RestoreDeletingPath(string deletingPath, string originalPath)
    {
        var attributes = File.GetAttributes(deletingPath);
        if ((attributes & FileAttributes.Directory) != 0) Directory.Move(deletingPath, originalPath);
        else File.Move(deletingPath, originalPath);
    }

    private static async Task DeleteTreeNoFollowAsync(
        string path,
        CancellationToken cancellationToken)
    {
        FileAttributes rootAttributes;
        try { rootAttributes = File.GetAttributes(path); }
        catch (Exception exception) when (exception is FileNotFoundException or DirectoryNotFoundException)
        {
            return;
        }
        if ((rootAttributes & FileAttributes.Directory) == 0)
        {
            await DeleteRegularFileAsync(path, rootAttributes, cancellationToken).ConfigureAwait(false);
            return;
        }
        if ((rootAttributes & FileAttributes.ReparsePoint) != 0)
        {
            Directory.Delete(path);
            return;
        }

        var directories = new List<string> { path };
        var directoryLinks = new List<string>();
        var fileLinks = new List<string>();
        var regularFiles = new List<(string Path, FileAttributes Attributes)>();
        var pending = new Stack<string>();
        pending.Push(path);
        while (pending.Count > 0)
        {
            var current = pending.Pop();
            foreach (var entry in new DirectoryInfo(current).EnumerateFileSystemInfos())
            {
                var attributes = entry.Attributes;
                if ((attributes & FileAttributes.Directory) != 0)
                {
                    if ((attributes & FileAttributes.ReparsePoint) != 0 || entry.LinkTarget is not null)
                        directoryLinks.Add(entry.FullName);
                    else
                    {
                        directories.Add(entry.FullName);
                        pending.Push(entry.FullName);
                    }
                }
                else
                {
                    if ((attributes & FileAttributes.ReparsePoint) != 0 || entry.LinkTarget is not null)
                        fileLinks.Add(entry.FullName);
                    else
                        regularFiles.Add((entry.FullName, attributes));
                }
            }
        }

        var linkCounts = await FileLinkInspector.GetLinkCountsAsync(
            regularFiles.Select(value => value.Path).ToArray(),
            cancellationToken).ConfigureAwait(false);
        if (linkCounts.Values.Any(value => value != 1))
            throw new RuntimePackException("Runtime-pack cleanup refused a hard-linked file.");
        foreach (var directory in directories)
            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(
                    directory,
                    File.GetUnixFileMode(directory) |
                    UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        foreach (var link in fileLinks) File.Delete(link);
        foreach (var link in directoryLinks) Directory.Delete(link);
        foreach (var file in regularFiles)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (OperatingSystem.IsWindows())
                File.SetAttributes(file.Path, file.Attributes & ~FileAttributes.ReadOnly);
            File.Delete(file.Path);
        }
        foreach (var directory in directories.OrderByDescending(value => value.Length))
        {
            Directory.Delete(directory);
        }
    }

    private static async Task DeleteRegularFileAsync(
        string path,
        FileAttributes attributes,
        CancellationToken cancellationToken)
    {
        if ((attributes & FileAttributes.ReparsePoint) != 0)
        {
            File.Delete(path);
            return;
        }
        if (await FileLinkInspector.GetLinkCountAsync(path, cancellationToken).ConfigureAwait(false) != 1)
            throw new RuntimePackException("Runtime-pack cleanup refused a hard-linked file.");
        if (OperatingSystem.IsWindows())
            File.SetAttributes(path, attributes & ~FileAttributes.ReadOnly);
        File.Delete(path);
    }

    private static bool PathEntryExists(string path)
    {
        try
        {
            _ = File.GetAttributes(path);
            return true;
        }
        catch (Exception exception) when (exception is FileNotFoundException or DirectoryNotFoundException)
        {
            return false;
        }
    }

    private static void RequireRegularStateFile(string path)
    {
        var info = new FileInfo(path);
        if (!info.Exists || info.LinkTarget is not null ||
            (info.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new RuntimePackException("Runtime-pack state file is missing or linked.");
    }

    private static void EnsureUnlinkedDirectory(string path)
    {
        var info = new DirectoryInfo(path);
        if (!info.Exists || info.LinkTarget is not null ||
            (info.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new RuntimePackException("Runtime-pack controlled directory is missing or linked.");
    }

    private static void ValidateIdentifier(string value, string label)
    {
        if (value.Length is < 1 or > 64 || !value.All(character =>
                character is >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '_'))
            throw new RuntimePackException($"Runtime-pack {label} is invalid.");
    }

    private static void ValidateSha256(string value, string label)
    {
        if (value.Length != 64 || !value.All(character =>
                character is >= '0' and <= '9' or >= 'a' and <= 'f'))
            throw new RuntimePackException($"Runtime-pack {label} is invalid.");
    }

    private static StringComparison PathComparison =>
        OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
}
