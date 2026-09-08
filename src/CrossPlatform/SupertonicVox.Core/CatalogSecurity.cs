using System.Text.Json;
using System.Text.Json.Serialization;
using System.Security.Cryptography;
using System.Globalization;
using System.Text;
using NSec.Cryptography;

namespace SupertonicVox.Core;

public sealed record CatalogTrustOptions
{
    public required string KeyId { get; init; }
    public required byte[] PublicKey { get; init; }
    public required string TrustRootVersion { get; init; }
    public required long BundledSequenceFloor { get; init; }
    public required bool DevelopmentTrustRoot { get; init; }
    public required bool RemoteRefreshEnabled { get; init; }
    public required IReadOnlySet<string> AllowedEngineIds { get; init; }
    public required IReadOnlySet<string> AllowedOrigins { get; init; }
    public required IReadOnlySet<string> AllowedLicenses { get; init; }
}

public sealed class CatalogSecurityException(string message) : IOException(message);

public static class CatalogTrustBootstrapVerifier
{
    public static byte[] Verify(
        CatalogTrustDocument trustDocument,
        CatalogTrustBootstrapDocument bootstrapDocument)
    {
        ArgumentNullException.ThrowIfNull(trustDocument);
        ArgumentNullException.ThrowIfNull(bootstrapDocument);
        if (!string.Equals(trustDocument.KeyId, bootstrapDocument.KeyId, StringComparison.Ordinal) ||
            !string.Equals(
                trustDocument.TrustRootVersion,
                bootstrapDocument.TrustRootVersion,
                StringComparison.Ordinal) ||
            trustDocument.DevelopmentOnly != bootstrapDocument.DevelopmentOnly)
        {
            throw new CatalogSecurityException("Catalog trust document does not match the pinned bootstrap.");
        }
        byte[] publicKey;
        try
        {
            publicKey = Convert.FromBase64String(trustDocument.PublicKey);
        }
        catch (FormatException)
        {
            throw new CatalogSecurityException("Catalog trust public key is not valid base64.");
        }
        if (publicKey.Length != 32)
            throw new CatalogSecurityException("Catalog trust public key is not a raw Ed25519 key.");
        var fingerprint = Convert.ToHexStringLower(SHA256.HashData(publicKey));
        if (bootstrapDocument.PublicKeySha256.Length != 64 ||
            !bootstrapDocument.PublicKeySha256.All(character =>
                character is >= '0' and <= '9' or >= 'a' and <= 'f') ||
            !CryptographicOperations.FixedTimeEquals(
                System.Text.Encoding.ASCII.GetBytes(fingerprint),
                System.Text.Encoding.ASCII.GetBytes(bootstrapDocument.PublicKeySha256)))
        {
            throw new CatalogSecurityException("Catalog trust public key fingerprint mismatch.");
        }
        return publicKey;
    }
}

public interface ICatalogSignatureVerifier
{
    bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature);
}

public sealed class Ed25519CatalogSignatureVerifier : ICatalogSignatureVerifier
{
    public bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        try
        {
            var imported = PublicKey.Import(
                SignatureAlgorithm.Ed25519,
                publicKey,
                KeyBlobFormat.RawPublicKey);
            return SignatureAlgorithm.Ed25519.Verify(imported, data, signature);
        }
        catch (Exception exception) when (exception is ArgumentException or CryptographicException)
        {
            return false;
        }
    }
}

public sealed class CatalogService(
    CatalogTrustOptions trust,
    ICatalogSignatureVerifier signatureVerifier)
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        Converters = { new JsonStringEnumConverter(namingPolicy: null, allowIntegerValues: false) },
    };

    public EngineCatalog LoadBundled(ReadOnlySpan<byte> catalogBytes, ReadOnlySpan<byte> signatureDocumentBytes)
    {
        var signature = ParseSignature(signatureDocumentBytes);
        VerifySignature(catalogBytes, signature);
        var catalog = ParseCatalog(catalogBytes);
        Validate(catalog, trust.BundledSequenceFloor, requireStrictlyNewer: false);
        if (catalog.Sequence != trust.BundledSequenceFloor)
        {
            throw new CatalogSecurityException("Bundled catalog sequence does not equal the pinned floor.");
        }
        return catalog;
    }

    public EngineCatalog AcceptRemote(
        ReadOnlySpan<byte> catalogBytes,
        ReadOnlySpan<byte> signatureDocumentBytes,
        long persistedAcceptedSequence)
    {
        if (!trust.RemoteRefreshEnabled || trust.DevelopmentTrustRoot)
        {
            throw new CatalogSecurityException(
                "Remote catalog refresh is disabled while the interim development trust root is active.");
        }
        var signature = ParseSignature(signatureDocumentBytes);
        VerifySignature(catalogBytes, signature);
        var catalog = ParseCatalog(catalogBytes);
        var sequenceFloor = Math.Max(trust.BundledSequenceFloor, persistedAcceptedSequence);
        Validate(catalog, sequenceFloor, requireStrictlyNewer: true);
        return catalog;
    }

    private CatalogSignature ParseSignature(ReadOnlySpan<byte> bytes)
    {
        try
        {
            return JsonSerializer.Deserialize<CatalogSignature>(bytes, JsonOptions)
                   ?? throw new CatalogSecurityException("Catalog signature document is empty.");
        }
        catch (JsonException exception)
        {
            throw new CatalogSecurityException($"Catalog signature document is invalid: {exception.Message}");
        }
    }

    private EngineCatalog ParseCatalog(ReadOnlySpan<byte> bytes)
    {
        try
        {
            return JsonSerializer.Deserialize<EngineCatalog>(bytes, JsonOptions)
                   ?? throw new CatalogSecurityException("Engine catalog is empty.");
        }
        catch (JsonException exception)
        {
            throw new CatalogSecurityException($"Engine catalog JSON is invalid: {exception.Message}");
        }
    }

    private void VerifySignature(ReadOnlySpan<byte> catalogBytes, CatalogSignature signature)
    {
        if (!string.Equals(signature.Algorithm, "Ed25519", StringComparison.Ordinal) ||
            !string.Equals(signature.KeyId, trust.KeyId, StringComparison.Ordinal))
        {
            throw new CatalogSecurityException("Catalog signature metadata does not match the pinned trust root.");
        }
        byte[] signatureBytes;
        try
        {
            signatureBytes = Convert.FromBase64String(signature.Signature);
        }
        catch (FormatException)
        {
            throw new CatalogSecurityException("Catalog signature is not valid base64.");
        }
        if (!signatureVerifier.Verify(trust.PublicKey, catalogBytes, signatureBytes))
        {
            throw new CatalogSecurityException("Engine catalog signature verification failed.");
        }
    }

    private void Validate(EngineCatalog catalog, long sequenceFloor, bool requireStrictlyNewer)
    {
        if (catalog.SchemaVersion != 1) throw new CatalogSecurityException("Unsupported catalog schema version.");
        if (!string.Equals(catalog.TrustRootVersion, trust.TrustRootVersion, StringComparison.Ordinal))
            throw new CatalogSecurityException("Catalog trust-root version mismatch.");
        if (catalog.DevelopmentOnly != trust.DevelopmentTrustRoot)
            throw new CatalogSecurityException("Catalog development trust marker mismatch.");
        if (catalog.CreatedUtc > DateTimeOffset.UtcNow.AddMinutes(5))
            throw new CatalogSecurityException("Catalog creation time is in the future.");
        if (requireStrictlyNewer ? catalog.Sequence <= sequenceFloor : catalog.Sequence < sequenceFloor)
            throw new CatalogSecurityException("Catalog rollback or replay was rejected.");
        if (catalog.Engines.Count == 0) throw new CatalogSecurityException("Catalog has no engines.");

        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var engine in catalog.Engines)
        {
            ValidateEngine(engine, catalog.DevelopmentOnly);
            if (!ids.Add(engine.Id)) throw new CatalogSecurityException($"Duplicate engine ID: {engine.Id}");
        }
    }

    private void ValidateEngine(EngineDescriptor engine, bool developmentOnly)
    {
        if (string.IsNullOrWhiteSpace(engine.Id) || string.IsNullOrWhiteSpace(engine.DisplayName) ||
            string.IsNullOrWhiteSpace(engine.Version) || string.IsNullOrWhiteSpace(engine.ModelRevision))
            throw new CatalogSecurityException("Engine identity metadata is incomplete.");
        if (!trust.AllowedEngineIds.Contains(engine.Id))
            throw new CatalogSecurityException($"Unrecognized engine ID: {engine.Id}");
        if (!trust.AllowedLicenses.Contains(engine.CodeLicense) ||
            !trust.AllowedLicenses.Contains(engine.ModelLicense))
            throw new CatalogSecurityException($"Unapproved license for engine: {engine.Id}");
        if (!double.IsFinite(engine.KoreanQualityScore) || engine.KoreanQualityScore is < 0 or > 100)
            throw new CatalogSecurityException($"Invalid Korean quality score for engine: {engine.Id}");
        if (engine.Platforms.Count == 0 || engine.Platforms.Contains(PlatformKind.Unknown) ||
            engine.Platforms.Any(value => !Enum.IsDefined(value)) || engine.Platforms.Distinct().Count() != engine.Platforms.Count)
            throw new CatalogSecurityException($"Invalid platform list for engine: {engine.Id}");
        if (engine.Architectures.Count == 0 || engine.Architectures.Contains(CpuArchitectureKind.Unknown) ||
            engine.Architectures.Any(value => !Enum.IsDefined(value)) ||
            engine.Architectures.Distinct().Count() != engine.Architectures.Count)
            throw new CatalogSecurityException($"Invalid architecture list for engine: {engine.Id}");
        if (engine.Backends.Count == 0 || engine.Backends.Any(value => !Enum.IsDefined(value)) ||
            engine.Backends.Distinct().Count() != engine.Backends.Count)
            throw new CatalogSecurityException($"No execution backend for engine: {engine.Id}");
        if (engine.DownloadBytes < 0)
            throw new CatalogSecurityException($"Invalid download size for engine: {engine.Id}");

        var artifactNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        long artifactBytes = 0;
        foreach (var artifact in engine.Artifacts)
        {
            if (string.IsNullOrWhiteSpace(artifact.Name) ||
                artifact.Name != Path.GetFileName(artifact.Name) ||
                artifact.Name is "." or "..")
                throw new CatalogSecurityException($"Unsafe artifact name for engine: {engine.Id}");
            if (!artifactNames.Add(artifact.Name))
                throw new CatalogSecurityException($"Duplicate artifact name for engine: {engine.Id}");
            if (artifact.DownloadUri.Scheme != Uri.UriSchemeHttps ||
                !trust.AllowedOrigins.Contains(artifact.DownloadUri.GetLeftPart(UriPartial.Authority)))
                throw new CatalogSecurityException($"Unapproved artifact origin for engine: {engine.Id}");
            if (artifact.SizeBytes <= 0 || artifact.Sha256.Length != 64 ||
                !artifact.Sha256.All(character => Uri.IsHexDigit(character)))
                throw new CatalogSecurityException($"Invalid artifact integrity metadata for engine: {engine.Id}");
            if (artifact.Platforms.Count == 0 || artifact.Platforms.Any(value =>
                    value == PlatformKind.Unknown || !Enum.IsDefined(value) || !engine.Platforms.Contains(value)))
                throw new CatalogSecurityException($"Invalid artifact platform selector for engine: {engine.Id}");
            if (artifact.Architectures.Count == 0 || artifact.Architectures.Any(value =>
                    value == CpuArchitectureKind.Unknown || !Enum.IsDefined(value) || !engine.Architectures.Contains(value)))
                throw new CatalogSecurityException($"Invalid artifact architecture selector for engine: {engine.Id}");
            if (artifact.Backends.Count == 0 || artifact.Backends.Any(value =>
                    !Enum.IsDefined(value) || !engine.Backends.Contains(value)))
                throw new CatalogSecurityException($"Invalid artifact backend selector for engine: {engine.Id}");
            ValidateArtifactKind(engine, artifact);
            try
            {
                artifactBytes = checked(artifactBytes + artifact.SizeBytes);
            }
            catch (OverflowException)
            {
                throw new CatalogSecurityException($"Artifact sizes overflow for engine: {engine.Id}");
            }
        }
        if (!engine.IsBundled && engine.Artifacts.Count > 0 && artifactBytes != engine.DownloadBytes)
            throw new CatalogSecurityException($"Artifact sizes do not match download size for engine: {engine.Id}");
        if (!developmentOnly && string.Equals(engine.Id, "voxcpm2", StringComparison.Ordinal) &&
            !engine.Artifacts.Any(value => value.Kind == EngineArtifactKind.RuntimePackTar))
            throw new CatalogSecurityException("The production VoxCPM2 engine has no signed runtime-pack artifacts.");
    }

    private static void ValidateArtifactKind(EngineDescriptor engine, EngineArtifact artifact)
    {
        if (!Enum.IsDefined(artifact.Kind))
            throw new CatalogSecurityException($"Invalid artifact kind for engine: {engine.Id}");
        if (artifact.Kind == EngineArtifactKind.OpaqueFile)
        {
            if (string.Equals(engine.Id, "voxcpm2", StringComparison.Ordinal))
                throw new CatalogSecurityException("VoxCPM2 artifacts must use the signed runtime-pack format.");
            if (artifact.RuntimePack is not null)
                throw new CatalogSecurityException(
                    $"Opaque artifact contains runtime-pack metadata for engine: {engine.Id}");
            return;
        }

        var pack = artifact.RuntimePack;
        if (pack is null || !Enum.IsDefined(pack.ArchiveProfile) ||
            pack.ArchiveProfile != RuntimePackArchiveProfile.UstarV1 ||
            pack.ProtocolVersion != 2 ||
            !string.Equals(pack.EngineVersion, engine.Version, StringComparison.Ordinal) ||
            !string.Equals(pack.ModelRevision, engine.ModelRevision, StringComparison.Ordinal) ||
            pack.Platform == PlatformKind.Unknown || !Enum.IsDefined(pack.Platform) ||
            pack.Architecture == CpuArchitectureKind.Unknown || !Enum.IsDefined(pack.Architecture) ||
            !Enum.IsDefined(pack.Backend) ||
            artifact.Platforms.Count != 1 || artifact.Platforms[0] != pack.Platform ||
            artifact.Architectures.Count != 1 || artifact.Architectures[0] != pack.Architecture ||
            artifact.Backends.Count != 1 || artifact.Backends[0] != pack.Backend ||
            !IsLowerSha256(pack.ManifestSha256) || !IsLowerSha256(pack.PackFingerprint) ||
            pack.ExtractedFileCount is < 2 or > 50_001 ||
            pack.ExtractedBytes is < 1 or > 16L * 1024 * 1024 * 1024)
        {
            throw new CatalogSecurityException($"Invalid runtime-pack metadata for engine: {engine.Id}");
        }
        if (!string.Equals(engine.Id, "voxcpm2", StringComparison.Ordinal))
            throw new CatalogSecurityException($"Runtime-pack artifacts are not enabled for engine: {engine.Id}");
    }

    private static bool IsLowerSha256(string value) =>
        value.Length == 64 && value.All(character =>
            character is >= '0' and <= '9' or >= 'a' and <= 'f');
}

public sealed class CatalogSequenceStore(string filePath)
{
    private const int LockRetryMilliseconds = 50;
    private static readonly TimeSpan LockTimeout = TimeSpan.FromSeconds(30);

    public async Task<long> ReadAsync(CancellationToken cancellationToken = default)
    {
        if (!File.Exists(filePath)) return 0;
        var text = await File.ReadAllTextAsync(filePath, cancellationToken).ConfigureAwait(false);
        if (!long.TryParse(text, out var value) || value < 0)
            throw new CatalogSecurityException("Persisted catalog sequence state is corrupt.");
        return value;
    }

    public async Task WriteAsync(long sequence, CancellationToken cancellationToken = default)
    {
        if (sequence < 0) throw new ArgumentOutOfRangeException(nameof(sequence));
        var fullPath = Path.GetFullPath(filePath);
        var directory = Path.GetDirectoryName(fullPath)
                        ?? throw new InvalidOperationException("Catalog sequence directory is unavailable.");
        Directory.CreateDirectory(directory);
        var temporary = Path.Combine(directory, $".{Path.GetFileName(fullPath)}.{Guid.NewGuid():N}.tmp");
        try
        {
            var bytes = Encoding.UTF8.GetBytes(sequence.ToString(CultureInfo.InvariantCulture));
            await using (var stream = new FileStream(
                             temporary,
                             FileMode.CreateNew,
                             FileAccess.Write,
                             FileShare.None,
                             4096,
                             FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temporary, fullPath, true);
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }

    public async Task<T> ExecuteExclusiveAsync<T>(
        Func<CancellationToken, Task<T>> action,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(action);
        var fullPath = Path.GetFullPath(filePath);
        var directory = Path.GetDirectoryName(fullPath)
                        ?? throw new InvalidOperationException("Catalog sequence directory is unavailable.");
        Directory.CreateDirectory(directory);
        var lockPath = fullPath + ".lock";
        var started = DateTimeOffset.UtcNow;
        FileStream lease;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                lease = new FileStream(
                    lockPath,
                    FileMode.OpenOrCreate,
                    FileAccess.ReadWrite,
                    FileShare.None,
                    1,
                    FileOptions.Asynchronous);
                break;
            }
            catch (IOException) when (DateTimeOffset.UtcNow - started < LockTimeout)
            {
                await Task.Delay(LockRetryMilliseconds, cancellationToken).ConfigureAwait(false);
            }
            catch (IOException exception)
            {
                throw new CatalogSecurityException(
                    $"Could not acquire the catalog sequence lock: {exception.Message}");
            }
        }
        await using (lease)
        {
            return await action(cancellationToken).ConfigureAwait(false);
        }
    }
}

public sealed class RemoteCatalogAcceptanceService(
    CatalogService catalogService,
    CatalogSequenceStore sequenceStore)
{
    public async Task<EngineCatalog> AcceptAndPersistAsync(
        ReadOnlyMemory<byte> catalogBytes,
        ReadOnlyMemory<byte> signatureDocumentBytes,
        CancellationToken cancellationToken = default)
    {
        return await sequenceStore.ExecuteExclusiveAsync(async lockedCancellationToken =>
        {
            var persistedSequence = await sequenceStore.ReadAsync(lockedCancellationToken).ConfigureAwait(false);
            var catalog = catalogService.AcceptRemote(
                catalogBytes.Span,
                signatureDocumentBytes.Span,
                persistedSequence);
            await sequenceStore.WriteAsync(catalog.Sequence, lockedCancellationToken).ConfigureAwait(false);
            return catalog;
        }, cancellationToken).ConfigureAwait(false);
    }
}
