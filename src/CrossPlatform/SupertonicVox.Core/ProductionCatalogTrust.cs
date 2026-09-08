using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SupertonicVox.Core;

public sealed class ProductionCatalogTrustVerifier(ICatalogSignatureVerifier signatureVerifier)
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        Converters = { new JsonStringEnumConverter(namingPolicy: null, allowIntegerValues: false) },
    };

    public CatalogTrustManifestDocument VerifyManifest(
        ReadOnlySpan<byte> manifestBytes,
        ReadOnlySpan<byte> signatureDocumentBytes,
        CatalogTrustDocument rootTrust,
        CatalogTrustBootstrapDocument bootstrap,
        long persistedManifestSequence,
        DateTimeOffset now)
    {
        if (rootTrust.DevelopmentOnly || bootstrap.DevelopmentOnly)
            throw new CatalogSecurityException("A production trust manifest cannot use a development root.");
        if (persistedManifestSequence < 0)
            throw new CatalogSecurityException("Persisted trust-manifest sequence is invalid.");
        var rootKey = CatalogTrustBootstrapVerifier.Verify(rootTrust, bootstrap);
        var signature = Parse<CatalogSignature>(signatureDocumentBytes, "trust-manifest signature");
        if (!string.Equals(signature.Algorithm, "Ed25519", StringComparison.Ordinal) ||
            !string.Equals(signature.KeyId, rootTrust.KeyId, StringComparison.Ordinal))
            throw new CatalogSecurityException("Trust-manifest signature metadata does not match the root.");
        var signatureBytes = DecodeSignature(signature.Signature, "trust-manifest");
        if (!signatureVerifier.Verify(rootKey, manifestBytes, signatureBytes))
            throw new CatalogSecurityException("Trust-manifest signature verification failed.");

        var manifest = Parse<CatalogTrustManifestDocument>(manifestBytes, "trust manifest");
        if (manifest.SchemaVersion != 1 || manifest.Sequence <= persistedManifestSequence)
            throw new CatalogSecurityException("Trust-manifest rollback or schema mismatch was rejected.");
        if (manifest.CreatedUtc > now.AddMinutes(5) || manifest.ExpiresUtc <= now ||
            manifest.ExpiresUtc <= manifest.CreatedUtc)
            throw new CatalogSecurityException("Trust-manifest validity period is invalid.");
        if (!string.Equals(manifest.TrustRootVersion, rootTrust.TrustRootVersion, StringComparison.Ordinal) ||
            !string.Equals(manifest.RootKeyId, rootTrust.KeyId, StringComparison.Ordinal) ||
            !string.Equals(
                manifest.RootPublicKeySha256,
                bootstrap.PublicKeySha256,
                StringComparison.Ordinal))
            throw new CatalogSecurityException("Trust manifest does not bind to the pinned root.");
        if (manifest.ActiveCatalogKeys.Count == 0)
            throw new CatalogSecurityException("Trust manifest has no active catalog keys.");

        var keyIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var key in manifest.ActiveCatalogKeys)
        {
            if (string.IsNullOrWhiteSpace(key.KeyId) || !keyIds.Add(key.KeyId) ||
                key.NotAfterUtc <= key.NotBeforeUtc)
                throw new CatalogSecurityException("Trust manifest contains an invalid catalog key.");
            _ = DecodePublicKey(key.PublicKey, key.KeyId);
        }
        var revoked = new HashSet<string>(StringComparer.Ordinal);
        foreach (var revocation in manifest.Revocations)
        {
            if (string.IsNullOrWhiteSpace(revocation.KeyId) ||
                string.IsNullOrWhiteSpace(revocation.Reason) ||
                revocation.RevokedUtc > now.AddMinutes(5) ||
                !revoked.Add(revocation.KeyId))
                throw new CatalogSecurityException("Trust manifest contains an invalid revocation.");
        }
        return manifest;
    }

    public CatalogTrustOptions ResolveCatalogTrust(
        CatalogTrustManifestDocument manifest,
        ReadOnlySpan<byte> catalogSignatureDocumentBytes,
        long bundledSequenceFloor,
        IReadOnlySet<string> allowedEngineIds,
        IReadOnlySet<string> allowedOrigins,
        IReadOnlySet<string> allowedLicenses,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        var signature = Parse<CatalogSignature>(catalogSignatureDocumentBytes, "catalog signature");
        if (!string.Equals(signature.Algorithm, "Ed25519", StringComparison.Ordinal))
            throw new CatalogSecurityException("Catalog signature algorithm is invalid.");
        if (manifest.Revocations.Any(value =>
                string.Equals(value.KeyId, signature.KeyId, StringComparison.Ordinal) &&
                value.RevokedUtc <= now))
            throw new CatalogSecurityException("Catalog signing key is revoked.");
        var matches = manifest.ActiveCatalogKeys.Where(value =>
            string.Equals(value.KeyId, signature.KeyId, StringComparison.Ordinal)).ToArray();
        if (matches.Length != 1 || now < matches[0].NotBeforeUtc || now >= matches[0].NotAfterUtc)
            throw new CatalogSecurityException("Catalog signing key is unknown, expired, or not yet valid.");
        return new CatalogTrustOptions
        {
            KeyId = matches[0].KeyId,
            PublicKey = DecodePublicKey(matches[0].PublicKey, matches[0].KeyId),
            TrustRootVersion = manifest.TrustRootVersion,
            BundledSequenceFloor = bundledSequenceFloor,
            DevelopmentTrustRoot = false,
            RemoteRefreshEnabled = true,
            AllowedEngineIds = allowedEngineIds,
            AllowedOrigins = allowedOrigins,
            AllowedLicenses = allowedLicenses,
        };
    }

    public static CatalogAcceptanceState CreateState(
        CatalogTrustManifestDocument manifest,
        ReadOnlySpan<byte> manifestBytes,
        EngineCatalog catalog,
        ReadOnlySpan<byte> catalogBytes)
    {
        return new CatalogAcceptanceState
        {
            RootPublicKeySha256 = manifest.RootPublicKeySha256,
            TrustRootVersion = manifest.TrustRootVersion,
            TrustManifestSequence = manifest.Sequence,
            TrustManifestSha256 = Convert.ToHexStringLower(SHA256.HashData(manifestBytes)),
            CatalogSequence = catalog.Sequence,
            CatalogSha256 = Convert.ToHexStringLower(SHA256.HashData(catalogBytes)),
        };
    }

    private static T Parse<T>(ReadOnlySpan<byte> bytes, string label)
    {
        try
        {
            return JsonSerializer.Deserialize<T>(bytes, JsonOptions)
                   ?? throw new CatalogSecurityException($"The {label} is empty.");
        }
        catch (JsonException exception)
        {
            throw new CatalogSecurityException($"The {label} is invalid: {exception.Message}");
        }
    }

    private static byte[] DecodeSignature(string encoded, string label)
    {
        try
        {
            var bytes = Convert.FromBase64String(encoded);
            if (bytes.Length != 64) throw new FormatException();
            return bytes;
        }
        catch (FormatException)
        {
            throw new CatalogSecurityException($"The {label} signature is invalid.");
        }
    }

    private static byte[] DecodePublicKey(string encoded, string keyId)
    {
        try
        {
            var bytes = Convert.FromBase64String(encoded);
            if (bytes.Length != 32) throw new FormatException();
            return bytes;
        }
        catch (FormatException)
        {
            throw new CatalogSecurityException($"Catalog public key is invalid: {keyId}");
        }
    }
}
