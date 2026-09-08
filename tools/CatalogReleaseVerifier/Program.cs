using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using SupertonicVox.Core;

if (args.Length != 8)
{
    Console.Error.WriteLine(
        "Usage: CatalogReleaseVerifier <catalog.json> <catalog-signature.json> " +
        "<root-trust.json> <bootstrap.json> <trust-manifest.json> " +
        "<trust-manifest-signature.json> <report.json> " +
        "<previous-verifier-report.json|--first-production-release>");
    return 2;
}

try
{
    var inputs = args.Take(6).Select(Path.GetFullPath).ToArray();
    var inputRoles = new[]
    {
        "catalog",
        "catalogSignature",
        "rootTrust",
        "bootstrap",
        "trustManifest",
        "trustManifestSignature",
    };
    var reportPath = Path.GetFullPath(args[6]);
    var firstProductionRelease = string.Equals(
        args[7],
        "--first-production-release",
        StringComparison.Ordinal);
    var baselinePath = firstProductionRelease ? null : Path.GetFullPath(args[7]);
    if (inputs.Contains(reportPath, StringComparer.OrdinalIgnoreCase) ||
        (baselinePath is not null && string.Equals(reportPath, baselinePath, StringComparison.OrdinalIgnoreCase)))
        throw new CatalogSecurityException("The report path must not replace a release input.");
    foreach (var path in inputs)
        RequireRegularSingleLinkFile(path);
    if (baselinePath is not null) RequireRegularSingleLinkFile(baselinePath);

    var inputBytes = new byte[inputs.Length][];
    for (var index = 0; index < inputs.Length; index++)
        inputBytes[index] = await ReadBoundedBytesAsync(inputs[index]);
    var catalogBytes = inputBytes[0];
    var catalogSignatureBytes = inputBytes[1];
    var rootTrustBytes = inputBytes[2];
    var bootstrapBytes = inputBytes[3];
    var manifestBytes = inputBytes[4];
    var manifestSignatureBytes = inputBytes[5];
    var jsonOptions = new JsonSerializerOptions
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter(namingPolicy: null, allowIntegerValues: false) },
    };
    var rootTrust = JsonSerializer.Deserialize<CatalogTrustDocument>(rootTrustBytes, jsonOptions)
                    ?? throw new CatalogSecurityException("The production root trust document is empty.");
    var bootstrap = JsonSerializer.Deserialize<CatalogTrustBootstrapDocument>(bootstrapBytes, jsonOptions)
                    ?? throw new CatalogSecurityException("The production bootstrap document is empty.");
    if (rootTrust.DevelopmentOnly || bootstrap.DevelopmentOnly ||
        rootTrust.KeyId.Contains("development", StringComparison.OrdinalIgnoreCase) ||
        rootTrust.TrustRootVersion.Contains("development", StringComparison.OrdinalIgnoreCase))
        throw new CatalogSecurityException("Development trust material is forbidden in a production release.");

    CatalogAcceptanceState? baseline = null;
    byte[]? baselineBytes = null;
    if (baselinePath is not null)
    {
        baselineBytes = await ReadBoundedBytesAsync(baselinePath);
        baseline = DeserializeBaseline(
            baselineBytes,
            jsonOptions);
        ValidateState(baseline);
    }
    var verifier = new ProductionCatalogTrustVerifier(new Ed25519CatalogSignatureVerifier());
    var now = DateTimeOffset.UtcNow;
    var manifest = verifier.VerifyManifest(
        manifestBytes,
        manifestSignatureBytes,
        rootTrust,
        bootstrap,
        baseline?.TrustManifestSequence ?? 0,
        now);
    var trust = verifier.ResolveCatalogTrust(
        manifest,
        catalogSignatureBytes,
        rootTrust.BundledSequenceFloor,
        new HashSet<string>(["supertonic-3", "voxcpm2", "melotts-ko"], StringComparer.Ordinal),
        new HashSet<string>(["https://github.com", "https://huggingface.co"], StringComparer.Ordinal),
        new HashSet<string>(["MIT", "OpenRAIL-M", "Apache-2.0"], StringComparer.Ordinal),
        now);
    var catalog = new CatalogService(trust, new Ed25519CatalogSignatureVerifier())
        .LoadBundled(catalogBytes, catalogSignatureBytes);
    ValidateProductionCatalog(catalog);
    var state = ProductionCatalogTrustVerifier.CreateState(manifest, manifestBytes, catalog, catalogBytes);
    if (baseline is not null)
    {
        if (!string.Equals(
                baseline.RootPublicKeySha256,
                state.RootPublicKeySha256,
                StringComparison.Ordinal) ||
            !string.Equals(baseline.TrustRootVersion, state.TrustRootVersion, StringComparison.Ordinal))
            throw new CatalogSecurityException(
                "Root rotation requires a separately signed application release and cannot be implicit.");
        if (state.CatalogSequence <= baseline.CatalogSequence)
            throw new CatalogSecurityException("Catalog sequence did not advance beyond the release baseline.");
    }

    var evidenceFiles = new SortedDictionary<string, object>(StringComparer.Ordinal);
    for (var index = 0; index < inputs.Length; index++)
    {
        evidenceFiles[inputRoles[index]] = Identity(inputs[index], inputBytes[index]);
    }
    object baselineEvidence;
    if (firstProductionRelease)
    {
        baselineEvidence = new { mode = "first-production-release" };
    }
    else
    {
        baselineEvidence = new
        {
            mode = "previous-verifier-report",
            file = Identity(baselinePath!, baselineBytes!),
        };
    }
    var report = new
    {
        schemaVersion = 1,
        productionCatalogEligible = true,
        verifiedUtc = now,
        rootKeyId = rootTrust.KeyId,
        catalogSigningKeyId = trust.KeyId,
        state,
        baseline = baselineEvidence,
        evidenceFiles,
        openExternalControls = new[]
        {
            "offline-or-hsm-root-custody",
            "two-person-approval",
            "rotation-and-revocation-drill",
            "signed-release-provenance",
        },
    };
    await WriteJsonAtomicAsync(reportPath, report, jsonOptions);
    Console.WriteLine(JsonSerializer.Serialize(new
    {
        productionCatalogEligible = true,
        catalogSequence = catalog.Sequence,
        manifestSequence = manifest.Sequence,
    }));
    return 0;
}
catch (Exception exception) when (exception is
       CatalogSecurityException or IOException or UnauthorizedAccessException or JsonException or
       CryptographicException or ArgumentException)
{
    Console.Error.WriteLine(JsonSerializer.Serialize(new
    {
        catalogReleaseVerificationError = exception.Message,
    }));
    return 4;
}

static void ValidateProductionCatalog(EngineCatalog catalog)
{
    if (catalog.DevelopmentOnly)
        throw new CatalogSecurityException("A production catalog cannot be development-only.");
    foreach (var engine in catalog.Engines)
    {
        if (engine.CodeLicense == "REVIEW-PENDING" || engine.ModelLicense == "REVIEW-PENDING")
            throw new CatalogSecurityException($"Unreviewed license remains: {engine.Id}");
        if (!engine.IsBundled && engine.Artifacts.Count == 0)
            throw new CatalogSecurityException($"Optional production engine has no artifacts: {engine.Id}");
        foreach (var artifact in engine.Artifacts)
        {
            if (!string.IsNullOrEmpty(artifact.DownloadUri.UserInfo) ||
                !string.IsNullOrEmpty(artifact.DownloadUri.Query) ||
                !string.IsNullOrEmpty(artifact.DownloadUri.Fragment) ||
                !artifact.DownloadUri.IsDefaultPort)
                throw new CatalogSecurityException($"Production artifact URI is not canonical: {engine.Id}");
        }
    }
}

static void ValidateState(CatalogAcceptanceState state)
{
    if (state.TrustManifestSequence < 0 || state.CatalogSequence < 0 ||
        !IsSha256(state.RootPublicKeySha256) ||
        !IsSha256(state.TrustManifestSha256) ||
        !IsSha256(state.CatalogSha256) ||
        string.IsNullOrWhiteSpace(state.TrustRootVersion))
        throw new CatalogSecurityException("The catalog baseline state is invalid.");
}

static bool IsSha256(string value) => value.Length == 64 && value.All(character =>
    character is >= '0' and <= '9' or >= 'a' and <= 'f');

static void RequireRegularSingleLinkFile(string path)
{
    var info = new FileInfo(path);
    if (!info.Exists || (info.Attributes & FileAttributes.ReparsePoint) != 0)
        throw new CatalogSecurityException($"Release input is missing or a reparse point: {info.Name}");
    if (OperatingSystem.IsWindows())
    {
        using var handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (NativeMethods.GetFileInformationByHandle(handle, out var fileInformation) == 0)
            throw new IOException(
                $"Could not inspect release input links: {info.Name}",
                new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError()));
        if (fileInformation.NumberOfLinks != 1)
            throw new CatalogSecurityException($"Release input is hard-linked: {info.Name}");
    }
}

static CatalogAcceptanceState DeserializeBaseline(
    byte[] bytes,
    JsonSerializerOptions options)
{
    using var document = JsonDocument.Parse(bytes);
    var stateElement = document.RootElement.ValueKind == JsonValueKind.Object &&
                       document.RootElement.TryGetProperty("state", out var nested)
        ? nested
        : document.RootElement;
    return stateElement.Deserialize<CatalogAcceptanceState>(options)
           ?? throw new CatalogSecurityException("The catalog baseline state is empty.");
}

static async Task<byte[]> ReadBoundedBytesAsync(string path)
{
    const int maximumBytes = 16 * 1024 * 1024;
    await using var stream = new FileStream(
        path,
        FileMode.Open,
        FileAccess.Read,
        FileShare.Read,
        64 * 1024,
        FileOptions.Asynchronous | FileOptions.SequentialScan);
    if (stream.Length is < 1 or > maximumBytes)
        throw new CatalogSecurityException($"Release input size is invalid: {Path.GetFileName(path)}");
    var bytes = new byte[checked((int)stream.Length)];
    await stream.ReadExactlyAsync(bytes);
    if (stream.Length != bytes.Length)
        throw new CatalogSecurityException($"Release input changed while reading: {Path.GetFileName(path)}");
    return bytes;
}

static object Identity(string path, byte[] bytes)
{
    return new
    {
        name = Path.GetFileName(path),
        sha256 = Convert.ToHexStringLower(SHA256.HashData(bytes)),
        sizeBytes = bytes.LongLength,
    };
}

static async Task WriteJsonAtomicAsync(string path, object value, JsonSerializerOptions options)
{
    var directory = Path.GetDirectoryName(path)
                    ?? throw new CatalogSecurityException("Report directory is unavailable.");
    Directory.CreateDirectory(directory);
    var temporary = Path.Combine(directory, $".{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");
    try
    {
        await using (var stream = new FileStream(
                         temporary,
                         FileMode.CreateNew,
                         FileAccess.Write,
                         FileShare.None,
                         4096,
                         FileOptions.WriteThrough | FileOptions.Asynchronous))
        {
            await JsonSerializer.SerializeAsync(stream, value, options);
            await stream.FlushAsync();
            stream.Flush(flushToDisk: true);
        }
        File.Move(temporary, path, overwrite: true);
    }
    finally
    {
        if (File.Exists(temporary)) File.Delete(temporary);
    }
}

[StructLayout(LayoutKind.Sequential)]
internal struct ByHandleFileInformation
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

internal static partial class NativeMethods
{
    [LibraryImport("kernel32.dll", SetLastError = true)]
    internal static partial int GetFileInformationByHandle(
        SafeFileHandle hFile,
        out ByHandleFileInformation lpFileInformation);
}
