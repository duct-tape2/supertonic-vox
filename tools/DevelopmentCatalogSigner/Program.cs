using System.Text.Json;
using System.Text.Json.Serialization;
using NSec.Cryptography;
using SupertonicVox.Core;

if (args.Length != 4)
{
    Console.Error.WriteLine(
        "Usage: DevelopmentCatalogSigner <catalog.json> <signature.json> <trust.json> <bootstrap.json>");
    return 2;
}

var catalogPath = Path.GetFullPath(args[0]);
var catalogBytes = await File.ReadAllBytesAsync(catalogPath);
using var catalogDocument = JsonDocument.Parse(catalogBytes);
var root = catalogDocument.RootElement;
if (!root.GetProperty("developmentOnly").GetBoolean())
    throw new InvalidOperationException("This tool refuses to sign a production catalog.");
var sequence = root.GetProperty("sequence").GetInt64();
var trustRootVersion = root.GetProperty("trustRootVersion").GetString()
                       ?? throw new InvalidDataException("Catalog trust root is missing.");
var keyId = trustRootVersion.Replace("development", "svx-development", StringComparison.Ordinal);

using var key = Key.Create(SignatureAlgorithm.Ed25519, new KeyCreationParameters
{
    ExportPolicy = KeyExportPolicies.AllowPlaintextExport,
});
var signature = SignatureAlgorithm.Ed25519.Sign(key, catalogBytes);
var publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
var jsonOptions = new JsonSerializerOptions
{
    PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    WriteIndented = true,
    Converters = { new JsonStringEnumConverter() },
};
var signatureDocument = JsonSerializer.SerializeToUtf8Bytes(new CatalogSignature
{
    Algorithm = "Ed25519",
    KeyId = keyId,
    Signature = Convert.ToBase64String(signature),
}, jsonOptions);
var trustDocument = JsonSerializer.SerializeToUtf8Bytes(new CatalogTrustDocument
{
    KeyId = keyId,
    PublicKey = Convert.ToBase64String(publicKey),
    TrustRootVersion = trustRootVersion,
    BundledSequenceFloor = sequence,
    DevelopmentOnly = true,
}, jsonOptions);
var bootstrapDocument = JsonSerializer.SerializeToUtf8Bytes(new CatalogTrustBootstrapDocument
{
    KeyId = keyId,
    PublicKeySha256 = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(publicKey)),
    TrustRootVersion = trustRootVersion,
    DevelopmentOnly = true,
}, jsonOptions);

await WriteAtomicAsync(Path.GetFullPath(args[1]), signatureDocument);
await WriteAtomicAsync(Path.GetFullPath(args[2]), trustDocument);
await WriteAtomicAsync(Path.GetFullPath(args[3]), bootstrapDocument);
Console.WriteLine($"Signed development catalog sequence {sequence}; private key was not persisted.");
return 0;

static async Task WriteAtomicAsync(string path, byte[] bytes)
{
    var directory = Path.GetDirectoryName(path)
                    ?? throw new InvalidOperationException("Output directory is unavailable.");
    Directory.CreateDirectory(directory);
    var temporary = Path.Combine(directory, $".{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");
    try
    {
        await File.WriteAllBytesAsync(temporary, bytes);
        File.Move(temporary, path, true);
    }
    finally
    {
        if (File.Exists(temporary)) File.Delete(temporary);
    }
}
