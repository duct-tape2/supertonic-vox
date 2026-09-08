using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using NSec.Cryptography;
using SupertonicVox.Core;

namespace SupertonicVox.Core.Tests;

internal static class TestFixtures
{
    public const ulong GiB = 1024UL * 1024 * 1024;

    public static EngineDescriptor Supertonic() => new()
    {
        Id = "supertonic-3",
        DisplayName = "Supertonic 3",
        Version = "3.0",
        ModelRevision = "super-rev",
        CodeLicense = "MIT",
        ModelLicense = "OpenRAIL-M",
        KoreanQualityScore = 90,
        IsBundled = true,
        DownloadBytes = 0,
        MinimumMemoryBytes = 4 * GiB,
        MinimumFreeDiskBytes = 1 * GiB,
        MinimumGpuMemoryBytes = 0,
        Features = EngineFeatures.GeneralTts,
        Platforms = [PlatformKind.Windows, PlatformKind.MacOS],
        Architectures = [CpuArchitectureKind.X64, CpuArchitectureKind.Arm64],
        Backends = [AccelerationBackend.OnnxCpu],
        Artifacts = [],
    };

    public static EngineDescriptor Vox() => new()
    {
        Id = "voxcpm2",
        DisplayName = "VoxCPM2",
        Version = "2.0.3",
        ModelRevision = "vox-rev",
        CodeLicense = "Apache-2.0",
        ModelLicense = "Apache-2.0",
        KoreanQualityScore = 78,
        IsBundled = false,
        DownloadBytes = 5_000_000_000,
        MinimumMemoryBytes = 12 * GiB,
        MinimumFreeDiskBytes = 8 * GiB,
        MinimumGpuMemoryBytes = 8 * GiB,
        Features = EngineFeatures.GeneralTts | EngineFeatures.VoiceDesign | EngineFeatures.VoiceCloning | EngineFeatures.ReferenceAudio,
        Platforms = [PlatformKind.Windows, PlatformKind.MacOS],
        Architectures = [CpuArchitectureKind.X64, CpuArchitectureKind.Arm64],
        Backends = [AccelerationBackend.Cpu, AccelerationBackend.Cuda, AccelerationBackend.Mps],
        Artifacts = [],
    };

    public static EngineDescriptor Melo() => new()
    {
        Id = "melotts-ko",
        DisplayName = "MeloTTS Korean",
        Version = "1.0",
        ModelRevision = "melo-rev",
        CodeLicense = "MIT",
        ModelLicense = "MIT",
        KoreanQualityScore = 72,
        IsBundled = false,
        DownloadBytes = 220_000_000,
        MinimumMemoryBytes = 4 * GiB,
        MinimumFreeDiskBytes = 1 * GiB,
        MinimumGpuMemoryBytes = 0,
        Features = EngineFeatures.GeneralTts,
        Platforms = [PlatformKind.Windows, PlatformKind.MacOS],
        Architectures = [CpuArchitectureKind.X64, CpuArchitectureKind.Arm64],
        Backends = [AccelerationBackend.Cpu, AccelerationBackend.Mps],
        Artifacts = [],
    };

    public static HardwareProfile Hardware(
        PlatformKind platform,
        CpuArchitectureKind architecture,
        ulong memory,
        params GpuDevice[] gpus) => new()
        {
            Platform = platform,
            Architecture = architecture,
            CpuName = "Fixture CPU",
            LogicalCoreCount = 8,
            TotalMemoryBytes = memory,
            AvailableMemoryBytes = memory / 2,
            FreeDiskBytes = 100 * GiB,
            IsAppleSilicon = platform == PlatformKind.MacOS && architecture == CpuArchitectureKind.Arm64,
            Gpus = gpus,
            CpuFeatures = [],
            Fingerprint = $"fixture-{platform}-{architecture}-{memory}-{string.Join('-', gpus.Select(gpu => gpu.Name))}",
        };

    public static (byte[] CatalogBytes, byte[] SignatureDocument, CatalogTrustOptions Trust) SignedCatalog(
        EngineCatalog? catalog = null,
        bool development = true,
        bool remoteEnabled = false)
    {
        catalog ??= new EngineCatalog
        {
            SchemaVersion = 1,
            Sequence = 1,
            CreatedUtc = DateTimeOffset.UtcNow,
            TrustRootVersion = "test-root-v1",
            DevelopmentOnly = development,
            Engines = [Supertonic(), Vox(), Melo()],
        };
        var options = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            Converters = { new JsonStringEnumConverter() },
        };
        var catalogBytes = JsonSerializer.SerializeToUtf8Bytes(catalog, options);
        using var key = Key.Create(SignatureAlgorithm.Ed25519, new KeyCreationParameters
        {
            ExportPolicy = KeyExportPolicies.AllowPlaintextExport,
        });
        var publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        var signature = SignatureAlgorithm.Ed25519.Sign(key, catalogBytes);
        var signatureBytes = JsonSerializer.SerializeToUtf8Bytes(new CatalogSignature
        {
            Algorithm = "Ed25519",
            KeyId = "test-key-v1",
            Signature = Convert.ToBase64String(signature),
        }, options);
        var trust = new CatalogTrustOptions
        {
            KeyId = "test-key-v1",
            PublicKey = publicKey,
            TrustRootVersion = "test-root-v1",
            BundledSequenceFloor = 1,
            DevelopmentTrustRoot = development,
            RemoteRefreshEnabled = remoteEnabled,
            AllowedEngineIds = new HashSet<string>(["supertonic-3", "voxcpm2", "melotts-ko"], StringComparer.Ordinal),
            AllowedOrigins = new HashSet<string>(["https://github.com", "https://huggingface.co"], StringComparer.OrdinalIgnoreCase),
            AllowedLicenses = new HashSet<string>(["MIT", "Apache-2.0", "OpenRAIL-M"], StringComparer.Ordinal),
        };
        return (catalogBytes, signatureBytes, trust);
    }

    public static string Sha256(byte[] data) =>
        Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();
}
