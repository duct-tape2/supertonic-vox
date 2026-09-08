using System.Text.Json.Serialization;

namespace SupertonicVox.Core;

[JsonConverter(typeof(JsonStringEnumConverter<PlatformKind>))]
public enum PlatformKind
{
    Unknown,
    Windows,
    MacOS,
}

[JsonConverter(typeof(JsonStringEnumConverter<CpuArchitectureKind>))]
public enum CpuArchitectureKind
{
    Unknown,
    X64,
    Arm64,
}

[JsonConverter(typeof(JsonStringEnumConverter<AccelerationBackend>))]
public enum AccelerationBackend
{
    Cpu,
    OnnxCpu,
    Cuda,
    Metal,
    Mps,
}

[Flags]
[JsonConverter(typeof(JsonStringEnumConverter<EngineFeatures>))]
public enum EngineFeatures
{
    None = 0,
    GeneralTts = 1,
    VoiceDesign = 2,
    VoiceCloning = 4,
    ReferenceAudio = 8,
}

[JsonConverter(typeof(JsonStringEnumConverter<EngineInstallState>))]
public enum EngineInstallState
{
    Bundled,
    NotInstalled,
    Installing,
    Installed,
    Invalid,
}

[JsonConverter(typeof(JsonStringEnumConverter<EngineArtifactKind>))]
public enum EngineArtifactKind
{
    OpaqueFile,
    RuntimePackTar,
}

[JsonConverter(typeof(JsonStringEnumConverter<RuntimePackArchiveProfile>))]
public enum RuntimePackArchiveProfile
{
    UstarV1,
}

public sealed record GpuDevice(
    string Name,
    AccelerationBackend Backend,
    ulong MemoryBytes,
    bool IsIntegrated);

public sealed record HardwareProfile
{
    public required PlatformKind Platform { get; init; }
    public required CpuArchitectureKind Architecture { get; init; }
    public required string CpuName { get; init; }
    public required int LogicalCoreCount { get; init; }
    public required ulong TotalMemoryBytes { get; init; }
    public required ulong AvailableMemoryBytes { get; init; }
    public required ulong FreeDiskBytes { get; init; }
    public required bool IsAppleSilicon { get; init; }
    public required IReadOnlyList<GpuDevice> Gpus { get; init; }
    public required IReadOnlyList<string> CpuFeatures { get; init; }
    public required string Fingerprint { get; init; }
}

public sealed record EngineArtifact
{
    public required string Name { get; init; }
    public required Uri DownloadUri { get; init; }
    public required long SizeBytes { get; init; }
    public required string Sha256 { get; init; }
    public required IReadOnlyList<PlatformKind> Platforms { get; init; }
    public required IReadOnlyList<CpuArchitectureKind> Architectures { get; init; }
    public required IReadOnlyList<AccelerationBackend> Backends { get; init; }
    public string? ETag { get; init; }
    public EngineArtifactKind Kind { get; init; } = EngineArtifactKind.OpaqueFile;
    public RuntimePackArtifactMetadata? RuntimePack { get; init; }
}

public sealed record RuntimePackArtifactMetadata
{
    public required RuntimePackArchiveProfile ArchiveProfile { get; init; }
    public required int ProtocolVersion { get; init; }
    public required string EngineVersion { get; init; }
    public required string ModelRevision { get; init; }
    public required PlatformKind Platform { get; init; }
    public required CpuArchitectureKind Architecture { get; init; }
    public required AccelerationBackend Backend { get; init; }
    public required string ManifestSha256 { get; init; }
    public required string PackFingerprint { get; init; }
    public required int ExtractedFileCount { get; init; }
    public required long ExtractedBytes { get; init; }
}

public sealed record EngineDescriptor
{
    public required string Id { get; init; }
    public required string DisplayName { get; init; }
    public required string Version { get; init; }
    public required string ModelRevision { get; init; }
    public required string CodeLicense { get; init; }
    public required string ModelLicense { get; init; }
    public required double KoreanQualityScore { get; init; }
    public required bool IsBundled { get; init; }
    public required long DownloadBytes { get; init; }
    public required ulong MinimumMemoryBytes { get; init; }
    public required ulong MinimumFreeDiskBytes { get; init; }
    public required ulong MinimumGpuMemoryBytes { get; init; }
    public required EngineFeatures Features { get; init; }
    public required IReadOnlyList<PlatformKind> Platforms { get; init; }
    public required IReadOnlyList<CpuArchitectureKind> Architectures { get; init; }
    public required IReadOnlyList<AccelerationBackend> Backends { get; init; }
    public required IReadOnlyList<EngineArtifact> Artifacts { get; init; }
}

public sealed record EngineCatalog
{
    public required int SchemaVersion { get; init; }
    public required long Sequence { get; init; }
    public required DateTimeOffset CreatedUtc { get; init; }
    public required string TrustRootVersion { get; init; }
    public required bool DevelopmentOnly { get; init; }
    public required IReadOnlyList<EngineDescriptor> Engines { get; init; }
}

public sealed record CatalogSignature
{
    public required string Algorithm { get; init; }
    public required string KeyId { get; init; }
    public required string Signature { get; init; }
}

public sealed record CatalogTrustDocument
{
    public required string KeyId { get; init; }
    public required string PublicKey { get; init; }
    public required string TrustRootVersion { get; init; }
    public required long BundledSequenceFloor { get; init; }
    public required bool DevelopmentOnly { get; init; }
}

public sealed record CatalogTrustBootstrapDocument
{
    public required string KeyId { get; init; }
    public required string PublicKeySha256 { get; init; }
    public required string TrustRootVersion { get; init; }
    public required bool DevelopmentOnly { get; init; }
}

public sealed record CatalogSigningKeyDocument
{
    public required string KeyId { get; init; }
    public required string PublicKey { get; init; }
    public required DateTimeOffset NotBeforeUtc { get; init; }
    public required DateTimeOffset NotAfterUtc { get; init; }
}

public sealed record CatalogKeyRevocationDocument
{
    public required string KeyId { get; init; }
    public required DateTimeOffset RevokedUtc { get; init; }
    public required string Reason { get; init; }
}

public sealed record CatalogTrustManifestDocument
{
    public required int SchemaVersion { get; init; }
    public required long Sequence { get; init; }
    public required DateTimeOffset CreatedUtc { get; init; }
    public required DateTimeOffset ExpiresUtc { get; init; }
    public required string TrustRootVersion { get; init; }
    public required string RootKeyId { get; init; }
    public required string RootPublicKeySha256 { get; init; }
    public required IReadOnlyList<CatalogSigningKeyDocument> ActiveCatalogKeys { get; init; }
    public required IReadOnlyList<CatalogKeyRevocationDocument> Revocations { get; init; }
}

public sealed record CatalogAcceptanceState
{
    public required string RootPublicKeySha256 { get; init; }
    public required string TrustRootVersion { get; init; }
    public required long TrustManifestSequence { get; init; }
    public required string TrustManifestSha256 { get; init; }
    public required long CatalogSequence { get; init; }
    public required string CatalogSha256 { get; init; }
}

public sealed record BenchmarkResult
{
    public required string EngineId { get; init; }
    public required string ModelRevision { get; init; }
    public required string HardwareFingerprint { get; init; }
    public required string AppVersion { get; init; }
    public required bool Success { get; init; }
    public required bool WavValid { get; init; }
    public required double ColdStartMilliseconds { get; init; }
    public required double RealTimeFactor { get; init; }
    public required ulong PeakMemoryBytes { get; init; }
    public required DateTimeOffset CreatedUtc { get; init; }
    public string ExecutionFingerprint { get; init; } = string.Empty;
}

public sealed record RecommendationRequest
{
    public required HardwareProfile Hardware { get; init; }
    public required IReadOnlyList<EngineDescriptor> Engines { get; init; }
    public required IReadOnlyDictionary<string, BenchmarkResult> Benchmarks { get; init; }
    public required string AppVersion { get; init; }
    public IReadOnlyDictionary<string, EngineInstallState> InstallStates { get; init; } =
        new Dictionary<string, EngineInstallState>(StringComparer.Ordinal);
    public IReadOnlyDictionary<string, string> ExecutionFingerprints { get; init; } =
        new Dictionary<string, string>(StringComparer.Ordinal);
    public EngineFeatures RequiredFeatures { get; init; } = EngineFeatures.GeneralTts;
    public string? ManualEngineId { get; init; }
}

public sealed record EngineCandidateScore
{
    public required EngineDescriptor Engine { get; init; }
    public required bool Eligible { get; init; }
    public required double Score { get; init; }
    public required bool LatencyPending { get; init; }
    public required AccelerationBackend? SelectedBackend { get; init; }
    public required IReadOnlyList<string> Reasons { get; init; }
}

public sealed record EngineRecommendation
{
    public required EngineDescriptor SelectedEngine { get; init; }
    public required double Score { get; init; }
    public required bool IsManualOverride { get; init; }
    public required bool LatencyPending { get; init; }
    public required AccelerationBackend SelectedBackend { get; init; }
    public required IReadOnlyList<string> Reasons { get; init; }
    public required IReadOnlyList<EngineCandidateScore> Candidates { get; init; }
}

public sealed record ArtifactInstallConsent(
    string EngineId,
    string ArtifactName,
    long SizeBytes,
    string LicenseId,
    string TargetDirectory,
    bool Approved);

public sealed record ArtifactInstallResult(
    string FinalPath,
    long BytesWritten,
    string Sha256,
    bool Resumed);

public sealed record SynthesisRequest
{
    public required string Text { get; init; }
    public string Language { get; init; } = "ko";
    public string VoiceId { get; init; } = "M1";
    public float Speed { get; init; } = 1.05f;
    public int QualitySteps { get; init; } = 8;
    public byte[]? ReferenceAudio { get; init; }
    public string? ReferenceTranscript { get; init; }
}

public sealed record SynthesisResult
{
    public required byte[] WavBytes { get; init; }
    public required int SampleRate { get; init; }
    public required short Channels { get; init; }
    public required short BitsPerSample { get; init; }
    public required TimeSpan Duration { get; init; }
    public required string EngineId { get; init; }
    public required string ModelRevision { get; init; }
    public required string VoiceId { get; init; }
}

public interface IHardwareProfiler
{
    Task<HardwareProfile> ProfileAsync(string dataDirectory, CancellationToken cancellationToken = default);
}

public interface IEngineProvider : IAsyncDisposable
{
    string EngineId { get; }
    string ModelRevision { get; }
    Task<bool> IsReadyAsync(CancellationToken cancellationToken = default);
    Task EnsureReadyAsync(CancellationToken cancellationToken = default);
    Task<SynthesisResult> SynthesizeAsync(
        SynthesisRequest request,
        CancellationToken cancellationToken = default);
    Task StopAsync(CancellationToken cancellationToken = default);
}

public interface IBenchmarkCache
{
    Task<BenchmarkResult?> GetAsync(
        string appVersion,
        string engineId,
        string modelRevision,
        string hardwareFingerprint,
        CancellationToken cancellationToken = default);

    Task PutAsync(BenchmarkResult result, CancellationToken cancellationToken = default);
}

public interface IArtifactInstaller
{
    Task<ArtifactInstallResult> InstallAsync(
        EngineDescriptor engine,
        EngineArtifact artifact,
        ArtifactInstallConsent consent,
        string destinationDirectory,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Sends exactly one HTTP request and returns redirect responses without following them.
/// </summary>
public interface INoRedirectArtifactTransport
{
    Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken = default);
}

public interface IFileSpaceProbe
{
    ulong GetAvailableBytes(string path);
}

public interface IProcessRunner
{
    Task<ProcessResult> RunAsync(
        string fileName,
        IReadOnlyList<string> arguments,
        TimeSpan timeout,
        CancellationToken cancellationToken = default);
}

public sealed record ProcessResult(int ExitCode, string StandardOutput, string StandardError)
{
    public bool Success => ExitCode == 0;
}
