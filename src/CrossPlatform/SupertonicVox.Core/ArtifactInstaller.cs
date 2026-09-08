using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;

namespace SupertonicVox.Core;

public sealed class DriveFileSpaceProbe : IFileSpaceProbe
{
    public ulong GetAvailableBytes(string path)
    {
        var fullPath = Path.GetFullPath(path);
        var root = Path.GetPathRoot(fullPath)
                   ?? throw new InvalidOperationException("Could not determine the destination drive.");
        return checked((ulong)new DriveInfo(root).AvailableFreeSpace);
    }
}

public sealed class NoRedirectHttpTransport : INoRedirectArtifactTransport, IDisposable
{
    private readonly HttpClient client;

    public NoRedirectHttpTransport(TimeSpan timeout)
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseProxy = false,
            AutomaticDecompression = DecompressionMethods.None,
        };
        client = new HttpClient(handler, disposeHandler: true) { Timeout = timeout };
    }

    public Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken = default) =>
        client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);

    public void Dispose() => client.Dispose();
}

public sealed class ArtifactInstaller(
    INoRedirectArtifactTransport httpTransport,
    IFileSpaceProbe fileSpaceProbe,
    IReadOnlySet<string> allowedOrigins,
    IReadOnlyCollection<EngineDescriptor> verifiedCatalogEngines) : IArtifactInstaller
{
    private const int BufferSize = 128 * 1024;
    private readonly IReadOnlySet<string> trustedOrigins =
        allowedOrigins.ToHashSet(StringComparer.OrdinalIgnoreCase);
    private readonly IReadOnlyDictionary<string, TrustedEngine> trustedEngines =
        SnapshotTrustedEngines(verifiedCatalogEngines);

    public async Task<ArtifactInstallResult> InstallAsync(
        EngineDescriptor engine,
        EngineArtifact artifact,
        ArtifactInstallConsent consent,
        string destinationDirectory,
        CancellationToken cancellationToken = default)
    {
        ValidateCatalogMembership(engine, artifact);
        ValidateConsent(engine, artifact, consent, destinationDirectory);
        ValidateOrigin(artifact.DownloadUri);
        Directory.CreateDirectory(destinationDirectory);
        var fullDirectory = Path.GetFullPath(destinationDirectory);
        var finalPath = Path.GetFullPath(Path.Combine(fullDirectory, artifact.Name));
        if (!finalPath.StartsWith(fullDirectory + Path.DirectorySeparatorChar, StringComparison.Ordinal))
            throw new InvalidDataException("Artifact target escaped the destination directory.");

        var partialPath = finalPath + ".partial";
        var etagPath = partialPath + ".etag";
        var existingLength = File.Exists(partialPath) ? new FileInfo(partialPath).Length : 0;
        if (existingLength < 0 || existingLength > artifact.SizeBytes)
        {
            DeleteIfPresent(partialPath);
            DeleteIfPresent(etagPath);
            existingLength = 0;
        }
        if (existingLength == artifact.SizeBytes)
        {
            var existingDigest = await ComputeSha256Async(partialPath, cancellationToken).ConfigureAwait(false);
            if (string.Equals(existingDigest, artifact.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                File.Move(partialPath, finalPath, true);
                DeleteIfPresent(etagPath);
                return new ArtifactInstallResult(finalPath, existingLength, existingDigest, true);
            }
            DeleteIfPresent(partialPath);
            DeleteIfPresent(etagPath);
            existingLength = 0;
        }
        var required = checked((ulong)Math.Max(0, artifact.SizeBytes - existingLength));
        var safetyMargin = Math.Max(64UL * 1024 * 1024, checked((ulong)artifact.SizeBytes / 20));
        if (fileSpaceProbe.GetAvailableBytes(fullDirectory) < required + safetyMargin)
            throw new IOException("There is not enough free space for the verified artifact download.");

        var requestedResume = existingLength > 0;
        try
        {
            EntityTagHeaderValue? ifRange = null;
            if (requestedResume)
            {
                if (File.Exists(etagPath))
                {
                    var etagText = await File.ReadAllTextAsync(etagPath, cancellationToken).ConfigureAwait(false);
                    if (EntityTagHeaderValue.TryParse(etagText, out var etag)) ifRange = etag;
                }
            }

            using var response = await SendFollowingApprovedRedirectsAsync(
                artifact.DownloadUri,
                requestedResume ? existingLength : null,
                ifRange,
                cancellationToken).ConfigureAwait(false);
            if (response.StatusCode is not HttpStatusCode.OK and not HttpStatusCode.PartialContent)
                throw new HttpRequestException($"Artifact server returned {(int)response.StatusCode}.");
            ValidateOrigin(response.RequestMessage?.RequestUri ?? artifact.DownloadUri);

            var append = requestedResume && response.StatusCode == HttpStatusCode.PartialContent;
            if (append)
            {
                var contentRange = response.Content.Headers.ContentRange;
                if (contentRange?.From != existingLength ||
                    (contentRange.Length is not null && contentRange.Length != artifact.SizeBytes))
                {
                    throw new InvalidDataException("Artifact server returned an invalid resume range.");
                }
            }
            var startLength = append ? existingLength : 0;
            if (!append && requestedResume)
            {
                DeleteIfPresent(partialPath);
                DeleteIfPresent(etagPath);
            }
            var responseEtag = response.Headers.ETag?.ToString();
            if (!string.IsNullOrWhiteSpace(responseEtag))
                await File.WriteAllTextAsync(etagPath, responseEtag, cancellationToken).ConfigureAwait(false);

            await using var source = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            await using (var destination = new FileStream(
                             partialPath,
                             append ? FileMode.Append : FileMode.Create,
                             FileAccess.Write,
                             FileShare.None,
                             BufferSize,
                             FileOptions.Asynchronous | FileOptions.SequentialScan))
            {
                var buffer = new byte[BufferSize];
                var total = startLength;
                while (true)
                {
                    var read = await source.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                    if (read == 0) break;
                    total = checked(total + read);
                    if (total > artifact.SizeBytes)
                        throw new InvalidDataException("Artifact exceeded its declared size.");
                    await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                }
                await destination.FlushAsync(cancellationToken).ConfigureAwait(false);
            }

            var info = new FileInfo(partialPath);
            if (info.Length != artifact.SizeBytes)
                throw new InvalidDataException("Artifact size does not match the signed catalog.");
            var digest = await ComputeSha256Async(partialPath, cancellationToken).ConfigureAwait(false);
            if (!string.Equals(digest, artifact.Sha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Artifact SHA-256 does not match the signed catalog.");

            File.Move(partialPath, finalPath, true);
            DeleteIfPresent(etagPath);
            return new ArtifactInstallResult(finalPath, info.Length, digest, append);
        }
        catch (InvalidDataException)
        {
            DeleteIfPresent(partialPath);
            DeleteIfPresent(etagPath);
            throw;
        }
    }

    private void ValidateOrigin(Uri uri)
    {
        if (uri.Scheme != Uri.UriSchemeHttps || !trustedOrigins.Contains(uri.GetLeftPart(UriPartial.Authority)))
            throw new InvalidDataException("Artifact origin is not approved.");
    }

    private void ValidateCatalogMembership(EngineDescriptor engine, EngineArtifact artifact)
    {
        if (!trustedEngines.TryGetValue(engine.Id, out var trusted) ||
            !string.Equals(engine.Version, trusted.Version, StringComparison.Ordinal) ||
            !string.Equals(engine.ModelRevision, trusted.ModelRevision, StringComparison.Ordinal) ||
            !string.Equals(engine.CodeLicense, trusted.CodeLicense, StringComparison.Ordinal) ||
            !string.Equals(engine.ModelLicense, trusted.ModelLicense, StringComparison.Ordinal) ||
            !trusted.Artifacts.Contains(TrustedArtifact.From(artifact)))
        {
            throw new InvalidOperationException(
                "The engine artifact is not an exact member of the verified catalog snapshot.");
        }
    }

    private async Task<HttpResponseMessage> SendFollowingApprovedRedirectsAsync(
        Uri initialUri,
        long? rangeStart,
        EntityTagHeaderValue? ifRange,
        CancellationToken cancellationToken)
    {
        const int maximumRedirects = 5;
        var currentUri = initialUri;
        for (var redirectCount = 0; redirectCount <= maximumRedirects; redirectCount++)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, currentUri);
            if (rangeStart is not null)
            {
                request.Headers.Range = new RangeHeaderValue(rangeStart, null);
                if (ifRange is not null) request.Headers.IfRange = new RangeConditionHeaderValue(ifRange);
            }
            var response = await httpTransport.SendAsync(request, cancellationToken).ConfigureAwait(false);
            if (!IsRedirect(response.StatusCode)) return response;

            var location = response.Headers.Location;
            response.Dispose();
            if (location is null) throw new InvalidDataException("Artifact redirect did not include a location.");
            if (redirectCount == maximumRedirects)
                throw new InvalidDataException("Artifact download exceeded the redirect limit.");
            currentUri = location.IsAbsoluteUri ? location : new Uri(currentUri, location);
            ValidateOrigin(currentUri);
        }
        throw new InvalidDataException("Artifact redirect handling failed.");
    }

    private static bool IsRedirect(HttpStatusCode statusCode) => statusCode is
        HttpStatusCode.Moved or
        HttpStatusCode.Redirect or
        HttpStatusCode.RedirectMethod or
        HttpStatusCode.TemporaryRedirect or
        HttpStatusCode.PermanentRedirect;

    private static IReadOnlyDictionary<string, TrustedEngine> SnapshotTrustedEngines(
        IReadOnlyCollection<EngineDescriptor> engines)
    {
        ArgumentNullException.ThrowIfNull(engines);
        var snapshot = new Dictionary<string, TrustedEngine>(StringComparer.Ordinal);
        foreach (var engine in engines)
        {
            if (!snapshot.TryAdd(
                    engine.Id,
                    new TrustedEngine(
                        engine.Version,
                        engine.ModelRevision,
                        engine.CodeLicense,
                        engine.ModelLicense,
                        engine.Artifacts.Select(TrustedArtifact.From).ToHashSet())))
            {
                throw new ArgumentException($"Duplicate verified engine ID: {engine.Id}", nameof(engines));
            }
        }
        return snapshot;
    }

    private static void ValidateConsent(
        EngineDescriptor engine,
        EngineArtifact artifact,
        ArtifactInstallConsent consent,
        string destinationDirectory)
    {
        if (!consent.Approved ||
            consent.EngineId != engine.Id ||
            consent.ArtifactName != artifact.Name ||
            consent.SizeBytes != artifact.SizeBytes ||
            consent.LicenseId != engine.ModelLicense ||
            Path.GetFullPath(consent.TargetDirectory) != Path.GetFullPath(destinationDirectory))
            throw new InvalidOperationException("Explicit artifact installation consent is missing or stale.");
    }

    private static async Task<string> ComputeSha256Async(string path, CancellationToken cancellationToken)
    {
        await using var source = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            BufferSize,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        using var sha256 = SHA256.Create();
        var digest = await sha256.ComputeHashAsync(source, cancellationToken).ConfigureAwait(false);
        return Convert.ToHexString(digest).ToLowerInvariant();
    }

    private static void DeleteIfPresent(string path)
    {
        try
        {
            if (File.Exists(path)) File.Delete(path);
        }
        catch
        {
        }
    }

    private sealed record TrustedEngine(
        string Version,
        string ModelRevision,
        string CodeLicense,
        string ModelLicense,
        IReadOnlySet<TrustedArtifact> Artifacts);

    private sealed record TrustedArtifact(
        string Name,
        string AbsoluteUri,
        long SizeBytes,
        string Sha256,
        string? ETag,
        EngineArtifactKind Kind,
        string Platforms,
        string Architectures,
        string Backends,
        TrustedRuntimePack? RuntimePack)
    {
        public static TrustedArtifact From(EngineArtifact artifact) => new(
            artifact.Name,
            artifact.DownloadUri.AbsoluteUri,
            artifact.SizeBytes,
            artifact.Sha256,
            artifact.ETag,
            artifact.Kind,
            string.Join(',', artifact.Platforms.Order()),
            string.Join(',', artifact.Architectures.Order()),
            string.Join(',', artifact.Backends.Order()),
            TrustedRuntimePack.From(artifact.RuntimePack));
    }

    private sealed record TrustedRuntimePack(
        RuntimePackArchiveProfile ArchiveProfile,
        int ProtocolVersion,
        string EngineVersion,
        string ModelRevision,
        PlatformKind Platform,
        CpuArchitectureKind Architecture,
        AccelerationBackend Backend,
        string ManifestSha256,
        string PackFingerprint,
        int ExtractedFileCount,
        long ExtractedBytes)
    {
        public static TrustedRuntimePack? From(RuntimePackArtifactMetadata? metadata) =>
            metadata is null
                ? null
                : new TrustedRuntimePack(
                    metadata.ArchiveProfile,
                    metadata.ProtocolVersion,
                    metadata.EngineVersion,
                    metadata.ModelRevision,
                    metadata.Platform,
                    metadata.Architecture,
                    metadata.Backend,
                    metadata.ManifestSha256,
                    metadata.PackFingerprint,
                    metadata.ExtractedFileCount,
                    metadata.ExtractedBytes);
    }
}
