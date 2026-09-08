using System.Net;
using System.Net.Http.Headers;
using SupertonicVox.Core;

namespace SupertonicVox.Core.Tests;

public sealed class ArtifactInstallerTests
{
    [Fact]
    public async Task ApprovedDownloadVerifiesAndMovesAtomically()
    {
        using var temporary = new TemporaryDirectory();
        var data = "verified artifact"u8.ToArray();
        var transport = new ArtifactHandler(data);
        var (engine, artifact, consent) = Fixture(data, temporary.Path);
        var installer = CreateInstaller(transport, engine);
        var result = await installer.InstallAsync(engine, artifact, consent, temporary.Path);
        Assert.Equal(data, await File.ReadAllBytesAsync(result.FinalPath));
        Assert.False(File.Exists(result.FinalPath + ".partial"));
        Assert.False(result.Resumed);
    }

    [Fact]
    public async Task ExistingPartialUsesRangeAndIfRange()
    {
        using var temporary = new TemporaryDirectory();
        var data = "resumable verified artifact"u8.ToArray();
        var (engine, artifact, consent) = Fixture(data, temporary.Path, etag: "\"v1\"");
        var partial = Path.Combine(temporary.Path, artifact.Name + ".partial");
        await File.WriteAllBytesAsync(partial, data[..8]);
        await File.WriteAllTextAsync(partial + ".etag", "\"v1\"");
        var handler = new ArtifactHandler(data, "\"v1\"");
        var installer = CreateInstaller(handler, engine);
        var result = await installer.InstallAsync(engine, artifact, consent, temporary.Path);
        Assert.True(result.Resumed);
        Assert.Equal(8, handler.RequestedRangeStart);
        Assert.Equal("\"v1\"", handler.IfRange);
    }

    [Fact]
    public async Task HashMismatchDeletesUntrustedPartial()
    {
        using var temporary = new TemporaryDirectory();
        var expected = "expected"u8.ToArray();
        var tampered = "tampered"u8.ToArray();
        var (engine, artifact, consent) = Fixture(expected, temporary.Path);
        var installer = CreateInstaller(new ArtifactHandler(tampered), engine);
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            installer.InstallAsync(engine, artifact, consent, temporary.Path));
        Assert.False(File.Exists(Path.Combine(temporary.Path, artifact.Name + ".partial")));
    }

    [Fact]
    public async Task MissingConsentMakesNoRequest()
    {
        using var temporary = new TemporaryDirectory();
        var data = "artifact"u8.ToArray();
        var (engine, artifact, consent) = Fixture(data, temporary.Path);
        var handler = new ArtifactHandler(data);
        var installer = CreateInstaller(handler, engine);
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            installer.InstallAsync(engine, artifact, consent with { Approved = false }, temporary.Path));
        Assert.Equal(0, handler.RequestCount);
    }

    [Fact]
    public async Task UnapprovedOriginMakesNoRequest()
    {
        using var temporary = new TemporaryDirectory();
        var data = "artifact"u8.ToArray();
        var (engine, artifact, consent) = Fixture(
            data,
            temporary.Path,
            uri: new Uri("https://evil.example/artifact.bin"));
        var handler = new ArtifactHandler(data);
        var installer = CreateInstaller(handler, engine);
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            installer.InstallAsync(engine, artifact, consent, temporary.Path));
        Assert.Equal(0, handler.RequestCount);
    }

    [Fact]
    public async Task RedirectToUnapprovedOriginIsRejected()
    {
        using var temporary = new TemporaryDirectory();
        var data = "artifact"u8.ToArray();
        var (engine, artifact, consent) = Fixture(data, temporary.Path);
        var handler = new ArtifactHandler(data, redirectUri: new Uri("https://evil.example/artifact.bin"));
        var installer = CreateInstaller(handler, engine);
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            installer.InstallAsync(engine, artifact, consent, temporary.Path));
        Assert.Equal(1, handler.RequestCount);
        Assert.False(File.Exists(Path.Combine(temporary.Path, artifact.Name + ".partial")));
    }

    [Fact]
    public async Task RedirectToApprovedOriginIsFollowedExplicitly()
    {
        using var temporary = new TemporaryDirectory();
        var data = "artifact"u8.ToArray();
        var (engine, artifact, consent) = Fixture(data, temporary.Path);
        var handler = new ArtifactHandler(
            data,
            redirectUri: new Uri("https://github.com/example/release-assets/artifact.bin"));
        var installer = CreateInstaller(handler, engine);

        var result = await installer.InstallAsync(engine, artifact, consent, temporary.Path);

        Assert.Equal(2, handler.RequestCount);
        Assert.Equal(data, await File.ReadAllBytesAsync(result.FinalPath));
    }

    [Fact]
    public async Task CompleteVerifiedPartialActivatesWithoutNetwork()
    {
        using var temporary = new TemporaryDirectory();
        var data = "already complete"u8.ToArray();
        var (engine, artifact, consent) = Fixture(data, temporary.Path);
        await File.WriteAllBytesAsync(Path.Combine(temporary.Path, artifact.Name + ".partial"), data);
        var handler = new ArtifactHandler(data);
        var installer = CreateInstaller(handler, engine);

        var result = await installer.InstallAsync(engine, artifact, consent, temporary.Path);

        Assert.True(result.Resumed);
        Assert.Equal(0, handler.RequestCount);
        Assert.Equal(data, await File.ReadAllBytesAsync(result.FinalPath));
    }

    [Fact]
    public async Task ForgedAllowedOriginArtifactMakesNoRequest()
    {
        using var temporary = new TemporaryDirectory();
        var data = "artifact"u8.ToArray();
        var (engine, artifact, _) = Fixture(data, temporary.Path);
        var forged = artifact with
        {
            DownloadUri = new Uri("https://github.com/attacker/forged.bin"),
            Sha256 = new string('a', 64),
        };
        var forgedConsent = new ArtifactInstallConsent(
            engine.Id,
            forged.Name,
            forged.SizeBytes,
            engine.ModelLicense,
            temporary.Path,
            true);
        var handler = new ArtifactHandler(data);
        var installer = CreateInstaller(handler, engine);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            installer.InstallAsync(engine, forged, forgedConsent, temporary.Path));

        Assert.Equal(0, handler.RequestCount);
    }

    [Fact]
    public async Task ForgedRuntimePackIdentityMakesNoRequest()
    {
        using var temporary = new TemporaryDirectory();
        var data = "runtime pack archive"u8.ToArray();
        var (engine, artifact, consent) = Fixture(data, temporary.Path);
        var metadata = new RuntimePackArtifactMetadata
        {
            ArchiveProfile = RuntimePackArchiveProfile.UstarV1,
            ProtocolVersion = 2,
            EngineVersion = engine.Version,
            ModelRevision = engine.ModelRevision,
            Platform = PlatformKind.MacOS,
            Architecture = CpuArchitectureKind.Arm64,
            Backend = AccelerationBackend.Cpu,
            ManifestSha256 = new string('b', 64),
            PackFingerprint = new string('c', 64),
            ExtractedFileCount = 3,
            ExtractedBytes = 4096,
        };
        artifact = artifact with
        {
            Kind = EngineArtifactKind.RuntimePackTar,
            Platforms = [PlatformKind.MacOS],
            Architectures = [CpuArchitectureKind.Arm64],
            RuntimePack = metadata,
        };
        engine = engine with { Artifacts = [artifact] };
        var installer = CreateInstaller(new ArtifactHandler(data), engine);
        var forged = artifact with
        {
            RuntimePack = metadata with { PackFingerprint = new string('d', 64) },
        };

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            installer.InstallAsync(engine, forged, consent, temporary.Path));
    }

    private static (EngineDescriptor Engine, EngineArtifact Artifact, ArtifactInstallConsent Consent) Fixture(
        byte[] data,
        string destination,
        string? etag = null,
        Uri? uri = null)
    {
        var artifact = new EngineArtifact
        {
            Name = "artifact.bin",
            DownloadUri = uri ?? new Uri("https://github.com/example/artifact.bin"),
            SizeBytes = data.Length,
            Sha256 = TestFixtures.Sha256(data),
            Platforms = [PlatformKind.Windows, PlatformKind.MacOS],
            Architectures = [CpuArchitectureKind.X64, CpuArchitectureKind.Arm64],
            Backends = [AccelerationBackend.Cpu],
            ETag = etag,
        };
        var engine = TestFixtures.Melo() with
        {
            ModelLicense = "MIT",
            Artifacts = [artifact],
        };
        var consent = new ArtifactInstallConsent(
            engine.Id,
            artifact.Name,
            artifact.SizeBytes,
            engine.ModelLicense,
            destination,
            true);
        return (engine, artifact, consent);
    }

    private static IReadOnlySet<string> AllowedOrigins() =>
        new HashSet<string>(["https://github.com"], StringComparer.OrdinalIgnoreCase);

    private static ArtifactInstaller CreateInstaller(
        INoRedirectArtifactTransport transport,
        params EngineDescriptor[] verifiedEngines) =>
        new(
            transport,
            new FixedSpaceProbe(10 * TestFixtures.GiB),
            AllowedOrigins(),
            verifiedEngines);

    private sealed class FixedSpaceProbe(ulong bytes) : IFileSpaceProbe
    {
        public ulong GetAvailableBytes(string path) => bytes;
    }

    private sealed class ArtifactHandler(
        byte[] data,
        string etag = "\"default\"",
        Uri? redirectUri = null) : INoRedirectArtifactTransport
    {
        public int RequestCount { get; private set; }
        public long? RequestedRangeStart { get; private set; }
        public string? IfRange { get; private set; }

        public Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken = default)
        {
            RequestCount++;
            var start = request.Headers.Range?.Ranges.Single().From;
            RequestedRangeStart = start;
            IfRange = request.Headers.IfRange?.EntityTag?.ToString();
            if (redirectUri is not null && request.RequestUri != redirectUri)
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.Redirect)
                {
                    Headers = { Location = redirectUri },
                    RequestMessage = request,
                });
            }
            var body = start is null ? data : data[(int)start.Value..];
            var response = new HttpResponseMessage(start is null ? HttpStatusCode.OK : HttpStatusCode.PartialContent)
            {
                Content = new ByteArrayContent(body),
                RequestMessage = request,
            };
            response.Headers.ETag = EntityTagHeaderValue.Parse(etag);
            if (start is not null)
            {
                response.Content.Headers.ContentRange = new ContentRangeHeaderValue(
                    start.Value,
                    data.LongLength - 1,
                    data.LongLength);
            }
            return Task.FromResult(response);
        }
    }
}
