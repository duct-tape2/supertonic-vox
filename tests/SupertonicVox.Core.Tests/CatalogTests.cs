using System.Text.Json;
using System.Security.Cryptography;
using System.Text.Json.Serialization;
using NSec.Cryptography;
using SupertonicVox.Core;

namespace SupertonicVox.Core.Tests;

public sealed class CatalogTests
{
    [Fact]
    public void TrustBootstrapPinsTheExactPublicKeyFingerprint()
    {
        var fixture = TestFixtures.SignedCatalog();
        var trust = TrustDocument(fixture.Trust);
        var bootstrap = BootstrapDocument(fixture.Trust);

        var verified = CatalogTrustBootstrapVerifier.Verify(trust, bootstrap);

        Assert.Equal(fixture.Trust.PublicKey, verified);
    }

    [Fact]
    public void TrustBootstrapRejectsKeyAndMetadataSubstitution()
    {
        var fixture = TestFixtures.SignedCatalog();
        var trust = TrustDocument(fixture.Trust);
        var bootstrap = BootstrapDocument(fixture.Trust);

        Assert.Throws<CatalogSecurityException>(() =>
            CatalogTrustBootstrapVerifier.Verify(
                trust,
                bootstrap with { PublicKeySha256 = new string('0', 64) }));
        Assert.Throws<CatalogSecurityException>(() =>
            CatalogTrustBootstrapVerifier.Verify(
                trust,
                bootstrap with { DevelopmentOnly = !bootstrap.DevelopmentOnly }));
    }

    [Fact]
    public void ProductionManifestSelectsAnActiveLeafKeyAndLoadsTheCatalog()
    {
        var fixture = ProductionTrustFixture();
        var verifier = new ProductionCatalogTrustVerifier(new Ed25519CatalogSignatureVerifier());

        var manifest = verifier.VerifyManifest(
            fixture.ManifestBytes,
            fixture.ManifestSignature,
            fixture.RootTrust,
            fixture.Bootstrap,
            persistedManifestSequence: 0,
            fixture.Now);
        var trust = verifier.ResolveCatalogTrust(
            manifest,
            fixture.CatalogSignature,
            bundledSequenceFloor: 5,
            new HashSet<string>(["supertonic-3"], StringComparer.Ordinal),
            new HashSet<string>(["https://huggingface.co"], StringComparer.Ordinal),
            new HashSet<string>(["MIT", "OpenRAIL-M"], StringComparer.Ordinal),
            fixture.Now);
        var catalog = new CatalogService(trust, new Ed25519CatalogSignatureVerifier())
            .LoadBundled(fixture.CatalogBytes, fixture.CatalogSignature);
        var state = ProductionCatalogTrustVerifier.CreateState(
            manifest,
            fixture.ManifestBytes,
            catalog,
            fixture.CatalogBytes);

        Assert.Equal(5, catalog.Sequence);
        Assert.Equal(1, state.TrustManifestSequence);
        Assert.Equal(fixture.Bootstrap.PublicKeySha256, state.RootPublicKeySha256);
    }

    [Fact]
    public void ProductionManifestRejectsTamperingRollbackAndRevokedLeafKeys()
    {
        var fixture = ProductionTrustFixture(revokeLeaf: true);
        var verifier = new ProductionCatalogTrustVerifier(new Ed25519CatalogSignatureVerifier());

        var tampered = fixture.ManifestBytes.ToArray();
        tampered[^2] ^= 1;
        Assert.Throws<CatalogSecurityException>(() => verifier.VerifyManifest(
            tampered,
            fixture.ManifestSignature,
            fixture.RootTrust,
            fixture.Bootstrap,
            persistedManifestSequence: 0,
            fixture.Now));
        Assert.Throws<CatalogSecurityException>(() => verifier.VerifyManifest(
            fixture.ManifestBytes,
            fixture.ManifestSignature,
            fixture.RootTrust,
            fixture.Bootstrap,
            persistedManifestSequence: 1,
            fixture.Now));

        var manifest = verifier.VerifyManifest(
            fixture.ManifestBytes,
            fixture.ManifestSignature,
            fixture.RootTrust,
            fixture.Bootstrap,
            persistedManifestSequence: 0,
            fixture.Now);
        Assert.Throws<CatalogSecurityException>(() => verifier.ResolveCatalogTrust(
            manifest,
            fixture.CatalogSignature,
            bundledSequenceFloor: 5,
            new HashSet<string>(["supertonic-3"], StringComparer.Ordinal),
            new HashSet<string>(["https://huggingface.co"], StringComparer.Ordinal),
            new HashSet<string>(["MIT", "OpenRAIL-M"], StringComparer.Ordinal),
            fixture.Now));
    }

    [Fact]
    public void ValidBundledCatalogLoads()
    {
        var fixture = TestFixtures.SignedCatalog();
        var service = new CatalogService(fixture.Trust, new Ed25519CatalogSignatureVerifier());
        var catalog = service.LoadBundled(fixture.CatalogBytes, fixture.SignatureDocument);
        Assert.Equal(3, catalog.Engines.Count);
    }

    [Fact]
    public void TamperedCatalogFailsClosed()
    {
        var fixture = TestFixtures.SignedCatalog();
        fixture.CatalogBytes[^2] ^= 1;
        var service = new CatalogService(fixture.Trust, new Ed25519CatalogSignatureVerifier());
        Assert.Throws<CatalogSecurityException>(() =>
            service.LoadBundled(fixture.CatalogBytes, fixture.SignatureDocument));
    }

    [Fact]
    public void WrongPublicKeyFailsClosed()
    {
        var fixture = TestFixtures.SignedCatalog();
        var other = TestFixtures.SignedCatalog();
        var trust = fixture.Trust with { PublicKey = other.Trust.PublicKey };
        var service = new CatalogService(trust, new Ed25519CatalogSignatureVerifier());
        Assert.Throws<CatalogSecurityException>(() =>
            service.LoadBundled(fixture.CatalogBytes, fixture.SignatureDocument));
    }

    [Fact]
    public void InterimTrustRootHardDisablesRemoteRefresh()
    {
        var fixture = TestFixtures.SignedCatalog(development: true, remoteEnabled: true);
        var service = new CatalogService(fixture.Trust, new Ed25519CatalogSignatureVerifier());
        Assert.Throws<CatalogSecurityException>(() =>
            service.AcceptRemote(fixture.CatalogBytes, fixture.SignatureDocument, 1));
    }

    [Fact]
    public void SignedCatalogRollbackIsRejected()
    {
        var fixture = TestFixtures.SignedCatalog(development: false, remoteEnabled: true);
        var service = new CatalogService(fixture.Trust, new Ed25519CatalogSignatureVerifier());
        Assert.Throws<CatalogSecurityException>(() =>
            service.AcceptRemote(fixture.CatalogBytes, fixture.SignatureDocument, 1));
    }

    [Fact]
    public void UnknownEngineIsRejectedEvenWhenSigned()
    {
        var catalog = new EngineCatalog
        {
            SchemaVersion = 1,
            Sequence = 1,
            CreatedUtc = DateTimeOffset.UtcNow,
            TrustRootVersion = "test-root-v1",
            DevelopmentOnly = true,
            Engines = [TestFixtures.Supertonic() with { Id = "arbitrary-github-code" }],
        };
        var fixture = TestFixtures.SignedCatalog(catalog);
        var service = new CatalogService(fixture.Trust, new Ed25519CatalogSignatureVerifier());
        Assert.Throws<CatalogSecurityException>(() =>
            service.LoadBundled(fixture.CatalogBytes, fixture.SignatureDocument));
    }

    [Fact]
    public void UnapprovedOriginIsRejected()
    {
        var artifact = new EngineArtifact
        {
            Name = "engine.zip",
            DownloadUri = new Uri("https://evil.example/engine.zip"),
            SizeBytes = 10,
            Sha256 = new string('a', 64),
            Platforms = [PlatformKind.Windows],
            Architectures = [CpuArchitectureKind.X64],
            Backends = [AccelerationBackend.Cpu],
        };
        var catalog = new EngineCatalog
        {
            SchemaVersion = 1,
            Sequence = 1,
            CreatedUtc = DateTimeOffset.UtcNow,
            TrustRootVersion = "test-root-v1",
            DevelopmentOnly = true,
            Engines = [TestFixtures.Melo() with { Artifacts = [artifact] }],
        };
        var fixture = TestFixtures.SignedCatalog(catalog);
        var service = new CatalogService(fixture.Trust, new Ed25519CatalogSignatureVerifier());
        Assert.Throws<CatalogSecurityException>(() =>
            service.LoadBundled(fixture.CatalogBytes, fixture.SignatureDocument));
    }

    [Fact]
    public async Task CorruptPersistedSequenceFailsClosed()
    {
        using var temporary = new TemporaryDirectory();
        var path = Path.Combine(temporary.Path, "catalog-sequence.txt");
        await File.WriteAllTextAsync(path, "not-a-sequence");

        await Assert.ThrowsAsync<CatalogSecurityException>(() =>
            new CatalogSequenceStore(path).ReadAsync());
    }

    [Fact]
    public void DuplicateArtifactNamesAreRejected()
    {
        var first = ValidArtifact("engine.bin", 10);
        var second = ValidArtifact("ENGINE.bin", 10) with
        {
            DownloadUri = new Uri("https://github.com/example/other.bin"),
        };
        var engine = TestFixtures.Melo() with
        {
            DownloadBytes = 20,
            Artifacts = [first, second],
        };
        var fixture = TestFixtures.SignedCatalog(Catalog(engine));

        Assert.Throws<CatalogSecurityException>(() =>
            new CatalogService(fixture.Trust, new Ed25519CatalogSignatureVerifier())
                .LoadBundled(fixture.CatalogBytes, fixture.SignatureDocument));
    }

    [Fact]
    public void ArtifactSizeSumAndSelectorsAreValidated()
    {
        var artifact = ValidArtifact("engine.bin", 10);
        var badSize = TestFixtures.Melo() with { DownloadBytes = 11, Artifacts = [artifact] };
        var sizeFixture = TestFixtures.SignedCatalog(Catalog(badSize));
        Assert.Throws<CatalogSecurityException>(() =>
            new CatalogService(sizeFixture.Trust, new Ed25519CatalogSignatureVerifier())
                .LoadBundled(sizeFixture.CatalogBytes, sizeFixture.SignatureDocument));

        var badSelector = artifact with { Platforms = [PlatformKind.Windows] };
        var macOnly = TestFixtures.Melo() with
        {
            DownloadBytes = 10,
            Platforms = [PlatformKind.MacOS],
            Artifacts = [badSelector],
        };
        var selectorFixture = TestFixtures.SignedCatalog(Catalog(macOnly));
        Assert.Throws<CatalogSecurityException>(() =>
            new CatalogService(selectorFixture.Trust, new Ed25519CatalogSignatureVerifier())
                .LoadBundled(selectorFixture.CatalogBytes, selectorFixture.SignatureDocument));
    }

    [Fact]
    public void RuntimePackArtifactBindsExtractedIdentityAndExactTarget()
    {
        var artifact = RuntimePackArtifact();
        var engine = TestFixtures.Vox() with
        {
            DownloadBytes = artifact.SizeBytes,
            Artifacts = [artifact],
        };
        var fixture = TestFixtures.SignedCatalog(Catalog(engine));

        var loaded = new CatalogService(fixture.Trust, new Ed25519CatalogSignatureVerifier())
            .LoadBundled(fixture.CatalogBytes, fixture.SignatureDocument);

        Assert.Equal(EngineArtifactKind.RuntimePackTar, loaded.Engines.Single().Artifacts.Single().Kind);
        Assert.Equal(RuntimePackArchiveProfile.UstarV1,
            loaded.Engines.Single().Artifacts.Single().RuntimePack!.ArchiveProfile);
    }

    [Fact]
    public void RuntimePackArtifactRejectsMissingOrMismatchedMetadata()
    {
        var artifact = RuntimePackArtifact();
        var missing = artifact with { RuntimePack = null };
        var wrongTarget = artifact with
        {
            RuntimePack = artifact.RuntimePack! with { Backend = AccelerationBackend.Cuda },
        };

        foreach (var invalid in new[] { missing, wrongTarget })
        {
            var engine = TestFixtures.Vox() with
            {
                DownloadBytes = invalid.SizeBytes,
                Artifacts = [invalid],
            };
            var fixture = TestFixtures.SignedCatalog(Catalog(engine));
            Assert.Throws<CatalogSecurityException>(() =>
                new CatalogService(fixture.Trust, new Ed25519CatalogSignatureVerifier())
                    .LoadBundled(fixture.CatalogBytes, fixture.SignatureDocument));
        }
    }

    [Fact]
    public void ProductionCatalogRejectsUnavailableVoxRuntime()
    {
        var catalog = new EngineCatalog
        {
            SchemaVersion = 1,
            Sequence = 1,
            CreatedUtc = DateTimeOffset.UtcNow,
            TrustRootVersion = "test-root-v1",
            DevelopmentOnly = false,
            Engines = [TestFixtures.Vox()],
        };
        var fixture = TestFixtures.SignedCatalog(catalog, development: false);

        Assert.Throws<CatalogSecurityException>(() =>
            new CatalogService(fixture.Trust, new Ed25519CatalogSignatureVerifier())
                .LoadBundled(fixture.CatalogBytes, fixture.SignatureDocument));
    }

    [Fact]
    public void VoxCatalogRejectsOpaqueArtifactSubstitution()
    {
        var opaque = ValidArtifact("voxcpm2.bin", 10) with
        {
            Platforms = [PlatformKind.MacOS],
            Architectures = [CpuArchitectureKind.Arm64],
            Backends = [AccelerationBackend.Cpu],
        };
        var engine = TestFixtures.Vox() with { DownloadBytes = 10, Artifacts = [opaque] };
        var fixture = TestFixtures.SignedCatalog(Catalog(engine));

        Assert.Throws<CatalogSecurityException>(() =>
            new CatalogService(fixture.Trust, new Ed25519CatalogSignatureVerifier())
                .LoadBundled(fixture.CatalogBytes, fixture.SignatureDocument));
    }

    [Fact]
    public async Task RemoteAcceptancePersistsSequenceBeforeReturning()
    {
        using var temporary = new TemporaryDirectory();
        var remoteCatalog = Catalog(TestFixtures.Supertonic()) with
        {
            Sequence = 2,
            DevelopmentOnly = false,
        };
        var fixture = TestFixtures.SignedCatalog(remoteCatalog, development: false, remoteEnabled: true);
        var store = new CatalogSequenceStore(Path.Combine(temporary.Path, "accepted-sequence.txt"));
        var acceptance = new RemoteCatalogAcceptanceService(
            new CatalogService(fixture.Trust, new Ed25519CatalogSignatureVerifier()),
            store);

        var accepted = await acceptance.AcceptAndPersistAsync(fixture.CatalogBytes, fixture.SignatureDocument);

        Assert.Equal(2, accepted.Sequence);
        Assert.Equal(2, await store.ReadAsync());
        await Assert.ThrowsAsync<CatalogSecurityException>(() =>
            acceptance.AcceptAndPersistAsync(fixture.CatalogBytes, fixture.SignatureDocument));
    }

    [Fact]
    public async Task SeparateStoresSerializeExclusiveSequenceActions()
    {
        using var temporary = new TemporaryDirectory();
        var path = Path.Combine(temporary.Path, "sequence.txt");
        var firstStore = new CatalogSequenceStore(path);
        var secondStore = new CatalogSequenceStore(path);
        var firstEntered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseFirst = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var secondEntered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        var first = firstStore.ExecuteExclusiveAsync(async cancellationToken =>
        {
            firstEntered.SetResult();
            await releaseFirst.Task.WaitAsync(cancellationToken);
            return 1;
        });
        await firstEntered.Task;
        var second = secondStore.ExecuteExclusiveAsync(_ =>
        {
            secondEntered.SetResult();
            return Task.FromResult(2);
        });

        await Task.Delay(100);
        Assert.False(secondEntered.Task.IsCompleted);
        releaseFirst.SetResult();
        var results = await Task.WhenAll(first, second);
        Assert.Equal([1, 2], results);
    }

    private static EngineCatalog Catalog(EngineDescriptor engine) => new()
    {
        SchemaVersion = 1,
        Sequence = 1,
        CreatedUtc = DateTimeOffset.UtcNow,
        TrustRootVersion = "test-root-v1",
        DevelopmentOnly = true,
        Engines = [engine],
    };

    private static EngineArtifact ValidArtifact(string name, long size) => new()
    {
        Name = name,
        DownloadUri = new Uri($"https://github.com/example/{name}"),
        SizeBytes = size,
        Sha256 = new string('a', 64),
        Platforms = [PlatformKind.Windows, PlatformKind.MacOS],
        Architectures = [CpuArchitectureKind.X64, CpuArchitectureKind.Arm64],
        Backends = [AccelerationBackend.Cpu, AccelerationBackend.Mps],
    };

    private static EngineArtifact RuntimePackArtifact() => new()
    {
        Name = "voxcpm2-macos-arm64-cpu.svxpack.tar",
        DownloadUri = new Uri("https://github.com/example/voxcpm2-macos-arm64-cpu.svxpack.tar"),
        SizeBytes = 1_048_576,
        Sha256 = new string('a', 64),
        Platforms = [PlatformKind.MacOS],
        Architectures = [CpuArchitectureKind.Arm64],
        Backends = [AccelerationBackend.Cpu],
        Kind = EngineArtifactKind.RuntimePackTar,
        RuntimePack = new RuntimePackArtifactMetadata
        {
            ArchiveProfile = RuntimePackArchiveProfile.UstarV1,
            ProtocolVersion = 2,
            EngineVersion = "2.0.3",
            ModelRevision = "vox-rev",
            Platform = PlatformKind.MacOS,
            Architecture = CpuArchitectureKind.Arm64,
            Backend = AccelerationBackend.Cpu,
            ManifestSha256 = new string('b', 64),
            PackFingerprint = new string('c', 64),
            ExtractedFileCount = 3,
            ExtractedBytes = 4096,
        },
    };

    private static CatalogTrustDocument TrustDocument(CatalogTrustOptions trust) => new()
    {
        KeyId = trust.KeyId,
        PublicKey = Convert.ToBase64String(trust.PublicKey),
        TrustRootVersion = trust.TrustRootVersion,
        BundledSequenceFloor = trust.BundledSequenceFloor,
        DevelopmentOnly = trust.DevelopmentTrustRoot,
    };

    private static CatalogTrustBootstrapDocument BootstrapDocument(CatalogTrustOptions trust) => new()
    {
        KeyId = trust.KeyId,
        PublicKeySha256 = Convert.ToHexStringLower(SHA256.HashData(trust.PublicKey)),
        TrustRootVersion = trust.TrustRootVersion,
        DevelopmentOnly = trust.DevelopmentTrustRoot,
    };

    private static ProductionFixture ProductionTrustFixture(bool revokeLeaf = false)
    {
        var now = DateTimeOffset.UtcNow;
        using var root = Key.Create(SignatureAlgorithm.Ed25519, new KeyCreationParameters
        {
            ExportPolicy = KeyExportPolicies.AllowPlaintextExport,
        });
        using var leaf = Key.Create(SignatureAlgorithm.Ed25519, new KeyCreationParameters
        {
            ExportPolicy = KeyExportPolicies.AllowPlaintextExport,
        });
        var rootPublicKey = root.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        var leafPublicKey = leaf.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        var rootFingerprint = Convert.ToHexStringLower(SHA256.HashData(rootPublicKey));
        var options = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            Converters = { new JsonStringEnumConverter() },
        };
        var manifest = new CatalogTrustManifestDocument
        {
            SchemaVersion = 1,
            Sequence = 1,
            CreatedUtc = now.AddMinutes(-1),
            ExpiresUtc = now.AddDays(30),
            TrustRootVersion = "production-test-root-v1",
            RootKeyId = "production-root-v1",
            RootPublicKeySha256 = rootFingerprint,
            ActiveCatalogKeys =
            [
                new CatalogSigningKeyDocument
                {
                    KeyId = "catalog-leaf-v1",
                    PublicKey = Convert.ToBase64String(leafPublicKey),
                    NotBeforeUtc = now.AddDays(-1),
                    NotAfterUtc = now.AddDays(7),
                },
            ],
            Revocations = revokeLeaf
                ?
                [
                    new CatalogKeyRevocationDocument
                    {
                        KeyId = "catalog-leaf-v1",
                        RevokedUtc = now.AddMinutes(-1),
                        Reason = "fixture revocation",
                    },
                ]
                : [],
        };
        var manifestBytes = JsonSerializer.SerializeToUtf8Bytes(manifest, options);
        var manifestSignature = JsonSerializer.SerializeToUtf8Bytes(new CatalogSignature
        {
            Algorithm = "Ed25519",
            KeyId = "production-root-v1",
            Signature = Convert.ToBase64String(SignatureAlgorithm.Ed25519.Sign(root, manifestBytes)),
        }, options);
        var catalog = new EngineCatalog
        {
            SchemaVersion = 1,
            Sequence = 5,
            CreatedUtc = now,
            TrustRootVersion = "production-test-root-v1",
            DevelopmentOnly = false,
            Engines = [TestFixtures.Supertonic()],
        };
        var catalogBytes = JsonSerializer.SerializeToUtf8Bytes(catalog, options);
        var catalogSignature = JsonSerializer.SerializeToUtf8Bytes(new CatalogSignature
        {
            Algorithm = "Ed25519",
            KeyId = "catalog-leaf-v1",
            Signature = Convert.ToBase64String(SignatureAlgorithm.Ed25519.Sign(leaf, catalogBytes)),
        }, options);
        return new ProductionFixture(
            now,
            new CatalogTrustDocument
            {
                KeyId = "production-root-v1",
                PublicKey = Convert.ToBase64String(rootPublicKey),
                TrustRootVersion = "production-test-root-v1",
                BundledSequenceFloor = 5,
                DevelopmentOnly = false,
            },
            new CatalogTrustBootstrapDocument
            {
                KeyId = "production-root-v1",
                PublicKeySha256 = rootFingerprint,
                TrustRootVersion = "production-test-root-v1",
                DevelopmentOnly = false,
            },
            manifestBytes,
            manifestSignature,
            catalogBytes,
            catalogSignature);
    }

    private sealed record ProductionFixture(
        DateTimeOffset Now,
        CatalogTrustDocument RootTrust,
        CatalogTrustBootstrapDocument Bootstrap,
        byte[] ManifestBytes,
        byte[] ManifestSignature,
        byte[] CatalogBytes,
        byte[] CatalogSignature);
}
