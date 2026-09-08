using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Windows.Input;
using SupertonicVox.Core;

namespace SupertonicVox.Desktop;

public sealed class MainWindowViewModel : ObservableObject, IAsyncDisposable
{
    private static readonly string AppVersion =
        Assembly.GetExecutingAssembly()
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
            .InformationalVersion.Split('+', 2)[0]
        ?? throw new InvalidOperationException("Application version metadata is unavailable.");
    private readonly EngineRecommendationService recommendationService = new();
    private readonly string dataDirectory = AppDataPaths.GetDataDirectory();
    private UserPreferenceStore? preferenceStore;
    private HardwareProfile? hardware;
    private EngineCatalog? catalog;
    private JsonBenchmarkCache? benchmarkCache;
    private RuntimePackManager? runtimePackManager;
    private NoRedirectHttpTransport? artifactTransport;
    private IReadOnlyDictionary<string, BenchmarkResult> benchmarks =
        new Dictionary<string, BenchmarkResult>(StringComparer.Ordinal);
    private readonly Dictionary<string, EngineInstallState> installStates =
        new(StringComparer.Ordinal);
    private bool initialized;
    private bool developmentTrustRoot = true;
    private string status = "하드웨어 분석 중…";
    private string hardwareSummary = "CPU, 메모리, GPU와 디스크를 로컬에서 확인하고 있습니다.";
    private string recommendationTitle = "분석 중";
    private string recommendationSummary = "추천 결과를 준비하고 있습니다.";
    private string securitySummary = "서명된 카탈로그를 확인하는 중입니다.";
    private string engineActionSummary = "선택한 엔진의 설치 상태를 확인하는 중입니다.";
    private string activeEngineSummary = "검증된 로컬 엔진을 준비하고 있습니다.";
    private EngineChoiceViewModel? selectedEngineChoice;
    private SupertonicEngineProvider? supertonicProvider;
    private VoxCpm2SidecarProvider? voxProvider;
    private IEngineProvider? activeProvider;
    private VerifiedRuntimePack? activeVoxPack;
    private InstalledRuntimePackRecord? invalidVoxRecord;
    private EngineRecommendation? currentRecommendation;
    private CancellationTokenSource? synthesisCancellation;
    private SynthesisResult? latestAudio;
    private bool synthesisReady;
    private bool isSynthesizing;
    private bool engineOperationRunning;
    private string synthesisText = "안녕하세요. 내 컴퓨터에서 안전하게 만드는 한국어 음성입니다.";
    private string synthesisStatus = "검증된 Supertonic 3 모델을 찾는 중입니다.";
    private string selectedVoiceId = "M1";

    public MainWindowViewModel()
    {
        ApplySelectionCommand = new AsyncRelayCommand(
            ApplySelectionAsync,
            () => initialized && SelectedEngineChoice is not null,
            HandleCommandError);
        AutoSelectCommand = new AsyncRelayCommand(AutoSelectAsync, () => initialized, HandleCommandError);
        InstallEngineCommand = new AsyncRelayCommand(
            InstallSelectedEngineAsync,
            CanInstallSelectedEngine,
            HandleCommandError);
        UninstallEngineCommand = new AsyncRelayCommand(
            UninstallSelectedEngineAsync,
            CanUninstallSelectedEngine,
            HandleCommandError);
        SynthesizeCommand = new AsyncRelayCommand(
            SynthesizeAsync,
            () => synthesisReady && !isSynthesizing,
            HandleCommandError);
        CancelSynthesisCommand = new AsyncRelayCommand(CancelSynthesisAsync, () => isSynthesizing, HandleCommandError);
        PlayCommand = new AsyncRelayCommand(
            PlayAsync,
            () => latestAudio is not null && !isSynthesizing,
            HandleCommandError);
        SaveCommand = new AsyncRelayCommand(
            SaveAsync,
            () => latestAudio is not null && !isSynthesizing,
            HandleCommandError);
    }

    public ObservableCollection<EngineChoiceViewModel> EngineChoices { get; } = [];
    public ObservableCollection<EngineCardViewModel> EngineCards { get; } = [];
    public ICommand ApplySelectionCommand { get; }
    public ICommand AutoSelectCommand { get; }
    public ICommand InstallEngineCommand { get; }
    public ICommand UninstallEngineCommand { get; }
    public ICommand SynthesizeCommand { get; }
    public ICommand CancelSynthesisCommand { get; }
    public ICommand PlayCommand { get; }
    public ICommand SaveCommand { get; }
    public ObservableCollection<string> VoiceIds { get; } = ["M1"];

    public string SynthesisText
    {
        get => synthesisText;
        set
        {
            if (SetField(ref synthesisText, value)) RaiseSynthesisCommandState();
        }
    }

    public string SynthesisStatus
    {
        get => synthesisStatus;
        private set => SetField(ref synthesisStatus, value);
    }

    public string SelectedVoiceId
    {
        get => selectedVoiceId;
        set => SetField(ref selectedVoiceId, value);
    }

    public string Status
    {
        get => status;
        private set => SetField(ref status, value);
    }

    public string HardwareSummary
    {
        get => hardwareSummary;
        private set => SetField(ref hardwareSummary, value);
    }

    public string RecommendationTitle
    {
        get => recommendationTitle;
        private set => SetField(ref recommendationTitle, value);
    }

    public string RecommendationSummary
    {
        get => recommendationSummary;
        private set => SetField(ref recommendationSummary, value);
    }

    public string SecuritySummary
    {
        get => securitySummary;
        private set => SetField(ref securitySummary, value);
    }

    public string EngineActionSummary
    {
        get => engineActionSummary;
        private set => SetField(ref engineActionSummary, value);
    }

    public string ActiveEngineSummary
    {
        get => activeEngineSummary;
        private set => SetField(ref activeEngineSummary, value);
    }

    public EngineChoiceViewModel? SelectedEngineChoice
    {
        get => selectedEngineChoice;
        set
        {
            if (SetField(ref selectedEngineChoice, value))
            {
                UpdateEngineActionSummary();
                RaiseCommandState();
            }
        }
    }

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            Directory.CreateDirectory(dataDirectory);
            catalog = LoadVerifiedBundledCatalog();
            var profiler = new HardwareProfiler(new SystemProcessRunner());
            hardware = await profiler.ProfileAsync(dataDirectory, cancellationToken);
            HardwareSummary = FormatHardware(hardware);

            benchmarkCache = new JsonBenchmarkCache(Path.Combine(dataDirectory, "benchmarks.json"));
            benchmarks = await LoadBenchmarksAsync(catalog, hardware, benchmarkCache, cancellationToken);
            preferenceStore = new UserPreferenceStore(Path.Combine(dataDirectory, "preferences.json"));
            var preferences = await preferenceStore.LoadAsync(cancellationToken);
            await InitializeSupertonicAsync(benchmarkCache, cancellationToken);
            await InitializeRuntimePacksAsync(cancellationToken);

            EngineRecommendation recommendation;
            try
            {
                recommendation = Recommend(preferences.ManualEngineId);
            }
            catch (InvalidOperationException) when (!string.IsNullOrWhiteSpace(preferences.ManualEngineId))
            {
                await preferenceStore.SaveAsync(new UserPreferences(null), cancellationToken);
                recommendation = Recommend(null);
            }

            await PresentAsync(recommendation, cancellationToken);
            initialized = true;
            Status = "오프라인 분석 완료";
            SecuritySummary = developmentTrustRoot
                ? "✓ Ed25519 내장 카탈로그 검증 완료 · 시작 네트워크 0건 · 개발 신뢰키에서는 원격 갱신 차단"
                : "✓ 운영 bootstrap fingerprint와 Ed25519 카탈로그 검증 완료 · 시작 네트워크 0건";
            RaiseCommandState();
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            Status = "안전 정지";
            RecommendationTitle = "카탈로그 또는 하드웨어 분석 실패";
            RecommendationSummary = exception.Message;
            SecuritySummary = "합성과 다운로드를 활성화하지 않았습니다.";
        }
    }

    private EngineCatalog LoadVerifiedBundledCatalog()
    {
        var trustJsonOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            PropertyNameCaseInsensitive = false,
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        };
        var trustDocument = JsonSerializer.Deserialize<CatalogTrustDocument>(
                                EmbeddedAssets.Read("engine-catalog.trust.json"),
                                trustJsonOptions)
                            ?? throw new InvalidDataException("Catalog trust document is empty.");
        var bootstrapDocument = JsonSerializer.Deserialize<CatalogTrustBootstrapDocument>(
                                    EmbeddedAssets.Read("engine-catalog.bootstrap.json"),
                                    trustJsonOptions)
                                ?? throw new InvalidDataException("Catalog trust bootstrap is empty.");
#if SVX_PRODUCTION_CATALOG_ASSETS
        if (trustDocument.DevelopmentOnly || bootstrapDocument.DevelopmentOnly)
            throw new CatalogSecurityException(
                "A production catalog build cannot use development trust material.");
#endif
        var publicKey = CatalogTrustBootstrapVerifier.Verify(trustDocument, bootstrapDocument);
        developmentTrustRoot = trustDocument.DevelopmentOnly;
        var allowedEngineIds = new HashSet<string>(
            ["supertonic-3", "voxcpm2", "melotts-ko"],
            StringComparer.Ordinal);
        var allowedOrigins = new HashSet<string>(
            ["https://github.com", "https://huggingface.co"],
            StringComparer.Ordinal);
        var allowedLicenses = trustDocument.DevelopmentOnly
            ? new HashSet<string>(["MIT", "OpenRAIL-M", "REVIEW-PENDING"], StringComparer.Ordinal)
            : new HashSet<string>(["MIT", "OpenRAIL-M", "Apache-2.0"], StringComparer.Ordinal);
        var signatureBytes = EmbeddedAssets.Read("engine-catalog.signature.json");
        CatalogTrustOptions trust;
        if (trustDocument.DevelopmentOnly)
        {
            trust = new CatalogTrustOptions
            {
                KeyId = trustDocument.KeyId,
                PublicKey = publicKey,
                TrustRootVersion = trustDocument.TrustRootVersion,
                BundledSequenceFloor = trustDocument.BundledSequenceFloor,
                DevelopmentTrustRoot = true,
                RemoteRefreshEnabled = false,
                AllowedEngineIds = allowedEngineIds,
                AllowedOrigins = allowedOrigins,
                AllowedLicenses = allowedLicenses,
            };
        }
        else
        {
            var verifier = new ProductionCatalogTrustVerifier(new Ed25519CatalogSignatureVerifier());
            var manifest = verifier.VerifyManifest(
                EmbeddedAssets.Read("engine-catalog.trust-manifest.json"),
                EmbeddedAssets.Read("engine-catalog.trust-manifest.signature.json"),
                trustDocument,
                bootstrapDocument,
                persistedManifestSequence: 0,
                DateTimeOffset.UtcNow);
            trust = verifier.ResolveCatalogTrust(
                manifest,
                signatureBytes,
                trustDocument.BundledSequenceFloor,
                allowedEngineIds,
                allowedOrigins,
                allowedLicenses,
                DateTimeOffset.UtcNow);
        }
        var catalogBytes = EmbeddedAssets.Read("engine-catalog.json");
        var catalog = new CatalogService(trust, new Ed25519CatalogSignatureVerifier())
            .LoadBundled(catalogBytes, signatureBytes);
        if (!trustDocument.DevelopmentOnly && catalog.Engines.Any(engine =>
                !engine.IsBundled && engine.Artifacts.Count == 0))
            throw new CatalogSecurityException(
                "Production catalog contains an optional engine without installable artifacts.");
        return catalog;
    }

    private async Task<IReadOnlyDictionary<string, BenchmarkResult>> LoadBenchmarksAsync(
        EngineCatalog engineCatalog,
        HardwareProfile profile,
        IBenchmarkCache cache,
        CancellationToken cancellationToken)
    {
        var results = new Dictionary<string, BenchmarkResult>(StringComparer.Ordinal);
        foreach (var engine in engineCatalog.Engines)
        {
            var result = await cache.GetAsync(
                AppVersion,
                engine.Id,
                engine.ModelRevision,
                profile.Fingerprint,
                cancellationToken);
            if (result is not null) results[engine.Id] = result;
        }
        return results;
    }

    private EngineRecommendation Recommend(string? manualEngineId)
    {
        if (catalog is null || hardware is null) throw new InvalidOperationException("Initialization is incomplete.");
        return recommendationService.Recommend(new RecommendationRequest
        {
            Hardware = hardware,
            Engines = catalog.Engines,
            Benchmarks = benchmarks,
            AppVersion = AppVersion,
            InstallStates = installStates,
            ExecutionFingerprints = activeVoxPack is null
                ? new Dictionary<string, string>(StringComparer.Ordinal)
                : new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["voxcpm2"] = activeVoxPack.PackFingerprint,
                },
            RequiredFeatures = EngineFeatures.GeneralTts,
            ManualEngineId = manualEngineId,
        });
    }

    private async Task ApplySelectionAsync()
    {
        if (SelectedEngineChoice is null || preferenceStore is null) return;
        try
        {
            var recommendation = Recommend(SelectedEngineChoice.Id);
            await preferenceStore.SaveAsync(new UserPreferences(SelectedEngineChoice.Id));
            await PresentAsync(recommendation);
            Status = "사용자 선택 적용됨";
        }
        catch (InvalidOperationException exception)
        {
            Status = "선택 불가";
            RecommendationSummary = exception.Message;
        }
    }

    private async Task AutoSelectAsync()
    {
        if (preferenceStore is null) return;
        await preferenceStore.SaveAsync(new UserPreferences(null));
        await PresentAsync(Recommend(null));
        Status = "자동 추천 적용됨";
    }

    private async Task InitializeSupertonicAsync(
        IBenchmarkCache benchmarkCache,
        CancellationToken cancellationToken)
    {
        if (!SupertonicModelLocator.TryResolve(
                AppContext.BaseDirectory,
                Environment.GetEnvironmentVariable(SupertonicModelLocator.EnvironmentVariable),
                out var root))
        {
            SynthesisStatus = "모델 경로는 절대 경로여야 합니다. 합성은 비활성화했습니다.";
            return;
        }

        var provider = new SupertonicEngineProvider(new SupertonicProviderOptions
        {
            OnnxDirectory = Path.Combine(root, "onnx"),
            VoiceStyleDirectory = Path.Combine(root, "voice_styles"),
        });
        if (!await provider.IsReadyAsync(cancellationToken))
        {
            await provider.DisposeAsync();
            installStates[SupertonicModelManifest.EngineId] = EngineInstallState.Invalid;
            SynthesisStatus = "검증된 Supertonic 3 모델이 없습니다. 패키지 모델 설치가 필요합니다.";
            return;
        }

        supertonicProvider = provider;
        installStates[provider.EngineId] = EngineInstallState.Bundled;
        synthesisReady = true;
        if (hardware is not null)
        {
            var benchmark = await benchmarkCache.GetAsync(
                AppVersion,
                provider.EngineId,
                provider.ModelRevision,
                hardware.Fingerprint,
                cancellationToken);
            if (benchmark is null)
            {
                SynthesisStatus = "공식 모델 검증 완료 · 첫 로컬 성능 측정 중…";
                benchmark = await new EngineBenchmarkService().RunAsync(
                    provider,
                    hardware,
                    AppVersion,
                    benchmarkCache,
                    cancellationToken);
            }
            benchmarks = new Dictionary<string, BenchmarkResult>(benchmarks, StringComparer.Ordinal)
            {
                [provider.EngineId] = benchmark,
            };
            if (benchmark.Success)
            {
                SynthesisStatus = $"✓ 공식 SHA-256 검증 · 실측 RTF {benchmark.RealTimeFactor:0.00} · 한국어 합성 준비됨";
            }
            else
            {
                synthesisReady = false;
                SynthesisStatus = "모델은 검증됐지만 로컬 성능 측정에 실패해 합성을 비활성화했습니다.";
            }
        }
        RaiseSynthesisCommandState();
    }

    private async Task InitializeRuntimePacksAsync(CancellationToken cancellationToken)
    {
        if (catalog is null) throw new InvalidOperationException("Catalog initialization is incomplete.");
        artifactTransport = new NoRedirectHttpTransport(TimeSpan.FromHours(6));
        var allowedOrigins = new HashSet<string>(
            ["https://github.com", "https://huggingface.co"],
            StringComparer.OrdinalIgnoreCase);
        var artifactInstaller = new ArtifactInstaller(
            artifactTransport,
            new DriveFileSpaceProbe(),
            allowedOrigins,
            catalog.Engines);
        runtimePackManager = new RuntimePackManager(
            Path.Combine(dataDirectory, "runtime-packs"),
            artifactInstaller);
        var inventory = await runtimePackManager.GetInventoryAsync(cancellationToken);
        invalidVoxRecord = inventory.Invalid.FirstOrDefault(value =>
            string.Equals(value.EngineId, "voxcpm2", StringComparison.Ordinal));
        activeVoxPack = await runtimePackManager.GetActiveAsync("voxcpm2", cancellationToken);
        if (activeVoxPack is null)
        {
            installStates["voxcpm2"] = invalidVoxRecord is not null
                ? EngineInstallState.Invalid
                : EngineInstallState.NotInstalled;
            return;
        }
        var voxEngine = catalog.Engines.Single(value => value.Id == "voxcpm2");
        if (!voxEngine.Artifacts.Any(artifact => MatchesCatalogPack(artifact, activeVoxPack)))
        {
            installStates["voxcpm2"] = EngineInstallState.Invalid;
            EngineActionSummary =
                "설치된 VoxCPM2 팩은 현재 서명 카탈로그에 없으므로 실행하지 않습니다. 삭제 후 승인된 팩을 설치해야 합니다.";
            return;
        }
        installStates["voxcpm2"] = EngineInstallState.Installed;
        voxProvider = CreateVoxProvider(activeVoxPack);
        if (!benchmarks.TryGetValue("voxcpm2", out var benchmark) ||
            !benchmark.Success || !benchmark.WavValid ||
            !string.Equals(
                benchmark.ExecutionFingerprint,
                activeVoxPack.PackFingerprint,
                StringComparison.Ordinal))
            installStates["voxcpm2"] = EngineInstallState.Invalid;
    }

    private VoxCpm2SidecarProvider CreateVoxProvider(VerifiedRuntimePack pack) => new(
        pack,
        Path.Combine(dataDirectory, "voxcpm2"),
        new OwnedSidecarProcessHost(new RuntimePackVerifier()));

    private static bool MatchesCatalogPack(EngineArtifact artifact, VerifiedRuntimePack pack)
    {
        var metadata = artifact.RuntimePack;
        return artifact.Kind == EngineArtifactKind.RuntimePackTar && metadata is not null &&
               metadata.ProtocolVersion == pack.Manifest.ProtocolVersion &&
               string.Equals(metadata.EngineVersion, pack.Manifest.EngineVersion, StringComparison.Ordinal) &&
               string.Equals(metadata.ModelRevision, pack.Manifest.ModelRevision, StringComparison.Ordinal) &&
               metadata.Platform == pack.Manifest.Platform &&
               metadata.Architecture == pack.Manifest.Architecture &&
               metadata.Backend == pack.Manifest.Backend &&
               string.Equals(metadata.ManifestSha256, pack.ManifestSha256, StringComparison.Ordinal) &&
               string.Equals(metadata.PackFingerprint, pack.PackFingerprint, StringComparison.Ordinal);
    }

    private bool CanInstallSelectedEngine()
    {
        if (!initialized || engineOperationRunning || SelectedEngineChoice is null || catalog is null) return false;
        var engine = catalog.Engines.FirstOrDefault(value => value.Id == SelectedEngineChoice.Id);
        if (engine is null || engine.IsBundled) return false;
        var artifact = SelectCompatibleRuntimeArtifact(engine);
        if (artifact is null) return false;
        return installStates.GetValueOrDefault(engine.Id) != EngineInstallState.Installed ||
               !string.Equals(
                   activeVoxPack?.PackFingerprint,
                   artifact.RuntimePack?.PackFingerprint,
                   StringComparison.Ordinal);
    }

    private bool CanUninstallSelectedEngine() =>
        initialized && !engineOperationRunning && SelectedEngineChoice?.Id == "voxcpm2" &&
        (activeVoxPack is not null || invalidVoxRecord is not null) && runtimePackManager is not null;

    private async Task InstallSelectedEngineAsync()
    {
        if (SelectedEngineChoice is null || catalog is null || runtimePackManager is null ||
            benchmarkCache is null || hardware is null)
            return;
        var engine = catalog.Engines.Single(value => value.Id == SelectedEngineChoice.Id);
        var artifact = SelectCompatibleRuntimeArtifact(engine)
                       ?? throw new InvalidOperationException(
                           "이 컴퓨터용으로 서명된 런타임팩이 카탈로그에 없습니다.");
        engineOperationRunning = true;
        installStates[engine.Id] = EngineInstallState.Installing;
        Status = "VoxCPM2 설치 중";
        EngineActionSummary =
            $"{FormatBytes(artifact.SizeBytes)} 다운로드 후 {FormatBytes(artifact.RuntimePack!.ExtractedBytes)}를 로컬에 검증·설치합니다.";
        RaiseCommandState();
        try
        {
            var consent = new ArtifactInstallConsent(
                engine.Id,
                artifact.Name,
                artifact.SizeBytes,
                engine.ModelLicense,
                runtimePackManager.DownloadDirectory,
                true);
            var installed = await runtimePackManager.InstallAsync(
                engine,
                artifact,
                consent,
                stopExistingProvider: StopAndDisposeVoxProviderAsync);
            if (voxProvider is not null)
            {
                await voxProvider.StopAsync();
                await voxProvider.DisposeAsync();
            }
            activeVoxPack = installed.Pack;
            invalidVoxRecord = null;
            voxProvider = CreateVoxProvider(installed.Pack);
            SynthesisStatus = "VoxCPM2 런타임 검증 완료 · 한국어 실측 벤치마크 중…";
            var benchmark = await new EngineBenchmarkService().RunAsync(
                voxProvider,
                hardware,
                AppVersion,
                benchmarkCache,
                voiceId: "vox_news_f",
                executionFingerprint: installed.Pack.PackFingerprint);
            benchmarks = new Dictionary<string, BenchmarkResult>(benchmarks, StringComparer.Ordinal)
            {
                [engine.Id] = benchmark,
            };
            if (!benchmark.Success || !benchmark.WavValid)
            {
                installStates[engine.Id] = EngineInstallState.Invalid;
                await preferenceStore!.SaveAsync(new UserPreferences(null));
                await PresentAsync(Recommend(null));
                Status = "VoxCPM2 벤치마크 실패 · Supertonic 3 유지";
                EngineActionSummary = "팩 무결성은 통과했지만 실제 합성이 실패했습니다. 설치/업데이트를 눌러 다시 검증할 수 있습니다.";
                return;
            }

            installStates[engine.Id] = EngineInstallState.Installed;
            await preferenceStore!.SaveAsync(new UserPreferences(engine.Id));
            await PresentAsync(Recommend(engine.Id));
            Status = installed.ReusedExistingPack ? "VoxCPM2 재검증 완료" : "VoxCPM2 설치 완료";
        }
        finally
        {
            engineOperationRunning = false;
            UpdateEngineActionSummary();
            RaiseCommandState();
        }
    }

    private async Task UninstallSelectedEngineAsync()
    {
        if (runtimePackManager is null) return;
        var fingerprint = activeVoxPack?.PackFingerprint ?? invalidVoxRecord?.PackFingerprint;
        if (fingerprint is null) return;
        engineOperationRunning = true;
        RaiseCommandState();
        try
        {
            await runtimePackManager.UninstallAsync(
                "voxcpm2",
                fingerprint,
                async cancellationToken =>
                {
                    synthesisCancellation?.Cancel();
                    if (voxProvider is not null)
                    {
                        await voxProvider.StopAsync(cancellationToken);
                        await voxProvider.DisposeAsync();
                        if (ReferenceEquals(activeProvider, voxProvider)) activeProvider = null;
                        voxProvider = null;
                    }
                });
            activeVoxPack = await runtimePackManager.GetActiveAsync("voxcpm2");
            invalidVoxRecord = null;
            if (activeVoxPack is null)
            {
                installStates["voxcpm2"] = EngineInstallState.NotInstalled;
            }
            else
            {
                voxProvider = CreateVoxProvider(activeVoxPack);
                installStates["voxcpm2"] = EngineInstallState.Installed;
            }
            await preferenceStore!.SaveAsync(new UserPreferences(null));
            await PresentAsync(Recommend(null));
            Status = "VoxCPM2 제거 완료";
        }
        finally
        {
            engineOperationRunning = false;
            UpdateEngineActionSummary();
            RaiseCommandState();
        }
    }

    private EngineArtifact? SelectCompatibleRuntimeArtifact(EngineDescriptor engine)
    {
        if (hardware is null) return null;
        var selectedBackend = currentRecommendation?.Candidates
            .FirstOrDefault(value => value.Engine.Id == engine.Id)?.SelectedBackend;
        var candidates = engine.Artifacts.Where(artifact =>
                artifact.Kind == EngineArtifactKind.RuntimePackTar && artifact.RuntimePack is not null &&
                artifact.RuntimePack.Platform == hardware.Platform &&
                artifact.RuntimePack.Architecture == hardware.Architecture)
            .ToArray();
        return candidates.FirstOrDefault(value => value.RuntimePack!.Backend == selectedBackend) ??
               candidates.FirstOrDefault();
    }

    private async Task StopAndDisposeVoxProviderAsync(CancellationToken cancellationToken)
    {
        synthesisCancellation?.Cancel();
        if (voxProvider is null) return;
        await voxProvider.StopAsync(cancellationToken);
        await voxProvider.DisposeAsync();
        if (ReferenceEquals(activeProvider, voxProvider)) activeProvider = null;
        voxProvider = null;
    }

    private async Task SynthesizeAsync()
    {
        if (activeProvider is null) return;
        isSynthesizing = true;
        latestAudio = null;
        synthesisCancellation?.Dispose();
        synthesisCancellation = new CancellationTokenSource();
        SynthesisStatus = $"{activeProvider.EngineId}로 로컬 음성을 만드는 중…";
        RaiseSynthesisCommandState();
        var started = DateTimeOffset.UtcNow;
        try
        {
            latestAudio = await activeProvider.SynthesizeAsync(new SynthesisRequest
            {
                Text = SynthesisText,
                Language = "ko",
                VoiceId = SelectedVoiceId,
                Speed = 1.05f,
                QualitySteps = 8,
            }, synthesisCancellation.Token);
            var elapsed = DateTimeOffset.UtcNow - started;
            SynthesisStatus =
                $"✓ {latestAudio.Duration.TotalSeconds:0.00}초 음성 생성 완료 · 처리 {elapsed.TotalSeconds:0.00}초 · 외부 전송 0건";
        }
        catch (OperationCanceledException)
        {
            SynthesisStatus = "합성을 취소했습니다.";
        }
        catch (Exception exception)
        {
            SynthesisStatus = $"안전 정지: {exception.Message}";
        }
        finally
        {
            synthesisCancellation?.Dispose();
            synthesisCancellation = null;
            isSynthesizing = false;
            RaiseSynthesisCommandState();
        }
    }

    private async Task CancelSynthesisAsync()
    {
        if (activeProvider is null) return;
        SynthesisStatus = "합성 취소 중…";
        synthesisCancellation?.Cancel();
        await activeProvider.StopAsync();
    }

    private async Task PlayAsync()
    {
        if (latestAudio is null) return;
        var previewDirectory = Path.Combine(dataDirectory, "preview");
        var previewPath = Path.Combine(previewDirectory, "latest.wav");
        await WriteAtomicallyAsync(previewPath, latestAudio.WavBytes);
        var runner = new SystemProcessRunner();
        ProcessResult result;
        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            result = await runner.RunAsync("/usr/bin/afplay", [previewPath], TimeSpan.FromMinutes(3));
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            const string command = "$p=New-Object System.Media.SoundPlayer $args[0];$p.PlaySync()";
            result = await runner.RunAsync(
                "powershell.exe",
                ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command, previewPath],
                TimeSpan.FromMinutes(3));
        }
        else
        {
            throw new PlatformNotSupportedException("Audio playback is supported on Windows and macOS.");
        }
        SynthesisStatus = result.Success ? "재생 완료" : "재생기에 오류가 발생했습니다.";
    }

    private async Task SaveAsync()
    {
        if (latestAudio is null) return;
        var documents = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        if (string.IsNullOrWhiteSpace(documents)) documents = dataDirectory;
        var directory = Path.Combine(documents, "SupertonicVox");
        var safeEngine = latestAudio.EngineId.All(character => char.IsAsciiLetterOrDigit(character) || character == '-')
            ? latestAudio.EngineId
            : "local-tts";
        var path = Path.Combine(directory, $"{safeEngine}-{DateTime.Now:yyyyMMdd-HHmmss}.wav");
        await WriteAtomicallyAsync(path, latestAudio.WavBytes);
        SynthesisStatus = $"저장 완료: {path}";
    }

    private static async Task WriteAtomicallyAsync(string path, byte[] bytes)
    {
        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath)
                        ?? throw new InvalidOperationException("저장 폴더를 확인할 수 없습니다.");
        Directory.CreateDirectory(directory);
        var temporary = Path.Combine(directory, $".{Path.GetFileName(fullPath)}.{Guid.NewGuid():N}.tmp");
        try
        {
            await File.WriteAllBytesAsync(temporary, bytes);
            File.Move(temporary, fullPath, true);
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }

    private async Task PresentAsync(
        EngineRecommendation recommendation,
        CancellationToken cancellationToken = default)
    {
        currentRecommendation = recommendation;
        RecommendationTitle = recommendation.SelectedEngine.DisplayName;
        var mode = recommendation.IsManualOverride ? "사용자 고정" : "자동 추천";
        var speed = recommendation.LatencyPending ? "속도 벤치마크 대기" : "실측 속도 반영";
        RecommendationSummary =
            $"{mode} · {recommendation.SelectedBackend} · 점수 {recommendation.Score:0.0} · {speed}. " +
            string.Join(" ", recommendation.Reasons.Take(2));

        EngineChoices.Clear();
        EngineCards.Clear();
        foreach (var candidate in recommendation.Candidates)
        {
            var choice = new EngineChoiceViewModel(candidate.Engine.Id, candidate.Engine.DisplayName);
            EngineChoices.Add(choice);
            if (candidate.Engine.Id == recommendation.SelectedEngine.Id) SelectedEngineChoice = choice;
            var state = installStates.GetValueOrDefault(
                candidate.Engine.Id,
                candidate.Engine.IsBundled ? EngineInstallState.Bundled : EngineInstallState.NotInstalled);
            EngineCards.Add(EngineCardViewModel.From(candidate, state));
        }
        await SelectActiveProviderAsync(recommendation.SelectedEngine.Id, cancellationToken);
        UpdateEngineActionSummary();
    }

    private async Task SelectActiveProviderAsync(string engineId, CancellationToken cancellationToken)
    {
        IEngineProvider? next = engineId switch
        {
            "supertonic-3" => supertonicProvider,
            "voxcpm2" => voxProvider,
            _ => null,
        };
        if (next is null)
            throw new InvalidOperationException("선택한 엔진은 검증된 실행기를 준비하지 못했습니다.");
        if (activeProvider is not null && !ReferenceEquals(activeProvider, next))
            await activeProvider.StopAsync(cancellationToken);
        activeProvider = next;
        VoiceIds.Clear();
        if (engineId == "voxcpm2")
        {
            foreach (var voice in new[] { "vox_news_f", "vox_calm_f", "vox_emotive_f", "vox_trust_m" })
                VoiceIds.Add(voice);
            SelectedVoiceId = "vox_news_f";
            ActiveEngineSummary =
                "VoxCPM2는 서명된 런타임팩을 매 실행 전 재검증하며 합성 중 네트워크를 차단합니다.";
        }
        else
        {
            VoiceIds.Add("M1");
            SelectedVoiceId = "M1";
            ActiveEngineSummary =
                "Supertonic 3 모델은 시작 전에 SHA-256을 검증하며 합성 중 네트워크를 사용하지 않습니다.";
        }
        synthesisReady = true;
        latestAudio = null;
        RaiseSynthesisCommandState();
    }

    private void UpdateEngineActionSummary()
    {
        if (SelectedEngineChoice is null || catalog is null)
        {
            EngineActionSummary = "엔진을 선택하면 설치·라이선스·용량 정보를 표시합니다.";
            return;
        }
        var engine = catalog.Engines.FirstOrDefault(value => value.Id == SelectedEngineChoice.Id);
        if (engine is null) return;
        if (engine.IsBundled)
        {
            EngineActionSummary = "기본 탑재 엔진 · 추가 다운로드 없음 · 모델 SHA-256 검증";
            return;
        }
        var artifact = SelectCompatibleRuntimeArtifact(engine);
        if (artifact is null)
        {
            EngineActionSummary =
                $"현재 {hardware?.Platform} {hardware?.Architecture}용 검수·서명된 팩이 아직 없습니다. 임의 GitHub 코드는 실행하지 않습니다.";
            return;
        }
        var state = installStates.GetValueOrDefault(engine.Id, EngineInstallState.NotInstalled);
        EngineActionSummary = state switch
        {
            EngineInstallState.Installing => "검증된 팩을 다운로드·설치하는 중입니다.",
            EngineInstallState.Installed =>
                $"설치됨 · {artifact.RuntimePack!.Backend} · 모델 {engine.ModelLicense} · 삭제 시 원고·생성 WAV는 유지됩니다.",
            EngineInstallState.Invalid =>
                $"재검증 필요 · {FormatBytes(artifact.SizeBytes)} · 모델 {engine.ModelLicense} · 설치/업데이트로 다시 시험합니다.",
            _ =>
                $"설치 버튼이 명시적 동의입니다 · 다운로드 {FormatBytes(artifact.SizeBytes)} · 설치 후 {FormatBytes(artifact.RuntimePack!.ExtractedBytes)} · 모델 {engine.ModelLicense}",
        };
    }

    private void RaiseCommandState()
    {
        (ApplySelectionCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
        (AutoSelectCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
        (InstallEngineCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
        (UninstallEngineCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
    }

    private void RaiseSynthesisCommandState()
    {
        (SynthesizeCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
        (CancelSynthesisCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
        (PlayCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
        (SaveCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
    }

    private void HandleCommandError(Exception exception)
    {
        Status = "작업 오류";
        SynthesisStatus = $"안전 정지: {exception.Message}";
        RaiseSynthesisCommandState();
    }

    public async ValueTask DisposeAsync()
    {
        synthesisCancellation?.Cancel();
        synthesisCancellation?.Dispose();
        synthesisCancellation = null;
        if (voxProvider is not null)
        {
            await voxProvider.DisposeAsync();
            voxProvider = null;
        }
        if (supertonicProvider is not null)
        {
            await supertonicProvider.DisposeAsync();
            supertonicProvider = null;
        }
        artifactTransport?.Dispose();
        artifactTransport = null;
        activeProvider = null;
    }

    private static string FormatHardware(HardwareProfile profile)
    {
        var memory = FormatBytes(profile.TotalMemoryBytes);
        var disk = FormatBytes(profile.FreeDiskBytes);
        var gpu = profile.Gpus.Count == 0
            ? "GPU 정보 없음"
            : string.Join(", ", profile.Gpus.Select(device => $"{device.Name} ({device.Backend})"));
        return $"{profile.Platform} {profile.Architecture} · {profile.CpuName} · {profile.LogicalCoreCount} logical cores · RAM {memory} · 여유 디스크 {disk} · {gpu}";
    }

    private static string FormatBytes(ulong bytes) => FormatBytes(checked((long)Math.Min(bytes, long.MaxValue)));

    internal static string FormatBytes(long bytes)
    {
        if (bytes <= 0) return "내장 또는 미확정";
        var gib = bytes / 1024d / 1024d / 1024d;
        return gib >= 1 ? $"{gib:0.0} GiB" : $"{bytes / 1024d / 1024d:0} MiB";
    }
}

public sealed record EngineChoiceViewModel(string Id, string DisplayName);

public sealed record EngineCardViewModel(
    string Name,
    string Availability,
    string Quality,
    string Speed,
    string Size,
    string Features)
{
    public static EngineCardViewModel From(
        EngineCandidateScore candidate,
        EngineInstallState installState)
    {
        var engine = candidate.Engine;
        var availability = installState switch
        {
            EngineInstallState.Bundled => "기본 탑재 · 검증됨",
            EngineInstallState.Installed => $"설치됨 · {candidate.SelectedBackend}",
            EngineInstallState.Installing => "설치 중",
            EngineInstallState.Invalid => "재검증 필요",
            _ when candidate.SelectedBackend is not null => $"설치 가능성 · {candidate.SelectedBackend}",
            _ => "현재 사양에서 제외",
        };
        var speed = candidate.LatencyPending ? "속도: 첫 벤치마크 대기" : "속도: 로컬 실측 반영";
        var cloning = engine.Features.HasFlag(EngineFeatures.VoiceCloning) ? "복제 지원" : "일반 TTS";
        return new EngineCardViewModel(
            engine.DisplayName,
            availability,
            $"한국어 품질: {engine.KoreanQualityScore:0}/100",
            speed,
            $"추가 용량: {MainWindowViewModel.FormatBytes(engine.DownloadBytes)}",
            cloning);
    }
}

public abstract class ObservableObject : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    protected bool SetField<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return false;
        field = value;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        return true;
    }
}

internal sealed class AsyncRelayCommand(
    Func<Task> execute,
    Func<bool> canExecute,
    Action<Exception> onError) : ICommand
{
    private bool running;

    public event EventHandler? CanExecuteChanged;

    public bool CanExecute(object? parameter) => !running && canExecute();

    public async void Execute(object? parameter)
    {
        if (!CanExecute(parameter)) return;
        running = true;
        RaiseCanExecuteChanged();
        try
        {
            await execute();
        }
        catch (Exception exception)
        {
            onError(exception);
        }
        finally
        {
            running = false;
            RaiseCanExecuteChanged();
        }
    }

    public void RaiseCanExecuteChanged() => CanExecuteChanged?.Invoke(this, EventArgs.Empty);
}

internal static class EmbeddedAssets
{
    public static byte[] Read(string fileName)
    {
        var resourceName = $"SupertonicVox.Desktop.Assets.{fileName}";
        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resourceName)
                           ?? throw new IOException($"Embedded asset is missing: {fileName}");
        using var memory = new MemoryStream();
        stream.CopyTo(memory);
        return memory.ToArray();
    }
}

internal static class AppDataPaths
{
    public static string GetDataDirectory()
    {
        if (OperatingSystem.IsMacOS())
        {
            return Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                "Library",
                "Application Support",
                "SupertonicVox");
        }
        return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "SupertonicVox");
    }
}
