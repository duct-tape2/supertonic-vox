[CmdletBinding(DefaultParameterSetName = 'Preflight')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Preflight')]
    [switch]$PreflightUnsigned,
    [Parameter(Mandatory, ParameterSetName = 'Capture')]
    [switch]$CapturePublishInventory,
    [switch]$OfflineModels,
    [string]$ModelCache,
    [string]$Output,
    [string]$Dotnet = 'dotnet',
    [string]$Python = 'python',
    [string]$PackageVersion,
    [switch]$ProductionCatalogAssets,
    [string]$CatalogAssetRoot
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Invoke-Native {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$Arguments,
        [string]$LogPath
    )
    if ($LogPath) {
        & $FilePath @Arguments 2>&1 | Tee-Object -FilePath $LogPath
    }
    else {
        & $FilePath @Arguments
    }
    if ($LASTEXITCODE -ne 0) {
        throw "$FilePath failed with exit code $LASTEXITCODE."
    }
}

function Get-FileIdentity {
    param([Parameter(Mandatory)][string]$Path)
    $Item = Get-Item -LiteralPath $Path -Force
    if (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $Item.PSIsContainer) {
        throw "Evidence input is not a regular file: $Path"
    }
    return [ordered]@{
        name = $Item.Name
        sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
        sizeBytes = [long]$Item.Length
    }
}

function Write-JsonAtomic {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][object]$Value
    )
    $Directory = Split-Path -Parent $Path
    New-Item -ItemType Directory -Force -Path $Directory | Out-Null
    $Temporary = Join-Path $Directory ".$(Split-Path -Leaf $Path).$([Guid]::NewGuid().ToString('N')).tmp"
    try {
        $Json = $Value | ConvertTo-Json -Depth 10
        [IO.File]::WriteAllText($Temporary, $Json + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $Temporary -Destination $Path -Force
    }
    finally {
        Remove-Item -LiteralPath $Temporary -Force -ErrorAction SilentlyContinue
    }
}

if (-not [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [Runtime.InteropServices.OSPlatform]::Windows)) {
    throw 'Windows packaging requires a Windows build host.'
}
if ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne
    [Runtime.InteropServices.Architecture]::X64) {
    throw 'This package target requires Windows x64.'
}
if (-not [Environment]::Is64BitProcess) {
    throw 'Run the preflight from a 64-bit PowerShell process.'
}
$ScriptDirectory = Split-Path -Parent $PSCommandPath
$RepoRoot = [IO.Path]::GetFullPath((Join-Path $ScriptDirectory '..'))
Set-Location $RepoRoot

[xml]$VersionProps = Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $RepoRoot 'Directory.Build.props')
$VersionNodes = @($VersionProps.Project.PropertyGroup.Version | Where-Object { $_ })
if ($VersionNodes.Count -ne 1) {
    throw 'Directory.Build.props must contain exactly one Version.'
}
$SourceVersion = [string]$VersionNodes[0]
if (-not $PackageVersion) {
    $PackageVersion = if ($env:SVX_PACKAGE_VERSION) { $env:SVX_PACKAGE_VERSION } else { $SourceVersion }
}
if ($PackageVersion -notmatch '^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$') {
    throw 'PackageVersion is invalid.'
}
if ($PackageVersion -ne $SourceVersion) {
    throw "PackageVersion must match Directory.Build.props ($SourceVersion)."
}
if ($ProductionCatalogAssets) {
    if (-not $CatalogAssetRoot) {
        throw 'Production catalog assets require -CatalogAssetRoot.'
    }
    $CatalogAssetRoot = [IO.Path]::GetFullPath($CatalogAssetRoot)
    foreach ($CatalogFile in @(
            'engine-catalog.json',
            'engine-catalog.signature.json',
            'engine-catalog.trust.json',
            'engine-catalog.bootstrap.json',
            'engine-catalog.trust-manifest.json',
            'engine-catalog.trust-manifest.signature.json')) {
        $CatalogPath = Join-Path $CatalogAssetRoot $CatalogFile
        if (-not (Test-Path -LiteralPath $CatalogPath -PathType Leaf)) {
            throw "Production catalog asset is missing: $CatalogFile"
        }
        if (((Get-Item -LiteralPath $CatalogPath -Force).Attributes -band
                [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Production catalog asset is a reparse point: $CatalogFile"
        }
    }
}
elseif ($CatalogAssetRoot) {
    throw '-CatalogAssetRoot is accepted only with -ProductionCatalogAssets.'
}

foreach ($Command in @('git', $Dotnet, $Python)) {
    if (-not (Get-Command $Command -ErrorAction SilentlyContinue)) {
        throw "Missing required command: $Command"
    }
}

$ReleaseCommit = (& git rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $ReleaseCommit -notmatch '^[0-9a-f]{40}$') {
    throw 'Unable to resolve the release commit.'
}
$ShortCommit = (& git rev-parse --short=12 HEAD).Trim()
$SourceEpoch = [long](& git show -s --format=%ct $ReleaseCommit).Trim()
$TrackedDirty = (& git status --porcelain --untracked-files=no) -join [Environment]::NewLine
if ($LASTEXITCODE -ne 0 -or -not [string]::IsNullOrWhiteSpace($TrackedDirty)) {
    throw 'Tracked changes are not committed; refusing commit-bound packaging.'
}

$RequiredInputs = @(
    'global.json',
    'Directory.Build.props',
    'SupertonicVox.CrossPlatform.slnx',
    'packaging/build-windows-release.ps1',
    'packaging/windows-publish-allowlist.json',
    'tools/windows_preflight_contract.py',
    'tools/fetch_supertonic_model.py',
    'tools/release_privacy_gate.py',
    'tools/release_privacy_rules.json'
)
foreach ($TrackedInput in $RequiredInputs) {
    & git cat-file -e "$ReleaseCommit`:$TrackedInput" 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "Release input is not present in the audited commit: $TrackedInput"
    }
}

$ExpectedSdkVersion = (Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $RepoRoot 'global.json') |
        ConvertFrom-Json).sdk.version
$ActualSdkVersion = (& $Dotnet --version).Trim()
if ($LASTEXITCODE -ne 0 -or $ActualSdkVersion -ne $ExpectedSdkVersion) {
    throw "Expected .NET SDK $ExpectedSdkVersion but found $ActualSdkVersion."
}
$DotnetCommand = Get-Command $Dotnet
$DotnetExecutable = [IO.Path]::GetFullPath($DotnetCommand.Source)
$DotnetSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $DotnetExecutable).Hash.ToLowerInvariant()

$Allowlist = Join-Path $RepoRoot 'packaging\windows-publish-allowlist.json'
$ContractTool = Join-Path $RepoRoot 'tools\windows_preflight_contract.py'
Invoke-Native $Python @($ContractTool, 'verify-source-modes', '--repo', $RepoRoot, '--commit', $ReleaseCommit)
if ($PreflightUnsigned) {
    Invoke-Native $Python @(
        $ContractTool, 'validate-allowlist', '--allowlist', $Allowlist,
        '--sdk-version', $ActualSdkVersion, '--require-approved'
    )
}
else {
    Invoke-Native $Python @(
        $ContractTool, 'validate-allowlist', '--allowlist', $Allowlist,
        '--sdk-version', $ActualSdkVersion
    )
}

if (-not $ModelCache) {
    $ModelCache = Join-Path $RepoRoot 'artifacts\model-cache\supertonic-3'
}
$ModelCache = [IO.Path]::GetFullPath($ModelCache)
if (-not $Output) {
    $Output = if ($PreflightUnsigned) {
        Join-Path $RepoRoot "artifacts\windows-preflight\$ShortCommit"
    }
    else {
        Join-Path $RepoRoot "artifacts\windows-inventory\$ShortCommit"
    }
}
$Output = [IO.Path]::GetFullPath($Output)
if (Test-Path -LiteralPath $Output) {
    throw "Output already exists: $Output"
}

$WorkRoot = Join-Path ([IO.Path]::GetTempPath()) "svx-windows-preflight.$([Guid]::NewGuid().ToString('N'))"
$SourceArchive = Join-Path $WorkRoot 'source.zip'
$SourceRoot = Join-Path $WorkRoot 'source'
$PublishRoot = Join-Path $WorkRoot 'publish'
$EvidenceRoot = Join-Path $WorkRoot 'evidence'
$PackageRoot = Join-Path $WorkRoot 'package\SupertonicVox'
$ExtractedRoot = Join-Path $WorkRoot 'extracted'
$ArtifactName = "SupertonicVox-$PackageVersion-windows-x64-UNSIGNED-NOT-FOR-DISTRIBUTION.zip"
$ArtifactPath = Join-Path $WorkRoot $ArtifactName
$OutputParent = Split-Path -Parent $Output
$OutputName = Split-Path -Leaf $Output
$OutputPartial = Join-Path $OutputParent ".$OutputName.partial"
$Published = $false

try {
    New-Item -ItemType Directory -Force -Path $WorkRoot, $SourceRoot, $PublishRoot, $EvidenceRoot | Out-Null
    New-Item -ItemType Directory -Force -Path $OutputParent | Out-Null
    if (Test-Path -LiteralPath $OutputPartial) {
        throw "Partial output already exists: $OutputPartial"
    }

    Invoke-Native 'git' @('archive', '--format=zip', "--output=$SourceArchive", $ReleaseCommit)
    Expand-Archive -LiteralPath $SourceArchive -DestinationPath $SourceRoot

    $ArchivedContract = Join-Path $SourceRoot 'tools\windows_preflight_contract.py'
    $ArchivedOpenGateTool = Join-Path $SourceRoot 'tools\release_open_gates.py'
    $ArchivedOpenGateContract = Join-Path $SourceRoot 'packaging\release-open-gates.json'
    $ArchivedGateTraceability = Join-Path $SourceRoot 'packaging\release-gate-traceability.json'
    $ArchivedPrivacyGate = Join-Path $SourceRoot 'tools\release_privacy_gate.py'
    $ArchivedFetchTool = Join-Path $SourceRoot 'tools\fetch_supertonic_model.py'
    $ArchivedAllowlist = Join-Path $SourceRoot 'packaging\windows-publish-allowlist.json'
    $Solution = Join-Path $SourceRoot 'SupertonicVox.CrossPlatform.slnx'
    $DesktopProject = Join-Path $SourceRoot 'src\CrossPlatform\SupertonicVox.Desktop\SupertonicVox.Desktop.csproj'
    $TestProject = Join-Path $SourceRoot 'tests\SupertonicVox.Core.Tests\SupertonicVox.Core.Tests.csproj'
    $SmokeProject = Join-Path $SourceRoot 'tools\SupertonicSmoke\SupertonicSmoke.csproj'
    Invoke-Native $Python @(
        $ArchivedOpenGateTool, 'validate-contract', '--contract', $ArchivedOpenGateContract
    )
    Invoke-Native $Python @(
        $ArchivedOpenGateTool, 'validate-traceability',
        '--contract', $ArchivedOpenGateContract,
        '--traceability', $ArchivedGateTraceability
    )
    $RequiredOpenGates = @(
        (Get-Content -LiteralPath $ArchivedOpenGateContract -Raw | ConvertFrom-Json).requiredOpenGateIds
    )

    $FetchArguments = @(
        $ArchivedFetchTool,
        '--destination', $ModelCache,
        '--report', (Join-Path $EvidenceRoot 'model-fetch-report.json')
    )
    if ($OfflineModels) { $FetchArguments += '--offline' }
    if ($PreflightUnsigned) {
        Invoke-Native $Python $FetchArguments
    }

    Invoke-Native $Dotnet @('restore', $Solution, '--locked-mode', '--runtime', 'win-x64')
    Invoke-Native $Dotnet @(
        'build', $Solution, '--configuration', 'Release', '--no-restore', '--runtime', 'win-x64'
    ) (Join-Path $EvidenceRoot 'build.txt')
    Invoke-Native $Dotnet @(
        'test', $TestProject, '--configuration', 'Release', '--no-build', '--runtime', 'win-x64'
    ) (Join-Path $EvidenceRoot 'tests.txt')
    $PublishArguments = @(
        'publish', $DesktopProject,
        '--configuration', 'Release',
        '--runtime', 'win-x64',
        '--self-contained', 'true',
        '--no-restore',
        '-p:DebugType=None',
        '-p:DebugSymbols=false',
        '--output', $PublishRoot
    )
    if ($ProductionCatalogAssets) {
        $PublishArguments += '-p:CatalogProductionAssets=true'
        $PublishArguments += "-p:CatalogAssetRoot=$CatalogAssetRoot"
    }
    Invoke-Native $Dotnet $PublishArguments (Join-Path $EvidenceRoot 'publish.txt')

    $CrashDumpHelper = Join-Path $PublishRoot 'createdump.exe'
    Remove-Item -LiteralPath $CrashDumpHelper -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $CrashDumpHelper) {
        throw 'Crash dump helper must not be distributed.'
    }

    Invoke-Native $Python @($ArchivedPrivacyGate, '--self-test')
    Invoke-Native $Python @(
        $ArchivedPrivacyGate, $PublishRoot,
        '--release-commit', $ReleaseCommit,
        '--report', (Join-Path $EvidenceRoot 'publish-privacy-report.json')
    )

    if ($CapturePublishInventory) {
        $Candidate = Join-Path $EvidenceRoot 'windows-publish-inventory-candidate.json'
        Invoke-Native $Python @(
            $ArchivedContract, 'capture-inventory',
            '--publish', $PublishRoot,
            '--sdk-version', $ActualSdkVersion,
            '--output', $Candidate
        )
        New-Item -ItemType Directory -Path $OutputPartial | Out-Null
        Copy-Item -LiteralPath $Candidate, (Join-Path $EvidenceRoot 'publish-privacy-report.json') `
            -Destination $OutputPartial
        Move-Item -LiteralPath $OutputPartial -Destination $Output
        $Published = $true
        Write-Host "Windows publish inventory captured for review: $Output"
        Write-Host 'Release eligible: false'
        return
    }

    $PublishInventoryReport = Join-Path $EvidenceRoot 'publish-inventory-report.json'
    Invoke-Native $Python @(
        $ArchivedContract, 'compare-publish',
        '--allowlist', $ArchivedAllowlist,
        '--publish', $PublishRoot,
        '--report', $PublishInventoryReport
    )

    New-Item -ItemType Directory -Force -Path $PackageRoot | Out-Null
    foreach ($Item in Get-ChildItem -LiteralPath $PublishRoot -Recurse -File -Force) {
        $Relative = $Item.FullName.Substring($PublishRoot.Length).TrimStart('\', '/')
        $Destination = Join-Path $PackageRoot $Relative
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Destination) | Out-Null
        Copy-Item -LiteralPath $Item.FullName -Destination $Destination
    }

    $ModelRoot = Join-Path $PackageRoot 'Models\Supertonic3'
    $ModelFiles = @(
        'onnx\duration_predictor.onnx',
        'onnx\text_encoder.onnx',
        'onnx\vector_estimator.onnx',
        'onnx\vocoder.onnx',
        'onnx\tts.json',
        'onnx\unicode_indexer.json',
        'voice_styles\M1.json'
    )
    foreach ($Relative in $ModelFiles) {
        $Source = Join-Path $ModelCache $Relative
        if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) {
            throw "Verified model cache file is missing: $Relative"
        }
        $SourceItem = Get-Item -LiteralPath $Source -Force
        if (($SourceItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Verified model cache file is a reparse point: $Relative"
        }
        $Destination = Join-Path $ModelRoot $Relative
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Destination) | Out-Null
        Copy-Item -LiteralPath $Source -Destination $Destination
    }
    Invoke-Native $Python @(
        $ArchivedFetchTool,
        '--destination', $ModelRoot,
        '--report', (Join-Path $EvidenceRoot 'bundled-model-report.json'),
        '--offline'
    )

    $LicenseRoot = Join-Path $PackageRoot 'Licenses'
    New-Item -ItemType Directory -Force -Path $LicenseRoot | Out-Null
    Copy-Item -LiteralPath (Join-Path $SourceRoot 'THIRD_PARTY_NOTICES.md') -Destination $PackageRoot
    Copy-Item -LiteralPath (Join-Path $SourceRoot 'licenses\Supertonic-v3.0.0_MIT.txt') -Destination $LicenseRoot
    Copy-Item -LiteralPath (Join-Path $SourceRoot 'licenses\Supertonic-3_OpenRAIL-M.txt') -Destination $LicenseRoot
    [IO.File]::WriteAllLines(
        (Join-Path $PackageRoot 'UNSIGNED-NOT-FOR-DISTRIBUTION.txt'),
        @(
            'This artifact is unsigned and NOT FOR DISTRIBUTION.',
            'It exists only to verify Windows packaging and privacy controls.'
        ),
        [Text.UTF8Encoding]::new($false)
    )

    $SmokeWav = Join-Path $WorkRoot 'supertonic-smoke.wav'
    try {
        Invoke-Native $Dotnet @(
            'run', '--project', $SmokeProject,
            '--configuration', 'Release',
            '--runtime', 'win-x64',
            '--no-build', '--no-restore', '--',
            (Join-Path $ModelRoot 'onnx'),
            (Join-Path $ModelRoot 'voice_styles'),
            $SmokeWav
        ) (Join-Path $EvidenceRoot 'supertonic-smoke.txt')
        if (-not (Test-Path -LiteralPath $SmokeWav -PathType Leaf)) {
            throw 'Supertonic smoke did not produce a WAV.'
        }
    }
    finally {
        Remove-Item -LiteralPath $SmokeWav -Force -ErrorAction SilentlyContinue
    }

    $PackagePrivacyReport = Join-Path $EvidenceRoot 'package-privacy-report.json'
    Invoke-Native $Python @(
        $ArchivedPrivacyGate, $PackageRoot,
        '--release-commit', $ReleaseCommit,
        '--report', $PackagePrivacyReport
    )
    Invoke-Native $Python @(
        $ArchivedContract, 'create-zip',
        '--source', (Split-Path -Parent $PackageRoot),
        '--output', $ArtifactPath,
        '--epoch', $SourceEpoch
    )

    $ZipPrivacyReport = Join-Path $EvidenceRoot 'zip-privacy-report.json'
    Invoke-Native $Python @(
        $ArchivedPrivacyGate, $ArtifactPath,
        '--release-commit', $ReleaseCommit,
        '--report', $ZipPrivacyReport
    )
    Expand-Archive -LiteralPath $ArtifactPath -DestinationPath $ExtractedRoot
    $ExtractedPrivacyReport = Join-Path $EvidenceRoot 'extracted-privacy-report.json'
    Invoke-Native $Python @(
        $ArchivedPrivacyGate, $ExtractedRoot,
        '--release-commit', $ReleaseCommit,
        '--report', $ExtractedPrivacyReport
    )

    $ArtifactIdentity = Get-FileIdentity $ArtifactPath
    $EvidenceInputs = [ordered]@{
        modelFetchReport = Get-FileIdentity (Join-Path $EvidenceRoot 'model-fetch-report.json')
        modelReport = Get-FileIdentity (Join-Path $EvidenceRoot 'bundled-model-report.json')
        publishInventory = Get-FileIdentity $PublishInventoryReport
        publishPrivacy = Get-FileIdentity (Join-Path $EvidenceRoot 'publish-privacy-report.json')
        packagePrivacy = Get-FileIdentity $PackagePrivacyReport
        zipPrivacy = Get-FileIdentity $ZipPrivacyReport
        extractedPrivacy = Get-FileIdentity $ExtractedPrivacyReport
        buildLog = Get-FileIdentity (Join-Path $EvidenceRoot 'build.txt')
        testLog = Get-FileIdentity (Join-Path $EvidenceRoot 'tests.txt')
        publishLog = Get-FileIdentity (Join-Path $EvidenceRoot 'publish.txt')
        smokeLog = Get-FileIdentity (Join-Path $EvidenceRoot 'supertonic-smoke.txt')
    }
    $EvidencePrivacyReport = Join-Path $WorkRoot 'evidence-privacy-report.json'
    Invoke-Native $Python @(
        $ArchivedPrivacyGate, $EvidenceRoot,
        '--release-commit', $ReleaseCommit,
        '--report', $EvidencePrivacyReport
    )
    Copy-Item -LiteralPath $EvidencePrivacyReport -Destination $EvidenceRoot
    $EvidenceInputs.evidencePrivacy = Get-FileIdentity (Join-Path $EvidenceRoot 'evidence-privacy-report.json')
    $ReleaseEvidencePath = Join-Path $EvidenceRoot 'release-evidence.json'
    $ReleaseEvidence = [ordered]@{
        schemaVersion = 1
        mode = 'preflight-unsigned'
        releaseEligible = $false
        releaseCommit = $ReleaseCommit
        sourceMode = 'git-archive'
        packageVersion = $PackageVersion
        artifact = [ordered]@{
            name = $ArtifactName
            sha256 = $ArtifactIdentity.sha256
            sizeBytes = $ArtifactIdentity.sizeBytes
        }
        toolchain = [ordered]@{
            dotnetSdkVersion = $ActualSdkVersion
            dotnetExecutableSha256 = $DotnetSha256
        }
        evidenceFiles = $EvidenceInputs
        openGates = $RequiredOpenGates
    }
    Write-JsonAtomic $ReleaseEvidencePath $ReleaseEvidence
    Invoke-Native $Python @($ArchivedContract, 'validate-evidence', '--evidence', $ReleaseEvidencePath)

    New-Item -ItemType Directory -Path $OutputPartial | Out-Null
    Copy-Item -LiteralPath $ArtifactPath -Destination $OutputPartial
    Copy-Item -Path (Join-Path $EvidenceRoot '*') -Destination $OutputPartial
    $CopiedArtifact = Join-Path $OutputPartial $ArtifactName
    $CopiedIdentity = Get-FileIdentity $CopiedArtifact
    if ($CopiedIdentity.sha256 -ne $ArtifactIdentity.sha256 -or
        $CopiedIdentity.sizeBytes -ne $ArtifactIdentity.sizeBytes) {
        throw 'Copied Windows artifact identity does not match audited evidence.'
    }
    Invoke-Native $Python @(
        $ArchivedContract, 'validate-evidence',
        '--evidence', (Join-Path $OutputPartial 'release-evidence.json'),
        '--output-root', $OutputPartial
    )
    Move-Item -LiteralPath $OutputPartial -Destination $Output
    $Published = $true
    Write-Host "Unsigned privacy-gated Windows preflight created: $Output"
    Write-Host 'Release eligible: false'
}
finally {
    if (-not $Published) {
        Remove-Item -LiteralPath $OutputPartial -Recurse -Force -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $WorkRoot -Recurse -Force -ErrorAction SilentlyContinue
}
