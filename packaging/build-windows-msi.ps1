[CmdletBinding(DefaultParameterSetName = 'Capture')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Capture')]
    [switch]$CaptureSigningPolicy,
    [Parameter(Mandatory, ParameterSetName = 'Staging')]
    [switch]$BuildStagingMsi,
    [Parameter(Mandatory, ParameterSetName = 'Production')]
    [switch]$BuildProductionMsi,
    [string]$InstallerContract,
    [string]$SigningPolicy,
    [string]$ModelCache,
    [string]$Output,
    [string]$Dotnet = 'dotnet',
    [string]$Python = 'python',
    [string]$SignTool,
    [string]$CertificateThumbprint,
    [ValidateSet('CurrentUser', 'LocalMachine')]
    [string]$CertificateStoreScope = 'CurrentUser',
    [string]$ProductionCatalogAssetRoot,
    [string]$CatalogBaseline,
    [switch]$FirstProductionCatalog,
    [string]$SourceLicenseApproval,
    [string]$ModelRedistributionApproval,
    [switch]$FirstRelease,
    [string]$PriorSignedMsi
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
    if ($Item.PSIsContainer -or
        ($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Expected a regular file: $Path"
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
        $Json = $Value | ConvertTo-Json -Depth 20
        [IO.File]::WriteAllText(
            $Temporary,
            $Json + [Environment]::NewLine,
            [Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $Temporary -Destination $Path -Force
    }
    finally {
        Remove-Item -LiteralPath $Temporary -Force -ErrorAction SilentlyContinue
    }
}

function Get-CertificateSha256 {
    param([Parameter(Mandatory)][Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    $Hasher = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($Hasher.ComputeHash($Certificate.RawData))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $Hasher.Dispose()
    }
}

function Test-CodeSigningEku {
    param([Parameter(Mandatory)][Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    foreach ($Extension in $Certificate.Extensions) {
        if ($Extension -is [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
            foreach ($Oid in $Extension.EnhancedKeyUsages) {
                if ($Oid.Value -eq '1.3.6.1.5.5.7.3.3') { return $true }
            }
        }
    }
    return $false
}

function Assert-TrustedCertificate {
    param([Parameter(Mandatory)][Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    $Chain = [Security.Cryptography.X509Certificates.X509Chain]::new()
    try {
        $Chain.ChainPolicy.RevocationMode =
            [Security.Cryptography.X509Certificates.X509RevocationMode]::Online
        $Chain.ChainPolicy.RevocationFlag =
            [Security.Cryptography.X509Certificates.X509RevocationFlag]::ExcludeRoot
        if (-not $Chain.Build($Certificate)) {
            throw "Certificate chain validation failed: $($Certificate.Subject)"
        }
    }
    finally {
        $Chain.Dispose()
    }
}

function Get-VerifiedSignature {
    param(
        [Parameter(Mandatory)][string]$Path,
        [object[]]$AllowedSigners,
        [switch]$RequireTimestamp
    )
    $Signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($Signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
        -not $Signature.SignerCertificate) {
        throw "Authenticode signature is not valid: $Path ($($Signature.Status))"
    }
    Assert-TrustedCertificate $Signature.SignerCertificate
    if (-not (Test-CodeSigningEku $Signature.SignerCertificate)) {
        throw "Signer lacks the Code Signing EKU: $Path"
    }
    $Leaf = Get-CertificateSha256 $Signature.SignerCertificate
    $Subject = $Signature.SignerCertificate.Subject.Normalize(
        [Text.NormalizationForm]::FormKC).Trim()
    if ($AllowedSigners -and $AllowedSigners.Count -gt 0) {
        $Matched = $false
        foreach ($Allowed in $AllowedSigners) {
            if ($Leaf -eq ([string]$Allowed.leafCertificateSha256).ToLowerInvariant() -and
                $Subject -eq [string]$Allowed.subject) {
                $Matched = $true
                break
            }
        }
        if (-not $Matched) {
            throw "Authenticode signer does not match the approved signer set: $Path"
        }
    }
    if ($RequireTimestamp) {
        if (-not $Signature.TimeStamperCertificate) {
            throw "RFC3161 timestamp is missing: $Path"
        }
        Assert-TrustedCertificate $Signature.TimeStamperCertificate
    }
    return [ordered]@{
        leafCertificateSha256 = $Leaf
        subject = $Subject
        serialNumber = $Signature.SignerCertificate.SerialNumber
        codeSigningEku = $true
        timestampVerified = [bool]$Signature.TimeStamperCertificate
        timestampAuthoritySubject = if ($Signature.TimeStamperCertificate) {
            $Signature.TimeStamperCertificate.Subject
        } else { $null }
    }
}

function Get-MsiIdentity {
    param([Parameter(Mandatory)][string]$Path)
    $Installer = New-Object -ComObject WindowsInstaller.Installer
    $Database = $null
    $View = $null
    $Summary = $null
    try {
        $Database = $Installer.OpenDatabase($Path, 0)
        $Properties = [ordered]@{}
        foreach ($PropertyName in @('ProductCode', 'ProductVersion', 'UpgradeCode')) {
            $View = $Database.OpenView(
                "SELECT ``Value`` FROM ``Property`` WHERE ``Property``='$PropertyName'")
            $View.Execute()
            $Record = $View.Fetch()
            if (-not $Record) { throw "MSI $PropertyName is missing." }
            $Properties[$PropertyName] = [string]$Record.StringData(1)
            $View.Close()
            [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($View)
            $View = $null
        }
        $Summary = $Installer.SummaryInformation($Path, 0)
        $PackageCode = [string]$Summary.Property(9)
        if ($Properties.ProductCode -notmatch '^\{[0-9A-Fa-f-]{36}\}$' -or
            $Properties.UpgradeCode -notmatch '^\{[0-9A-Fa-f-]{36}\}$' -or
            $Properties.ProductVersion -notmatch '^[0-9]+\.[0-9]+\.[0-9]+$' -or
            $PackageCode -notmatch '^\{[0-9A-Fa-f-]{36}\}$') {
            throw 'MSI product/package identity is invalid.'
        }
        return [ordered]@{
            productCode = $Properties.ProductCode.Trim('{}').ToUpperInvariant()
            productVersion = $Properties.ProductVersion
            upgradeCode = $Properties.UpgradeCode.Trim('{}').ToUpperInvariant()
            packageCode = $PackageCode.Trim('{}').ToUpperInvariant()
        }
    }
    finally {
        if ($View) { $View.Close() }
        foreach ($ComObject in @($Summary, $View, $Database, $Installer)) {
            if ($ComObject) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($ComObject) }
        }
    }
}

if (-not [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [Runtime.InteropServices.OSPlatform]::Windows) -or
    [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne
        [Runtime.InteropServices.Architecture]::X64 -or
    -not [Environment]::Is64BitProcess) {
    throw 'MSI packaging requires 64-bit Windows x64.'
}

$ScriptDirectory = Split-Path -Parent $PSCommandPath
$RepoRoot = [IO.Path]::GetFullPath((Join-Path $ScriptDirectory '..'))
Set-Location $RepoRoot
foreach ($Command in @('git', $Dotnet, $Python)) {
    if (-not (Get-Command $Command -ErrorAction SilentlyContinue)) {
        throw "Missing required command: $Command"
    }
}
$ReleaseCommit = (& git rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $ReleaseCommit -notmatch '^[0-9a-f]{40}$') {
    throw 'Unable to resolve the release commit.'
}
$TrackedDirty = (& git status --porcelain --untracked-files=no) -join [Environment]::NewLine
if ($LASTEXITCODE -ne 0 -or -not [string]::IsNullOrWhiteSpace($TrackedDirty)) {
    throw 'Tracked changes are not committed; refusing commit-bound MSI work.'
}
$ShortCommit = (& git rev-parse --short=12 HEAD).Trim()
[xml]$VersionProps = Get-Content -Raw -Encoding UTF8 -LiteralPath (
    Join-Path $RepoRoot 'Directory.Build.props')
$PackageVersion = [string](@($VersionProps.Project.PropertyGroup.Version | Where-Object { $_ }))[0]
if ($PackageVersion -notmatch '^[0-9]+\.[0-9]+\.[0-9]+$') {
    throw 'MSI requires a three-field numeric package version.'
}

if (-not $InstallerContract) {
    $InstallerContract = Join-Path $RepoRoot 'packaging\windows-installer-contract.json'
}
if (-not $SigningPolicy) {
    $SigningPolicy = Join-Path $RepoRoot 'packaging\windows-signing-policy.json'
}
$InstallerContract = [IO.Path]::GetFullPath($InstallerContract)
$SigningPolicy = [IO.Path]::GetFullPath($SigningPolicy)
$ExpectedInstallerContract = [IO.Path]::GetFullPath(
    (Join-Path $RepoRoot 'packaging\windows-installer-contract.json'))
$ExpectedSigningPolicy = [IO.Path]::GetFullPath(
    (Join-Path $RepoRoot 'packaging\windows-signing-policy.json'))
if (-not [string]::Equals(
        $InstallerContract, $ExpectedInstallerContract,
        [StringComparison]::OrdinalIgnoreCase) -or
    -not [string]::Equals(
        $SigningPolicy, $ExpectedSigningPolicy,
        [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Installer contract and signing policy must be the checked-in release-commit files.'
}
$ContractTool = Join-Path $RepoRoot 'tools\windows_msi_contract.py'
$PreflightScript = Join-Path $RepoRoot 'packaging\build-windows-release.ps1'
$OpenGateContract = Join-Path $RepoRoot 'packaging\release-open-gates.json'
$GateTraceability = Join-Path $RepoRoot 'packaging\release-gate-traceability.json'
$PrivacyGate = Join-Path $RepoRoot 'tools\release_privacy_gate.py'
$IsProduction = $BuildProductionMsi.IsPresent

$CommitBoundInputs = @(
    '.config/dotnet-tools.json',
    'Directory.Build.props',
    'packaging/build-windows-msi.ps1',
    'packaging/build-windows-release.ps1',
    'packaging/release-open-gates.json',
    'packaging/release-gate-traceability.json',
    'packaging/final-release-signing-policy.json',
    'packaging/windows-installer-contract.json',
    'packaging/windows-msi-evidence.schema.json',
    'packaging/windows-signing-policy.json',
    'packaging/windows',
    'tools/CatalogReleaseVerifier',
    'tools/release_open_gates.py',
    'tools/release_privacy_gate.py',
    'tools/windows_msi_contract.py'
)
foreach ($TrackedInput in $CommitBoundInputs) {
    & git cat-file -e "$ReleaseCommit`:$TrackedInput" 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "MSI release input is not present in the release commit: $TrackedInput"
    }
}
Invoke-Native $Python @(
    (Join-Path $RepoRoot 'tools\release_open_gates.py'), 'validate-traceability',
    '--contract', $OpenGateContract,
    '--traceability', $GateTraceability
)
$InputStatus = (& git status --porcelain --untracked-files=all -- @CommitBoundInputs) -join (
    [Environment]::NewLine)
if ($LASTEXITCODE -ne 0 -or -not [string]::IsNullOrWhiteSpace($InputStatus)) {
    throw 'MSI release inputs differ from the release commit or include untracked files.'
}

$ContractArguments = @($ContractTool, 'validate-contract', '--contract', $InstallerContract)
if ($IsProduction) { $ContractArguments += '--production' }
Invoke-Native $Python $ContractArguments
if (-not $CaptureSigningPolicy) {
    Invoke-Native $Python @(
        $ContractTool, 'validate-policy', '--policy', $SigningPolicy, '--production')
}

if ($IsProduction) {
    foreach ($Approval in @($SourceLicenseApproval, $ModelRedistributionApproval)) {
        if (-not $Approval -or -not (Test-Path -LiteralPath $Approval -PathType Leaf) -or
            ((Get-Item -LiteralPath $Approval -Force).Attributes -band
                [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Production MSI requires regular external source/model approval records.'
        }
    }
    if (-not $ProductionCatalogAssetRoot) {
        throw 'Production MSI requires -ProductionCatalogAssetRoot.'
    }
    if (-not $CertificateThumbprint -or $CertificateThumbprint -notmatch '^[0-9A-Fa-f]{40}$') {
        throw 'Production MSI requires a certificate-store SHA-1 thumbprint.'
    }
    if (-not $SignTool) {
        $SignToolCommand = Get-Command 'signtool.exe' -ErrorAction SilentlyContinue
        if (-not $SignToolCommand) { throw 'Windows SDK SignTool is required.' }
        $SignTool = $SignToolCommand.Source
    }
}

if (-not $Output) {
    $Output = if ($CaptureSigningPolicy) {
        Join-Path $RepoRoot "artifacts\windows-signing-policy\$ShortCommit"
    }
    elseif ($BuildStagingMsi) {
        Join-Path $RepoRoot "artifacts\windows-msi-staging\$ShortCommit"
    }
    else {
        Join-Path $RepoRoot "artifacts\windows-msi-production\$ShortCommit"
    }
}
$Output = [IO.Path]::GetFullPath($Output)
if (Test-Path -LiteralPath $Output) { throw "Output already exists: $Output" }
$OutputParent = Split-Path -Parent $Output
$OutputName = Split-Path -Leaf $Output
$OutputPartial = Join-Path $OutputParent ".$OutputName.partial"
if (Test-Path -LiteralPath $OutputPartial) { throw "Partial output exists: $OutputPartial" }

$WorkRoot = Join-Path ([IO.Path]::GetTempPath()) "svx-msi.$([Guid]::NewGuid().ToString('N'))"
$PreflightOutput = Join-Path $WorkRoot 'preflight'
$Extracted = Join-Path $WorkRoot 'extracted'
$EvidenceRoot = Join-Path $WorkRoot 'evidence'
$WixRoot = Join-Path $WorkRoot 'wix'
$Published = $false
try {
    New-Item -ItemType Directory -Force -Path $WorkRoot, $Extracted, $EvidenceRoot, $WixRoot | Out-Null
    New-Item -ItemType Directory -Force -Path $OutputParent | Out-Null
    $CatalogVerificationReport = $null
    if ($IsProduction) {
        if ($FirstProductionCatalog -and $CatalogBaseline) {
            throw 'Choose either -FirstProductionCatalog or -CatalogBaseline, not both.'
        }
        if (-not $FirstProductionCatalog -and -not $CatalogBaseline) {
            throw 'Production catalog verification requires a prior baseline or -FirstProductionCatalog.'
        }
        $CatalogVerificationReport = Join-Path $EvidenceRoot 'production-catalog-verification.json'
        $CatalogVerifierProject = Join-Path $RepoRoot 'tools\CatalogReleaseVerifier\CatalogReleaseVerifier.csproj'
        Invoke-Native $Dotnet @('restore', $CatalogVerifierProject, '--locked-mode') `
            (Join-Path $EvidenceRoot 'catalog-verifier-restore.txt')
        $CatalogVerificationArguments = @(
            'run', '--project', $CatalogVerifierProject,
            '--configuration', 'Release', '--no-restore', '--',
            (Join-Path $ProductionCatalogAssetRoot 'engine-catalog.json'),
            (Join-Path $ProductionCatalogAssetRoot 'engine-catalog.signature.json'),
            (Join-Path $ProductionCatalogAssetRoot 'engine-catalog.trust.json'),
            (Join-Path $ProductionCatalogAssetRoot 'engine-catalog.bootstrap.json'),
            (Join-Path $ProductionCatalogAssetRoot 'engine-catalog.trust-manifest.json'),
            (Join-Path $ProductionCatalogAssetRoot 'engine-catalog.trust-manifest.signature.json'),
            $CatalogVerificationReport,
            $(if ($FirstProductionCatalog) { '--first-production-release' } else {
                    [IO.Path]::GetFullPath($CatalogBaseline) }))
        Invoke-Native $Dotnet $CatalogVerificationArguments `
            (Join-Path $EvidenceRoot 'catalog-verifier.txt')
    }
    $PowerShellPath = (Get-Process -Id $PID).Path
    $PreflightArguments = @(
        '-NoProfile', '-NonInteractive', '-File', $PreflightScript,
        '-PreflightUnsigned', '-OfflineModels', '-Output', $PreflightOutput,
        '-Dotnet', $Dotnet, '-Python', $Python)
    if ($ModelCache) { $PreflightArguments += @('-ModelCache', $ModelCache) }
    if ($IsProduction) {
        $PreflightArguments += @(
            '-ProductionCatalogAssets',
            '-CatalogAssetRoot', ([IO.Path]::GetFullPath($ProductionCatalogAssetRoot)))
    }
    Invoke-Native $PowerShellPath $PreflightArguments (Join-Path $EvidenceRoot 'preflight.txt')
    $Archives = @(Get-ChildItem -LiteralPath $PreflightOutput -File -Filter '*.zip')
    if ($Archives.Count -ne 1) { throw 'Expected exactly one unsigned preflight ZIP.' }
    Expand-Archive -LiteralPath $Archives[0].FullName -DestinationPath $Extracted
    $PayloadRoots = @(Get-ChildItem -LiteralPath $Extracted -Directory -Force)
    if ($PayloadRoots.Count -ne 1) { throw 'Expected exactly one package root in the preflight ZIP.' }
    $PayloadRoot = $PayloadRoots[0].FullName
    Remove-Item -LiteralPath (Join-Path $PayloadRoot 'UNSIGNED-NOT-FOR-DISTRIBUTION.txt') `
        -Force -ErrorAction Stop

    $PreInventory = Join-Path $EvidenceRoot 'pre-sign-inventory.json'
    Invoke-Native $Python @(
        $ContractTool, 'capture-inventory', '--root', $PayloadRoot, '--output', $PreInventory)
    if ($CaptureSigningPolicy) {
        $Candidate = Join-Path $EvidenceRoot 'windows-signing-policy-candidate.json'
        Invoke-Native $Python @(
            $ContractTool, 'create-policy-candidate', '--inventory', $PreInventory,
            '--output', $Candidate)
        New-Item -ItemType Directory -Path $OutputPartial | Out-Null
        Copy-Item -LiteralPath $Candidate, $PreInventory -Destination $OutputPartial
        Copy-Item -LiteralPath (Join-Path $PreflightOutput 'release-evidence.json') `
            -Destination $OutputPartial
        Move-Item -LiteralPath $OutputPartial -Destination $Output
        $Published = $true
        Write-Host "Signing-policy candidate created for human review: $Output"
        Write-Host 'Release eligible: false'
        return
    }

    $PreTransition = Join-Path $EvidenceRoot 'pre-sign-transition.json'
    Invoke-Native $Python @(
        $ContractTool, 'verify-inventory', '--policy', $SigningPolicy,
        '--inventory', $PreInventory, '--phase', 'pre-sign', '--report', $PreTransition)
    $Policy = Get-Content -Raw -Encoding UTF8 -LiteralPath $SigningPolicy | ConvertFrom-Json
    $ObservedMsiSigner = $null
    $ObservedTimestamp = $null
    if ($IsProduction) {
        foreach ($Entry in $Policy.entries) {
            $Path = Join-Path $PayloadRoot ([string]$Entry.path).Replace('/', '\')
            switch ([string]$Entry.action) {
                'owner-sign' {
                    if ((Get-AuthenticodeSignature -LiteralPath $Path).Status -ne
                        [System.Management.Automation.SignatureStatus]::NotSigned) {
                        throw "Owner-sign file was not unsigned before signing: $($Entry.path)"
                    }
                    $SignArguments = @('sign')
                    if ($CertificateStoreScope -eq 'LocalMachine') { $SignArguments += '/sm' }
                    $SignArguments += @(
                        '/sha1', $CertificateThumbprint,
                        '/fd', 'SHA256',
                        '/tr', 'https://timestamp.digicert.com',
                        '/td', 'SHA256',
                        $Path)
                    Invoke-Native $SignTool $SignArguments
                    $OwnerAllowed = @($Policy.ownerCertificate)
                    [void](Get-VerifiedSignature -Path $Path -AllowedSigners $OwnerAllowed -RequireTimestamp)
                }
                'verify-existing-authenticode' {
                    [void](Get-VerifiedSignature -Path $Path -AllowedSigners @($Entry.allowedSigners) -RequireTimestamp)
                }
                'approved-unsigned-pe' {
                    if ((Get-AuthenticodeSignature -LiteralPath $Path).Status -ne
                        [System.Management.Automation.SignatureStatus]::NotSigned) {
                        throw "Approved-unsigned PE changed signature state: $($Entry.path)"
                    }
                }
                'hash-only-non-pe' { }
                default { throw "Unknown signing action: $($Entry.action)" }
            }
        }
    }

    $FinalInventory = Join-Path $EvidenceRoot 'final-inventory.json'
    Invoke-Native $Python @(
        $ContractTool, 'capture-inventory', '--root', $PayloadRoot, '--output', $FinalInventory)
    $TransitionReport = if ($IsProduction) {
        Join-Path $EvidenceRoot 'final-transition.json'
    } else { $PreTransition }
    if ($IsProduction) {
        Invoke-Native $Python @(
            $ContractTool, 'verify-inventory', '--policy', $SigningPolicy,
            '--inventory', $FinalInventory, '--phase', 'final', '--report', $TransitionReport)
    }

    Copy-Item -LiteralPath (Join-Path $RepoRoot 'packaging\windows\SupertonicVox.wixproj') `
        -Destination $WixRoot
    Copy-Item -LiteralPath (Join-Path $RepoRoot 'packaging\windows\Product.wxs') `
        -Destination $WixRoot
    $GeneratedComponents = Join-Path $WixRoot 'GeneratedComponents.wxs'
    Invoke-Native $Python @(
        $ContractTool, 'generate-components', '--contract', $InstallerContract,
        '--inventory', $FinalInventory, '--output', $GeneratedComponents)
    $ProductCode = (& $Python $ContractTool derive-product-code `
        --contract $InstallerContract --version $PackageVersion).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'ProductCode derivation failed.' }
    $ShortcutGuid = (& $Python $ContractTool derive-component-guid `
        --contract $InstallerContract --path 'installer/start-menu-shortcut').Trim()
    if ($LASTEXITCODE -ne 0) { throw 'Shortcut component GUID derivation failed.' }
    $ContractPayload = Get-Content -Raw -Encoding UTF8 -LiteralPath $InstallerContract | ConvertFrom-Json
    $DefineConstants = @(
        "ProductName=$($ContractPayload.package.name)",
        "Manufacturer=$($ContractPayload.identity.manufacturer)",
        "ProductVersion=$PackageVersion",
        "ProductCode=$ProductCode",
        "UpgradeCode=$($ContractPayload.identity.upgradeCode)",
        "ShortcutComponentGuid=$ShortcutGuid",
        "PayloadRoot=$PayloadRoot") -join ';'
    Invoke-Native $Dotnet @('tool', 'restore') (Join-Path $EvidenceRoot 'dotnet-tool-restore.txt')
    Invoke-Native $Dotnet @(
        'build', (Join-Path $WixRoot 'SupertonicVox.wixproj'),
        '--configuration', 'Release',
        "-p:DefineConstants=$DefineConstants",
        "-p:GeneratedComponentsFile=$GeneratedComponents") (Join-Path $EvidenceRoot 'wix-build.txt')
    $MsiCandidates = @(Get-ChildItem -LiteralPath $WixRoot -Recurse -File -Filter '*.msi')
    if ($MsiCandidates.Count -ne 1) { throw 'Expected exactly one WiX MSI output.' }
    $UnsignedMsi = $MsiCandidates[0].FullName
    $UnsignedMsiIdentity = Get-FileIdentity $UnsignedMsi
    Invoke-Native $Dotnet @(
        'tool', 'run', 'wix', '--', 'msi', 'validate', $UnsignedMsi) `
        (Join-Path $EvidenceRoot 'wix-ice-validation.txt')
    $IceMsiIdentity = Get-FileIdentity $UnsignedMsi
    if ($IceMsiIdentity.sha256 -ne $UnsignedMsiIdentity.sha256) {
        throw 'ICE validation changed the unsigned MSI.'
    }
    $SignedMsiIdentity = $null
    if ($IsProduction) {
        $SignArguments = @('sign')
        if ($CertificateStoreScope -eq 'LocalMachine') { $SignArguments += '/sm' }
        $SignArguments += @(
            '/sha1', $CertificateThumbprint,
            '/fd', 'SHA256',
            '/tr', 'https://timestamp.digicert.com',
            '/td', 'SHA256',
            $UnsignedMsi)
        Invoke-Native $SignTool $SignArguments (Join-Path $EvidenceRoot 'msi-sign.txt')
        Invoke-Native $SignTool @('verify', '/pa', '/all', '/v', $UnsignedMsi) `
            (Join-Path $EvidenceRoot 'msi-signature-verify.txt')
        $ObservedMsiSigner = Get-VerifiedSignature -Path $UnsignedMsi `
            -AllowedSigners @($Policy.ownerCertificate) -RequireTimestamp
        $ObservedTimestamp = [ordered]@{
            url = 'https://timestamp.digicert.com'
            digestAlgorithm = 'SHA-256'
            authoritySubject = $ObservedMsiSigner.timestampAuthoritySubject
            verified = $true
        }
        $SignedMsiIdentity = Get-FileIdentity $UnsignedMsi
    }
    $MsiIdentity = Get-MsiIdentity $UnsignedMsi
    if ($MsiIdentity.productCode -ne $ProductCode) {
        throw 'Built MSI ProductCode does not match the derived ProductCode.'
    }

    $PayloadPrivacyReport = Join-Path $EvidenceRoot 'msi-payload-privacy-report.json'
    Invoke-Native $Python @(
        $PrivacyGate, $PayloadRoot, '--release-commit', $ReleaseCommit,
        '--report', $PayloadPrivacyReport)
    $PreInventoryPayload = Get-Content -Raw -Encoding UTF8 -LiteralPath $PreInventory | ConvertFrom-Json
    $FinalInventoryPayload = Get-Content -Raw -Encoding UTF8 -LiteralPath $FinalInventory | ConvertFrom-Json
    $TransitionPayload = Get-Content -Raw -Encoding UTF8 -LiteralPath $TransitionReport | ConvertFrom-Json
    $OpenGates = @((Get-Content -Raw -Encoding UTF8 -LiteralPath $OpenGateContract |
            ConvertFrom-Json).requiredOpenGateIds)
    $EffectiveFirstRelease = if ($BuildStagingMsi) { $true } else { [bool]$FirstRelease }
    $PriorHash = $null
    if (-not $EffectiveFirstRelease) {
        if (-not $PriorSignedMsi -or -not (Test-Path -LiteralPath $PriorSignedMsi -PathType Leaf)) {
            throw 'A later release requires -PriorSignedMsi.'
        }
        $PriorFile = Get-FileIdentity $PriorSignedMsi
        [void](Get-VerifiedSignature -Path $PriorSignedMsi `
                -AllowedSigners @($Policy.ownerCertificate) -RequireTimestamp)
        $PriorIdentity = Get-MsiIdentity $PriorSignedMsi
        if ($PriorIdentity.upgradeCode -ne [string]$ContractPayload.identity.upgradeCode) {
            throw 'Prior signed MSI UpgradeCode does not match the current product family.'
        }
        if ([version]$PriorIdentity.productVersion -ge [version]$PackageVersion) {
            throw 'Prior signed MSI version must be lower than the current package version.'
        }
        $PriorHash = $PriorFile.sha256
    }
    $NativeChecks = [ordered]@{
        firstRelease = $EffectiveFirstRelease
        cleanInstall = 'missing'
        offlineSynthesis = 'missing'
        saveRestart = 'missing'
        uninstall = 'missing'
        noOrphanProcesses = 'missing'
        upgrade = if ($EffectiveFirstRelease) { 'not-applicable-first-release' } else { 'missing' }
        downgradePrevention = if ($EffectiveFirstRelease) { 'not-applicable-first-release' } else { 'missing' }
        priorSignedMsiSha256 = $PriorHash
    }
    $Evidence = [ordered]@{
        schemaVersion = 2
        releaseEligible = $false
        sourceCommit = $ReleaseCommit
        packageVersion = $PackageVersion
        identityMode = [string]$ContractPayload.identity.status
        upgradeCode = [string]$ContractPayload.identity.upgradeCode
        productCode = $MsiIdentity.productCode
        packageCode = $MsiIdentity.packageCode
        contractSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $InstallerContract).Hash.ToLowerInvariant()
        signingPolicySha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $SigningPolicy).Hash.ToLowerInvariant()
        preSignInventorySha256 = [string]$PreInventoryPayload.inventorySha256
        finalInventorySha256 = [string]$FinalInventoryPayload.inventorySha256
        payloadManifestSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $FinalInventory).Hash.ToLowerInvariant()
        unsignedMsiSha256 = $UnsignedMsiIdentity.sha256
        iceValidatedUnsignedMsiSha256 = $IceMsiIdentity.sha256
        signedMsiSha256 = if ($SignedMsiIdentity) { $SignedMsiIdentity.sha256 } else { $null }
        msiSigner = $ObservedMsiSigner
        timestamp = $ObservedTimestamp
        toolchain = [ordered]@{
            dotnetSdkVersion = (& $Dotnet --version).Trim()
            wixSdkVersion = '7.0.0'
            powerShellVersion = $PSVersionTable.PSVersion.ToString()
            windowsVersion = [Environment]::OSVersion.VersionString
            signToolVersion = if ($SignTool) { (Get-Item -LiteralPath $SignTool).VersionInfo.FileVersion } else { $null }
        }
        signingDecisions = @($TransitionPayload.decisions)
        iceValidation = [ordered]@{
            status = 'passed'
            unsignedMsiSha256 = $IceMsiIdentity.sha256
            suppressions = @()
        }
        privacyEvidence = @((Get-FileIdentity $PayloadPrivacyReport))
        externalApprovals = [ordered]@{
            sourceLicense = if ($IsProduction) { Get-FileIdentity $SourceLicenseApproval } else { $null }
            modelRedistribution = if ($IsProduction) {
                Get-FileIdentity $ModelRedistributionApproval
            } else { $null }
            productionCatalogVerification = if ($IsProduction) {
                Get-FileIdentity $CatalogVerificationReport
            } else { $null }
        }
        nativeChecks = $NativeChecks
        openGates = $OpenGates
    }
    $EvidencePath = Join-Path $EvidenceRoot 'windows-msi-evidence.json'
    Write-JsonAtomic $EvidencePath $Evidence
    Invoke-Native $Python @(
        $ContractTool, 'validate-evidence', '--contract', $InstallerContract,
        '--policy', $SigningPolicy, '--evidence', $EvidencePath)

    New-Item -ItemType Directory -Path $OutputPartial | Out-Null
    $ArtifactName = if ($IsProduction) {
        "SupertonicVox-$PackageVersion-windows-x64-SIGNED-NOT-RELEASE-ELIGIBLE.msi"
    } else {
        "SupertonicVox-$PackageVersion-windows-x64-STAGING-UNSIGNED-NOT-FOR-DISTRIBUTION.msi"
    }
    Copy-Item -LiteralPath $UnsignedMsi -Destination (Join-Path $OutputPartial $ArtifactName)
    Copy-Item -LiteralPath $EvidenceRoot -Destination $OutputPartial -Recurse
    Move-Item -LiteralPath $OutputPartial -Destination $Output
    $Published = $true
    Write-Host "MSI validation output created: $Output"
    Write-Host 'Release eligible: false'
}
finally {
    if (-not $Published) {
        Remove-Item -LiteralPath $OutputPartial -Recurse -Force -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $WorkRoot -Recurse -Force -ErrorAction SilentlyContinue
}
