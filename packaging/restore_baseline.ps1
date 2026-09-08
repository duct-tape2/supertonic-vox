$ErrorActionPreference = 'Stop'
$OverlayRoot = [IO.Path]::GetFullPath($PSScriptRoot)
$AppRoot = [IO.Path]::GetFullPath((Split-Path -Parent $OverlayRoot))
$ManifestPath = Join-Path $OverlayRoot 'BASELINE_OVERLAY_MANIFEST.json'
$AddedPath = Join-Path $OverlayRoot 'ADDED_HARDENED_FILES.txt'

if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
    throw "Baseline overlay manifest not found: $ManifestPath"
}

Write-Host 'Close Supertonic + VoxCPM2 before continuing.'
$Manifest = Get-Content -Raw -LiteralPath $ManifestPath | ConvertFrom-Json

foreach ($Item in $Manifest.files) {
    $OverlayFile = [IO.Path]::GetFullPath((Join-Path $OverlayRoot ([string]$Item.overlay)))
    $TargetFile = [IO.Path]::GetFullPath((Join-Path $AppRoot ([string]$Item.target)))
    if (-not $OverlayFile.StartsWith($OverlayRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Unsafe overlay path: $OverlayFile"
    }
    if (-not $TargetFile.StartsWith($AppRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Unsafe restore target: $TargetFile"
    }
    if (-not (Test-Path -LiteralPath $OverlayFile -PathType Leaf)) {
        throw "Baseline file missing: $OverlayFile"
    }
    $Directory = Split-Path -Parent $TargetFile
    New-Item -ItemType Directory -Force -Path $Directory | Out-Null
    $Temporary = Join-Path $Directory ('.' + [IO.Path]::GetFileName($TargetFile) + '.' + [Guid]::NewGuid().ToString('N') + '.tmp')
    try {
        Copy-Item -LiteralPath $OverlayFile -Destination $Temporary -Force
        Move-Item -LiteralPath $Temporary -Destination $TargetFile -Force
    }
    finally {
        if (Test-Path -LiteralPath $Temporary) {
            Remove-Item -LiteralPath $Temporary -Force
        }
    }
}

if (Test-Path -LiteralPath $AddedPath -PathType Leaf) {
    foreach ($Relative in Get-Content -LiteralPath $AddedPath) {
        if ([string]::IsNullOrWhiteSpace($Relative) -or $Relative.TrimStart().StartsWith('#')) {
            continue
        }
        $Target = [IO.Path]::GetFullPath((Join-Path $AppRoot $Relative))
        if (-not $Target.StartsWith($AppRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
            throw "Unsafe added-file path: $Target"
        }
        if (Test-Path -LiteralPath $Target -PathType Leaf) {
            Remove-Item -LiteralPath $Target -Force
        }
    }
}

$Failures = @()
foreach ($Item in $Manifest.files) {
    $TargetFile = Join-Path $AppRoot ([string]$Item.target)
    if (-not (Test-Path -LiteralPath $TargetFile -PathType Leaf)) {
        $Failures += "missing: $($Item.target)"
        continue
    }
    $Info = Get-Item -LiteralPath $TargetFile
    $Hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $TargetFile).Hash.ToLowerInvariant()
    if ($Info.Length -ne [long]$Item.size -or $Hash -ne ([string]$Item.sha256).ToLowerInvariant()) {
        $Failures += "mismatch: $($Item.target)"
    }
}
if ($Failures.Count) {
    throw "Baseline restore verification failed:`n$($Failures -join [Environment]::NewLine)"
}
Write-Host "Baseline restored and verified: $($Manifest.files.Count) files."
