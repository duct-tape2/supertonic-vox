param(
    [Parameter(Mandatory)]
    [string]$ReleaseRoot,
    [string]$Manifest = (Join-Path $ReleaseRoot 'FILE_MANIFEST_SHA256.json')
)

$ErrorActionPreference = 'Stop'
$ReleaseRoot = [IO.Path]::GetFullPath($ReleaseRoot)
if (-not (Test-Path -LiteralPath $ReleaseRoot -PathType Container)) {
    throw "Release root not found: $ReleaseRoot"
}
$ReleaseRootInfo = Get-Item -LiteralPath $ReleaseRoot -Force
if (($ReleaseRootInfo.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'The release root must not be a reparse point.'
}
$RootPrefix = $ReleaseRoot.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
$Manifest = [IO.Path]::GetFullPath($Manifest)
if (-not $Manifest.StartsWith($RootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Manifest is outside the release root: $Manifest"
}
if (-not (Test-Path -LiteralPath $Manifest -PathType Leaf)) {
    throw "Manifest not found: $Manifest"
}

$ManifestInfo = Get-Item -LiteralPath $Manifest -Force
if (($ManifestInfo.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'The release manifest must not be a reparse point.'
}
$Items = Get-Content -Raw -Encoding UTF8 -LiteralPath $Manifest | ConvertFrom-Json
if ([int]$Items.schema_version -ne 1 -or [string]$Items.algorithm -ne 'SHA-256') {
    throw 'Unsupported release manifest schema or algorithm.'
}
if ([int]$Items.file_count -ne @($Items.files).Count) {
    throw 'Release manifest file_count does not match its file list.'
}

$Failures = [Collections.Generic.List[string]]::new()
$ExpectedPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$Checked = 0
$CheckedBytes = 0L
foreach ($Item in $Items.files) {
    $Relative = ([string]$Item.path).Replace('/', [IO.Path]::DirectorySeparatorChar)
    if ([string]::IsNullOrWhiteSpace($Relative) -or [IO.Path]::IsPathRooted($Relative)) {
        $Failures.Add("PATH $($Item.path)")
        continue
    }
    try {
        $Path = [IO.Path]::GetFullPath((Join-Path $ReleaseRoot $Relative))
    }
    catch {
        $Failures.Add("PATH $($Item.path)")
        continue
    }
    if (-not $Path.StartsWith($RootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        $Failures.Add("PATH $($Item.path)")
        continue
    }
    $CanonicalRelative = $Path.Substring($RootPrefix.Length).Replace([IO.Path]::DirectorySeparatorChar, '/')
    if (-not $ExpectedPaths.Add($CanonicalRelative)) {
        $Failures.Add("DUPLICATE $($Item.path)")
        continue
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        $Failures.Add("MISSING $($Item.path)")
        continue
    }
    $Info = Get-Item -LiteralPath $Path -Force
    if (($Info.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        $Failures.Add("REPARSE $($Item.path)")
        continue
    }
    if ($Info.Length -ne [long]$Item.size) {
        $Failures.Add("SIZE $($Item.path)")
        continue
    }
    $Hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
    if ($Hash -ne ([string]$Item.sha256).ToLowerInvariant()) {
        $Failures.Add("HASH $($Item.path)")
        continue
    }
    $Checked++
    $CheckedBytes += $Info.Length
}

if ($Checked -ne [int]$Items.file_count) {
    $Failures.Add("COUNT expected=$($Items.file_count) checked=$Checked")
}
if ($CheckedBytes -ne [long]$Items.total_bytes) {
    $Failures.Add("BYTES expected=$($Items.total_bytes) checked=$CheckedBytes")
}

$ManifestRelative = $Manifest.Substring($RootPrefix.Length).Replace([IO.Path]::DirectorySeparatorChar, '/')
$SelfExcluded = [string]$Items.manifest_self_excluded
if ([string]::IsNullOrWhiteSpace($SelfExcluded) -or $SelfExcluded -ne $ManifestRelative) {
    $Failures.Add("MANIFEST_SELF expected=$ManifestRelative declared=$SelfExcluded")
}
$ActualPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($Entry in Get-ChildItem -LiteralPath $ReleaseRoot -Recurse -Force) {
    if (($Entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        $Failures.Add("REPARSE_UNLISTED $($Entry.FullName.Substring($RootPrefix.Length))")
        continue
    }
    if (-not $Entry.PSIsContainer) {
        $FullPath = [IO.Path]::GetFullPath($Entry.FullName)
        if (-not $FullPath.StartsWith($RootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            $Failures.Add("PATH_UNLISTED $($Entry.FullName)")
            continue
        }
        [void]$ActualPaths.Add($FullPath.Substring($RootPrefix.Length).Replace([IO.Path]::DirectorySeparatorChar, '/'))
    }
}
foreach ($Actual in $ActualPaths) {
    if ($Actual -ne $ManifestRelative -and -not $ExpectedPaths.Contains($Actual)) {
        $Failures.Add("UNEXPECTED $Actual")
    }
}
foreach ($Expected in $ExpectedPaths) {
    if (-not $ActualPaths.Contains($Expected)) {
        $Failures.Add("MISSING_SET $Expected")
    }
}

if ($Failures.Count) {
    $Failures | Select-Object -First 50 | ForEach-Object { Write-Error $_ }
    throw "Release verification failed with $($Failures.Count) error(s)."
}
Write-Host "Release verification passed: $Checked files, $CheckedBytes bytes, no unlisted files or reparse points."
