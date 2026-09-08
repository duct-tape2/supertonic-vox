param(
    [Parameter(Mandatory)]
    [string]$StagingRoot,
    [Parameter(Mandatory)]
    [string]$OutputDirectory,
    [Parameter(Mandatory)]
    [string]$SevenZip,
    [string]$ArchiveName = 'Supertonic_VoxCPM2_OFFLINE_PAYLOAD_2026-07-27.zip'
)

$ErrorActionPreference = 'Stop'
$StagingRoot = [IO.Path]::GetFullPath($StagingRoot)
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
$SevenZip = [IO.Path]::GetFullPath($SevenZip)
if (-not (Test-Path -LiteralPath $StagingRoot -PathType Container)) {
    throw "Staging root not found: $StagingRoot"
}
if (-not (Test-Path -LiteralPath $SevenZip -PathType Leaf)) {
    throw "7-Zip not found: $SevenZip"
}
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$ArchivePath = Join-Path $OutputDirectory $ArchiveName
$Existing = @(Get-ChildItem -LiteralPath $OutputDirectory -File | Where-Object {
    $_.Name -eq $ArchiveName -or $_.Name -like "$ArchiveName.*"
})
if ($Existing.Count) {
    throw "Refusing to overwrite existing archive output: $($Existing[0].FullName)"
}

$Parent = Split-Path -Parent $StagingRoot
$Leaf = Split-Path -Leaf $StagingRoot
Push-Location $Parent
try {
    & $SevenZip a '-tzip' '-mx=1' '-mcu=on' '-v500000000b' $ArchivePath $Leaf
    if ($LASTEXITCODE -ne 0) {
        throw "7-Zip archive creation failed: $LASTEXITCODE"
    }
}
finally {
    Pop-Location
}
if (Test-Path -LiteralPath $ArchivePath -PathType Leaf) {
    throw "Unexpected unsplit archive was left behind: $ArchivePath"
}

$Parts = @(
    Get-ChildItem -LiteralPath $OutputDirectory -File |
        Where-Object { $_.Name -match ('^' + [regex]::Escape($ArchiveName) + '\.\d{3}$') } |
        Sort-Object Name
)
if (-not $Parts.Count) {
    throw 'No split archive parts were created.'
}

$CombinedHasher = [Security.Cryptography.SHA256]::Create()
$CombinedSize = 0L
$Records = @()
try {
    for ($Position = 0; $Position -lt $Parts.Count; $Position++) {
        $Part = $Parts[$Position]
        $ExpectedName = '{0}.{1:D3}' -f $ArchiveName, ($Position + 1)
        if ($Part.Name -ne $ExpectedName) {
            throw "Part numbering is not contiguous: $($Part.Name)"
        }
        if ($Part.Length -gt 500000000) {
            throw "Part exceeds 500,000,000 bytes: $($Part.Name)"
        }
        if ($Position -lt $Parts.Count - 1 -and $Part.Length -ne 500000000) {
            throw "Non-final part is not exactly 500,000,000 bytes: $($Part.Name)"
        }
        $PartHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Part.FullName).Hash.ToLowerInvariant()
        $Stream = [IO.File]::OpenRead($Part.FullName)
        try {
            $Buffer = New-Object byte[] (4 * 1024 * 1024)
            while (($Read = $Stream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {
                [void]$CombinedHasher.TransformBlock($Buffer, 0, $Read, $Buffer, 0)
                $CombinedSize += $Read
            }
        }
        finally {
            $Stream.Dispose()
        }
        $Records += [ordered]@{
            index = $Position + 1
            name = $Part.Name
            size = [long]$Part.Length
            sha256 = $PartHash
        }
    }
    $Empty = New-Object byte[] 0
    [void]$CombinedHasher.TransformFinalBlock($Empty, 0, 0)
    $CombinedHash = ([BitConverter]::ToString($CombinedHasher.Hash)).Replace('-', '').ToLowerInvariant()
}
finally {
    $CombinedHasher.Dispose()
}

$Manifest = [ordered]@{
    schema_version = 1
    format = 'zip64-multivolume'
    archive_name = $ArchiveName
    compression = 'zip/deflate-fast'
    max_part_bytes = 500000000
    part_count = $Records.Count
    combined_size = $CombinedSize
    combined_sha256 = $CombinedHash
    payload_root = $Leaf
    file_manifest = 'FILE_MANIFEST_SHA256.json'
    created_utc = [DateTime]::UtcNow.ToString('o')
    parts = $Records
}
$Manifest | ConvertTo-Json -Depth 6 | Set-Content -Encoding utf8 (Join-Path $OutputDirectory 'PARTS_MANIFEST.json')
$Records | ForEach-Object { "$($_.sha256) *$($_.name)" } |
    Set-Content -Encoding ascii (Join-Path $OutputDirectory 'PARTS_SHA256.txt')

Write-Host "Created $($Records.Count) parts; combined bytes=$CombinedSize; SHA-256=$CombinedHash"
