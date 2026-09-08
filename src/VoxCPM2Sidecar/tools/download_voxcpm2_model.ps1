[CmdletBinding()]
param(
    [string]$DestinationDirectory,
    [switch]$ProbeOnly,
    [Int64]$MinimumModelScopeBytesPerSecond = 2097152,
    [ValidateRange(1, 20)]
    [int]$HfResumeAttempts = 8
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$HfRepository = "openbmb/VoxCPM2"
$HfRevision = "bffb3df5a29440629464e5e839f4d214c8714c3d"
$ModelScopeRepository = "OpenBMB/VoxCPM2"
$ModelScopeRevision = "04123d1676da3fd7e1f2d4ed847408950c9cf26d"
$KnownModelScopeIp = "47.251.62.57"
$Curl = (Get-Command curl.exe -ErrorAction Stop).Source
$NewLine = [Environment]::NewLine

$Artifacts = @(
    [pscustomobject]@{
        Name = "config.json"
        Kind = "small"
        Size = [Int64]4336
        Sha256 = "405f0dcd92f7feba6011ed4eac5c8d4f74cba9712f07fd5cfa3063bbdd95402c"
        HfEtag = "792f1c223ed607f9e508c0a0deb15dd9532483be"
        XetHash = ""
    },
    [pscustomobject]@{
        Name = "special_tokens_map.json"
        Kind = "small"
        Size = [Int64]1632
        Sha256 = "068594063e37662c02b21acf42ebb334ef6a74fb810e68a2368f88f08351de76"
        HfEtag = "8619dda6f3eb6d60d0a1bb274820054e46f41699"
        XetHash = ""
    },
    [pscustomobject]@{
        Name = "tokenization_voxcpm2.py"
        Kind = "small"
        Size = [Int64]2895
        Sha256 = "84489ea32b6ee0cae22ed5480cacb6df85c46624c3119be9a2021c3649a12729"
        HfEtag = "e7d768677298d058fa6ef8b160e3ca4430997fad"
        XetHash = ""
    },
    [pscustomobject]@{
        Name = "tokenizer.json"
        Kind = "small"
        Size = [Int64]3676772
        Sha256 = "f8984687e4a92a3503d521396d454b7d68e9fdaab2a0288eb3536c7c1aa4bc20"
        HfEtag = "41a5c2a8dba4058dd1ad73fb898abf5e4f64f0f9"
        XetHash = ""
    },
    [pscustomobject]@{
        Name = "tokenizer_config.json"
        Kind = "small"
        Size = [Int64]5059
        Sha256 = "e78a3ebb48a0b9437efd1823b6b726c823da89e49dd8bcc90c02419d9baa772b"
        HfEtag = "fecf4cdae73b57053cac2ad34c67febbe4e4f08b"
        XetHash = ""
    },
    [pscustomobject]@{
        Name = "audiovae.pth"
        Kind = "large"
        Size = [Int64]376951122
        Sha256 = "94b5d51e107e0507d4acc976cfdadb64edd6fd06d1f751dadbf2fd1594274bf1"
        HfEtag = "94b5d51e107e0507d4acc976cfdadb64edd6fd06d1f751dadbf2fd1594274bf1"
        XetHash = "f9ecfd88c9471d9574719d7996d1ef0da1db65ec988cfc9f933f4aa99f2de4bb"
    },
    [pscustomobject]@{
        Name = "model.safetensors"
        Kind = "large"
        Size = [Int64]4580080592
        Sha256 = "f7f964cfa9da23653baec6e6f7750719977ad944ed9f95fe52fe3a620506891d"
        HfEtag = "f7f964cfa9da23653baec6e6f7750719977ad944ed9f95fe52fe3a620506891d"
        XetHash = "45afd9afa29b02b0db6d0025d3849d2ef1e6f067c0d77e4b6af74cfc139fc622"
    }
)

function Get-HeaderValue {
    param(
        [object[]]$Headers,
        [string]$Name
    )

    $prefix = $Name + ":"
    foreach ($lineObject in $Headers) {
        $line = [string]$lineObject
        if ($line.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
            return $line.Substring($prefix.Length).Trim()
        }
    }
    return $null
}

function Get-HfMetadata {
    param(
        [pscustomobject]$Artifact,
        [switch]$RequireSignedUrl
    )

    $url = "https://huggingface.co/$HfRepository/resolve/$HfRevision/$($Artifact.Name)"
    $headers = @(& $Curl --ssl-no-revoke -sS -I --connect-timeout 30 --max-time 60 $url)
    if ($LASTEXITCODE -ne 0) {
        throw "Hugging Face HEAD failed for $($Artifact.Name), curl exit $LASTEXITCODE"
    }

    $repoCommit = Get-HeaderValue -Headers $headers -Name "X-Repo-Commit"
    if ($repoCommit -ne $HfRevision) {
        throw "Unexpected HF revision for $($Artifact.Name): '$repoCommit'"
    }

    $etag = Get-HeaderValue -Headers $headers -Name "X-Linked-ETag"
    if ([string]::IsNullOrWhiteSpace($etag)) {
        throw "HF did not return X-Linked-ETag for $($Artifact.Name)"
    }
    $etag = $etag.Trim([char]34).ToLowerInvariant()
    if ($etag -ne $Artifact.HfEtag) {
        throw "Unexpected HF ETag for $($Artifact.Name): '$etag'"
    }

    if ($Artifact.Kind -eq "large") {
        $linkedSizeText = Get-HeaderValue -Headers $headers -Name "X-Linked-Size"
        $linkedSize = [Int64]0
        if (-not [Int64]::TryParse($linkedSizeText, [ref]$linkedSize) -or $linkedSize -ne $Artifact.Size) {
            throw "Unexpected HF linked size for $($Artifact.Name): '$linkedSizeText'"
        }

        $xetHash = Get-HeaderValue -Headers $headers -Name "X-Xet-Hash"
        if ($xetHash -ne $Artifact.XetHash) {
            throw "Unexpected HF Xet hash for $($Artifact.Name): '$xetHash'"
        }
    }

    if (-not $RequireSignedUrl) {
        return
    }

    $location = Get-HeaderValue -Headers $headers -Name "Location"
    if ([string]::IsNullOrWhiteSpace($location)) {
        throw "HF did not return a signed Location for $($Artifact.Name)"
    }

    $signedUri = [Uri]$location
    if ($signedUri.Scheme -ne "https" -or $signedUri.Host -ne "cas-bridge.xethub.hf.co") {
        throw "Refusing unexpected HF download host: $($signedUri.AbsoluteUri)"
    }

    return $signedUri.AbsoluteUri
}

function Get-ModelScopeTree {
    param([string]$IpAddress)

    $url = "https://$IpAddress/api/v1/models/$ModelScopeRepository/repo/files?Revision=$ModelScopeRevision&Recursive=true"
    $raw = @(& $Curl --ssl-no-revoke -k -fLsS --connect-timeout 10 --max-time 30 $url 2>$null)
    if ($LASTEXITCODE -ne 0) {
        return $null
    }

    try {
        $tree = (($raw | ForEach-Object { [string]$_ }) -join $NewLine) | ConvertFrom-Json
    }
    catch {
        return $null
    }

    if ($tree.Code -ne 200 -or -not $tree.Success) {
        return $null
    }

    foreach ($artifact in $Artifacts) {
        $matches = @($tree.Data.Files | Where-Object { $_.Path -eq $artifact.Name })
        if ($matches.Count -ne 1) {
            return $null
        }
        $entry = $matches[0]
        if ([Int64]$entry.Size -ne $artifact.Size) {
            return $null
        }
        if ([string]$entry.Sha256 -ne $artifact.Sha256) {
            return $null
        }
    }

    return $tree
}

function Find-WorkingModelScopeIp {
    $resolved = @()
    try {
        $resolved = @(
            Resolve-DnsName www.modelscope.cn -Type A -ErrorAction Stop |
                Where-Object { $_.Type -eq "A" -and $_.IPAddress } |
                Select-Object -ExpandProperty IPAddress
        )
    }
    catch {
        Write-Warning "ModelScope DNS lookup failed; trying the last verified address."
    }

    $candidates = @($resolved + $KnownModelScopeIp | Select-Object -Unique)
    foreach ($ip in $candidates) {
        Write-Host "Checking ModelScope mirror at $ip ..."
        $tree = Get-ModelScopeTree -IpAddress $ip
        if ($null -ne $tree) {
            Write-Host "ModelScope revision and all pinned file hashes match at $ip."
            return $ip
        }
    }

    throw "No ModelScope IP returned the pinned revision metadata."
}

function Get-ModelScopeFileUrl {
    param(
        [string]$IpAddress,
        [string]$FileName
    )

    $escapedName = [Uri]::EscapeDataString($FileName)
    return "https://$IpAddress/api/v1/models/$ModelScopeRepository/repo?Revision=$ModelScopeRevision&FilePath=$escapedName"
}

function Assert-ArtifactFile {
    param(
        [string]$Path,
        [pscustomobject]$Artifact
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Missing artifact: $Path"
    }

    $length = (Get-Item -LiteralPath $Path).Length
    if ($length -ne $Artifact.Size) {
        throw "Wrong size for $($Artifact.Name): $length, expected $($Artifact.Size)"
    }

    $sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($sha256 -ne $Artifact.Sha256) {
        throw "Wrong SHA-256 for $($Artifact.Name): $sha256"
    }
}

function Test-InstalledArtifact {
    param(
        [string]$DestinationPath,
        [pscustomobject]$Artifact
    )

    if (-not (Test-Path -LiteralPath $DestinationPath -PathType Leaf)) {
        return $false
    }

    Assert-ArtifactFile -Path $DestinationPath -Artifact $Artifact
    Write-Host "Already verified: $($Artifact.Name)"
    return $true
}

function Commit-Artifact {
    param(
        [string]$PartPath,
        [string]$DestinationPath,
        [pscustomobject]$Artifact
    )

    Assert-ArtifactFile -Path $PartPath -Artifact $Artifact
    if (Test-Path -LiteralPath $DestinationPath) {
        throw "Refusing to overwrite existing destination: $DestinationPath"
    }
    [IO.File]::Move($PartPath, $DestinationPath)
    Write-Host "Installed and verified: $($Artifact.Name)"
}

function Download-SmallArtifact {
    param(
        [string]$ModelScopeIp,
        [string]$StageDirectory,
        [string]$DestinationPath,
        [pscustomobject]$Artifact
    )

    Get-HfMetadata -Artifact $Artifact
    $partPath = Join-Path $StageDirectory ($Artifact.Name + ".part")
    $url = Get-ModelScopeFileUrl -IpAddress $ModelScopeIp -FileName $Artifact.Name

    Write-Host "Downloading pinned ModelScope file: $($Artifact.Name)"
    & $Curl --ssl-no-revoke -k -fL -sS --retry 5 --retry-all-errors --retry-delay 2 --connect-timeout 30 --max-time 900 -o $partPath $url
    if ($LASTEXITCODE -ne 0) {
        throw "ModelScope download failed for $($Artifact.Name), curl exit $LASTEXITCODE"
    }

    Commit-Artifact -PartPath $partPath -DestinationPath $DestinationPath -Artifact $Artifact
}

function Measure-ModelScopeSpeed {
    param(
        [string]$ModelScopeIp,
        [pscustomobject]$Artifact
    )

    $url = Get-ModelScopeFileUrl -IpAddress $ModelScopeIp -FileName $Artifact.Name
    $output = @(
        & $Curl --ssl-no-revoke -k -fL -sS --connect-timeout 20 --max-time 90 -r 0-1048575 -o NUL -w "%{speed_download}" $url 2>$null
    )
    if ($LASTEXITCODE -ne 0 -or $output.Count -eq 0) {
        return [double]0
    }

    $speedText = ([string]$output[-1]).Trim()
    $speed = [double]0
    $style = [Globalization.NumberStyles]::Float
    $culture = [Globalization.CultureInfo]::InvariantCulture
    if (-not [double]::TryParse($speedText, $style, $culture, [ref]$speed)) {
        return [double]0
    }
    return $speed
}

function Try-DownloadLargeFromModelScope {
    param(
        [string]$ModelScopeIp,
        [string]$StageDirectory,
        [string]$DestinationPath,
        [pscustomobject]$Artifact
    )

    $partPath = Join-Path $StageDirectory ($Artifact.Name + ".part")
    if (Test-Path -LiteralPath $partPath) {
        Write-Host "A partial file already exists; preserving it for HF resume."
        return $false
    }

    $speed = Measure-ModelScopeSpeed -ModelScopeIp $ModelScopeIp -Artifact $Artifact
    Write-Host ("ModelScope probe for {0}: {1:N0} bytes/sec" -f $Artifact.Name, $speed)
    if ($speed -lt $MinimumModelScopeBytesPerSecond) {
        Write-Host "ModelScope is below the configured speed gate; using the signed HF fallback."
        return $false
    }

    $url = Get-ModelScopeFileUrl -IpAddress $ModelScopeIp -FileName $Artifact.Name
    Write-Host "Downloading large file from the primary ModelScope mirror: $($Artifact.Name)"
    & $Curl --ssl-no-revoke -k -fL --progress-bar --retry 3 --retry-all-errors --retry-delay 3 --connect-timeout 30 --max-time 3400 --speed-limit $MinimumModelScopeBytesPerSecond --speed-time 30 -o $partPath $url
    $curlExit = $LASTEXITCODE
    if ($curlExit -ne 0) {
        Write-Warning "ModelScope transfer stopped with curl exit $curlExit; HF will resume the part."
        return $false
    }

    try {
        Commit-Artifact -PartPath $partPath -DestinationPath $DestinationPath -Artifact $Artifact
        return $true
    }
    catch {
        Remove-Item -LiteralPath $partPath -Force -ErrorAction SilentlyContinue
        Write-Warning "Completed ModelScope file failed validation; restarting from the signed HF source."
        return $false
    }
}

function Download-LargeFromHf {
    param(
        [string]$StageDirectory,
        [string]$DestinationPath,
        [pscustomobject]$Artifact
    )

    $partPath = Join-Path $StageDirectory ($Artifact.Name + ".part")
    if (Test-Path -LiteralPath $partPath) {
        $partLength = (Get-Item -LiteralPath $partPath).Length
        if ($partLength -gt $Artifact.Size) {
            throw "Partial file is larger than expected: $partPath"
        }
    }

    for ($attempt = 1; $attempt -le $HfResumeAttempts; $attempt++) {
        $currentLength = [Int64]0
        if (Test-Path -LiteralPath $partPath) {
            $currentLength = (Get-Item -LiteralPath $partPath).Length
        }
        if ($currentLength -eq $Artifact.Size) {
            break
        }

        Write-Host "HF signed transfer $attempt/$HfResumeAttempts for $($Artifact.Name), offset $currentLength"
        $signedUrl = Get-HfMetadata -Artifact $Artifact -RequireSignedUrl
        $arguments = @(
            "--ssl-no-revoke",
            "-fL",
            "--progress-bar",
            "--retry", "3",
            "--retry-all-errors",
            "--retry-delay", "3",
            "--connect-timeout", "30",
            "--max-time", "3400",
            "--speed-limit", "1024",
            "--speed-time", "60"
        )
        if ($currentLength -gt 0) {
            $arguments += @("-C", "-")
        }
        $arguments += @("-o", $partPath, $signedUrl)

        & $Curl @arguments
        $curlExit = $LASTEXITCODE
        if ($curlExit -ne 0) {
            Write-Warning "HF transfer returned curl exit $curlExit; refreshing the signed URL."
            Start-Sleep -Seconds 2
        }
    }

    Commit-Artifact -PartPath $partPath -DestinationPath $DestinationPath -Artifact $Artifact
}

function Invoke-Probe {
    param([string]$ModelScopeIp)

    Write-Host "Running read-only network probe. All response bodies go to memory or NUL."
    foreach ($artifact in $Artifacts) {
        if ($artifact.Kind -eq "large") {
            $signedUrl = Get-HfMetadata -Artifact $artifact -RequireSignedUrl
            $msSpeed = Measure-ModelScopeSpeed -ModelScopeIp $ModelScopeIp -Artifact $artifact
            Write-Host ("ModelScope {0}: {1:N0} bytes/sec" -f $artifact.Name, $msSpeed)

            & $Curl --ssl-no-revoke -fL -sS --connect-timeout 20 --max-time 90 -r 0-1048575 -o NUL $signedUrl
            if ($LASTEXITCODE -ne 0) {
                throw "HF CAS Range probe failed for $($artifact.Name)"
            }
            Write-Host "HF CAS Range probe passed: $($artifact.Name)"
        }
        else {
            Get-HfMetadata -Artifact $artifact
            $url = Get-ModelScopeFileUrl -IpAddress $ModelScopeIp -FileName $artifact.Name
            & $Curl --ssl-no-revoke -k -fL -sS --connect-timeout 20 --max-time 60 -r 0-63 -o NUL $url
            if ($LASTEXITCODE -ne 0) {
                throw "ModelScope Range probe failed for $($artifact.Name)"
            }
            Write-Host "Cross-source metadata probe passed: $($artifact.Name)"
        }
    }
    Write-Host "Probe completed without writing model files."
}

$modelScopeIp = Find-WorkingModelScopeIp
if ($ProbeOnly) {
    Invoke-Probe -ModelScopeIp $modelScopeIp
    exit 0
}

if ([string]::IsNullOrWhiteSpace($DestinationDirectory)) {
    throw "DestinationDirectory is required unless ProbeOnly is used."
}

$destination = [IO.Path]::GetFullPath($DestinationDirectory)
$stage = Join-Path $destination ".staging"
[IO.Directory]::CreateDirectory($destination) | Out-Null
[IO.Directory]::CreateDirectory($stage) | Out-Null

foreach ($artifact in @($Artifacts | Where-Object { $_.Kind -eq "small" })) {
    $destinationPath = Join-Path $destination $artifact.Name
    if (-not (Test-InstalledArtifact -DestinationPath $destinationPath -Artifact $artifact)) {
        Download-SmallArtifact -ModelScopeIp $modelScopeIp -StageDirectory $stage -DestinationPath $destinationPath -Artifact $artifact
    }
}

foreach ($artifact in @($Artifacts | Where-Object { $_.Kind -eq "large" })) {
    $destinationPath = Join-Path $destination $artifact.Name
    if (Test-InstalledArtifact -DestinationPath $destinationPath -Artifact $artifact) {
        continue
    }

    $installed = Try-DownloadLargeFromModelScope -ModelScopeIp $modelScopeIp -StageDirectory $stage -DestinationPath $destinationPath -Artifact $artifact
    if (-not $installed) {
        Download-LargeFromHf -StageDirectory $stage -DestinationPath $destinationPath -Artifact $artifact
    }
}

foreach ($artifact in $Artifacts) {
    Assert-ArtifactFile -Path (Join-Path $destination $artifact.Name) -Artifact $artifact
}

$provenanceSource = Join-Path $PSScriptRoot "voxcpm2-model-provenance.json"
if (Test-Path -LiteralPath $provenanceSource -PathType Leaf) {
    [IO.File]::Copy($provenanceSource, (Join-Path $destination "_download-provenance.json"), $true)
}

Write-Host "All seven VoxCPM2 runtime artifacts are installed and SHA-256 verified."
