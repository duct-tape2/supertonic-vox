param(
    [ValidateRange(7800, 7810)]
    [int]$Port = 7800,
    [switch]$Preload
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Python = Join-Path $Root 'python\python.exe'
$Packages = Join-Path $Root 'pkgs'

if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) {
    throw "Portable Python not found: $Python"
}

$env:PYTHONPATH = $Packages
$env:HF_HUB_OFFLINE = '1'
$env:TRANSFORMERS_OFFLINE = '1'
$env:HF_DATASETS_OFFLINE = '1'
$env:MODELSCOPE_OFFLINE = '1'
$env:TOKENIZERS_PARALLELISM = 'false'
if ([string]::IsNullOrWhiteSpace($env:TTS_LOCAL_AUTH_TOKEN)) {
    $env:TTS_LOCAL_AUTH_TOKEN = [Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
}
if ([string]::IsNullOrWhiteSpace($env:TTS_LOCAL_SESSION_ID)) {
    $env:TTS_LOCAL_SESSION_ID = [Guid]::NewGuid().ToString('N')
}

Write-Host "Local session: $env:TTS_LOCAL_SESSION_ID"
Write-Host 'The authentication token is available only in TTS_LOCAL_AUTH_TOKEN for this process tree.'

$Server = Join-Path $Root 'app\server.py'
$Arguments = @($Server, '--port', $Port)
if ($Preload) {
    $Arguments += '--preload'
}

Push-Location $Root
try {
    & $Python @Arguments
    exit $LASTEXITCODE
}
finally {
    Pop-Location
}
