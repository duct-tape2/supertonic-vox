param(
    [switch]$FullHash,
    [ValidateRange(7800, 7810)]
    [int]$ServerPort = 7800,
    [switch]$CheckServer
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
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

$Arguments = @((Join-Path $Root 'diagnostics\diagnose.py'))
if ($FullHash) {
    $Arguments += '--full-hash'
}
if ($CheckServer) {
    $Arguments += @('--server-port', $ServerPort)
}

& $Python @Arguments
exit $LASTEXITCODE
