param(
    [Parameter(Mandatory)]
    [string]$PayloadRoot,
    [string]$RepoRoot = $PSScriptRoot,
    [string]$EvidenceDirectory = (Join-Path $PSScriptRoot 'release-evidence\real-engines')
)

$ErrorActionPreference = 'Stop'
$RepoRoot = [IO.Path]::GetFullPath($RepoRoot)
$PayloadRoot = [IO.Path]::GetFullPath($PayloadRoot)
$EvidenceDirectory = [IO.Path]::GetFullPath($EvidenceDirectory)
if (-not [Environment]::Is64BitOperatingSystem -or $env:OS -ne 'Windows_NT') {
    throw 'Run this script on Windows x64 only.'
}
$WindowsBuild = [int](Get-CimInstance Win32_OperatingSystem).BuildNumber
if ($WindowsBuild -lt 22000) {
    throw "Run the production validation on fully patched Windows 11; found build $WindowsBuild."
}
if (-not (Test-Path -LiteralPath $PayloadRoot -PathType Container)) {
    throw "Payload root not found: $PayloadRoot"
}
New-Item -ItemType Directory -Force -Path $EvidenceDirectory | Out-Null

function New-RandomHex([int]$ByteCount) {
    $Bytes = New-Object byte[] $ByteCount
    $Generator = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $Generator.GetBytes($Bytes) }
    finally { $Generator.Dispose() }
    return -join ($Bytes | ForEach-Object { $_.ToString('x2') })
}

function Assert-PortFree([int]$Port) {
    $Listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $Port)
    try { $Listener.Start() }
    catch { throw "Loopback port $Port is already in use." }
    finally { try { $Listener.Stop() } catch {} }
}

function Test-PreboundPortGuard([int]$Port) {
    $Listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $Port)
    $Listener.Start()
    try {
        try {
            Assert-PortFree $Port
            throw "Pre-bound port guard unexpectedly accepted port $Port."
        }
        catch {
            if ($_.Exception.Message -notlike "Loopback port $Port is already in use.*") {
                throw
            }
        }
    }
    finally {
        $Listener.Stop()
    }
}

function Wait-ForOwnedPort([Diagnostics.Process]$Process, [int]$Port, [int]$TimeoutSeconds) {
    $Deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $Deadline) {
        $Process.Refresh()
        if ($Process.HasExited) {
            throw "Owned sidecar PID $($Process.Id) exited with code $($Process.ExitCode) before port $Port became ready."
        }
        $Client = [Net.Sockets.TcpClient]::new()
        try {
            $Client.Connect('127.0.0.1', $Port)
            $Listeners = @(Get-NetTCPConnection -LocalAddress '127.0.0.1' -LocalPort $Port -State Listen -ErrorAction Stop)
            if ($Listeners.Count -ne 1 -or [int]$Listeners[0].OwningProcess -ne $Process.Id) {
                $Owners = @($Listeners | ForEach-Object { $_.OwningProcess }) -join ','
                throw "Port $Port listener ownership mismatch: expected PID $($Process.Id), found $Owners."
            }
            return
        }
        catch {
            Start-Sleep -Milliseconds 500
        }
        finally {
            $Client.Dispose()
        }
    }
    throw "Owned sidecar PID $($Process.Id) did not open port $Port within $TimeoutSeconds seconds."
}

function Stop-OwnedProcess([Diagnostics.Process]$Process, [int]$Port) {
    if ($null -eq $Process) { return }
    $Process.Refresh()
    if (-not $Process.HasExited) {
        Stop-Process -Id $Process.Id -Force
        if (-not $Process.WaitForExit(10000)) {
            throw "Owned sidecar PID $($Process.Id) did not stop."
        }
    }
    $Deadline = [DateTime]::UtcNow.AddSeconds(10)
    while ([DateTime]::UtcNow -lt $Deadline) {
        try {
            Assert-PortFree $Port
            return
        }
        catch {
            Start-Sleep -Milliseconds 250
        }
    }
    throw "Loopback port $Port remained occupied after owned sidecar PID $($Process.Id) stopped."
}

function Invoke-Smoke([string]$Python, [string]$Engine, [int]$Port, [string]$OutputName) {
    $JsonPath = Join-Path $EvidenceDirectory "$Engine.json"
    $WavPath = Join-Path $EvidenceDirectory $OutputName
    & $Python (Join-Path $RepoRoot 'tests\real_engine_smoke.py') `
        --engine $Engine --port $Port --output $WavPath 2>&1 |
        Tee-Object -FilePath $JsonPath
    if ($LASTEXITCODE -ne 0) {
        throw "$Engine smoke failed with exit code $LASTEXITCODE."
    }
}

$OriginalPath = $env:PATH
$Sidecar = $null
$SidecarPort = 0
try {
    $SuperRoot = Join-Path $PayloadRoot '_internal\SupertonicLocal'
    $SuperPython = Join-Path $SuperRoot 'python\cpython-3.12.13-windows-x86_64-none\python.exe'
    $SuperServer = Join-Path $SuperRoot 'app\secure_server.py'
    $SuperPackages = Join-Path $SuperRoot '.venv\Lib\site-packages'
    foreach ($Required in @($SuperPython, $SuperServer, $SuperPackages)) {
        if (-not (Test-Path -LiteralPath $Required)) { throw "Missing Supertonic path: $Required" }
    }
    Test-PreboundPortGuard 7788
    Assert-PortFree 7788
    $env:TTS_LOCAL_AUTH_TOKEN = New-RandomHex 32
    $env:TTS_LOCAL_SESSION_ID = New-RandomHex 16
    $env:TTS_LOCAL_MODEL_REVISION = '0d6a2bed57a1c6ec4f7acf77d688c62337655dd1db2a5582b2b2d55c17f5efae'
    $env:PYTHONPATH = $SuperPackages
    $env:PYTHONNOUSERSITE = '1'
    $env:PYTHONUTF8 = '1'
    $env:HF_HUB_OFFLINE = '1'
    $env:TRANSFORMERS_OFFLINE = '1'
    $env:PATH = "$(Split-Path -Parent $SuperPython);$(Join-Path $SuperRoot '.venv\Scripts');$OriginalPath"
    $Sidecar = Start-Process -FilePath $SuperPython `
        -ArgumentList @("`"$SuperServer`"", '--port', '7788') `
        -WorkingDirectory $SuperRoot -NoNewWindow -PassThru `
        -RedirectStandardOutput (Join-Path $EvidenceDirectory 'supertonic.stdout.log') `
        -RedirectStandardError (Join-Path $EvidenceDirectory 'supertonic.stderr.log')
    $SidecarPort = 7788
    Wait-ForOwnedPort $Sidecar 7788 300
    Invoke-Smoke $SuperPython 'supertonic' 7788 'supertonic.wav'
    Stop-OwnedProcess $Sidecar 7788
    $Sidecar = $null
    $SidecarPort = 0

    $VoxRoot = Join-Path $PayloadRoot '_internal\VoxCPM2Local'
    $VoxPython = Join-Path $VoxRoot 'python\python.exe'
    $VoxServer = Join-Path $VoxRoot 'app\server.py'
    $VoxPackages = Join-Path $VoxRoot 'pkgs'
    foreach ($Required in @($VoxPython, $VoxServer, $VoxPackages)) {
        if (-not (Test-Path -LiteralPath $Required)) { throw "Missing VoxCPM2 path: $Required" }
    }
    Test-PreboundPortGuard 7800
    Assert-PortFree 7800
    $env:TTS_LOCAL_AUTH_TOKEN = New-RandomHex 32
    $env:TTS_LOCAL_SESSION_ID = New-RandomHex 16
    $env:VOXCPM_MODEL_REVISION = 'bffb3df5a29440629464e5e839f4d214c8714c3d'
    $env:VOXCPM_MODEL_DIR = Join-Path $VoxRoot 'models\VoxCPM2'
    $env:VOXCPM_OFFLINE = '1'
    $env:PYTHONPATH = $VoxPackages
    $env:PYTHONNOUSERSITE = '1'
    $env:PYTHONUTF8 = '1'
    $env:PYTHONDONTWRITEBYTECODE = '1'
    $env:HF_HUB_OFFLINE = '1'
    $env:TRANSFORMERS_OFFLINE = '1'
    $env:HF_DATASETS_OFFLINE = '1'
    $env:OMP_NUM_THREADS = '4'
    $env:MKL_NUM_THREADS = '4'
    $env:VOXCPM_INTRA_OP_THREADS = '4'
    $env:VOXCPM_INTER_OP_THREADS = '1'
    $env:PATH = "$(Split-Path -Parent $VoxPython);$OriginalPath"
    $Sidecar = Start-Process -FilePath $VoxPython `
        -ArgumentList @("`"$VoxServer`"", '--port', '7800', '--preload') `
        -WorkingDirectory $VoxRoot -NoNewWindow -PassThru `
        -RedirectStandardOutput (Join-Path $EvidenceDirectory 'voxcpm2.stdout.log') `
        -RedirectStandardError (Join-Path $EvidenceDirectory 'voxcpm2.stderr.log')
    $SidecarPort = 7800
    Wait-ForOwnedPort $Sidecar 7800 600
    Invoke-Smoke $VoxPython 'voxcpm2' 7800 'voxcpm2.wav'
    Stop-OwnedProcess $Sidecar 7800
    $Sidecar = $null
    $SidecarPort = 0
}
finally {
    if ($null -ne $Sidecar) {
        Stop-OwnedProcess $Sidecar $SidecarPort
    }
    $env:PATH = $OriginalPath
    Remove-Item Env:TTS_LOCAL_AUTH_TOKEN, Env:TTS_LOCAL_SESSION_ID -ErrorAction SilentlyContinue
}

Write-Host "Real-engine validation passed. Evidence: $EvidenceDirectory"
