param(
    [string]$Dotnet = 'dotnet',
    [string]$CscToolPath,
    [string]$VoxPython,
    [string]$VoxPackages,
    [string]$SupertonicPython,
    [string]$SupertonicPackages
)

$ErrorActionPreference = 'Stop'
$Root = $PSScriptRoot
$TestProject = Join-Path $Root 'tests\DesktopApp.SecurityTests\DesktopApp.SecurityTests.csproj'
$DotnetArguments = @('run', '--project', $TestProject, '-c', 'Release')
if (-not [string]::IsNullOrWhiteSpace($CscToolPath)) {
    $DotnetArguments += @(
        "-p:CscToolPath=$CscToolPath",
        '-p:CscToolExe=csc.cmd',
        '-p:UseSharedCompilation=false'
    )
}
& $Dotnet @DotnetArguments
if ($LASTEXITCODE -ne 0) { throw 'C# security tests failed.' }

if ($VoxPython) {
    $env:PYTHONPATH = $VoxPackages
    $env:TTS_LOCAL_AUTH_TOKEN = 'test-token'
    $env:TTS_LOCAL_SESSION_ID = 'test-session'
    & $VoxPython -m unittest discover -s (Join-Path $Root 'src\VoxCPM2Sidecar\tests') -v
    if ($LASTEXITCODE -ne 0) { throw 'VoxCPM2 Python tests failed.' }
}

if ($SupertonicPython) {
    $env:PYTHONPATH = (@($SupertonicPackages, (Join-Path $Root 'src\SupertonicSidecar')) -join [IO.Path]::PathSeparator)
    $env:TTS_LOCAL_AUTH_TOKEN = 'test-token'
    $env:TTS_LOCAL_SESSION_ID = 'test-session'
    & $SupertonicPython -m unittest discover -s (Join-Path $Root 'src\SupertonicSidecar\tests') -v
    if ($LASTEXITCODE -ne 0) { throw 'Supertonic Python tests failed.' }
}
