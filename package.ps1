param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',
    [string]$Dotnet = 'dotnet',
    [string]$CscToolPath
)

$ErrorActionPreference = 'Stop'
$Root = $PSScriptRoot
$Project = Join-Path $Root 'src\DesktopApp\TTS_WinForms_App.csproj'
$Publish = Join-Path $Root 'artifacts\publish'
New-Item -ItemType Directory -Force -Path $Publish | Out-Null
$RestoreArguments = @('restore', $Project, '--locked-mode', '-r', 'win-x64')
$Arguments = @(
    'publish', $Project, '-c', $Configuration, '--no-restore',
    '-r', 'win-x64', '--self-contained', 'true',
    '-o', $Publish
)
if (-not [string]::IsNullOrWhiteSpace($CscToolPath)) {
    $CompilerArguments = @(
        "-p:CscToolPath=$CscToolPath",
        '-p:CscToolExe=csc.cmd',
        '-p:UseSharedCompilation=false'
    )
    $RestoreArguments += $CompilerArguments
    $Arguments += $CompilerArguments
}
& $Dotnet @RestoreArguments
if ($LASTEXITCODE -ne 0) { throw "Restore failed with exit code $LASTEXITCODE." }
& $Dotnet @Arguments
if ($LASTEXITCODE -ne 0) { throw "Publish failed with exit code $LASTEXITCODE." }
Copy-Item -LiteralPath (Join-Path $Root 'src\SupertonicSidecar\secure_server.py') -Destination $Publish -Force
Write-Host "Published: $Publish"
