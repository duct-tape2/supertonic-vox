param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',
    [string]$Dotnet = 'dotnet',
    [string]$CscToolPath
)

$ErrorActionPreference = 'Stop'
$Root = $PSScriptRoot
$Project = Join-Path $Root 'src\DesktopApp\TTS_WinForms_App.csproj'
$RestoreArguments = @('restore', $Project, '--locked-mode')
$Arguments = @('build', $Project, '-c', $Configuration, '--no-restore')
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
if ($LASTEXITCODE -ne 0) { throw "Build failed with exit code $LASTEXITCODE." }
