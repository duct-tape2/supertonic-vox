param(
    [Parameter(Mandatory)]
    [string]$File,
    [string]$CertificateThumbprint,
    [string]$PfxPath,
    [Security.SecureString]$PfxPassword,
    [string]$TimestampUrl = 'http://timestamp.digicert.com'
)

$ErrorActionPreference = 'Stop'
if (($CertificateThumbprint -and $PfxPath) -or (-not $CertificateThumbprint -and -not $PfxPath)) {
    throw 'Specify exactly one of -CertificateThumbprint or -PfxPath.'
}
$SignTool = (Get-Command signtool.exe -ErrorAction Stop).Source
$Arguments = @('sign', '/fd', 'SHA256', '/tr', $TimestampUrl, '/td', 'SHA256')
if ($CertificateThumbprint) {
    $Arguments += @('/sha1', $CertificateThumbprint)
} else {
    $Arguments += @('/f', (Resolve-Path -LiteralPath $PfxPath).Path)
    if ($PfxPassword) {
        $Plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR(
            [Runtime.InteropServices.Marshal]::SecureStringToBSTR($PfxPassword))
        try { $Arguments += @('/p', $Plain) }
        finally { $Plain = $null }
    }
}
$Arguments += (Resolve-Path -LiteralPath $File).Path
& $SignTool @Arguments
if ($LASTEXITCODE -ne 0) { throw "signtool failed with exit code $LASTEXITCODE." }
Write-Host 'Signature applied. No certificate material was copied into the release.'
