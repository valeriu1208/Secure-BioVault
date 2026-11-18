# Generate a locally trusted TLS certificate for the Caddy HTTPS proxy (Windows).
# Each developer runs this on their own machine: it installs mkcert's local CA
# into this machine's trust store and issues a certificate signed by it.
#
# Usage: powershell -ExecutionPolicy Bypass -File scripts\gen-tls-cert.ps1 [-Force] [extra-hostname-or-ip ...]
param(
    [switch]$Force,
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$ExtraNames = @()
)
$ErrorActionPreference = "Stop"

Set-Location (Join-Path $PSScriptRoot "..")
$TlsDir = "secrets/tls"
$Cert = "$TlsDir/cert.pem"
$Key = "$TlsDir/key.pem"

if (-not (Get-Command mkcert -ErrorAction SilentlyContinue)) {
    Write-Error "mkcert is not installed. Install it with 'choco install mkcert' or 'scoop install mkcert'."
}

if (-not $Force -and ((Test-Path $Cert) -or (Test-Path $Key))) {
    Write-Error "TLS certificate already exists in $TlsDir. Re-run with -Force to replace it."
}

mkcert -install
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

New-Item -ItemType Directory -Force -Path $TlsDir | Out-Null
mkcert -cert-file $Cert -key-file $Key localhost 127.0.0.1 ::1 @ExtraNames
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "Certificate written to $Cert. Start the stack and open https://localhost"
