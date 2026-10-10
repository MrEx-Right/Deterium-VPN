# Downloads the official OpenVPN Windows installer, checks it, and unpacks the
# few files Deterium bundles into crates\deterium-proto-openvpn\assets\openvpn\.
# Nothing is installed on this PC: the MSI is only unpacked (msiexec /a).
#
#   pwsh ./tools/fetch-openvpn.ps1
#
# The build embeds whatever is in that folder into Deterium.exe. If the folder
# is empty the build still works, but the app then needs OpenVPN installed
# separately. The folder is git-ignored: the binaries are fetched on the user's
# own PC (tools/install.ps1 offers to), not stored in the source tree (they are
# GPL-2.0 licensed third-party programs).

$ErrorActionPreference = "Stop"
$version = "2.6.17-I001"
$msiName = "OpenVPN-$version-amd64.msi"
$url = "https://swupdate.openvpn.org/community/releases/$msiName"
# SHA-256 of the MSI as downloaded on 2026-10-06 from the official site.
# 2.6.x on purpose: OpenVPN 2.7 removed Wintun support (it wants the ovpn-dco or
# tap-windows6 drivers), and Deterium only ever installs the Wintun driver.
$sha256 = "961e38b4872f022cc63160bd1490af74e3adc88ec1f2e366964f1bbfaff6fce8"
$signer = "OpenVPN Inc."

$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$dest = Join-Path $root "crates\deterium-proto-openvpn\assets\openvpn"
$work = Join-Path ([IO.Path]::GetTempPath()) "deterium-openvpn-fetch"
Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $work | Out-Null

$msi = Join-Path $work $msiName
Write-Host "Downloading $url"
Invoke-WebRequest -Uri $url -OutFile $msi -UseBasicParsing

$hash = (Get-FileHash $msi -Algorithm SHA256).Hash.ToLower()
if ($hash -ne $sha256) { throw "SHA-256 mismatch: expected $sha256, got $hash" }
$sig = Get-AuthenticodeSignature $msi
if ($sig.Status -ne "Valid" -or $sig.SignerCertificate.Subject -notmatch [regex]::Escape($signer)) {
    throw "The installer's signature isn't a valid '$signer' signature ($($sig.Status))"
}
Write-Host "Checksum and signature are good."

$extract = Join-Path $work "x"
$p = Start-Process msiexec.exe -ArgumentList @("/a", "`"$msi`"", "/qn", "TARGETDIR=`"$extract`"") -Wait -PassThru
if ($p.ExitCode -ne 0) { throw "msiexec failed with $($p.ExitCode)" }

$wanted = @(
    "bin\openvpn.exe",
    "bin\libcrypto-3-x64.dll",
    "bin\libssl-3-x64.dll",
    "bin\libpkcs11-helper-1.dll",
    "bin\vcruntime140.dll",
    "ssl\modules\legacy.dll",
    "license.txt"
)
Remove-Item $dest -Recurse -Force -ErrorAction SilentlyContinue
foreach ($rel in $wanted) {
    $from = Join-Path $extract "OpenVPN\$rel"
    if (-not (Test-Path $from)) { throw "$rel is missing from the installer" }
    $to = Join-Path $dest $rel
    New-Item -ItemType Directory -Force (Split-Path $to) | Out-Null
    Copy-Item $from $to
}
Set-Content -Path (Join-Path $dest "VERSION") -Value $version -Encoding ASCII
Remove-Item $work -Recurse -Force
Write-Host "Done: OpenVPN $version unpacked to $dest"
