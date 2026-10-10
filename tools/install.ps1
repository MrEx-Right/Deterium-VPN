# Builds Deterium from this source tree and installs it for the current user.
# Nothing is downloaded as a ready-made program of ours: the app is compiled
# here, from the code you are looking at.
#
#   Install-Deterium.bat                 (double-click)
#   pwsh ./tools/install.ps1 [-InstallDir <folder>] [-SupportDir <folder>] [-NoShortcut] [-NoRegister] [-Yes]
#
# What it does:
#   1. checks that the Rust toolchain is there (it never installs one for you);
#   2. offers to fetch the official OpenVPN so the app has it built in
#      (tools/fetch-openvpn.ps1: pinned SHA-256 and signature check; only unpacked,
#      never installed);
#   3. cargo build --release;
#   4. puts Deterium.exe on your Desktop, adds a Start Menu shortcut and an entry
#      in Settings > Apps (both for this user only). The uninstaller is kept in
#      %LOCALAPPDATA%\Deterium.
#
# No administrator rights are needed. The background service, which does need
# them, is installed from inside the app (one permission prompt, your choice).
# Drivers: none are installed, now or later, apart from the signed Wintun
# adapter driver the app itself loads when it connects.

param(
    [string]$InstallDir = [Environment]::GetFolderPath("Desktop"),
    [string]$SupportDir = (Join-Path $env:LOCALAPPDATA "Deterium"),
    [switch]$NoShortcut,
    [switch]$NoRegister,
    [switch]$SkipOpenVpn,
    [switch]$Yes
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$openvpnAssets = Join-Path $root "crates\deterium-proto-openvpn\assets\openvpn\bin\openvpn.exe"

function Step($text) { Write-Host ""; Write-Host "== $text" -ForegroundColor Cyan }
function Stop-Install($text) { Write-Host ""; Write-Host $text -ForegroundColor Red; exit 1 }

Step "Checking the Rust toolchain"
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Stop-Install @"
Rust isn't installed, so Deterium can't be built yet.
  1. Install Rust from https://rustup.rs (choose the default "MSVC" option;
     it also tells you if the Visual Studio Build Tools are missing).
  2. Run this installer again.
"@
}
Write-Host (& cargo --version)

if (-not $SkipOpenVpn -and -not (Test-Path $openvpnAssets)) {
    Step "OpenVPN support"
    Write-Host "Deterium can carry the official OpenVPN inside the app, so nothing else has to be installed."
    Write-Host "That means downloading OpenVPN 2.6.17 (about 4 MB) from swupdate.openvpn.org."
    Write-Host "The download is checked against a fixed SHA-256 and OpenVPN Inc.'s signature, then only unpacked."
    $answer = if ($Yes) { "y" } else { Read-Host "Include OpenVPN? [Y/n]" }
    if ($answer -eq "" -or $answer -match "^[yY]") {
        & (Join-Path $PSScriptRoot "fetch-openvpn.ps1")
    } else {
        Write-Host "Skipping. WireGuard works either way; OpenVPN servers will need OpenVPN installed separately."
    }
}

Step "Building (the first build takes a few minutes)"
Push-Location $root
try {
    & cargo build --release -p deterium-gui
    if ($LASTEXITCODE -ne 0) { Stop-Install "The build failed (see the messages above)." }
} finally { Pop-Location }
$built = Join-Path $root "target\release\deterium-gui.exe"
if (-not (Test-Path $built)) { Stop-Install "The build finished but $built is missing." }

Step "Installing to $InstallDir"
New-Item -ItemType Directory -Force $InstallDir, $SupportDir | Out-Null
$target = Join-Path $InstallDir "Deterium.exe"
try {
    Copy-Item $built $target -Force
} catch {
    Stop-Install "Couldn't replace $target. Is Deterium still open? Close it (also from the tray icon) and run this again."
}
$uninstallScript = Join-Path $SupportDir "uninstall.ps1"
Copy-Item (Join-Path $PSScriptRoot "uninstall.ps1") $uninstallScript -Force
# Marks the folder as ours, so the uninstaller knows it may delete it.
Set-Content -Path (Join-Path $SupportDir ".deterium-support") -Value "Created by Deterium tools/install.ps1" -Encoding ASCII

if (-not $NoShortcut) {
    $programs = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs"
    $shell = New-Object -ComObject WScript.Shell
    $link = $shell.CreateShortcut((Join-Path $programs "Deterium VPN.lnk"))
    $link.TargetPath = $target
    $link.WorkingDirectory = $InstallDir
    $link.Description = "Deterium VPN - self-hosted VPN client"
    $link.Save()
    Write-Host "Start Menu shortcut: Deterium VPN"
}

if (-not $NoRegister) {
    $key = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\DeteriumVPN"
    $version = (Get-Item $target).VersionInfo.FileVersion
    New-Item -Path $key -Force | Out-Null
    $uninstaller = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$uninstallScript`" -InstallDir `"$InstallDir`""
    $values = @{
        DisplayName     = "Deterium VPN"
        DisplayVersion  = $version
        Publisher       = "Deterium contributors"
        InstallLocation = $InstallDir
        DisplayIcon     = $target
        UninstallString = $uninstaller
        NoModify        = 1
        NoRepair        = 1
    }
    foreach ($name in $values.Keys) { Set-ItemProperty -Path $key -Name $name -Value $values[$name] }
    Write-Host "Listed in Settings > Apps"
}

Write-Host ""
Write-Host "Deterium is installed: $target" -ForegroundColor Green
Write-Host "Open it from the Start Menu. The first time you connect it offers the background service (recommended)."
