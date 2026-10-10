# Removes what tools/install.ps1 put on this PC: Deterium.exe, the Start Menu
# shortcut, the Settings > Apps entry and (with your permission prompt) the
# background service. Your servers in %APPDATA%\Deterium are kept unless you
# pass -RemoveData.
#
#   pwsh ./uninstall.ps1 [-InstallDir <folder with Deterium.exe>] [-RemoveData] [-KeepService]
#
# Only Deterium.exe and this script's own folder are deleted, never the folder
# Deterium.exe was in (by default that is your Desktop).

param(
    [switch]$RemoveData,
    [switch]$KeepService,
    [string]$InstallDir = [Environment]::GetFolderPath("Desktop")
)

$ErrorActionPreference = "Stop"
$exe = Join-Path $InstallDir "Deterium.exe"

# The service lives in Program Files and needs administrator rights to remove.
# The app's own command does it, so the tunnel is torn down cleanly first.
if ((Test-Path $exe) -and -not $KeepService) {
    $status = (& $exe service status 2>$null | Out-String).Trim()
    if ($status -match "^installed") {
        Write-Host "Removing the background service (a permission prompt will appear)..."
        $p = Start-Process -FilePath $exe -ArgumentList "service", "uninstall" -Verb RunAs -Wait -PassThru
        if ($p.ExitCode -ne 0) {
            Write-Host "The service wasn't removed (exit code $($p.ExitCode)). Remove it from Deterium: Background service > Remove, then run this again." -ForegroundColor Red
            exit 1
        }
    }
}

Get-Process -Name "Deterium" -ErrorAction SilentlyContinue |
    Where-Object { $_.Path -and ($_.Path -like "$InstallDir*") } |
    ForEach-Object { $_.CloseMainWindow() | Out-Null; Start-Sleep -Milliseconds 800; if (-not $_.HasExited) { $_.Kill() } }

$shortcut = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Deterium VPN.lnk"
if (Test-Path $shortcut) { Remove-Item $shortcut -Force }
Remove-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\DeteriumVPN" -Recurse -Force -ErrorAction SilentlyContinue

if ($RemoveData) {
    $data = Join-Path $env:APPDATA "Deterium"
    if (Test-Path $data) { Remove-Item $data -Recurse -Force; Write-Host "Removed your saved servers ($data)." }
}

# Only the one file we installed. $InstallDir itself (the Desktop by default) stays.
if (Test-Path $exe) {
    try { Remove-Item $exe -Force -ErrorAction Stop }
    catch {
        Write-Host "Couldn't delete $exe. Close Deterium (also from the tray icon) and run this again." -ForegroundColor Red
        exit 1
    }
}

# This script lives in a folder of its own that it deletes (never the folder the
# app was in), so the last step runs from a copy.
$cleanup = Join-Path $env:TEMP "deterium-uninstall-cleanup.cmd"
# Only ever the installer's own support folder: running this script straight from
# a source checkout must not delete the checkout's tools folder.
$supportDir = Join-Path $env:LOCALAPPDATA "Deterium"
$lines = @("@echo off", "ping -n 3 127.0.0.1 >nul")
if ($PSScriptRoot.TrimEnd('\') -ieq $supportDir -or (Test-Path (Join-Path $PSScriptRoot ".deterium-support"))) {
    $lines += "rmdir /s /q `"$PSScriptRoot`""
}
$lines += "del `"%~f0`""
Set-Content -Path $cleanup -Value $lines -Encoding ASCII
Start-Process -FilePath "cmd.exe" -ArgumentList "/c", "`"$cleanup`"" -WindowStyle Hidden
Write-Host "Deterium was removed."
