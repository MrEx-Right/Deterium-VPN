# Helpers for the CI workflows that need a real tunnel. Dot-source it:
#
#   . ./tools/ci/live-tunnel.ps1
#
# They drive the ignored `hold_tunnel_open` test in
# crates/deterium-engine/tests/live_tunnel.rs, which brings a tunnel up, says
# "ready" through a file, and stays up until a `done` file appears.

$ErrorActionPreference = "Stop"

function Get-LiveTestExe {
    $found = Get-ChildItem -Path "target\debug\deps" -Filter "live_tunnel-*.exe" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $found) { throw "live_tunnel test binary not found; run 'cargo test -p deterium-engine --test live_tunnel --no-run' first" }
    return $found.FullName
}

function Get-Trace([string]$Url) {
    # Cloudflare's trace page lists, among others, ip= and warp=on|off.
    $text = & curl.exe -sS --max-time 20 $Url
    if ($LASTEXITCODE -ne 0) { throw "curl $Url failed (exit $LASTEXITCODE)" }
    $trace = @{}
    foreach ($line in ($text -split "`n")) {
        if ($line -match '^([A-Za-z_]+)=(.*)$') { $trace[$Matches[1]] = $Matches[2].Trim() }
    }
    return $trace
}

function Start-Hold([string]$Profile, [string]$Dir) {
    if (Test-Path $Dir) { Remove-Item $Dir -Recurse -Force }
    New-Item -ItemType Directory -Force $Dir | Out-Null
    $env:DETERIUM_LIVE_PROFILE = (Resolve-Path $Profile).Path
    $env:DETERIUM_LIVE_DIR = (Resolve-Path $Dir).Path
    $log = Join-Path $Dir "test.log"
    $proc = Start-Process -FilePath (Get-LiveTestExe) `
        -ArgumentList "hold_tunnel_open", "--ignored", "--nocapture", "--exact" `
        -PassThru -NoNewWindow -RedirectStandardOutput $log -RedirectStandardError "$log.err"
    $null = $proc.Handle   # without this PowerShell can't read ExitCode later
    return $proc
}

function Wait-Ready($Proc, [string]$Dir, [int]$TimeoutSec = 120) {
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        if (Test-Path (Join-Path $Dir "ready")) { return }
        if (Test-Path (Join-Path $Dir "failed")) {
            throw "the tunnel did not come up:`n$(Get-Content (Join-Path $Dir 'failed') -Raw)"
        }
        if ($Proc.HasExited) {
            throw "the test process exited early (code $($Proc.ExitCode)):`n$(Get-Content (Join-Path $Dir 'test.log') -Raw)`n$(Get-Content (Join-Path $Dir 'test.log.err') -Raw)"
        }
        Start-Sleep -Milliseconds 500
    }
    throw "timed out after $TimeoutSec s waiting for the tunnel"
}

# Asks the test to disconnect, and waits until it has done so cleanly.
function Stop-Hold($Proc, [string]$Dir, [int]$TimeoutSec = 60) {
    Set-Content -Path (Join-Path $Dir "done") -Value "done"
    if (-not $Proc.WaitForExit($TimeoutSec * 1000)) {
        $Proc.Kill()
        throw "the tunnel did not disconnect within $TimeoutSec s"
    }
    if ($Proc.ExitCode -ne 0) { throw "the test failed during disconnect (exit $($Proc.ExitCode))" }
    if (-not (Test-Path (Join-Path $Dir "disconnected"))) { throw "no clean-disconnect marker was written" }
    return (Get-Content (Join-Path $Dir "disconnected") -Raw)
}

# Simulates a crash: the process dies without disconnecting.
function Kill-Hold($Proc) {
    if (-not $Proc.HasExited) { $Proc.Kill(); $Proc.WaitForExit(15000) | Out-Null }
}

function Run-Recovery {
    # If an earlier step failed before the test was built, no tunnel was ever
    # brought up, so there is nothing to put back (and the real error is above).
    if (-not (Get-ChildItem -Path "target\debug\deps" -Filter "live_tunnel-*.exe" -ErrorAction SilentlyContinue)) {
        Write-Host "no live_tunnel test binary was built; nothing to recover"
        return
    }
    $exe = Get-LiveTestExe
    & $exe "recover_after_crash" "--ignored" "--nocapture" "--exact"
    if ($LASTEXITCODE -ne 0) { throw "recover_after_crash failed (exit $LASTEXITCODE)" }
}

# The adapter the Deterium tunnel created (Wintun), by driver description.
function Get-TunnelAdapterAlias {
    $adapter = Get-NetAdapter -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceDescription -like "*Wintun*" -and $_.Status -eq "Up" } |
        Select-Object -First 1
    if (-not $adapter) { return $null }
    return $adapter.InterfaceAlias
}

# Which interface Windows would use to reach an address.
function Get-EgressAlias([string]$Address) {
    $route = Find-NetRoute -RemoteIPAddress $Address -ErrorAction Stop |
        Where-Object { $_.InterfaceAlias } | Select-Object -First 1
    return $route.InterfaceAlias
}
