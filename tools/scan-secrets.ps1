# Fails if anything in the source tree looks like a real secret. Run it before
# publishing and in CI:  pwsh ./tools/scan-secrets.ps1
#
# It looks for what this project actually handles: WireGuard keys (32 bytes of
# base64, 44 characters), PEM private keys, and Windows-DPAPI blobs from a real
# profile. Test fixtures that need a key-shaped value use the throw-away keys
# listed in $Allowed, which protect nothing.

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

# Keys that exist only inside tests and documentation. Generated for that
# purpose; they were never configured on any server.
$Allowed = @(
    "AHuqsk/lVEUcMCJKwoyy9tSu6TUJba1CyfmMJ8OHzGw=",  # test private key
    "rJ7Pb5Ej25Q/LET9w856N4pej7pF4+UT7BSdLnfsKmo=",  # its public key
    "hNB8xHQbFgfPavZ3NEhjv5+SRZ6TESr65wrlc71XuxA="   # a test peer public key
)

$skipDirs = @("target", ".dev-keys", "profiles", ".git", "node_modules")
$files = Get-ChildItem -Path $root -Recurse -File -Force | Where-Object {
    $rel = $_.FullName.Substring($root.Length).TrimStart("\", "/")
    $top = ($rel -split "[\\/]")[0]
    ($skipDirs -notcontains $top) -and ($_.Length -lt 2MB) -and
    ($_.Extension -notin ".dll", ".exe", ".png", ".ico", ".pdb", ".lock")
}

$findings = @()
foreach ($f in $files) {
    $text = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction SilentlyContinue
    if (-not $text) { continue }
    $rel = $f.FullName.Substring($root.Length).TrimStart("\", "/")

    foreach ($m in [regex]::Matches($text, '(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{43}=(?![A-Za-z0-9+/=])')) {
        if ($Allowed -notcontains $m.Value) { $findings += "$rel : key-shaped value $($m.Value)" }
    }
    if ($text -match '-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----\s+[A-Za-z0-9+/=\r\n]{40,}') {
        # Documentation and tests mention the header; a real key has a body.
        if ($rel -notmatch '\.rs$|\.md$|\.ps1$') { $findings += "$rel : PEM private key" }
    }
    if ($text -match 'dpapi:v1:[A-Za-z0-9+/=]{40,}') {
        $findings += "$rel : encrypted profile secret (belongs to one Windows account, do not publish)"
    }
}

if ($findings.Count -gt 0) {
    Write-Host "Possible secrets found:" -ForegroundColor Red
    $findings | Sort-Object -Unique | ForEach-Object { Write-Host "  $_" }
    exit 1
}
Write-Host "No secrets found in $($files.Count) files."
