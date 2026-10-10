# Turns the profile `wgcf generate` writes (a Cloudflare WARP account) into the
# small, safe profile the CI tunnel tests use.
#
#   -In        wgcf-profile.conf
#   -Out       where to write the test profile
#   -Endpoint  optional host:port to put in place of the real endpoint (the
#              encryption test points it at a local UDP relay)
#
# What changes, and why:
#   * AllowedIPs becomes 1.1.1.1/32 and 1.0.0.1/32 only. The runner's own
#     traffic (including the connection to GitHub) never enters the tunnel, so a
#     broken tunnel can't cut the job off.
#   * DNS is dropped: the tests must not touch the runner's resolver.
#   * IPv6 addresses are dropped: the tests only exercise IPv4.
#   * No kill switch is set, for the same reason as the first point.
# The real endpoint is written next to the output as <Out>.endpoint.

param(
    [Parameter(Mandatory)][string]$In,
    [Parameter(Mandatory)][string]$Out,
    [string]$Endpoint = "",
    [switch]$MaskSecrets
)

$ErrorActionPreference = "Stop"
$values = @{}
foreach ($line in Get-Content $In) {
    if ($line -match '^\s*([A-Za-z]+)\s*=\s*(.+?)\s*$') {
        # wgcf writes one Address line per family; keep them all.
        if ($Matches[1] -eq "Address" -and $values.ContainsKey("Address")) {
            $values["Address"] += ", " + $Matches[2]
        } else {
            $values[$Matches[1]] = $Matches[2]
        }
    }
}
foreach ($need in "PrivateKey", "Address", "PublicKey", "Endpoint") {
    if (-not $values.ContainsKey($need)) { throw "$In has no $need line" }
}

if ($MaskSecrets) {
    # Keep the key out of the job log even if something prints the file.
    Write-Host "::add-mask::$($values['PrivateKey'])"
}

$v4 = @($values["Address"] -split "\s*,\s*" | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+/\d+$' })
if ($v4.Count -eq 0) { throw "the profile has no IPv4 address" }
$mtu = if ($values.ContainsKey("MTU")) { $values["MTU"] } else { "1280" }
$endpoint = if ($Endpoint) { $Endpoint } else { $values["Endpoint"] }

$conf = @(
    "[Interface]",
    "PrivateKey = $($values['PrivateKey'])",
    "Address = $($v4 -join ', ')",
    "MTU = $mtu",
    "",
    "[Peer]",
    "PublicKey = $($values['PublicKey'])",
    "Endpoint = $endpoint",
    "AllowedIPs = 1.1.1.1/32, 1.0.0.1/32",
    "PersistentKeepalive = 25"
)
Set-Content -Path $Out -Value $conf -Encoding ASCII
Set-Content -Path "$Out.endpoint" -Value $values["Endpoint"] -Encoding ASCII -NoNewline
Write-Host "Wrote $Out (endpoint $endpoint, routes 1.1.1.1/32 and 1.0.0.1/32 only)"
