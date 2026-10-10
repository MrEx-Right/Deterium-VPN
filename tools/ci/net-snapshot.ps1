# Writes a plain-text snapshot of what a VPN is allowed to change on a PC:
# network adapters, IPv4 addresses, IPv4 routes and DNS servers. It only reads.
#
#   net-snapshot.ps1 -Out before.txt
#   net-snapshot.ps1 -Out after.txt
#   net-snapshot.ps1 -Before before.txt -After after.txt   (exit code 1 if different)
#
# The tunnel tests take one before connecting and one after disconnecting and
# require them to match.

param(
    [string]$Out,
    [string]$Before,
    [string]$After
)

$ErrorActionPreference = "Stop"

if ($Before -or $After) {
    if (-not ($Before -and $After)) { throw "give both -Before and -After" }
    $a = Get-Content $Before
    $b = Get-Content $After
    $diff = Compare-Object $a $b
    if ($diff) {
        Write-Host "The network is NOT the same as before:" -ForegroundColor Red
        foreach ($d in $diff) {
            $side = if ($d.SideIndicator -eq "<=") { "only before" } else { "only after " }
            Write-Host "  $side | $($d.InputObject)"
        }
        exit 1
    }
    Write-Host "Network identical to the snapshot ($($a.Count) lines compared)."
    exit 0
}

if (-not $Out) { throw "give -Out <file>, or -Before <file> -After <file> to compare" }

$lines = New-Object System.Collections.Generic.List[string]

$lines.Add("# adapters (name | description | status)")
Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue |
    Sort-Object Name |
    ForEach-Object { $lines.Add("$($_.Name) | $($_.InterfaceDescription) | $($_.Status)") }

$lines.Add("# ipv4 addresses (interface | address/prefix)")
Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Sort-Object InterfaceAlias, IPAddress |
    ForEach-Object { $lines.Add("$($_.InterfaceAlias) | $($_.IPAddress)/$($_.PrefixLength)") }

$lines.Add("# ipv4 routes (destination | next hop | interface | metric)")
Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Sort-Object DestinationPrefix, InterfaceAlias, NextHop |
    ForEach-Object { $lines.Add("$($_.DestinationPrefix) | $($_.NextHop) | $($_.InterfaceAlias) | $($_.RouteMetric)") }

$lines.Add("# dns servers (interface | servers)")
Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Sort-Object InterfaceAlias |
    ForEach-Object { $lines.Add("$($_.InterfaceAlias) | $($_.ServerAddresses -join ',')") }

Set-Content -Path $Out -Value $lines -Encoding UTF8
Write-Host "Snapshot written to $Out ($($lines.Count) lines)"
