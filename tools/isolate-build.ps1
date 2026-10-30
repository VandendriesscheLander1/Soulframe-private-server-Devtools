# Block every exe of a pinned build from the network (Windows Firewall, needs admin).
# Loopback is not filtered by Windows Firewall, so a local sf-server stays reachable.
# -Server <ip>: also let the copy reach that one address (a friend's server, Phase 6). Block rules always beat
# allow rules in Windows Firewall, so the block rules cover every address *except* that one.
# -Path <folder>: a player's own game copy (for sf-launch.exe) instead of a pinned build's pristine + work copies.
# Usage (elevated): tools\isolate-build.ps1 -Name P16H6 [-Server 100.64.1.2]
#                   tools\isolate-build.ps1 -Path D:\SoulframePrivate [-Server 100.64.1.2]
# Undo:             Remove-NetFirewallRule -Group 'Soulframe-P16H6'   (or the group name it prints)
param(
    [Parameter(Mandatory, ParameterSetName = 'build')][string]$Name,
    [Parameter(Mandatory, ParameterSetName = 'copy')][string]$Path,
    [string]$Server,
    [string]$BuildsRoot = (Join-Path $PSScriptRoot '..\..\soulframe-builds')
)
$ErrorActionPreference = 'Stop'
if ($Path) {
    $copyDir = [IO.Path]::GetFullPath($Path)
    if ($copyDir -match '\\Soulframe\\Downloaded(\\|$)|\\steamapps\\|\\Epic Games\\') {
        throw "$copyDir is a real game install. Firewall a copy, never the live game."
    }
    $group = "Soulframe-Copy-$((Split-Path $copyDir -Leaf) -replace '[^A-Za-z0-9_-]', '_')"
    $copies = @{ '' = $copyDir }
} else {
    $root = [IO.Path]::GetFullPath((Join-Path $BuildsRoot $Name))
    $group = "Soulframe-$Name"
    # Rules for pristine and the patched work copy; firewall rules may name paths that don't exist yet.
    $copies = [ordered]@{ 'pristine' = "$root\pristine"; 'work' = "$root\work" }
}

function Get-AllBut([string]$ip) {
    # IPv4 ranges around one address, plus all of IPv6.
    $b = [Net.IPAddress]::Parse($ip).GetAddressBytes()
    if ($b.Length -ne 4) { throw "-Server must be an IPv4 address (got $ip)" }
    [Array]::Reverse($b)
    $n = [uint64][BitConverter]::ToUInt32($b, 0)
    $fmt = { param($v) $x = [BitConverter]::GetBytes([uint32]$v); [Array]::Reverse($x); ([Net.IPAddress]::new($x)).ToString() }
    $ranges = @()
    if ($n -gt 1) { $ranges += "0.0.0.1-$(& $fmt ($n - 1))" }
    if ($n -lt 4294967295) { $ranges += "$(& $fmt ($n + 1))-255.255.255.255" }
    $ranges + '::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
}
$remote = if ($Server) { Get-AllBut $Server } else { 'Any' }

$first = @($copies.Values)[0]
$exes = Get-ChildItem $first -Recurse -Filter *.exe | ForEach-Object { $_.FullName.Substring($first.Length) }
if (-not $exes) { throw "No .exe files under $first" }

# Never leave the copy unblocked: try the address list on one disabled rule before touching the real ones.
$probe = "$group-probe"
try {
    New-NetFirewallRule -Group $probe -DisplayName $probe -Program "$first$($exes[0])" -Direction Outbound -Action Block `
        -Enabled False -RemoteAddress $remote | Out-Null
} finally {
    Remove-NetFirewallRule -Group $probe -ErrorAction SilentlyContinue
}

function Add-Blocks($addresses) {
    foreach ($copy in $copies.Keys) {
        foreach ($exe in $exes) {
            foreach ($dir in 'Outbound', 'Inbound') {
                New-NetFirewallRule -Group $group -DisplayName "$group $copy$exe $dir" -Program "$($copies[$copy])$exe" `
                    -Direction $dir -Action Block -Profile Any -RemoteAddress $addresses | Out-Null
            }
        }
    }
}
Remove-NetFirewallRule -Group $group -ErrorAction SilentlyContinue
try {
    Add-Blocks $remote
} catch {
    Remove-NetFirewallRule -Group $group -ErrorAction SilentlyContinue
    Add-Blocks 'Any'  # back to blocking everything, then report the failure
    throw "Could not apply -Server $Server ($_). Everything is blocked again, as before."
}
Get-NetFirewallRule -Group $group | Select-Object DisplayName, Direction, Action | Format-Table -AutoSize
"Group: $group"
if ($Server) { "Blocked everything except $Server." }
