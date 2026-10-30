# Point *.soulframe.com at 127.0.0.1 and trust our local cert (Phase 2, findings/0011). Needs admin.
# Usage (elevated): tools\redirect.ps1 -On     before running the box against tools\dummy_server.py
#                   tools\redirect.ps1 -Off    before playing the LIVE game again (it can't log in while On)
# Both changes are machine-wide (the hosts file and the cert store are outside Sandboxie).
#Requires -RunAsAdministrator
param([switch]$On, [switch]$Off)
$ErrorActionPreference = 'Stop'
if ($On -eq $Off) { throw 'Pass exactly one of -On / -Off.' }

$hosts = "$env:SystemRoot\System32\drivers\etc\hosts"
$begin, $end = '# >>> soulframe-private-server', '# <<< soulframe-private-server'
# Pre-login hosts plus the ones the login response names (0007); content-dev/-test are unused clusters.
$names = 'origin', 'content', 'api', 'arbiter', 'irc' | ForEach-Object { "$_.soulframe.com" }
$cert = Join-Path $PSScriptRoot '..\certs\ca.crt'  # CA name-constrained to soulframe.com

# Drop any old block first, so -On is idempotent and -Off is just this.
$inBlock = $false
$lines = @(Get-Content $hosts | Where-Object {
    if ($_ -eq $begin) { $inBlock = $true }
    $keep = -not $inBlock
    if ($_ -eq $end) { $inBlock = $false }
    $keep
})
$thumb = (New-Object Security.Cryptography.X509Certificates.X509Certificate2 (Resolve-Path $cert).Path).Thumbprint
# By subject too, so certs from earlier versions of this script go as well.
Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Thumbprint -eq $thumb -or $_.Subject -like 'CN=soulframe private server*' } | Remove-Item

if ($On) {
    $lines += @($begin) + ($names | ForEach-Object { "127.0.0.1 $_" }) + @($end)
    Import-Certificate -FilePath $cert -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
}
# Something (Defender scanning, usually) briefly holds the hosts file open; retry instead of failing.
for ($try = 1; ; $try++) {
    try { [IO.File]::WriteAllLines($hosts, [string[]]$lines, [Text.Encoding]::ASCII); break }
    catch { if ($try -ge 20) { throw }; Start-Sleep -Milliseconds 500 }
}
Clear-DnsClientCache

$state = if ($On) { 'ON' } else { 'OFF' }
"Redirect $state. Hosts now resolve to:"
foreach ($n in $names) { try { "  $n -> " + [Net.Dns]::GetHostAddresses($n)[0] } catch { "  $n -> (no answer)" } }
"Cert $thumb in LocalMachine\Root: " + [bool](Get-ChildItem Cert:\LocalMachine\Root | Where-Object Thumbprint -eq $thumb)
