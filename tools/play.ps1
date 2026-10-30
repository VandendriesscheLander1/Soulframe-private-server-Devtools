# Launch a pinned build inside its Sandboxie box, refusing if isolation is not in place.
# Usage: tools\play.ps1                 (P16H6 pristine)
#        tools\play.ps1 -Copy work      (patched copy, Phase 2+)
param(
    [string]$Name = 'P16H6',
    [ValidateSet('pristine', 'work')][string]$Copy = 'pristine',
    [string]$Box = "Soulframe$Name",
    [string]$BuildsRoot = (Join-Path $PSScriptRoot '..\..\soulframe-builds')
)
$ErrorActionPreference = 'Stop'
$exe = [IO.Path]::GetFullPath((Join-Path $BuildsRoot "$Name\$Copy\Soulframe.x64.exe"))
if (-not (Test-Path $exe)) { throw "No exe at $exe" }

# 1. Firewall on, and an enabled outbound block rule for exactly this exe.
if (Get-NetFirewallProfile | Where-Object { -not $_.Enabled }) { throw 'A Windows Firewall profile is disabled.' }
$blocked = Get-NetFirewallApplicationFilter -Program $exe -ErrorAction SilentlyContinue | Get-NetFirewallRule |
    Where-Object { $_.Enabled -eq 'True' -and $_.Direction -eq 'Outbound' -and $_.Action -eq 'Block' }
if (-not $blocked) { throw "No outbound block rule for $exe. Run tools\isolate-build.ps1 -Name $Name as admin." }

# 2. Pristine must still match the pinned hash (the work copy is patched, so skip it there).
if ($Copy -eq 'pristine') {
    $want = (Select-String (Join-Path $PSScriptRoot "..\builds\$Name\manifest.sha256") -Pattern '  Soulframe\.x64\.exe$').Line.Split(' ')[0]
    $have = (Get-FileHash $exe -Algorithm SHA256).Hash.ToLower()
    if ($have -ne $want) { throw "Exe hash $have does not match the $Name pin $want." }
}

# 3. sf-bootstrap.dll in this box only: redirect to 127.0.0.1 + TLS checks off, no machine-wide change (0013).
$start = 'C:\Program Files\Sandboxie-Plus\Start.exe'
$sbieIni = 'C:\Program Files\Sandboxie-Plus\SbieIni.exe'
$dll = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\bootstrap\target\release\sf_bootstrap.dll'))
if (-not (Test-Path $dll)) { throw "No $dll. Run: cargo build --release --manifest-path bootstrap\Cargo.toml" }
$src = Join-Path $PSScriptRoot '..\bootstrap\src\lib.rs'
if ((Get-Item $src).LastWriteTime -gt (Get-Item $dll).LastWriteTime) {
    throw "sf_bootstrap.dll is older than lib.rs (a running game locks it). Close the game, then: cargo build --release --manifest-path bootstrap\Cargo.toml"
}
if ((& $sbieIni query $Box InjectDll64) -ne $dll) {
    & $sbieIni set $Box InjectDll64 $dll
    & $start /reload
}

# 4. Same flags the official launcher uses for the live game (from EE.log), minus the launcher itself.
$gameArgs = '-windowMode:2 -shaderCache:1 -graphicsDriver:dx11 -gpuPreference:2 -cluster:public -language:en'
Push-Location (Split-Path $exe)  # the game logs and may resolve paths from its working directory
try { & $start "/box:$Box" $exe $gameArgs.Split(' ') } finally { Pop-Location }
"Launched $Name/$Copy in box $Box (network blocked by firewall, *.soulframe.com -> 127.0.0.1 via sf-bootstrap)."
