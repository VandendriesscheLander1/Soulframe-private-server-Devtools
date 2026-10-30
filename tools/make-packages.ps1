# Build the two folders to hand out (Phase 7): dist\sf-host (the server, for whoever hosts) and dist\sf-join (for players).
# Usage: tools\make-packages.ps1 [-Server <address>]  (default 127.0.0.1: each player runs the server on their own PC)
# Neither folder contains game files. sf-host does contain data extracted from the game (gamedata): private use only.
param([string]$Server = '127.0.0.1')
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$dist = Join-Path $root 'dist'
$bin = Join-Path $root 'bootstrap\target\release'
if ((Get-Item "$root\bootstrap\src\lib.rs").LastWriteTime -gt (Get-Item "$bin\sf_bootstrap.dll").LastWriteTime) {
    throw 'sf_bootstrap.dll is older than lib.rs. Run: cargo build --release --manifest-path bootstrap\Cargo.toml'
}
Remove-Item $dist -Recurse -Force -ErrorAction SilentlyContinue

# Host: the server (tools\*.py with fixtures\ and gamedata\); it makes its own certs\ on first start.
$h = "$dist\sf-host"
$srv = "$h\soulframe-private-server"
New-Item -ItemType Directory -Force "$srv\tools", "$srv\data" | Out-Null
Copy-Item "$root\tools\*.py" "$srv\tools"
Copy-Item "$root\fixtures", "$root\gamedata" $srv -Recurse
if (Test-Path "$root\data\seed.json") { Copy-Item "$root\data\seed.json" "$srv\data" }  # new players start from this inventory
Copy-Item "$root\release\host\*" $h

# Join: launcher, DLL, the host's address, and the setup that copies + firewalls their own install.
$j = "$dist\sf-join"
New-Item -ItemType Directory -Force $j | Out-Null
Copy-Item "$bin\sf-launch.exe", "$bin\sf_bootstrap.dll", "$root\tools\isolate-build.ps1", "$root\release\join\*" $j
Set-Content "$j\sf-server.txt" $Server -Encoding ascii

Get-ChildItem $dist -Recurse -File | Measure-Object Length -Sum | ForEach-Object { "{0} files, {1:N0} MB in $dist" -f $_.Count, ($_.Sum / 1MB) }
