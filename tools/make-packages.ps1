# Build the two folders to hand out (Phase 7): dist\sf-host (the server, for whoever hosts) and dist\sf-join (for players).
# Usage: tools\make-packages.ps1 -Server <host address players use, e.g. a Tailscale 100.x IP>
# Neither folder contains game files. sf-host does contain data extracted from the game (soulframe-pipeline): private use only.
param([Parameter(Mandatory)][string]$Server)
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$dist = Join-Path $root 'dist'
$bin = Join-Path $root 'bootstrap\target\release'
if ((Get-Item "$root\bootstrap\src\lib.rs").LastWriteTime -gt (Get-Item "$bin\sf_bootstrap.dll").LastWriteTime) {
    throw 'sf_bootstrap.dll is older than lib.rs. Run: cargo build --release --manifest-path bootstrap\Cargo.toml'
}
Remove-Item $dist -Recurse -Force -ErrorAction SilentlyContinue

# Host: the server with the sibling folders it reads (tools\admin.py, tools\vendor.py), in the same layout.
$h = "$dist\sf-host"
$srv = "$h\soulframe-private-server"
New-Item -ItemType Directory -Force "$srv\tools", "$srv\data", "$srv\certs", "$h\soulframe-pipeline\Languages", "$h\soulframe-rust-workspace\research" | Out-Null
Copy-Item "$root\tools\*.py" "$srv\tools"
Copy-Item "$root\fixtures" $srv -Recurse
Copy-Item "$root\data\seed.json" "$srv\data"  # new players start from this inventory
Copy-Item "$root\certs\soulframe.crt", "$root\certs\soulframe.key", "$root\certs\ca.crt" "$srv\certs"  # never ca.key
Copy-Item "$root\..\soulframe-pipeline\formatted_packages.json" "$h\soulframe-pipeline"
Copy-Item "$root\..\soulframe-pipeline\Languages\Languages_en.json" "$h\soulframe-pipeline\Languages"
Copy-Item "$root\..\soulframe-rust-workspace\research\shop_rolls.py" "$h\soulframe-rust-workspace\research"
Copy-Item "$root\release\host\*" $h

# Join: launcher, DLL, the host's address, and the setup that copies + firewalls their own install.
$j = "$dist\sf-join"
New-Item -ItemType Directory -Force $j | Out-Null
Copy-Item "$bin\sf-launch.exe", "$bin\sf_bootstrap.dll", "$root\tools\isolate-build.ps1", "$root\release\join\*" $j
Set-Content "$j\sf-server.txt" $Server -Encoding ascii

Get-ChildItem $dist -Recurse -File | Measure-Object Length -Sum | ForEach-Object { "{0} files, {1:N0} MB in $dist" -f $_.Count, ($_.Sum / 1MB) }
