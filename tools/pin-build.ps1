# Snapshot the live Soulframe install into a pinned, read-only build folder.
# Usage: tools\pin-build.ps1 -Name P16H6
# Writes the game files OUTSIDE the repo (..\soulframe-builds\<Name>\pristine) and
# only a hash manifest inside it (builds\<Name>\manifest.sha256).
param(
    [Parameter(Mandatory)][string]$Name,
    [string]$Source = "$env:LOCALAPPDATA\Soulframe\Downloaded\Public",
    [string]$BuildsRoot = (Join-Path $PSScriptRoot '..\..\soulframe-builds')
)
$ErrorActionPreference = 'Stop'

if (Get-Process -Name 'Soulframe*', 'Launcher' -ErrorAction SilentlyContinue) {
    throw 'Close Soulframe and its launcher first; a copy taken mid-update is useless.'
}

$dest = [IO.Path]::GetFullPath((Join-Path $BuildsRoot "$Name\pristine"))
if (Test-Path $dest) { throw "$dest already exists; pick a new name or delete it yourself." }

robocopy $Source $dest /E /COPY:DAT /DCOPY:T /R:1 /W:1 /NFL /NDL /NP | Out-Host
if ($LASTEXITCODE -ge 8) { throw "robocopy failed ($LASTEXITCODE)" }

$label = (Get-Item "$dest\Soulframe.x64.exe").VersionInfo.FileVersion
$manifestDir = Join-Path $PSScriptRoot "..\builds\$Name"
New-Item -ItemType Directory -Force $manifestDir | Out-Null
$manifest = Join-Path $manifestDir 'manifest.sha256'

# Hash the copy, then verify the source still matches (catches a launcher update racing us).
$lines = Get-ChildItem $dest -Recurse -File -Force | Sort-Object FullName | ForEach-Object {
    $rel = $_.FullName.Substring($dest.Length + 1)
    $h = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower()
    $src = (Get-FileHash (Join-Path $Source $rel) -Algorithm SHA256).Hash.ToLower()
    if ($h -ne $src) { throw "Hash mismatch on $rel; source changed during copy." }
    "$h  $rel"
}
Set-Content -Path $manifest -Value (@("# $Name  build $label") + $lines) -Encoding utf8

# Read-only so nothing (us, tools, a stray launcher) edits the pristine copy.
Get-ChildItem $dest -Recurse -File -Force | ForEach-Object { $_.IsReadOnly = $true }

"Pinned $Name ($label): $dest"
"Manifest: $manifest ($($lines.Count) files)"
exit 0  # robocopy leaves $LASTEXITCODE=1 on success
