# One-time setup from a clone of the repo (run setup.cmd at the top): installs what's missing (Python, Rust,
# the C++ build tools), builds sf-launch.exe + sf_bootstrap.dll, then release\join\setup.ps1 copies your game
# and adds the firewall rules. Safe to run again; it skips what's already done.
param(
    [string]$Source = "$env:LOCALAPPDATA\Soulframe\Downloaded\Public",
    [string]$Dest = "$env:USERPROFILE\SoulframePrivate"
)
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$vsInstaller = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer"
$toolchain = 'stable-x86_64-pc-windows-msvc'

function Update-Path {
    $env:Path = [Environment]::GetEnvironmentVariable('Path', 'User') + ';' + [Environment]::GetEnvironmentVariable('Path', 'Machine') +
        ";$env:USERPROFILE\.cargo\bin"
}
function Install($id, $what, $extra = @()) {
    "Installing $what (winget $id)..."
    winget install -e --id $id --accept-package-agreements --accept-source-agreements @extra | Out-Host
    Update-Path
}
function Find-Python {
    # The py launcher first: an older python.exe earlier on PATH would otherwise hide a new 3.12.
    $code = 'import sys; print(sys.executable) if sys.version_info >= (3, 12) else sys.exit(1)'
    foreach ($try in { py -3 -c $code }, { python -c $code }) {
        try { $exe = & $try 2>$null; if ($LASTEXITCODE -eq 0 -and $exe) { return "$exe".Trim() } } catch {}
    }
}
function Test-Cpp {
    (Test-Path "$vsInstaller\vswhere.exe") -and
        [bool](& "$vsInstaller\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath)
}
Update-Path

if (-not (Get-Command winget -ErrorAction SilentlyContinue)) { throw 'winget is missing. Install "App Installer" from the Microsoft Store, then run setup.cmd again.' }
$python = Find-Python
if (-not $python) { Install 'Python.Python.3.12' 'Python 3.12'; $python = Find-Python }
if (-not $python) { throw 'Python 3.12+ still not found. Close this window and run setup.cmd again (a new window sees the new PATH).' }
Set-Content -LiteralPath "$root\.python-path" $python -Encoding ascii  # play.cmd starts the server with this one
& $python -m pip install --user --quiet --disable-pip-version-check cryptography
if ($LASTEXITCODE) { throw 'pip install cryptography failed' }

if (-not (Test-Cpp)) {
    $vs = if (Test-Path "$vsInstaller\vswhere.exe") { & "$vsInstaller\vswhere.exe" -latest -products * -property installationPath }
    if ($vs) {  # Visual Studio is there without C++: winget would only say "already installed"
        "Adding the C++ build tools to $vs (a few GB, takes a while)..."
        Start-Process "$vsInstaller\setup.exe" -Verb RunAs -Wait -ArgumentList ("modify --installPath `"$vs`" --quiet --wait --norestart " +
            '--add Microsoft.VisualStudio.Component.VC.Tools.x86.x64 --add Microsoft.VisualStudio.Component.Windows11SDK.22621')
    } else {
        Install 'Microsoft.VisualStudio.2022.BuildTools' 'the C++ build tools (a few GB, takes a while)' @('--override',
            '--quiet --wait --norestart --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended')
    }
    if (-not (Test-Cpp)) { throw 'The C++ build tools are still missing. Install "Desktop development with C++" in the Visual Studio Installer, then run setup.cmd again.' }
}
if (-not (Get-Command rustup -ErrorAction SilentlyContinue)) { Install 'Rustlang.Rustup' 'Rust' }
if (-not (Get-Command rustup -ErrorAction SilentlyContinue)) { throw 'Rust still not found. Close this window and run setup.cmd again.' }
rustup toolchain install $toolchain --profile minimal  # leaves your default toolchain alone
if ($LASTEXITCODE) { throw "rustup could not install $toolchain" }

"Building sf-launch.exe and sf_bootstrap.dll..."
cargo "+$toolchain" build --release --manifest-path "$root\bootstrap\Cargo.toml"
if ($LASTEXITCODE) { throw 'cargo build failed (see above)' }

# Copies the game and adds the firewall rules; it asks for admin itself.
& "$root\release\join\setup.ps1" -Source $Source -Dest $Dest
