# Build dist\SoulframePrivateServer.exe: the GUI (tools\server_gui.pyw) with the server, fixtures\, gamedata\ and the
# player setup (release\join + sf-launch.exe + sf_bootstrap.dll) inside. No game files. Run on Windows with what
# setup.cmd installs (Python 3.12+, Rust, the C++ build tools): powershell -ExecutionPolicy Bypass -File build.ps1
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$b = "$root\build"

cargo build --release --manifest-path "$root\bootstrap\Cargo.toml"
if ($LASTEXITCODE) { throw 'cargo build failed' }

if (-not (Test-Path "$b\venv\Scripts\python.exe")) { py -3 -m venv "$b\venv" }
& "$b\venv\Scripts\python.exe" -m pip install -q --disable-pip-version-check pyinstaller cryptography
if ($LASTEXITCODE) { throw 'pip install failed' }

# luau-compile 0.712 for the dev tools (devlua.py), the same pinned download as tools\setup.ps1.
$luau = "$root\tools\luau"
if (-not (Test-Path -LiteralPath "$luau\luau-compile.exe")) {
    $zip = "$b\luau-0.712-windows.zip"
    New-Item -ItemType Directory -Force $b | Out-Null
    Invoke-WebRequest 'https://github.com/luau-lang/luau/releases/download/0.712/luau-windows.zip' -OutFile $zip -UseBasicParsing
    if ((Get-FileHash -LiteralPath $zip).Hash -ne '7AFDCB791E16A08A7A3D21E8990DDB9A46E50E46092E132FB91ACC3045BB3D2F') {
        throw 'The Luau download is not the expected 0.712 build'
    }
    Expand-Archive -LiteralPath $zip -DestinationPath $luau -Force
}

# What release\join\setup.ps1 expects next to it (as in the sf-join package; no sf-server.txt = this PC).
New-Item -ItemType Directory -Force "$b\join" | Out-Null
Copy-Item "$root\release\join\*", "$root\tools\isolate-build.ps1", "$root\bootstrap\target\release\sf-launch.exe",
    "$root\bootstrap\target\release\sf_bootstrap.dll" "$b\join" -Force

& "$b\venv\Scripts\pyinstaller.exe" --noconfirm --onefile --windowed --name SoulframePrivateServer --collect-submodules cryptography `
    --distpath "$root\dist" --workpath "$b\pyi" --specpath $b `
    --add-data "$root\tools\*.py;tools" --add-data "$root\tools\devgui.pyw;tools" --add-data "$luau;tools\luau" `
    --add-data "$root\dev;dev" --add-data "$root\bootstrap\src\imgui.rs;bootstrap\src" --add-data "$root\fixtures;fixtures" --add-data "$root\gamedata;gamedata" --add-data "$b\join;join" `
    "$root\tools\server_gui.pyw"
if ($LASTEXITCODE) { throw 'pyinstaller failed' }
"Built $root\dist\SoulframePrivateServer.exe"
