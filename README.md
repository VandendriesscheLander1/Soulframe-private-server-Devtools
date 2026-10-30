# Soulframe private server devtools

A local server and launcher for playing a pinned Soulframe build (P16H6, `2026.10.08.15.20`) against your own
server instead of Digital Extremes' backend. Not affiliated with Digital Extremes.

No game files are in this repo. Everything game-derived comes from your own install.

## Layout

| Path | What |
|---|---|
| `tools/dummy_server.py` | The server (login, inventory, fixtures, hub relay) |
| `tools/admin.py` | Account admin (`python tools/admin.py accounts`) |
| `tools/devgui.pyw`, `tools/devlua.py`, `dev/dev.lua` | In-game dev tools |
| `tools/*.ps1` | Pin a build, make an isolated copy, redirect, launch |
| `bootstrap/` | Rust: `sf-launch.exe` and `sf_bootstrap.dll` (`cargo build --release`) |
| `release/host`, `release/join` | Host and player packages, see the README.txt in each |
| `fixtures/` | Response shapes the server replays |
| `builds/P16H6/manifest.sha256` | Hashes used to check the pinned build |

## Setup, step by step

For now everyone runs the server on their own PC: no shared host, no Tailscale, nothing to forward.
Each player gets two folders: `sf-host` (the server) and `sf-join` (the game setup). Both come from
step 2 below. Don't hand out `release/join` from this repo: it's only a template and `setup.cmd` fails there.

**You (on the PC with this repo): build the folders once**

1. Build the launcher and DLL:
   `cargo build --release --manifest-path bootstrap\Cargo.toml`
2. Build the packages:
   `tools\make-packages.ps1`
   This creates `dist\sf-host` and `dist\sf-join` (pointed at `127.0.0.1`, the player's own PC).
3. Zip `dist` and send it privately to the people who play. Don't post it publicly: `sf-host` contains
   data extracted from the game.

**Each player (Windows): setup, once**

1. Install Python 3.12+ from python.org and tick "Add to PATH".
2. Make sure Soulframe is on build P16H6 (2026.10.08) and you have about 13 GB free.
3. Unzip the folder. Check that `sf-join` contains `sf-server.txt`, `sf-launch.exe` and `sf_bootstrap.dll`.
4. Close Soulframe and its launcher.
5. Double-click `sf-join\setup.cmd` and accept the admin prompt. It copies the game to
   `%USERPROFILE%\SoulframePrivate` and adds firewall rules so that copy can only reach your own PC.
   If it can't find your install (Steam/Epic), it asks for the folder.

**Each player: every time you play**

1. Double-click `sf-host\host.cmd`. Leave that window open; it's the server. The first run installs
   one Python package (cryptography).
2. Double-click `%USERPROFILE%\SoulframePrivate\sf-launch.exe`.
3. Log in with a made-up email and password. The first login creates your account; use the same one next time.
4. When you're done, close the game, then close the server window.

Your saves are in `sf-host\soulframe-private-server\data\accounts`. Back that folder up to keep progress.
Linux and uninstalling: see [release/join/README.txt](release/join/README.txt).

**Later: one shared host.** Run `tools\make-packages.ps1 -Server <host's Tailscale 100.x IP>`, the host starts
the server with `host.cmd --host` from a terminal, and players only get `sf-join`. See
[release/host/README.txt](release/host/README.txt).

Never log in with your real Digital Extremes account on a private server, and don't run the private copy
alongside the real game.
