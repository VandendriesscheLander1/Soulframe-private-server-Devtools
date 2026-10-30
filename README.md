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

## Quick start

- **Host:** see [release/host/README.txt](release/host/README.txt).
- **Join:** see [release/join/README.txt](release/join/README.txt).

Never log in with your real Digital Extremes account on a private server, and don't run the private copy
alongside the real game.
