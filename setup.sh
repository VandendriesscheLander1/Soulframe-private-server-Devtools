#!/usr/bin/env bash
# One-time Linux setup from a clone of the repo (Arch, Ubuntu/Debian): a Python venv for the server, Rust + zig to
# cross-build sf-launch.exe and sf_bootstrap.dll for Wine (gcc only builds the build scripts that run on Linux), then
# release/join/setup.sh (Wine copy as user sfplay + firewall). Run as yourself; it asks for sudo. Safe to run again.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
[[ $EUID -ne 0 ]] || { echo "Run setup.sh as your normal user (it uses sudo itself)."; exit 1; }

. /etc/os-release
case " $ID ${ID_LIKE:-} " in
  *" arch "*) sudo pacman -S --needed --noconfirm python curl gcc ;;
  *" debian "* | *" ubuntu "*) sudo apt-get update && sudo apt-get install -y python3 python3-venv curl build-essential ;;
  *) echo "Unknown distro '$ID': make sure python3 (3.12+, with venv), curl and gcc are installed." ;;
esac

# The server's Python packages, and zig (cargo-zigbuild) as the cross compiler: no mingw, no C++ runtime DLLs.
[[ -x $here/.venv/bin/python ]] || python3 -m venv "$here/.venv"
"$here/.venv/bin/pip" install -q --disable-pip-version-check cryptography cargo-zigbuild

# Rust through rustup (it provides the Windows target). An existing rustup (yours, or Arch's rustup package) is reused,
# with or without a default toolchain; a distro rust/cargo without rustup stays as it is and rustup goes in ~/.cargo.
export PATH=~/.cargo/bin:$PATH
command -v rustup >/dev/null || curl -sSf https://sh.rustup.rs |
  RUSTUP_INIT_SKIP_PATH_CHECK=yes sh -s -- -y --profile minimal --default-toolchain none --no-modify-path
rustup toolchain install stable --profile minimal --target x86_64-pc-windows-gnu
echo "Building sf-launch.exe and sf_bootstrap.dll..."
PATH=$here/.venv/bin:$PATH cargo +stable zigbuild --release --target x86_64-pc-windows-gnu --manifest-path "$here/bootstrap/Cargo.toml"

exec bash "$here/release/join/setup.sh" "$@"
