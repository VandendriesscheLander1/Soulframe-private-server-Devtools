#!/usr/bin/env bash
# Linux version of setup.cmd (Arch, Ubuntu/Debian): a private copy of Soulframe that runs in Wine as its own user
# "sfplay", and an nftables rule so that user can only reach the host in sf-server.txt (and loopback).
# Your real game is only read (copied), never changed or started.
# Usage: bash setup.sh [folder with Soulframe.x64.exe]     (asks for sudo)
# Undo:  sudo systemctl disable --now sf-copy-firewall; sudo userdel -r sfplay;
#        sudo rm /etc/sf-copy.nft /etc/systemd/system/sf-copy-firewall.service /usr/local/bin/sf-play
set -euo pipefail
P16H6=3be7694b589a7e2ae92a53b3e26ed8c3bcfac8c34ff25d69045df374b35e4765  # Soulframe.x64.exe, build 2026.10.08.15.20
[[ $EUID -eq 0 ]] || exec sudo bash "$0" "$@"
me=${SUDO_USER:?run this from your normal account (it uses sudo itself)}
myhome=$(getent passwd "$me" | cut -d: -f6)
here=$(cd "$(dirname "$0")" && pwd)
user=sfplay
home=/home/$user
dest=$home/SoulframePrivate
as_user() { sudo -u "$user" env HOME="$home" WINEPREFIX="$home/.wine" WINEDEBUG=-all "$@"; }

# Wine resolves names inside the game, and the firewall blocks DNS for it, so the copy gets the IP, not a name.
server=$(head -n1 "$here/sf-server.txt" | tr -d '\r[:space:]')
ip=$(getent ahostsv4 "$server" | awk 'NR == 1 { print $1 }')
[[ $ip ]] || { echo "Could not find an IPv4 address for '$server' (sf-server.txt)."; exit 1; }

# The only distro-specific part.
. /etc/os-release
case " $ID ${ID_LIKE:-} " in
  *" arch "*)
    pacman -S --needed --noconfirm wine winetricks nftables xorg-xhost libpulse ||
      { echo "pacman failed. Wine is in [multilib]: enable it in /etc/pacman.conf, then run setup.sh again."; exit 1; } ;;
  *" debian "* | *" ubuntu "*)
    dpkg --add-architecture i386
    apt-get update
    apt-get install -y wine64 wine32:i386 winetricks nftables x11-xserver-utils pulseaudio-utils ;;
  *)
    echo "Unknown distro '$ID'. Install wine, winetricks, nftables, xhost and pactl yourself, then set SF_SKIP_PACKAGES=1."
    [[ ${SF_SKIP_PACKAGES:-} ]] || exit 1 ;;
esac

id "$user" &>/dev/null || useradd -m -s /usr/sbin/nologin "$user"
for g in video render audio; do getent group $g >/dev/null && usermod -aG $g "$user"; done

if [[ ! -f $dest/Soulframe.x64.exe ]]; then
  src=${1:-}
  for c in "$myhome"/.local/share/Steam/steamapps/common/Soulframe \
           "$myhome"/.var/app/com.valvesoftware.Steam/.local/share/Steam/steamapps/common/Soulframe \
           "$myhome"/.local/share/Steam/steamapps/compatdata/*/pfx/drive_c/users/*/AppData/Local/Soulframe/Downloaded/Public \
           "$myhome"/.wine/drive_c/users/*/AppData/Local/Soulframe/Downloaded/Public \
           "$myhome"/Games/*/drive_c/users/*/AppData/Local/Soulframe/Downloaded/Public; do
    [[ $src || ! -f $c/Soulframe.x64.exe ]] || src=$c
  done
  while [[ ! -f $src/Soulframe.x64.exe ]]; do
    read -rp "Soulframe install folder (the one with Soulframe.x64.exe): " src
  done
  ! pgrep -i '^(Soulframe|Launcher)' >/dev/null || { echo "Close Soulframe and its launcher first."; exit 1; }
  [[ $(sha256sum "$src/Soulframe.x64.exe" | cut -d' ' -f1) == "$P16H6" ]] ||
    { echo "Your Soulframe is a different version than this server supports (P16H6, 2026.10.08). Nothing was changed."; exit 1; }
  echo "Copying $src to $dest (about 13 GB, read-only on your real install)..."
  mkdir -p "$dest"
  cp -r "$src/." "$dest"
fi
[[ $(sha256sum "$dest/Soulframe.x64.exe" | cut -d' ' -f1) == "$P16H6" ]] || { echo "$dest is not build P16H6."; exit 1; }
cp "$here/sf-launch.exe" "$here/sf_bootstrap.dll" "$dest"
echo "$ip" > "$dest/sf-server.txt"
chown -R "$user:" "$home"

# Wine prefix with DXVK (the game is DirectX 11). Needs the internet once, so before the firewall rule.
if [[ ! -f $home/.wine/.sf-ready ]]; then
  nft delete table inet sf_copy 2>/dev/null || true
  as_user WINEDLLOVERRIDES='mscoree,mshtml=' wineboot -i
  as_user winetricks -q dxvk
  as_user touch "$home/.wine/.sf-ready"
fi

# Everything user sfplay sends goes to loopback or the host, or is rejected. Loaded at every boot.
cat > /etc/sf-copy.nft <<EOF
table inet sf_copy
delete table inet sf_copy
table inet sf_copy {
  chain out {
    type filter hook output priority 0; policy accept;
    meta skuid "$user" oifname "lo" accept
    meta skuid "$user" ip daddr $ip accept
    meta skuid "$user" reject
  }
}
EOF
cat > /etc/systemd/system/sf-copy-firewall.service <<EOF
[Unit]
Description=Soulframe private copy: user $user may only reach $ip
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$(command -v nft) -f /etc/sf-copy.nft
ExecStop=$(command -v nft) delete table inet sf_copy

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable sf-copy-firewall
systemctl restart sf-copy-firewall
if sudo -u "$user" timeout 5 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443' 2>/dev/null; then
  echo "The firewall rule did not take: $user can still reach the internet. Don't play; check 'sudo nft list ruleset'."
  exit 1
fi

install -m755 "$here/play.sh" /usr/local/bin/sf-play
echo
echo "Done. Play: run  sf-play  in a terminal as yourself (never Tools/Launcher.exe, never with your real Soulframe open)."
echo "Log in with a made-up email and password, NOT your Digital Extremes login."
