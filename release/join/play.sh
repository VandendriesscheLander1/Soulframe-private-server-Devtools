#!/usr/bin/env bash
# Start the private copy set up by setup.sh (installed as sf-play). Run as yourself: the game runs as user sfplay,
# on your screen and speakers. sf-launch.exe refuses to start if sfplay can reach the internet.
set -euo pipefail
[[ $EUID -ne 0 ]] || { echo "Run sf-play as your normal user, not root."; exit 1; }
systemctl is-active -q sf-copy-firewall || { echo "Firewall rule not loaded: sudo systemctl start sf-copy-firewall"; exit 1; }
xhost +SI:localuser:sfplay >/dev/null  # let sfplay draw on your screen (X11, or XWayland)
# sfplay can't open your PulseAudio/PipeWire socket, so share it on loopback (which the firewall allows).
pactl list modules short | grep -q module-native-protocol-tcp ||
  pactl load-module module-native-protocol-tcp port=4713 auth-ip-acl=127.0.0.1 auth-anonymous=1 >/dev/null ||
  echo "No sound: pactl could not share your audio."
exec sudo -u sfplay env HOME=/home/sfplay WINEPREFIX=/home/sfplay/.wine WINEDEBUG=-all DISPLAY="${DISPLAY:?no display}" \
  PULSE_SERVER=tcp:127.0.0.1:4713 wine /home/sfplay/SoulframePrivate/sf-launch.exe
