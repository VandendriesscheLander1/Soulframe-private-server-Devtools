Soulframe private server: the server
====================================

Playing on your own PC (the normal setup for now)
- Python 3.12+ (python.org; tick "Add to PATH"). host.cmd installs the one package it needs (cryptography).
- Double-click host.cmd and leave the window open while you play. It only listens on this PC (127.0.0.1).
- Then start the game with SoulframePrivate\sf-launch.exe (set up with sf-join\setup.cmd, see its README).

Later: hosting for other players
- Players need a way to reach you. Easiest: everyone joins the same Tailscale or ZeroTier network,
  so nothing needs to be forwarded. A VPS or port forwarding also works: open TCP 80 and 443.
- The sf-join they get must be built with your address: tools\make-packages.ps1 -Server <your address>.
- Windows: open a terminal here and run  host.cmd --host . Allow python.exe through the firewall when Windows asks
  (tick both Private and Public, since Tailscale networks often count as Public).
- Linux: sudo python3 soulframe-private-server/tools/dummy_server.py --host   (ports 80/443 need root)
- It prints the addresses players can use.

Accounts and saves
- The first login with an email creates that account and sets its password.
- Saves live in soulframe-private-server/data/accounts/<id>/inventory.json. Back up data/ to keep progress.
- soulframe-private-server/tools/admin.py accounts   lists accounts.
- Logs: soulframe-private-server/captures/dummy/<start time>/ (passwords are not logged).

Don't share this folder publicly: soulframe-pipeline holds data extracted from the game.
