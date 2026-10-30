Soulframe private server: hosting
=================================

What you need
- Python 3.12+ (python.org; tick "Add to PATH"). host.cmd installs the one package it needs (cryptography).
- A way for players to reach you. Easiest: everyone joins the same Tailscale or ZeroTier network,
  so nothing needs to be forwarded. A VPS or port forwarding also works: open TCP 80 and 443.
- No game install needed on the server machine.

Start
- Windows: double-click host.cmd. Allow python.exe through the firewall when Windows asks
  (tick both Private and Public, since Tailscale networks often count as Public).
- Linux: sudo python3 soulframe-private-server/tools/dummy_server.py --host   (ports 80/443 need root)
- It prints the addresses players can use. Give them the sf-join folder with that address in sf-server.txt.

Accounts and saves
- The first login with an email creates that account and sets its password.
- Saves live in soulframe-private-server/data/accounts/<id>/inventory.json. Back up data/ to keep progress.
- soulframe-private-server/tools/admin.py accounts   lists accounts.
- Logs: soulframe-private-server/captures/dummy/<start time>/ (passwords are not logged).

Don't share this folder publicly: soulframe-pipeline holds data extracted from the game.
