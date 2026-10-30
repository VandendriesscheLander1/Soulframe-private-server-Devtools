Soulframe private server: joining
=================================

What you need
- Soulframe installed and on build P16H6 (2026.10.08). Setup checks this and stops if it doesn't match.
- About 13 GB free disk space for a separate copy of the game.
- If the host told you to: Tailscale or ZeroTier, joined to their network.

Setup (once)
1. Close Soulframe and its launcher.
2. Double-click setup.cmd and say yes to the admin prompt.
   It copies your install to %USERPROFILE%\SoulframePrivate. Your real install is only read.
   Steam/Epic or another install folder? It will ask for the folder.
   It then adds Windows Firewall rules so that copy can reach the host's server and nothing else.

Play
- Double-click SoulframePrivate\sf-launch.exe.
- Log in with a made-up email and password. Never use your Digital Extremes login: the host's server sees it.
- Don't run the private copy and your real Soulframe at the same time.
- Never start Tools\Launcher.exe in the copy (it would try to update it; the firewall blocks it anyway).

How it stays away from your real game
- The copy is a separate folder. Its settings, logs and account data go to SoulframePrivate\sf-appdata,
  not to %LOCALAPPDATA%\Soulframe.
- sf-launch and sf_bootstrap.dll refuse to run on a real install (Soulframe\Downloaded, steamapps, Epic Games),
  refuse to start without the firewall rule, and stop the game before it runs if anything isn't hooked.
- The game can't start other programs (launcher, crash sender), and the firewall lets the copy reach
  only the host's address. No connection to Digital Extremes, no DE account involved.

Uninstall
- Run as admin:  Remove-NetFirewallRule -Group Soulframe-Copy-SoulframePrivate
- Delete the SoulframePrivate folder.
