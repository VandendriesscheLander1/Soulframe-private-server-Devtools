Soulframe private server: joining
=================================

Use this folder from the zip you were sent, not release\join from the repo. It must contain sf-server.txt,
sf-launch.exe and sf_bootstrap.dll. For now you run the server yourself: it's the sf-host folder next to this one.

What you need
- Python 3.12+ (python.org; tick "Add to PATH") for the server in sf-host.
- Soulframe installed and on build P16H6 (2026.10.08). Setup checks this and stops if it doesn't match.
- About 13 GB free disk space for a separate copy of the game.

Setup (once)
1. Close Soulframe and its launcher.
2. Double-click setup.cmd and say yes to the admin prompt.
   It copies your install to %USERPROFILE%\SoulframePrivate. Your real install is only read.
   Steam/Epic or another install folder? It will ask for the folder.
   It then adds Windows Firewall rules so that copy can reach only the server on your own PC.

Play
- First double-click sf-host\host.cmd and leave that window open (it's the server).
- Then double-click SoulframePrivate\sf-launch.exe.
- Log in with a made-up email and password. Never use your Digital Extremes login: the server stores what you type.
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

Linux (Arch, Ubuntu/Debian)
- Setup: open a terminal in this folder and run  bash setup.sh  (it asks for your sudo password).
  It installs Wine, winetricks and nftables, creates a user "sfplay", and copies your install (Steam, Lutris,
  or a Wine prefix; it asks if it can't find it) to /home/sfplay/SoulframePrivate.
  Arch: enable [multilib] in /etc/pacman.conf first.
- It also adds an nftables rule (service sf-copy-firewall, loaded at boot) so that sfplay can reach only the host
  and loopback. Windows Firewall doesn't exist under Wine; this rule does that job.
- Play: run  sf-play  as yourself. The game runs as sfplay on your screen. sf-launch refuses to start
  if sfplay can reach the internet.
- Sound is shared over loopback (anonymous PulseAudio on 127.0.0.1:4713), so other local users could use it too.
- Uninstall: see the "Undo" line at the top of setup.sh.
