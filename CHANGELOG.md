# Changelog

`build/release.ps1 -Publish` uses the section for the version being released as the GitHub
release notes, which ThermoForge shows when it offers the update.

## 1.0.1

- The Alerts tab's settings column now scrolls, so "Start with Windows" and the trusted list stay
  reachable on smaller screens
- First update delivered through ThermoForge's own in-app updater

## 1.0.0

First public release of ThermoForge by Forge Studio.

- **Hardware:** live CPU, GPU, drive, RAM, battery and fan sensors with a temperature history chart
- **Processes:** signature checks, malware look-alike and location heuristics, risky command lines,
  GPU use, crypto-miner detection, a 0–100 risk score and a trusted-programs list
- **Network:** every connection and listening port tied to its program, with checks for script hosts
  on the internet, hacking-tool / mining-pool / Tor ports, and programs "phoning home"
- **Startup:** Run keys, Startup folders, scheduled tasks, services, drivers, Winlogon, IFEO and WMI
  persistence, with a NEW badge and alert for anything added later
- **Security:** Microsoft Defender status and history, on-demand VirusTotal (hash only) and Defender
  scans, and an exportable HTML / JSON report
- **Alerts & tray:** notifications, tray status colours, close-to-tray
- **Start with Windows** in the tray with administrator rights (no UAC prompt at sign-in)
- **Automatic updates:** ThermoForge checks GitHub once a day and updates itself in one click;
  downloads are verified against the release's SHA-256 checksums
