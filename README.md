<p align="center"><img src="docs/logo.png" width="128" alt="ThermoForge logo"></p>

<h1 align="center">ThermoForge</h1>
<p align="center"><b>PC temperatures &amp; suspicious-process monitor for Windows</b><br>by <b><a href="https://gaaloulv36.github.io/open-forge-studio-website/">Open Forge Studio</a></b></p>

---

ThermoForge is a Windows desktop app (C# / .NET 10 / WPF) that shows live hardware temperatures and load,
and flags suspicious background activity: malware look-alikes, unsigned programs in odd folders,
script-based attacks, hidden auto-start entries and programs phoning home.

## Features

**Hardware tab**
- Live CPU, GPU, storage, RAM, battery and motherboard sensors via [LibreHardwareMonitor](https://github.com/LibreHardwareMonitor/LibreHardwareMonitor)
- Summary cards with colour-coded status (normal / warm / hot) per device type
- Rolling temperature history chart with selectable sensors
- Session min / max for every sensor
- Falls back to ACPI thermal zones when not running as administrator

**Processes tab**
- Every running process, refreshed every 3 s, with CPU %, memory, publisher and parent
- Digital signature check (embedded, Windows catalog and MSIX packages)
- Heuristics for malware-like behaviour (see [Process checks](#process-checks))
- GPU use per process (like Task Manager)
- **Risk score 0–100** per process: several weak signals add up to a strong one
- **Crypto-miner detection**: flags programs that keep the CPU or GPU busy while you're away
- **Trusted programs**: silence a program you know; trust breaks if the file ever changes
- Red badge on the tab with the number of Medium / High findings
- Search, "only flagged" filter, open file location, copy path, search online, end process
  (critical Windows processes are protected)

**Startup tab** (everything set to run automatically)
- Registry Run/RunOnce keys, Startup folders, scheduled tasks, auto-start services and drivers
- Hijack spots malware loves: Winlogon Shell/Userinit, Image File Execution Options debuggers,
  SilentProcessExit monitors, permanent WMI event subscriptions
- Each entry's file is resolved from its command and checked like a running process
  (signature, location, look-alike names, suspicious command lines), plus missing-file checks
- **NEW** badge and an alert for anything added after ThermoForge started watching
- Turn entries off/on the same way Task Manager and Task Scheduler do (nothing is deleted)
- Clean Microsoft-signed entries are hidden by default to keep the list short

**Network tab** (every connection and listening port, like TCPView)
- TCP and UDP, IPv4 and IPv6, each tied to its program; refreshed with the process list
- Direction (out / in / listening), where the other end is (this PC, local network, internet)
  and its reverse-DNS host name
- Network checks (see [Network checks](#network-checks)); they also count toward the
  program's risk score on the Processes tab, so they raise the same alerts
- "Check address online" opens the address's AbuseIPDB page (only when you click it)

**Security tab** (antivirus checks and reports)
- Microsoft Defender status (active / standing by for another antivirus, real-time protection,
  definition age) and its detection history; alerts if protection is switched off or Defender
  finds something while ThermoForge runs
- **Check on VirusTotal** for any process or startup file: only the file's SHA-256 is sent,
  never the file, and only when you click. Free API key, stored encrypted (DPAPI) for your Windows account
- **Scan with Defender** for any process or startup file (nothing is quarantined; you decide)
- "Check flagged files" looks up every flagged program in one go, paced to the free tier (4 a minute)
- Detections become findings, so they raise the risk score and alerts. Results are tied to the
  exact file (SHA-256), so a changed file has to be checked again
- **Export a report**: a self-contained HTML page (verdict, flagged items, temperatures, internet
  traffic, Defender history, file checks, alerts) that prints cleanly, or JSON

**Alerts & tray**
- Pop-up notifications when a process becomes risky, something new is set to start with
  Windows, a CPU/GPU/drive stays too hot, or antivirus protection is off / finds a threat
  (no repeats: once per risk level, and at most every 15 min per sensor)
- Alerts tab with history, notification settings, pause for 1 hour, and the trusted list
- Tray icon that turns amber (warning) or red (alert), with a live tooltip;
  closing the window keeps ThermoForge running in the tray (right-click › Exit to quit)

## Install

Download `ThermoForge-Setup-<version>.exe` from the Releases page and run it (Windows 10 1809+ / 11, x64).
It includes the .NET runtime, so nothing else is needed. The installer can set ThermoForge to
**start with Windows**: it then starts in the tray at sign-in **with administrator rights and no
UAC prompt** (a Task Scheduler logon task), so every sensor and process is visible. You can switch
this on or off later on the Alerts tab. A portable zip is also published for those who prefer no installer.

Opening ThermoForge while it's already running brings up the existing window instead of starting a second copy.

**Updates:** ThermoForge checks this repository's Releases once a day (switch it off on the Alerts tab,
or use "Check now"). When a new version is out you get a notification and a banner with
"Update now", "What's new" and "Skip this version". Updating downloads the installer, checks it
against the release's `SHA256SUMS.txt` (and, once builds are signed, that it's signed by the same
publisher), then closes ThermoForge, installs silently and reopens it. Nothing is sent to GitHub
besides the usual request for the latest release. Portable copies link to the download page instead.

Builds are not code-signed yet, so Windows SmartScreen may warn ("More info" › "Run anyway").

## Build from source

Requirements: [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0); optional but
recommended: administrator rights and the [PawnIO driver](https://pawnio.eu/).

```powershell
git clone https://github.com/gaaloulv36/thermoforge.git
cd thermoforge
dotnet run --project src/ThermoForge.UI
```

For full coverage:

1. **Run as administrator** (or use the in-app "Restart as administrator" button).
   Without admin rights, CPU, motherboard and RAM sensors are unavailable, and Windows hides
   the path and command line of system and elevated processes.
2. **Install the PawnIO driver.** LibreHardwareMonitor needs it for CPU temperatures:
   `winget install namazso.PawnIO` (or https://pawnio.eu/).

Data lives in `%LOCALAPPDATA%\ThermoForge\`: `settings.json` (notification settings),
`trusted.json` (trusted programs, with each file's SHA-256), `startup-baseline.json`
(when each startup entry was first seen), `reputation.json` (VirusTotal / Defender results per
SHA-256) and `crash.log`. The VirusTotal key is kept in `settings.json`, encrypted with DPAPI.

## Test

```powershell
dotnet test ThermoForge.slnx
```

## Release

```powershell
winget install JRSoftware.InnoSetup   # once
.\build\release.ps1
```

Runs the tests, publishes a self-contained win-x64 build, signs it if a certificate is configured
([docs/SIGNING.md](docs/SIGNING.md)), and writes the installer, a portable zip and `SHA256SUMS.txt`
to `artifacts\`. The version comes from `<Version>` in `src/ThermoForge.UI/ThermoForge.UI.csproj`.

Command-line switches: `--tray` (start hidden in the tray; used by the logon task),
`--autostart on|off` (create or remove the logon task; needs admin rights).

## Layout

| Project | Purpose |
|---|---|
| `src/ThermoForge.Core` | Sensor providers (LibreHardwareMonitor, ACPI thermal zones), process monitor (WMI), Authenticode verification, heuristics |
| `src/ThermoForge.UI` | WPF dashboard (MVVM via CommunityToolkit.Mvvm, charts via ScottPlot) |
| `tests/ThermoForge.Tests` | xUnit tests for Core logic |
| `installer/` | Inno Setup script |
| `build/` | Release and signing scripts |

## Process checks

Each process is checked every 3 s. Findings are hints, not verdicts: every rule has innocent explanations.

| Check | Severity |
|---|---|
| Windows process name (svchost, lsass, …) running outside System32 | High |
| Name one character off a Windows process (`scvhost.exe`) | High |
| Invalid / tampered digital signature | High |
| Unsigned **and** running from Temp, Public, Recycle Bin, AppData/ProgramData root | High |
| Encoded PowerShell, download-and-execute, mshta/certutil/regsvr32/rundll32 abuse | High |
| Office app starting cmd/PowerShell/script hosts | High |
| Runs from a suspicious folder (signed: one level lower) | Medium |
| Hidden-window PowerShell, Base64 decoding, browser starting a script host | Medium |
| Unsigned program in a normal location; execution-policy bypass | Low |
| Keeps CPU ≥ 25 % or GPU ≥ 40 % busy for 2+ min while you're away (2+ min idle) | High if unsigned, Medium if unknown, Low if signed |
| Microsoft Defender detects the file (on-demand scan) | High |
| VirusTotal: 5+ engines detect the file / 2–4 / 1 (or only "suspicious") | High / Medium / Low |

## Network checks

Connections are read from Windows' TCP/UDP tables every 3 s (no driver, no packet capture).

| Check | Severity |
|---|---|
| mshta, regsvr32 or certutil connecting to the internet | High |
| PowerShell, cmd, wscript/cscript, rundll32 or bitsadmin connecting to the internet | Medium |
| Remote port used by hacking tools (4444, 1337, 31337), mining pools (3333, 5555, 7777, 14444, …) or Tor (9001, 9050, …) | Medium |
| Host name of a known mining pool | Medium |
| Unsigned program accepting a connection from the internet | Medium |
| **Beaconing:** a new connection to the same address at a steady rhythm (6+ times, 10 s – 30 min apart) | Medium if unsigned, Low if unknown, ignored if signed |
| Unsigned program talking to the internet, or listening on all network interfaces | Low |
| IRC (6667, 6697) | Low |

Beaconing detection only sees connections that are still open at a poll, so very short check-ins can slip through.

**Risk score:** High = 60, Medium = 30, Low = 10 points, added up and capped at 100.
60+ is High risk, 30+ is Medium, anything above 0 is Low. Trusted programs score 0.

Signatures are verified with WinVerifyTrust, including Windows catalog signatures (most System32
binaries) and MSIX packages. Revocation is not checked, so no network access is needed.

## Roadmap

1. ~~Live temperature dashboard~~ (done)
2. ~~Process list with signature/path checks~~ (done)
3. ~~Risk engine, alerts, tray icon~~ (done)
4. ~~Startup/persistence scanner~~ (done)
5. ~~Network monitor~~ (done)
6. ~~VirusTotal / Defender integration, reports~~ (done)
7. ~~Start with Windows (elevated, in the tray), installer, signing pipeline~~ (done; signing needs a certificate)

## About Open Forge Studio

ThermoForge is part of **[Open Forge Studio](https://gaaloulv36.github.io/open-forge-studio-website/)**,
a suite of privacy-first, local-first micro-apps for Windows (ThermoForge, VaultForge, and more to come).
Need a customized version for your team or company? Get in touch through the website.
