<p align="center"><img src="docs/logo.png" width="128" alt="ThermoForge logo"></p>

<h1 align="center">ThermoForge</h1>
<p align="center"><b>PC temperatures &amp; suspicious-process monitor for Windows</b><br>by <b>Forge Studio</b></p>

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

**Alerts & tray**
- Pop-up notifications when a process becomes risky, something new is set to start with
  Windows, or a CPU/GPU/drive stays too hot
  (no repeats: once per risk level, and at most every 15 min per sensor)
- Alerts tab with history, notification settings, pause for 1 hour, and the trusted list
- Tray icon that turns amber (warning) or red (alert), with a live tooltip;
  closing the window keeps ThermoForge running in the tray (right-click › Exit to quit)

## Requirements

- Windows 10 / 11 (x64)
- [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0)
- Optional but recommended: administrator rights and the [PawnIO driver](https://pawnio.eu/)

## Run

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
(when each startup entry was first seen) and `crash.log`.

## Test

```powershell
dotnet test ThermoForge.slnx
```

## Layout

| Project | Purpose |
|---|---|
| `src/ThermoForge.Core` | Sensor providers (LibreHardwareMonitor, ACPI thermal zones), process monitor (WMI), Authenticode verification, heuristics |
| `src/ThermoForge.UI` | WPF dashboard (MVVM via CommunityToolkit.Mvvm, charts via ScottPlot) |
| `tests/ThermoForge.Tests` | xUnit tests for Core logic |

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
6. VirusTotal / Defender integration, reports
7. Background Windows Service + installer

## About Forge Studio

ThermoForge is part of the **Forge Studio** family of desktop tools
(ThermoForge, VaultForge, and more to come). Need a customized version for your team or
company? Get in touch: [YOUR LINKEDIN URL]
