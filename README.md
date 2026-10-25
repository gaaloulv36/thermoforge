# Temp Monitor

A Windows desktop app (C# / .NET 10 / WPF) that shows live hardware temperatures and load,
and flags suspicious background processes such as malware look-alikes, unsigned programs in odd
folders, or script-based attacks.

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
- Red badge on the tab with the number of Medium / High findings
- Search, "only flagged" filter, open file location, copy path, search online, end process
  (critical Windows processes are protected)

## Requirements

- Windows 10 / 11 (x64)
- [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0)
- Optional but recommended: administrator rights and the [PawnIO driver](https://pawnio.eu/)

## Run

```powershell
git clone https://github.com/gaaloulv36/temp-monitor.git
cd temp-monitor
dotnet run --project src/TempMonitor.UI
```

For full coverage:

1. **Run as administrator** (or use the in-app "Restart as administrator" button).
   Without admin rights, CPU, motherboard and RAM sensors are unavailable, and Windows hides
   the path and command line of system and elevated processes.
2. **Install the PawnIO driver.** LibreHardwareMonitor needs it for CPU temperatures:
   `winget install namazso.PawnIO` (or https://pawnio.eu/).

Crash details are written to `%LOCALAPPDATA%\TempMonitor\crash.log`.

## Test

```powershell
dotnet test TempMonitor.slnx
```

## Layout

| Project | Purpose |
|---|---|
| `src/TempMonitor.Core` | Sensor providers (LibreHardwareMonitor, ACPI thermal zones), process monitor (WMI), Authenticode verification, heuristics |
| `src/TempMonitor.UI` | WPF dashboard (MVVM via CommunityToolkit.Mvvm, charts via ScottPlot) |
| `tests/TempMonitor.Tests` | xUnit tests for Core logic |

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

Signatures are verified with WinVerifyTrust, including Windows catalog signatures (most System32
binaries) and MSIX packages. Revocation is not checked, so no network access is needed.

## Roadmap

1. ~~Live temperature dashboard~~ (done)
2. ~~Process list with signature/path checks~~ (done)
3. Risk engine, alerts, tray icon
4. Startup/persistence scanner
5. Network monitor
6. VirusTotal / Defender integration, reports
7. Background Windows Service + installer
