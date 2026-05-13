# Frontline Suite

**Security Scanner + Network Shield + System Health + Startup Manager + Windows Update + Event Log + Junk Cleaner + Hosts File + Firewall Manager**

Frontline Tech Consulting, LLC  
C# WinForms fallback build — No .NET SDK required  
Version 4.0.0

---

## What's inside

| Tab | What it does |
|-----|-------------|
| **Security Scanner** | Microsoft Defender scans (Quick, Full, Custom Folder), Update Definitions, DISM RestoreHealth, SFC /scannow, Recommended Sweep, Protection History |
| **Network Shield** | DNS management (AdGuard, Cloudflare, Quad9, Reset to DHCP), Local /24 network scan, Device inventory with new-device detection, CSV + TXT export |
| **System Health** | Full snapshot, Disk space (all drives with warnings), RAM & CPU info, System/OS info, Uptime, Pending reboot check, Battery status, Last 20 Event Log errors |
| **Startup Manager** | List all startup entries (HKCU + HKLM Run keys), enable/disable with one click, export list to log |
| **Windows Update** | Update history, last update date, pending reboot check, reset WU agent, clear download cache, service status |
| **Event Log Viewer** | Filter System/Application/Security log by level and count, click any row for full message detail, export to log file |
| **Junk Cleaner** | Scan preview (shows size before touching anything), clean User Temp, Windows Temp, Prefetch, Web cache, Thumbnail cache, WER reports, Recent Files. Files in use are skipped automatically |
| **Hosts File** | View and edit the hosts file directly in-app, Analyze button flags suspicious/non-default entries, Backup, Reset to Windows default, Flush DNS |
| **Firewall Manager** | Load all Windows Firewall rules into a filterable/searchable table. Filter by direction (Inbound/Outbound), status (Enabled/Disabled), and action (Allow/Block). Click a rule for details. Enable or disable individual rules with confirmation. Export full rule list to a log file |

All logs are saved to a single shared `logs\` folder inside the install directory.

---

## How to build and install

### Option A — One step (recommended)

Double-click **`INSTALL.cmd`**

This will:
1. Build `FrontlineSuite.exe` using the .NET Framework compiler already on your PC (no SDK needed)
2. Copy everything to `%LOCALAPPDATA%\Frontline Tech Consulting\Frontline Suite\`
3. Create a **Start Menu** shortcut
4. Launch the app

### Option B — Build only

Double-click **`BUILD_No_DotNet_SDK.cmd`**

Output: `publish\FrontlineSuite.exe` — run it from that folder directly.

---

## Requirements

- **Windows 10 or 11**
- **.NET Framework 4.x** — already included in Windows; no installation needed
- **Administrator** — required for DNS changes, Defender scans, DISM, SFC, and startup entry changes

The app will warn you at startup if it's not running as administrator.

---

## Folder layout

```
FrontlineSuite\
  src\
    FrontlineSuite.cs        ← combined source code (all 5 tabs)
    app.manifest
  assets\
    frontline_logo.ico
    frontline_logo.png
  docs\
    Frontline_Malware_Scan_Commands.txt
    Frontline_Network_Shield_Commands.txt
  BUILD_No_DotNet_SDK.cmd    ← build only
  INSTALL.cmd                ← build + install + shortcut
  README.md
```

---

## Notes

- Only scan networks you own or have permission to assess.
- DNS and startup changes require administrator privileges.
- Logs are local only — nothing is sent over the network by the app itself.
- The network scan covers the local /24 subnet only (safe range).
- Startup enable/disable writes to the Windows `StartupApproved` registry key (the same method Task Manager uses).
