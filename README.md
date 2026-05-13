# Frontline Suite

**Security Scanner + Network Shield — Combined into one app**

Frontline Tech Consulting, LLC  
C# WinForms fallback build — No .NET SDK required

---

## What's inside

| Tab | What it does |
|-----|-------------|
| **Security Scanner** | Microsoft Defender scans (Quick, Full, Custom Folder), Update Definitions, DISM RestoreHealth, SFC /scannow, Recommended Sweep, Protection History |
| **Network Shield** | DNS management (AdGuard, Cloudflare, Quad9, Reset to DHCP), Local /24 network scan, Device inventory with new-device detection, MAC/hostname/open-port notes, CSV + TXT export |

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
- **Administrator** — required for DNS changes, Defender scans, DISM, and SFC

The app will warn you at startup if it's not running as administrator.

---

## Folder layout

```
FrontlineSuite\
  src\
    FrontlineSuite.cs        ← combined source code
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
- DNS changes require administrator privileges.
- Logs are local only — nothing is sent over the network by the app itself.
- The network scan covers the local /24 subnet only (safe range).
