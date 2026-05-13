@echo off
setlocal EnableExtensions
color 0B
title Install Frontline Suite

set "ROOT=%~dp0"
set "EXE=%ROOT%publish\FrontlineSuite.exe"
set "INSTALLDIR=%LOCALAPPDATA%\Frontline Tech Consulting\Frontline Suite"

echo ============================================================
echo   Frontline Suite Installer
echo   Security Scanner  +  Network Shield
echo   Frontline Tech Consulting, LLC
echo ============================================================
echo.
echo This installer will:
echo   1. Build FrontlineSuite.exe if not already built
echo   2. Copy files to:
echo      %INSTALLDIR%
echo   3. Create a Start Menu shortcut
echo   4. Launch the app
echo.
echo No Desktop shortcut will be created.
echo.
pause

:: ── Step 1: Build if needed ───────────────────────────────────────────────
if not exist "%EXE%" (
    echo EXE not found. Building now...
    echo.
    call "%ROOT%BUILD_No_DotNet_SDK.cmd"
    if errorlevel 1 (
        echo.
        echo Build failed. Installation aborted.
        pause
        exit /b 1
    )
)

:: ── Step 2: Create install directory structure ────────────────────────────
if not exist "%INSTALLDIR%"          mkdir "%INSTALLDIR%"
if not exist "%INSTALLDIR%\assets"   mkdir "%INSTALLDIR%\assets"
if not exist "%INSTALLDIR%\docs"     mkdir "%INSTALLDIR%\docs"
if not exist "%INSTALLDIR%\logs"     mkdir "%INSTALLDIR%\logs"
if not exist "%INSTALLDIR%\data"     mkdir "%INSTALLDIR%\data"

:: ── Step 3: Copy files ────────────────────────────────────────────────────
echo Copying files...

copy /Y "%ROOT%publish\FrontlineSuite.exe"                        "%INSTALLDIR%\"          >nul
copy /Y "%ROOT%assets\frontline_logo.ico"                         "%INSTALLDIR%\assets\"   >nul
copy /Y "%ROOT%assets\frontline_logo.png"                         "%INSTALLDIR%\assets\"   >nul
copy /Y "%ROOT%docs\Frontline_Malware_Scan_Commands.txt"          "%INSTALLDIR%\docs\"     >nul 2>&1
copy /Y "%ROOT%docs\Frontline_Network_Shield_Commands.txt"        "%INSTALLDIR%\docs\"     >nul 2>&1

if errorlevel 1 (
    echo.
    echo ERROR: File copy failed. Check that the files exist in .\publish\ and .\assets\
    pause
    exit /b 1
)

:: ── Step 4: Create Start Menu shortcut ───────────────────────────────────
echo Creating Start Menu shortcut...

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
    "$shell = New-Object -ComObject WScript.Shell;" ^
    "$lnkPath = Join-Path ([Environment]::GetFolderPath('Programs')) 'Frontline Suite.lnk';" ^
    "$lnk = $shell.CreateShortcut($lnkPath);" ^
    "$lnk.TargetPath    = Join-Path $env:LOCALAPPDATA 'Frontline Tech Consulting\Frontline Suite\FrontlineSuite.exe';" ^
    "$lnk.WorkingDirectory = Join-Path $env:LOCALAPPDATA 'Frontline Tech Consulting\Frontline Suite';" ^
    "$ico = Join-Path $env:LOCALAPPDATA 'Frontline Tech Consulting\Frontline Suite\assets\frontline_logo.ico';" ^
    "if (Test-Path $ico) { $lnk.IconLocation = $ico };" ^
    "$lnk.Description = 'Frontline Suite - Security Scanner and Network Shield';" ^
    "$lnk.Save()"

if errorlevel 1 (
    echo WARNING: Could not create Start Menu shortcut.
    echo The app was still installed and can be run from:
    echo %INSTALLDIR%\FrontlineSuite.exe
    echo.
) else (
    echo Start Menu shortcut created.
    echo.
)

:: ── Done ──────────────────────────────────────────────────────────────────
echo ============================================================
echo   Installation complete!
echo.
echo   Location: %INSTALLDIR%
echo   Shortcut: Start Menu ^> Frontline Suite
echo.
echo   Logs are saved to: %INSTALLDIR%\logs\
echo ============================================================
echo.

start "" "%INSTALLDIR%\FrontlineSuite.exe"
pause
exit /b 0
