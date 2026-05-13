@echo off
setlocal EnableExtensions
color 0B
title Build Frontline Suite - No .NET SDK

set "ROOT=%~dp0"
set "SRC=%ROOT%src\FrontlineSuite.cs"
set "MANIFEST=%ROOT%src\app.manifest"
set "ICON=%ROOT%assets\frontline_logo.ico"
set "OUTDIR=%ROOT%publish"
set "OUT=%OUTDIR%\FrontlineSuite.exe"

if not exist "%OUTDIR%" mkdir "%OUTDIR%"

:: Locate csc.exe (ships with Windows .NET Framework 4.x – no SDK needed)
set "CSC="
if exist "%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe" set "CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not defined CSC if exist "%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe" set "CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe"

if not defined CSC (
    echo ERROR: csc.exe was not found.
    echo.
    echo This build uses the Windows .NET Framework compiler ^(no SDK needed^).
    echo Expected location:
    echo   %WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe
    echo.
    pause
    exit /b 1
)

echo Using compiler: %CSC%
echo.
echo Building FrontlineSuite.exe...

"%CSC%" /nologo /target:winexe /optimize+ /platform:anycpu ^
    /win32icon:"%ICON%" /win32manifest:"%MANIFEST%" ^
    /out:"%OUT%" "%SRC%" ^
    /reference:System.dll ^
    /reference:System.Core.dll ^
    /reference:System.Windows.Forms.dll ^
    /reference:System.Drawing.dll ^
    /reference:System.Net.dll

if errorlevel 1 (
    echo.
    echo Build FAILED.
    pause
    exit /b 1
)

:: Copy supporting files into publish\
if not exist "%OUTDIR%\assets" mkdir "%OUTDIR%\assets"
if not exist "%OUTDIR%\docs"   mkdir "%OUTDIR%\docs"
if not exist "%OUTDIR%\logs"   mkdir "%OUTDIR%\logs"
if not exist "%OUTDIR%\data"   mkdir "%OUTDIR%\data"

copy /Y "%ROOT%assets\frontline_logo.ico"                  "%OUTDIR%\assets\" >nul
copy /Y "%ROOT%assets\frontline_logo.png"                  "%OUTDIR%\assets\" >nul
copy /Y "%ROOT%docs\Frontline_Malware_Scan_Commands.txt"   "%OUTDIR%\docs\"   >nul 2>&1
copy /Y "%ROOT%docs\Frontline_Network_Shield_Commands.txt" "%OUTDIR%\docs\"   >nul 2>&1
copy /Y "%ROOT%docs\Frontline_Checkup_Report_Notes.txt"    "%OUTDIR%\docs\"   >nul 2>&1

echo.
echo Build complete:
echo %OUT%
echo.
pause
exit /b 0
