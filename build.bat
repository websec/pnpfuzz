@echo off
setlocal enabledelayedexpansion
rem ---------------------------------------------------------------------------
rem  pnpfuzz build script (MSVC)
rem
rem  Run from a "x64 Native Tools Command Prompt for VS", or just run this from
rem  a plain cmd.exe and it will locate and load the toolchain itself.
rem
rem  Requires: Visual Studio Build Tools (C++ workload) and the Windows SDK.
rem  Produces: pnpfuzz.exe in this directory.
rem ---------------------------------------------------------------------------

set OUT=pnpfuzz.exe
set OBJDIR=build

if "%1"=="clean" (
    if exist %OBJDIR% rmdir /s /q %OBJDIR%
    if exist %OUT% del /q %OUT%
    if exist pnpfuzz.pdb del /q pnpfuzz.pdb
    echo Cleaned.
    goto :eof
)

rem --- locate the toolchain if cl.exe is not already on PATH -----------------
where cl.exe >nul 2>&1
if %ERRORLEVEL%==0 goto :have_cl

echo [*] cl.exe not on PATH, looking for Visual Studio...

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" set "VSWHERE=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo [-] vswhere.exe not found.
    echo     Install "Visual Studio Build Tools" with the "Desktop development
    echo     with C++" workload, or open a "x64 Native Tools Command Prompt"
    echo     and run build.bat from there.
    exit /b 1
)

for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSPATH=%%i"
if "%VSPATH%"=="" (
    echo [-] No Visual Studio installation with the C++ toolset was found.
    exit /b 1
)

if not exist "%VSPATH%\VC\Auxiliary\Build\vcvarsall.bat" (
    echo [-] vcvarsall.bat missing under "%VSPATH%".
    exit /b 1
)

echo [*] Using %VSPATH%
call "%VSPATH%\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul
if errorlevel 1 (
    echo [-] vcvarsall.bat failed.
    exit /b 1
)

:have_cl
if not exist %OBJDIR% mkdir %OBJDIR%

rem  /MT   - static CRT, so the exe drops onto a bare VM with no redistributable
rem  /W3   - warnings; the SetupAPI surface is noisy at /W4
rem  /O2   - optimise; the sweep is I/O bound but the ID work is not
rem  wuguid.lib supplies CLSID_UpdateSession / IID_IWindowsDriverUpdate.
rem  _WIN32_WINNT / WINVER must be >= 0x0602: cfgmgr32.h gates the whole
rem  CM_Register_Notification family (HCMNOTIFICATION, CM_NOTIFY_FILTER,
rem  CM_NOTIFY_ACTION_*) behind WINVER >= _WIN32_WINNT_WIN8.
cl /nologo /W3 /O2 /MT /Zi ^
   /D_CRT_SECURE_NO_WARNINGS /D_WIN32_WINNT=0x0602 /DWINVER=0x0602 ^
   /Fo%OBJDIR%\ /Fd%OBJDIR%\pnpfuzz.pdb ^
   src\pnpfuzz.c src\devnode.c src\wu.c src\watch.c src\hwid.c src\sysinfo.c src\log.c src\vendor.c ^
   /Fe%OUT% ^
   /link /INCREMENTAL:NO /DEBUG /OPT:REF /OPT:ICF ^
   setupapi.lib newdev.lib cfgmgr32.lib ole32.lib oleaut32.lib wuguid.lib winhttp.lib ^
   advapi32.lib kernel32.lib user32.lib

if errorlevel 1 (
    echo.
    echo [-] Build failed.
    exit /b 1
)

echo.
echo [+] Built %OUT%
echo.
echo     Quick check ^(no privileges needed^):   %OUT% --help
echo     Everything else needs an ELEVATED prompt.
echo.
echo     Sweep, query only, auto-tuned for speed:
echo         %OUT% --vid 046D --pid 0000-FFFF --auto-batch
echo.
echo     Or prove batching is lossless manually first:
echo         %OUT% --verify-batch "USB\VID_06CB^&PID_0089" --batch 128
echo.
endlocal
