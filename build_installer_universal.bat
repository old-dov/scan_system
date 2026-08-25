@echo off
setlocal

set "ISCC_PATH=C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
if not exist "%ISCC_PATH%" set "ISCC_PATH=C:\Program Files\Inno Setup 6\ISCC.exe"
if not exist "%ISCC_PATH%" set "ISCC_PATH=%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe"

if not exist "dist\scan_system.exe" (
  echo [ERREUR] dist\scan_system.exe introuvable.
  echo Lance build_exe.bat d'abord.
  exit /b 1
)

if not exist "dist_x86\scan_system_x86.exe" (
  echo [ERREUR] dist_x86\scan_system_x86.exe introuvable.
  echo Lance build_exe_x86.bat d'abord.
  exit /b 1
)

if not exist "%ISCC_PATH%" (
  echo [ERREUR] Inno Setup 6 ^(ISCC.exe^) introuvable.
  exit /b 1
)

for /f %%i in ('powershell -NoProfile -Command "(Get-Date).ToString('yyyyMMdd.HHmm')"') do set "BUILD_TAG=%%i"
set "APP_VERSION=1.0.%BUILD_TAG%"
set "OUT_SUFFIX=_v%BUILD_TAG%"
set "OUT_FILE=installer_output_universal\ScanSystemSetup_Universal%OUT_SUFFIX%.exe"

echo [1/1] Compilation installeur universel...
"%ISCC_PATH%" /DMyAppVersion="%APP_VERSION%" /DMyOutputSuffix="%OUT_SUFFIX%" "installer_universal.iss"
if errorlevel 1 (
  echo [ERREUR] Echec compilation installeur universel.
  exit /b 1
)

call .\sign_file.bat "%OUT_FILE%"
if errorlevel 1 exit /b 1

echo [OK] Installeur universel genere: %OUT_FILE%
endlocal
