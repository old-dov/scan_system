@echo off
setlocal

set "ISCC_PATH=C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
if not exist "%ISCC_PATH%" (
  set "ISCC_PATH=C:\Program Files\Inno Setup 6\ISCC.exe"
)
if not exist "%ISCC_PATH%" (
  set "ISCC_PATH=%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe"
)

if not exist "dist\scan_system.exe" (
  echo [ERREUR] dist\scan_system.exe introuvable.
  echo Compile d'abord l'executable avec build_exe.bat
  exit /b 1
)

if not exist "%ISCC_PATH%" (
  echo [ERREUR] Inno Setup 6 ^(ISCC.exe^) n'est pas installe.
  echo Installe Inno Setup puis relance ce script.
  exit /b 1
)

for /f %%i in ('powershell -NoProfile -Command "(Get-Date).ToString('yyyyMMdd.HHmm')"') do set "BUILD_TAG=%%i"
set "APP_VERSION=1.0.%BUILD_TAG%"
set "OUT_SUFFIX=_v%BUILD_TAG%"
set "OUT_FILE=installer_output\ScanSystemSetup%OUT_SUFFIX%.exe"

echo [1/1] Compilation installeur Inno Setup...
"%ISCC_PATH%" /DMyAppVersion="%APP_VERSION%" /DMyOutputSuffix="%OUT_SUFFIX%" "installer.iss"
if errorlevel 1 (
  echo [ERREUR] Echec compilation installeur.
  exit /b 1
)

call .\sign_file.bat "%OUT_FILE%"
if errorlevel 1 exit /b 1

echo [OK] Installeur genere: %OUT_FILE%
endlocal
