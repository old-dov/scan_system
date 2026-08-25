@echo off
setlocal

if not exist "dist\scan_system.exe" (
  echo [ERREUR] dist\scan_system.exe introuvable.
  exit /b 1
)
if not exist "dist_x86\scan_system_x86.exe" (
  echo [ERREUR] dist_x86\scan_system_x86.exe introuvable.
  exit /b 1
)

for /f %%i in ('powershell -NoProfile -Command "(Get-Date).ToString('yyyyMMdd.HHmm')"') do set "BUILD_TAG=%%i"
set "OUT_DIR=portable_output"
set "STAGE=%OUT_DIR%\stage"
set "ZIP_FILE=%OUT_DIR%\ScanSystem_Portable_v%BUILD_TAG%.zip"

if exist "%STAGE%" rmdir /s /q "%STAGE%"
mkdir "%STAGE%"
mkdir "%STAGE%\x64"
mkdir "%STAGE%\x86"

copy /y "dist\scan_system.exe" "%STAGE%\x64\scan_system.exe" >nul
copy /y "dist_x86\scan_system_x86.exe" "%STAGE%\x86\scan_system_x86.exe" >nul

(
  echo Scan System - Portable
  echo.
  echo x64: lancer x64\scan_system.exe
  echo x86: lancer x86\scan_system_x86.exe
  echo.
  echo Ce package n'installe rien dans le registre.
) > "%STAGE%\README.txt"

if not exist "%OUT_DIR%" mkdir "%OUT_DIR%"
if exist "%ZIP_FILE%" del /f /q "%ZIP_FILE%"

powershell -NoProfile -Command "Compress-Archive -Path '%STAGE%\*' -DestinationPath '%ZIP_FILE%' -Force"
if errorlevel 1 (
  echo [ERREUR] Echec creation ZIP portable.
  exit /b 1
)

echo [OK] ZIP portable: %ZIP_FILE%
endlocal
