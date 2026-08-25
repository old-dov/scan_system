@echo off
setlocal

if "%~1"=="" (
  set "PYTHON=python"
) else (
  set "PYTHON=%~1"
)

echo [1/3] Installing dependencies...
"%PYTHON%" -m pip install --upgrade pip
if errorlevel 1 (
  echo [ERREUR] Echec mise a jour pip.
  exit /b 1
)
"%PYTHON%" -m pip install -r requirements.txt
if errorlevel 1 (
  echo [ERREUR] Echec installation dependances.
  exit /b 1
)

echo [2/3] Building EXE with PyInstaller...
"%PYTHON%" -m PyInstaller --clean --noconfirm --onefile --windowed --name scan_system --icon "pictures\scan_system.ico" --add-data "pictures\scan_system.ico;pictures" --add-data "pictures\icon_64x64.png;pictures" scanner_windows.py
if errorlevel 1 (
  echo [ERREUR] Echec compilation EXE x64.
  exit /b 1
)

echo [3/3] Done.
echo EXE generated at: dist\scan_system.exe

endlocal
