@echo off
setlocal

if "%~1"=="" (
  echo [ERREUR] Python 32 bits requis.
  echo Usage: build_exe_x86.bat "C:\Path\Python32\python.exe"
  exit /b 1
)

set "PYTHON=%~1"

echo [1/4] Verification architecture Python...
"%PYTHON%" -c "import struct,sys; sys.exit(0 if struct.calcsize('P')*8==32 else 1)"
if errorlevel 1 (
  echo [ERREUR] L'interpreteur fourni n'est pas en 32 bits.
  exit /b 1
)

echo [2/4] Installation dependances...
"%PYTHON%" -m pip install --upgrade pip
"%PYTHON%" -m pip install -r requirements.txt

echo [3/4] Build EXE x86...
"%PYTHON%" -m PyInstaller --clean --noconfirm --onefile --windowed --name scan_system_x86 --distpath dist_x86 scanner_windows.py
if errorlevel 1 (
  echo [ERREUR] Echec compilation EXE x86.
  exit /b 1
)

echo [4/4] OK: dist_x86\scan_system_x86.exe
endlocal
