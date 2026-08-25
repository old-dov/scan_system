@echo off
setlocal

set "PY64=d:/projets persos/scan_system/.venv/Scripts/python.exe"
set "PY32=C:\Users\muzee\AppData\Local\Programs\Python\Python312-32\python.exe"

echo [1/6] Build x64 exe...
if exist "%PY64%" (
  "%PY64%" -m pip install -r requirements.txt
  if errorlevel 1 exit /b 1
  "%PY64%" -m PyInstaller --clean --noconfirm --onefile --windowed --name scan_system --icon "pictures\scan_system.ico" --add-data "pictures\scan_system.ico;pictures" --add-data "pictures\icon_64x64.png;pictures" scanner_windows.py
) else (
  echo [ERREUR] Python x64 venv introuvable: %PY64%
  exit /b 1
)
if errorlevel 1 exit /b 1

echo [2/6] Build x86 exe...
if not exist "%PY32%" (
  echo [ERREUR] Python 32 bits introuvable: %PY32%
  exit /b 1
)
call .\build_exe_x86.bat "%PY32%"
if errorlevel 1 exit /b 1

echo [3/6] Build installers (x64/x86/universal)...
call .\build_installer.bat
if errorlevel 1 exit /b 1
call .\build_installer_x86.bat
if errorlevel 1 exit /b 1
call .\build_installer_universal.bat
if errorlevel 1 exit /b 1

echo [4/6] Build portable ZIP...
call .\build_portable_zip.bat
if errorlevel 1 exit /b 1

echo [5/6] Optional signing of latest installers...
set "SETUP64="
set "SETUP32="
set "SETUPUNI="

for /f "delims=" %%i in ('dir /b /o-d "installer_output\*.exe" 2^>nul') do (
  if not defined SETUP64 set "SETUP64=installer_output\%%i"
)
for /f "delims=" %%i in ('dir /b /o-d "installer_output_x86\*.exe" 2^>nul') do (
  if not defined SETUP32 set "SETUP32=installer_output_x86\%%i"
)
for /f "delims=" %%i in ('dir /b /o-d "installer_output_universal\*.exe" 2^>nul') do (
  if not defined SETUPUNI set "SETUPUNI=installer_output_universal\%%i"
)

if defined SETUP64 call .\sign_file.bat "%SETUP64%"
if errorlevel 1 exit /b 1
if defined SETUP32 call .\sign_file.bat "%SETUP32%"
if errorlevel 1 exit /b 1
if defined SETUPUNI call .\sign_file.bat "%SETUPUNI%"
if errorlevel 1 exit /b 1

echo [6/6] Termine.
endlocal
