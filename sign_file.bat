@echo off
setlocal

if "%~1"=="" (
  echo [ERREUR] Usage: sign_file.bat "C:\path\to\file.exe"
  exit /b 1
)

set "TARGET_FILE=%~1"
if not exist "%TARGET_FILE%" (
  echo [ERREUR] Fichier introuvable: %TARGET_FILE%
  exit /b 1
)

set "SIGNTOOL_PATH=C:\Program Files (x86)\Windows Kits\10\bin\x64\signtool.exe"
if not exist "%SIGNTOOL_PATH%" set "SIGNTOOL_PATH=C:\Program Files\Windows Kits\10\bin\x64\signtool.exe"

if not exist "%SIGNTOOL_PATH%" (
  echo [INFO] signtool.exe introuvable. Signature ignoree.
  exit /b 0
)

if "%TIMESTAMP_URL%"=="" set "TIMESTAMP_URL=http://timestamp.digicert.com"

if not "%CERT_FILE%"=="" (
  if "%CERT_PASSWORD%"=="" (
    echo [ERREUR] CERT_FILE defini mais CERT_PASSWORD absent.
    exit /b 1
  )
  echo [SIGN] Signature avec fichier certificat...
  "%SIGNTOOL_PATH%" sign /f "%CERT_FILE%" /p "%CERT_PASSWORD%" /fd sha256 /tr "%TIMESTAMP_URL%" /td sha256 "%TARGET_FILE%"
  exit /b %ERRORLEVEL%
)

if not "%CERT_THUMBPRINT%"=="" (
  echo [SIGN] Signature avec certificat magasin par empreinte...
  "%SIGNTOOL_PATH%" sign /sha1 "%CERT_THUMBPRINT%" /fd sha256 /tr "%TIMESTAMP_URL%" /td sha256 "%TARGET_FILE%"
  exit /b %ERRORLEVEL%
)

echo [INFO] Aucune config de certificat detectee ^(CERT_FILE/CERT_PASSWORD ou CERT_THUMBPRINT^). Signature ignoree.
exit /b 0
