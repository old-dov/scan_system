; Rust migration installer. Keep the Python installer usable until parity is verified.

#define MyAppName "Scan System"
#ifndef MyAppVersion
#define MyAppVersion "1.1.1"
#endif
#ifndef MyOutputSuffix
  #define MyOutputSuffix ""
#endif
#define MyAppPublisher "Scan System"
#define MyAppExeName "scan_system.exe"
#ifndef MyBuildDir
  #define MyBuildDir "rust\target\release"
#endif
; Must match installer.iss so a future Rust release can update the same install.
#define MyAppId "5E7D1AF1-CC8D-4D8E-8AF8-2C2C4F6C0D50"

[Setup]
AppId={{{#MyAppId}}}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\Scan System
DefaultGroupName=Scan System
DisableProgramGroupPage=yes
OutputDir=rust\installer_output
OutputBaseFilename=ScanSystemRustSetup-{#MyAppVersion}{#MyOutputSuffix}
Compression=lzma
SolidCompression=yes
WizardStyle=modern dynamic
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayIcon={app}\{#MyAppExeName}
SetupIconFile=pictures\scan_system.ico
SetupLogging=yes
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "french"; MessagesFile: "compiler:Languages\French.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Creer un raccourci sur le bureau"; GroupDescription: "Raccourcis:"; Flags: unchecked; Languages: french
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Shortcuts:"; Flags: unchecked; Languages: english

[Files]
Source: "{#MyBuildDir}\scan-system-gui.exe"; DestDir: "{app}"; DestName: "{#MyAppExeName}"; Flags: ignoreversion
Source: "{#MyBuildDir}\scan-system-cli.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\Scan System"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\Scan System"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[UninstallDelete]
Type: filesandordirs; Name: "{app}"

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Lancer Scan System"; Flags: nowait postinstall skipifsilent; Languages: french
Filename: "{app}\{#MyAppExeName}"; Description: "Launch Scan System"; Flags: nowait postinstall skipifsilent; Languages: english

[Code]
procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    if ActiveLanguage() = 'english' then
      SaveStringToFile(ExpandConstant('{app}\default_language.txt'), 'en', False)
    else
      SaveStringToFile(ExpandConstant('{app}\default_language.txt'), 'fr', False);
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  UninstallCommand: String;
  Key: String;
  ExitCode: Integer;
begin
  Result := '';
  { The existing AppId is recorded with two closing braces in the uninstall key. }
  Key := 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{' + '{#MyAppId}' + '}}_is1';
  if not RegQueryStringValue(HKLM64, Key, 'UninstallString', UninstallCommand) and
     not RegQueryStringValue(HKLM32, Key, 'UninstallString', UninstallCommand) then
    Exit;
  { The previous uninstaller suppresses the user-data prompt in silent mode. }
  if not Exec('>', UninstallCommand + ' /VERYSILENT /SUPPRESSMSGBOXES /NORESTART',
    '', SW_HIDE, ewWaitUntilTerminated, ExitCode) then
  begin
    Result := 'Impossible de lancer la desinstallation de la version precedente.';
    Exit;
  end;
  if ExitCode <> 0 then
  begin
    Result := 'La desinstallation precedente a echoue (code ' + IntToStr(ExitCode) + ').';
    Exit;
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  RunKey: String;
  InstalledCommand: String;
  CurrentCommand: String;
  DataDir: String;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    { Only remove values owned by this install in the current profile. }
    RunKey := 'Software\Microsoft\Windows\CurrentVersion\Run';
    InstalledCommand := Lowercase('"' + ExpandConstant('{app}\{#MyAppExeName}') + '"');
    if RegQueryStringValue(HKCU, RunKey, 'ScanSystemRustMonitor', CurrentCommand) and
       (Pos(InstalledCommand, Lowercase(CurrentCommand)) = 1) then
      RegDeleteValue(HKCU, RunKey, 'ScanSystemRustMonitor');
    if RegQueryStringValue(HKCU, RunKey, 'ScanSystemMonitor', CurrentCommand) and
       (Pos(InstalledCommand, Lowercase(CurrentCommand)) = 1) then
      RegDeleteValue(HKCU, RunKey, 'ScanSystemMonitor');

    DataDir := ExpandConstant('{localappdata}\ScanSystem');
    if (not UninstallSilent) and DirExists(DataDir) and
       (MsgBox('Supprimer aussi les donnees de ce profil ?' + #13#10 +
         DataDir + #13#10 + #13#10 + 'Cette action est irreversible.',
         mbConfirmation, MB_YESNO) = IDYES) then
    begin
      DelTree(DataDir, True, True, True);
    end;
  end;
end;
