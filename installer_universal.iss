; Inno Setup script for Scan System universal installer (x86 + x64)

#define MyAppName "Scan System"
#ifndef MyAppVersion
	#define MyAppVersion "1.0.0"
#endif
#ifndef MyOutputSuffix
	#define MyOutputSuffix ""
#endif
#define MyAppPublisher "Scan System"
#define MyAppExeName "scan_system.exe"
#define MyAppId "2E4BBDF3-1139-4B88-AB77-AB6185C54D0E"

[Setup]
AppId={{{#MyAppId}}}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\Scan System
UsePreviousAppDir=yes
DefaultGroupName=Scan System
DisableProgramGroupPage=yes
OutputDir=installer_output_universal
OutputBaseFilename=ScanSystemSetup_Universal{#MyOutputSuffix}
Compression=lzma
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x86compatible x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayIcon={app}\{#MyAppExeName}
SetupIconFile=pictures\scan_system.ico
SetupLogging=yes

[Languages]
Name: "french"; MessagesFile: "compiler:Languages\French.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Creer un raccourci sur le bureau"; GroupDescription: "Raccourcis:"; Flags: unchecked

[Files]
; x64 machine: install x64 build
Source: "dist\scan_system.exe"; DestDir: "{app}"; DestName: "{#MyAppExeName}"; Flags: ignoreversion; Check: IsWin64
; x86 machine: install x86 build
Source: "dist_x86\scan_system_x86.exe"; DestDir: "{app}"; DestName: "{#MyAppExeName}"; Flags: ignoreversion; Check: not IsWin64

[Icons]
Name: "{autoprograms}\Scan System"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\Scan System"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[UninstallDelete]
Type: filesandordirs; Name: "{app}"

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Lancer Scan System"; Flags: nowait postinstall skipifsilent

[Code]
function GetUninstallStringByAppId(const AppId: string): string;
var
	KeyPath: string;
	Value: string;
begin
	Result := '';
	KeyPath := 'Software\Microsoft\Windows\CurrentVersion\Uninstall\' + AppId + '_is1';

	if RegQueryStringValue(HKLM64, KeyPath, 'UninstallString', Value) then
	begin
		Result := Value;
		exit;
	end;

	if RegQueryStringValue(HKLM32, KeyPath, 'UninstallString', Value) then
	begin
		Result := Value;
		exit;
	end;

	if RegQueryStringValue(HKCU, KeyPath, 'UninstallString', Value) then
	begin
		Result := Value;
		exit;
	end;
end;

function RunLegacyUninstall(const LegacyAppId: string; const LegacyName: string): Boolean;
var
	UninstallCmd: string;
	Params: string;
	ResultCode: Integer;
	Confirm: Integer;
begin
	Result := True;
	UninstallCmd := GetUninstallStringByAppId(LegacyAppId);
	if UninstallCmd = '' then
		exit;

	Confirm := IDYES;
	if not WizardSilent then
		Confirm := MsgBox(
			'Une ancienne version (' + LegacyName + ') a ete detectee.' + #13#10 +
			'Elle sera desinstallee avant la mise a jour.' + #13#10 + #13#10 +
			'Continuer ?',
			mbConfirmation,
			MB_YESNO
		);

	if Confirm <> IDYES then
	begin
		Result := False;
		exit;
	end;

	Params := '/C "' + UninstallCmd + ' /VERYSILENT /SUPPRESSMSGBOXES /NORESTART"';
	if not Exec(ExpandConstant('{cmd}'), Params, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
	begin
		MsgBox('Echec de desinstallation de l''ancienne version: ' + LegacyName, mbError, MB_OK);
		Result := False;
		exit;
	end;

	if ResultCode <> 0 then
	begin
		MsgBox('La desinstallation de l''ancienne version a retourne un code: ' + IntToStr(ResultCode), mbError, MB_OK);
		Result := False;
		exit;
	end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
	if (CurUninstallStep = usPostUninstall) and (not UninstallSilent) then
	begin
		if MsgBox('Supprimer aussi les donnees utilisateur (rapports d''audit, cache des flux de menaces, logs) ?' + #13#10 + #13#10 +
			'Cette action est irreversible.', mbConfirmation, MB_YESNO) = IDYES then
		begin
			DelTree(ExpandConstant('{localappdata}\ScanSystem'), True, True, True);
		end;
	end;
end;

function InitializeSetup(): Boolean;
begin
	Result := True;

	{ Legacy AppIds from previous dedicated installers }
	if not RunLegacyUninstall('5E7D1AF1-CC8D-4D8E-8AF8-2C2C4F6C0D50', 'Scan System x64 (legacy)') then
	begin
		Result := False;
		exit;
	end;

	if not RunLegacyUninstall('B1CC4374-0583-4F5A-837F-B05F8C0A78DF', 'Scan System x86 (legacy)') then
	begin
		Result := False;
		exit;
	end;
end;
