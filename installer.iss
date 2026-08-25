; Inno Setup script for Scan System
; Produces an installer registered in Windows Apps & Features.

#define MyAppName "Scan System"
#ifndef MyAppVersion
	#define MyAppVersion "1.0.0"
#endif
#ifndef MyOutputSuffix
	#define MyOutputSuffix ""
#endif
#define MyAppPublisher "Scan System"
#define MyAppExeName "scan_system.exe"
#define MyAppId "5E7D1AF1-CC8D-4D8E-8AF8-2C2C4F6C0D50"

[Setup]
AppId={{{#MyAppId}}}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\Scan System
DefaultGroupName=Scan System
DisableProgramGroupPage=yes
OutputDir=installer_output
OutputBaseFilename=ScanSystemSetup{#MyOutputSuffix}
Compression=lzma
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayIcon={app}\{#MyAppExeName}
SetupLogging=yes

[Languages]
Name: "french"; MessagesFile: "compiler:Languages\French.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Creer un raccourci sur le bureau"; GroupDescription: "Raccourcis:"; Flags: unchecked

[Files]
Source: "dist\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion

[Dirs]
Name: "{commonappdata}\Scan System\Reports"

[Icons]
Name: "{autoprograms}\Scan System"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\Scan System"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Lancer Scan System"; Flags: nowait postinstall skipifsilent
