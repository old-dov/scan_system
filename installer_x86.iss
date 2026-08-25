; Inno Setup script for Scan System x86

#define MyAppName "Scan System (32-bit)"
#ifndef MyAppVersion
	#define MyAppVersion "1.0.0"
#endif
#ifndef MyOutputSuffix
	#define MyOutputSuffix ""
#endif
#define MyAppPublisher "Scan System"
#define MyAppExeName "scan_system_x86.exe"
#define MyAppId "B1CC4374-0583-4F5A-837F-B05F8C0A78DF"

[Setup]
AppId={{{#MyAppId}}}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf32}\Scan System
DefaultGroupName=Scan System
DisableProgramGroupPage=yes
OutputDir=installer_output_x86
OutputBaseFilename=ScanSystemSetup_x86{#MyOutputSuffix}
Compression=lzma
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x86compatible
ArchitecturesInstallIn64BitMode=x86compatible
UninstallDisplayIcon={app}\{#MyAppExeName}
SetupLogging=yes

[Languages]
Name: "french"; MessagesFile: "compiler:Languages\French.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Creer un raccourci sur le bureau"; GroupDescription: "Raccourcis:"; Flags: unchecked

[Files]
Source: "dist_x86\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion

[Dirs]
Name: "{commonappdata}\Scan System\Reports"

[Icons]
Name: "{autoprograms}\Scan System (32-bit)"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\Scan System (32-bit)"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Lancer Scan System (32-bit)"; Flags: nowait postinstall skipifsilent
