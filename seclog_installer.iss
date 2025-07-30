
; -- SecLog Installer Script --

[Setup]
AppName=SecLog Analyzer
AppVersion=1.0
DefaultDirName={pf}\SecLogAnalyzer
DefaultGroupName=SecLog Analyzer
UninstallDisplayIcon={app}\seclog_analyzer.exe
OutputDir=output
OutputBaseFilename=SecLog_Installer
SetupIconFile=seclog_icon.ico
Compression=lzma
SolidCompression=yes
PrivilegesRequired=admin
DisableProgramGroupPage=yes

[Files]
Source: "dist\SecLog.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "seclog_icon.ico"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\SecLog Analyzer"; Filename: "{app}\SecLog.exe"; IconFilename: "{app}\SecLog.exe"
Name: "{commondesktop}\SecLog Analyzer"; Filename: "{app}\SecLog.exe"; IconFilename: "{app}\SecLog.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop icon"; GroupDescription: "Additional icons:"

[Run]
Filename: "{app}\SecLog.exe"; Description: "Launch SecLog Analyzer"; Flags: nowait postinstall skipifsilent
