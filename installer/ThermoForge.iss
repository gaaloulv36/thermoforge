; ThermoForge installer (Inno Setup 6). Build it with build\release.ps1, which publishes the app,
; passes the version and output folders, and signs everything when a certificate is configured.

#ifndef AppVersion
  #define AppVersion "1.0.0"
#endif
#ifndef SourceDir
  #define SourceDir "..\artifacts\publish"
#endif
#ifndef OutputDir
  #define OutputDir "..\artifacts"
#endif

[Setup]
; Never change the AppId: Windows uses it to recognise upgrades and the uninstaller.
AppId={{312C1079-C50B-4581-8EB3-203D49286E21}
AppName=ThermoForge
AppVersion={#AppVersion}
AppVerName=ThermoForge {#AppVersion}
AppPublisher=Open Forge Studio
AppPublisherURL=https://gaaloulv36.github.io/open-forge-studio-website/
AppSupportURL=https://github.com/gaaloulv36/thermoforge/issues
AppCopyright=© Open Forge Studio
VersionInfoVersion={#AppVersion}
DefaultDirName={autopf}\Open Forge Studio\ThermoForge
DisableProgramGroupPage=yes
; Program Files and the "start with Windows" task both need admin rights.
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
OutputDir={#OutputDir}
OutputBaseFilename=ThermoForge-Setup-{#AppVersion}
SetupIconFile=..\src\ThermoForge.UI\Assets\ThermoForge.ico
UninstallDisplayIcon={app}\ThermoForge.exe
UninstallDisplayName=ThermoForge
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
; A running ThermoForge is detected by its mutex (see SingleInstance.cs) in [Code] below, not with
; AppMutex, so an in-app update can wait for the app to finish closing.
#ifdef Sign
SignTool=forgesign
SignedUninstaller=yes
#endif

[Tasks]
Name: "autostart"; Description: "Start ThermoForge with Windows (in the tray, with administrator rights for full sensor and process access)"
Name: "desktopicon"; Description: "Create a desktop shortcut"; Flags: unchecked

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[InstallDelete]
; Self-contained builds ship a full runtime; clear files an older version left behind.
Type: filesandordirs; Name: "{app}\*"

[Icons]
Name: "{autoprograms}\ThermoForge"; Filename: "{app}\ThermoForge.exe"; Comment: "PC temperatures and suspicious-activity monitor"
Name: "{autodesktop}\ThermoForge"; Filename: "{app}\ThermoForge.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\ThermoForge.exe"; Parameters: "--autostart on"; Tasks: autostart; Flags: runhidden waituntilterminated; StatusMsg: "Setting ThermoForge to start with Windows..."
Filename: "{app}\ThermoForge.exe"; Parameters: "--autostart off"; Tasks: not autostart; Flags: runhidden waituntilterminated
Filename: "{app}\ThermoForge.exe"; Description: "Open ThermoForge now"; Flags: nowait postinstall skipifsilent
; In-app updates run setup with /SILENT: reopen ThermoForge when done.
Filename: "{app}\ThermoForge.exe"; Flags: nowait; Check: WizardSilent

[UninstallRun]
Filename: "{app}\ThermoForge.exe"; Parameters: "--autostart off"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveAutoStart"

[Code]
const
  AppMutexName = 'Local\ThermoForge.Instance';

{ True once ThermoForge isn't running. An in-app update starts setup and then exits, so a silent
  run waits a few seconds for it; an interactive run asks the user to close it. }
function WaitForAppToClose(Silent: Boolean): Boolean;
var
  Tries: Integer;
begin
  Tries := 0;
  while Silent and CheckForMutexes(AppMutexName) and (Tries < 60) do
  begin
    Sleep(250);
    Tries := Tries + 1;
  end;
  while CheckForMutexes(AppMutexName) do
  begin
    if Silent or (MsgBox('ThermoForge is running. Close it (right-click its tray icon, then Exit) and click OK.',
                         mbInformation, MB_OKCANCEL) = IDCANCEL) then
    begin
      Result := False;
      exit;
    end;
  end;
  Result := True;
end;

function InitializeSetup(): Boolean;
begin
  Result := WaitForAppToClose(WizardSilent);
end;

function InitializeUninstall(): Boolean;
begin
  Result := WaitForAppToClose(UninstallSilent);
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  DataDir: String;
begin
  if CurUninstallStep <> usPostUninstall then
    exit;
  DataDir := ExpandConstant('{localappdata}\ThermoForge');
  if DirExists(DataDir) and not UninstallSilent and
     (MsgBox('Also delete your ThermoForge settings, trusted programs and scan history?' + #13#10#13#10 + DataDir,
             mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES) then
    DelTree(DataDir, True, True, True);
end;
