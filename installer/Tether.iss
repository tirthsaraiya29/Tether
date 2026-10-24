; ============================================================================
;  Tether — Inno Setup Installer Script
;
;  Layout assumed on disk:
;    installer\Tether.iss              (this file)
;    installer\pack\*                  (published app payload)
;    installer\pack\TetherCredentialProvider.dll
;
;  Build:
;    iscc.exe Tether.iss
; ============================================================================

#define MyAppName           "Tether"
#define MyAppVersion        "1.1.2"
#define MyAppPublisher      "Tether Project"
#define MyAppURL            "https://github.com/tirthsaraiya29/Tether"
#define MyAppExeName        "Tether.CommunicationService.exe"
#define MyDesktopUIExeName  "Tether.DesktopUI.exe"

#define MyServiceName       "TetherCommService"
#define MyServiceDisplay    "Tether Communication Service"
#define MyServiceDesc       "Tether background communication service: discovery, TLS transport, session orchestration."

#define MyCredProvDll       "TetherCredentialProvider.dll"
; Escaped double-brace '{{' prevents Inno from treating the GUID as a variable
#define MyCredProvGuid      "{{c8c8d282-f4f1-451d-96fc-a8b1f783117b}"
#define MyCredProvName      "TetherCredentialProvider"

; Compile-time relative path to published files
#define PackDir             "pack"

; ---------------------------------------------------------------------------
;  Runtime prerequisite URLs (official Microsoft endpoints)
; ---------------------------------------------------------------------------
#define UrlVCRedistX64      "https://aka.ms/vs/17/release/vc_redist.x64.exe"
#define UrlVCRedistX86      "https://aka.ms/vs/17/release/vc_redist.x86.exe"
#define UrlDotNetDesktop    "https://builds.dotnet.microsoft.com/dotnet/WindowsDesktop/10.0.13/windowsdesktop-runtime-10.0.13-win-x64.exe"

[Setup]
AppId={{8F2C3A41-9D7E-4B62-A8E3-1F6D4C2B7E09}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}

DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes

PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=commandline

ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

MinVersion=10.0.19041

WizardStyle=dynamic
WizardSizePercent=110

OutputDir=output
OutputBaseFilename=Tether-Setup-{#MyAppVersion}
Compression=lzma2/ultra64
SolidCompression=yes
LZMAUseSeparateProcess=yes

DisableWelcomePage=no
DisableReadyPage=no
AllowNoIcons=yes
CloseApplications=yes
RestartApplications=no
SetupLogging=yes
UninstallDisplayIcon={app}\{#MyDesktopUIExeName}
UninstallDisplayName={#MyAppName} {#MyAppVersion}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[CustomMessages]
english.InstallServiceTask=Install and configure Tether background service
english.FirewallTask=Add Windows Firewall rules (TCP 37123, UDP 37124)
english.DesktopShortcutTask=Create a desktop shortcut for Tether
english.LaunchUITask=Launch Tether Desktop UI with administrator privileges
english.VaultUninstallPrompt=Tether stores encrypted credentials in HKLM\SOFTWARE\Tether.%n%nDo you want to permanently erase this stored vault data?%n%nSelect 'No' to preserve your pairing for future installations.
english.ServiceStarting=Registering and starting {#MyServiceDisplay}...
english.ServiceStopping=Stopping {#MyServiceDisplay}...
english.StoppingExisting=Stopping existing Tether service...
english.PreparePrereq=Checking and retrieving prerequisites...
english.KillProcesses=Terminating active Tether processes...

[Tasks]
Name: "installservice";   Description: "{cm:InstallServiceTask}";    GroupDescription: "Core Components:"; Flags: checkedonce
Name: "firewall";         Description: "{cm:FirewallTask}";          GroupDescription: "Networking:";       Flags: checkedonce
Name: "desktopshortcut";  Description: "{cm:DesktopShortcutTask}";   GroupDescription: "Shortcuts:";        Flags: unchecked
Name: "launchui";         Description: "{cm:LaunchUITask}";          GroupDescription: "Post-install:";     Flags: checkedonce

[Files]
; Application payload
Source: "{#PackDir}\*"; DestDir: "{app}"; \
    Excludes: "{#MyCredProvDll}"; \
    Flags: ignoreversion recursesubdirs createallsubdirs

; Native Credential Provider DLL -> C:\Windows\System32
Source: "{#PackDir}\{#MyCredProvDll}"; DestDir: "{sys}"; \
    Flags: ignoreversion restartreplace uninsremovereadonly 64bit

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyDesktopUIExeName}"
Name: "{commondesktop}\{#MyAppName}"; Filename: "{app}\{#MyDesktopUIExeName}"; Tasks: desktopshortcut

[Registry]
; ---------------------------------------------------------------------------
;  Credential Provider Registration — 1:1 match with register.reg
; ---------------------------------------------------------------------------
; 1. COM CLSID InprocServer32 Entry
Root: HKLM64; Subkey: "SOFTWARE\Classes\CLSID\{#MyCredProvGuid}"; \
    ValueType: string; ValueName: ""; ValueData: "{#MyCredProvName}"; \
    Flags: uninsdeletekey

Root: HKLM64; Subkey: "SOFTWARE\Classes\CLSID\{#MyCredProvGuid}\InprocServer32"; \
    ValueType: string; ValueName: ""; ValueData: "{sys}\{#MyCredProvDll}"; \
    Flags: uninsdeletekey

Root: HKLM64; Subkey: "SOFTWARE\Classes\CLSID\{#MyCredProvGuid}\InprocServer32"; \
    ValueType: string; ValueName: "ThreadingModel"; ValueData: "Apartment"

; 2. Windows Logon Credential Provider
Root: HKLM64; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{#MyCredProvGuid}"; \
    ValueType: string; ValueName: ""; ValueData: "{#MyCredProvName}"; \
    Flags: uninsdeletekey

; 3. Windows Logon Credential Provider Filter
Root: HKLM64; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters\{#MyCredProvGuid}"; \
    ValueType: string; ValueName: ""; ValueData: "{#MyCredProvName}"; \
    Flags: uninsdeletekey

; 4. Encrypted configuration and secure pairing store
Root: HKLM64; Subkey: "SOFTWARE\{#MyAppName}"; Flags: createvalueifdoesntexist

; 5. Shell App Paths registration
Root: HKLM64; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{#MyDesktopUIExeName}"; \
    ValueType: string; ValueName: ""; ValueData: "{app}\{#MyDesktopUIExeName}"; \
    Flags: uninsdeletekey
Root: HKLM64; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{#MyDesktopUIExeName}"; \
    ValueType: string; ValueName: "Path"; ValueData: "{app}"

; 6. Windows Explorer Shell Context Menu ("Send to Phone — Tether")
Root: HKCR; Subkey: "*\shell\TetherSendToPhone"; ValueType: string; ValueName: ""; ValueData: "Send to Phone — Tether"; Flags: uninsdeletekey
Root: HKCR; Subkey: "*\shell\TetherSendToPhone"; ValueType: string; ValueName: "Icon"; ValueData: "{app}\{#MyDesktopUIExeName},0"
Root: HKCR; Subkey: "*\shell\TetherSendToPhone\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyDesktopUIExeName}"" ""--send"" ""%1"""

Root: HKCR; Subkey: "Directory\shell\TetherSendToPhone"; ValueType: string; ValueName: ""; ValueData: "Send to Phone — Tether"; Flags: uninsdeletekey
Root: HKCR; Subkey: "Directory\shell\TetherSendToPhone"; ValueType: string; ValueName: "Icon"; ValueData: "{app}\{#MyDesktopUIExeName},0"
Root: HKCR; Subkey: "Directory\shell\TetherSendToPhone\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyDesktopUIExeName}"" ""--send"" ""%1"""

[Run]
; Firewall Configuration
Filename: "{sys}\netsh.exe"; \
    Parameters: "advfirewall firewall add rule name=""Tether Protocol (TCP-In)"" dir=in action=allow protocol=TCP localport=37123 profile=any"; \
    Flags: runhidden waituntilterminated; \
    Tasks: firewall

Filename: "{sys}\netsh.exe"; \
    Parameters: "advfirewall firewall add rule name=""Tether Discovery (UDP-In)"" dir=in action=allow protocol=UDP localport=37124 profile=any"; \
    Flags: runhidden waituntilterminated; \
    Tasks: firewall

; Post-install launch with administrator privileges
Filename: "{app}\{#MyDesktopUIExeName}"; \
    Verb: "runas"; \
    Description: "{cm:LaunchUITask}"; \
    Flags: shellexec nowait postinstall skipifsilent; \
    Tasks: launchui

[UninstallRun]
; Clean firewall rules
Filename: "{sys}\netsh.exe"; \
    Parameters: "advfirewall firewall delete rule name=""Tether Protocol (TCP-In)"""; \
    Flags: runhidden waituntilterminated; \
    RunOnceId: "RemoveTetherTcpRule"

Filename: "{sys}\netsh.exe"; \
    Parameters: "advfirewall firewall delete rule name=""Tether Discovery (UDP-In)"""; \
    Flags: runhidden waituntilterminated; \
    RunOnceId: "RemoveTetherUdpRule"

[UninstallDelete]
Type: files;          Name: "{sys}\{#MyCredProvDll}"
Type: filesandordirs; Name: "{app}"
Type: filesandordirs; Name: "{commonappdata}\Tether"

; ============================================================================
;  PASCAL CODE SCRIPTING
; ============================================================================
[Code]

const
  { Service States }
  SERVICE_STOPPED          = $00000001;
  SERVICE_START_PENDING    = $00000002;
  SERVICE_STOP_PENDING     = $00000003;
  SERVICE_RUNNING          = $00000004;

  { Service Access Rights }
  SC_MANAGER_CONNECT       = $0001;
  SC_MANAGER_CREATE_SERVICE= $0002;
  SERVICE_QUERY_STATUS     = $0004;
  SERVICE_START            = $0010;
  SERVICE_STOP             = $0020;
  SERVICE_ALL_ACCESS       = $F01FF;

  { Service Configuration Flags }
  SERVICE_WIN32_OWN_PROCESS= $00000010;
  SERVICE_AUTO_START       = $00000002;
  SERVICE_ERROR_NORMAL     = $00000001;

type
  TServiceStatus = record
    dwServiceType:             DWORD;
    dwCurrentState:            DWORD;
    dwControlsAccepted:        DWORD;
    dwWin32ExitCode:           DWORD;
    dwServiceSpecificExitCode: DWORD;
    dwCheckPoint:              DWORD;
    dwWaitHint:                DWORD;
  end;

var
  DownloadPage: TDownloadWizardPage;

function OpenSCManager(lpMachineName, lpDatabaseName: string; dwDesiredAccess: DWORD): THandle;
  external 'OpenSCManagerW@advapi32.dll stdcall';

function OpenService(hSCManager: THandle; lpServiceName: string; dwDesiredAccess: DWORD): THandle;
  external 'OpenServiceW@advapi32.dll stdcall';

function CreateService(
  hSCManager: THandle;
  lpServiceName, lpDisplayName: string;
  dwDesiredAccess, dwServiceType, dwStartType, dwErrorControl: DWORD;
  lpBinaryPathName, lpLoadOrderGroup: string;
  lpdwTagId: DWORD;
  lpDependencies, lpServiceStartName, lpPassword: string): THandle;
  external 'CreateServiceW@advapi32.dll stdcall';

function StartService(hService: THandle; dwNumServiceArgs: DWORD; lpServiceArgVectors: DWORD): BOOL;
  external 'StartServiceW@advapi32.dll stdcall';

function QueryServiceStatus(hService: THandle; var lpServiceStatus: TServiceStatus): BOOL;
  external 'QueryServiceStatus@advapi32.dll stdcall';

function ControlService(hService: THandle; dwControl: DWORD; var lpServiceStatus: TServiceStatus): BOOL;
  external 'ControlService@advapi32.dll stdcall';

function CloseServiceHandle(hSCObject: THandle): BOOL;
  external 'CloseServiceHandle@advapi32.dll stdcall';

procedure SHChangeNotify(wEventId: Integer; uFlags: Cardinal; dwItem1, dwItem2: Cardinal);
  external 'SHChangeNotify@shell32.dll stdcall';

procedure Sleep(dwMilliseconds: DWORD);
  external 'Sleep@kernel32.dll stdcall';

{ --- Service Operations --- }

function ServiceExists(const ServiceName: string): Boolean;
var
  SCM, Svc: THandle;
begin
  Result := False;
  SCM := OpenSCManager('', '', SC_MANAGER_CONNECT);
  if SCM <> 0 then
  begin
    try
      Svc := OpenService(SCM, ServiceName, SERVICE_QUERY_STATUS);
      if Svc <> 0 then
      begin
        Result := True;
        CloseServiceHandle(Svc);
      end;
    finally
      CloseServiceHandle(SCM);
    end;
  end;
end;

function StopServiceIfRunning(const ServiceName: string): Boolean;
var
  SCM, Svc: THandle;
  Status: TServiceStatus;
  Waited: Integer;
begin
  Result := True;
  SCM := OpenSCManager('', '', SC_MANAGER_CONNECT);
  if SCM = 0 then Exit;
  try
    Svc := OpenService(SCM, ServiceName, SERVICE_QUERY_STATUS or SERVICE_STOP);
    if Svc = 0 then Exit;
    try
      if QueryServiceStatus(Svc, Status) then
      begin
        if (Status.dwCurrentState = SERVICE_RUNNING) or (Status.dwCurrentState = SERVICE_START_PENDING) then
        begin
          ControlService(Svc, SERVICE_STOP, Status);
          Waited := 0;
          while (Status.dwCurrentState <> SERVICE_STOPPED) and (Waited < 20) do
          begin
            Sleep(500);
            Inc(Waited);
            if not QueryServiceStatus(Svc, Status) then Break;
          end;
          Result := (Status.dwCurrentState = SERVICE_STOPPED);
        end;
      end;
    finally
      CloseServiceHandle(Svc);
    end;
  finally
    CloseServiceHandle(SCM);
  end;
end;

procedure DeleteServiceSilently(const ServiceName: string);
var
  ResultCode: Integer;
begin
  Exec(ExpandConstant('{sys}\sc.exe'), 'delete ' + ServiceName, '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

function InstallAndStartTetherService(): Boolean;
var
  SCM, Svc: THandle;
  BinPath: string;
  ResultCode: Integer;
begin
  Result := False;
  SCM := OpenSCManager('', '', SC_MANAGER_CONNECT or SC_MANAGER_CREATE_SERVICE);
  if SCM = 0 then Exit;

  try
    BinPath := '"' + ExpandConstant('{app}\{#MyAppExeName}') + '"';
    Svc := CreateService(
      SCM,
      '{#MyServiceName}',
      '{#MyServiceDisplay}',
      SERVICE_ALL_ACCESS,
      SERVICE_WIN32_OWN_PROCESS,
      SERVICE_AUTO_START,
      SERVICE_ERROR_NORMAL,
      BinPath,
      '', 0, '', '', ''
    );

    if Svc = 0 then
    begin
      { If creation failed because it already exists, open it }
      Svc := OpenService(SCM, '{#MyServiceName}', SERVICE_ALL_ACCESS);
    end;

    if Svc <> 0 then
    begin
      try
        { Configure description and recovery actions }
        Exec(ExpandConstant('{sys}\sc.exe'),
             'description {#MyServiceName} "{#MyServiceDesc}"',
             '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

        Exec(ExpandConstant('{sys}\sc.exe'),
             'failure {#MyServiceName} reset= 86400 actions= restart/5000/restart/10000/restart/30000',
             '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

        { Start the service }
        StartService(Svc, 0, 0);
        Result := True;
      finally
        CloseServiceHandle(Svc);
      end;
    end;
  finally
    CloseServiceHandle(SCM);
  end;
end;

{ --- Process Management --- }

procedure KillProcessByName(const ProcessName: string);
var
  ResultCode: Integer;
begin
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /T /IM "' + ProcessName + '"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

procedure StopAllTetherProcesses();
begin
  KillProcessByName('{#MyDesktopUIExeName}');
  KillProcessByName('Tether.SessionHelper.exe');
  KillProcessByName('{#MyAppExeName}');
  Sleep(500);
end;

{ --- Prerequisite Detection --- }

function IsVCRedistInstalled(const Arch: String): Boolean;
var
  Installed: Cardinal;
  RootKey: Integer;
begin
  if Arch = 'x64' then
    RootKey := HKLM64
  else
    RootKey := HKLM32;

  Result := RegQueryDWordValue(RootKey, 'SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\' + Arch, 'Installed', Installed) and (Installed = 1);
end;

function IsDotNetDesktopInstalled(): Boolean;
var
  BasePath: String;
  FindRec: TFindRec;
  Found: Boolean;
begin
  BasePath := ExpandConstant('{commonpf64}\dotnet\shared\Microsoft.WindowsDesktop.App');
  Found := False;

  if FindFirst(BasePath + '\10.*', FindRec) then
  begin
    try
      repeat
        if Pos('10.', FindRec.Name) = 1 then
        begin
          Found := True;
          Break;
        end;
      until not FindNext(FindRec);
    finally
      FindClose(FindRec);
    end;
  end;
  Result := Found;
end;

{ --- Inno Setup Event Hooks --- }

procedure InitializeWizard();
begin
  DownloadPage := CreateDownloadPage(SetupMessage(msgWizardPreparing), SetupMessage(msgPreparingDesc), nil);
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  NeedVcx64, NeedVcx86, NeedDotNet: Boolean;
  Vcx64Path, Vcx86Path, DotNetPath: String;
  ResultCode: Integer;
begin
  Result := True;

  if CurPageID = wpReady then
  begin
    NeedVcx64 := not IsVCRedistInstalled('x64');
    NeedVcx86 := not IsVCRedistInstalled('x86');
    NeedDotNet := not IsDotNetDesktopInstalled();

    if NeedVcx64 or NeedVcx86 or NeedDotNet then
    begin
      DownloadPage.Clear;
      if NeedVcx64 then
        DownloadPage.Add('{#UrlVCRedistX64}', 'vc_redist.x64.exe', '');
      if NeedVcx86 then
        DownloadPage.Add('{#UrlVCRedistX86}', 'vc_redist.x86.exe', '');
      if NeedDotNet then
        DownloadPage.Add('{#UrlDotNetDesktop}', 'dotnet10desktop-x64.exe', '');

      DownloadPage.Show;
      try
        try
          DownloadPage.Download;
        except
          if DownloadPage.AbortedByUser then
            Log('Download aborted by user.')
          else
            SuppressibleMsgBox(AddPeriod(GetExceptionMessage), mbCriticalError, MB_OK, IDOK);
          Result := False;
          Exit;
        end;

        if NeedVcx64 then
        begin
          Vcx64Path := ExpandConstant('{tmp}\vc_redist.x64.exe');
          Exec(Vcx64Path, '/install /quiet /norestart', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
        end;

        if NeedVcx86 then
        begin
          Vcx86Path := ExpandConstant('{tmp}\vc_redist.x86.exe');
          Exec(Vcx86Path, '/install /quiet /norestart', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
        end;

        if NeedDotNet then
        begin
          DotNetPath := ExpandConstant('{tmp}\dotnet10desktop-x64.exe');
          Exec(DotNetPath, '/install /quiet /norestart', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
        end;
      finally
        DownloadPage.Hide;
      end;
    end;
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';

  if ServiceExists('{#MyServiceName}') then
  begin
    WizardForm.StatusLabel.Caption := ExpandConstant('{cm:StoppingExisting}');
    StopServiceIfRunning('{#MyServiceName}');
    DeleteServiceSilently('{#MyServiceName}');
    Sleep(500);
  end;

  WizardForm.StatusLabel.Caption := ExpandConstant('{cm:KillProcesses}');
  StopAllTetherProcesses();
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    { Direct Win32 API installation of the Windows Service }
    if WizardIsTaskSelected('installservice') then
    begin
      WizardForm.StatusLabel.Caption := ExpandConstant('{cm:ServiceStarting}');
      InstallAndStartTetherService();
    end;

    SHChangeNotify($08000000, 0, 0, 0); { SHCNE_ASSOCCHANGED }
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  VaultKey: String;
begin
  if CurUninstallStep = usUninstall then
  begin
    { Stop and remove background service before files get cleaned }
    StopServiceIfRunning('{#MyServiceName}');
    DeleteServiceSilently('{#MyServiceName}');

    StopAllTetherProcesses();

    { Optional purge of the encrypted credentials vault }
    VaultKey := 'SOFTWARE\{#MyAppName}';
    if RegKeyExists(HKLM64, VaultKey) then
    begin
      if MsgBox(ExpandConstant('{cm:VaultUninstallPrompt}'), mbConfirmation, MB_YESNO) = IDYES then
      begin
        RegDeleteKeyIncludingSubkeys(HKLM64, VaultKey);
      end;
    end;
  end;
end;