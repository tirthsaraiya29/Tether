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
;
;  Requirements:
;    - Inno Setup 6.3+ (for WizardStyle=dynamic and x64compatible arch)
;    - Elevation (admin) — required for System32 DLL, HKLM registry, service
; ============================================================================

#define MyAppName           "Tether"
#define MyAppVersion        "1.0.0"
#define MyAppPublisher      "Tether"
#define MyAppURL            "https://github.com/tirthsaraiya29/Tether"
#define MyAppExeName        "Tether.CommunicationService.exe"
#define MyDesktopUIExeName  "Tether.DesktopUI.exe"

#define MyServiceName       "TetherCommService"
#define MyServiceDisplay    "Tether Communication Service"
#define MyServiceDesc       "Tether background communication service: discovery, TLS transport, session orchestration."

#define MyCredProvDll       "TetherCredentialProvider.dll"
; Double-brace the GUID so Inno treats { and } as literals, not constant refs.
#define MyCredProvGuid      "{{c8c8d282-f4f1-451d-96fc-a8b1f783117b}}"
#define MyCredProvName      "TetherCredentialProvider"

; Absolute path to the pack folder — change this if you move the project.
#define PackDir             "C:\Users\tirth\Downloads\Projects\Tether\installer\pack"

[Setup]
AppId={{8F2C3A41-9D7E-4B62-A8E3-1F6D4C2B7E09}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}

; Install into C:\Program Files\Tether
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes

; Elevation
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=commandline

; 64-bit only
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

; Modern Windows required (credential provider path)
MinVersion=10.0.19041

; Modern dark/light wizard that tracks Windows theme
WizardStyle=dynamic
WizardSizePercent=110

; Output
OutputDir=output
OutputBaseFilename=Tether-Setup-{#MyAppVersion}
Compression=lzma2/ultra64
SolidCompression=yes
LZMAUseSeparateProcess=yes

; UX
DisableWelcomePage=no
DisableReadyPage=no
AllowNoIcons=yes
CloseApplications=yes
RestartApplications=no
SetupLogging=yes
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppName} {#MyAppVersion}

; Signing (optional — fill in when you have a code-signing cert)
; SignTool=signtool
; SignedUninstaller=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

; Uncomment to add more languages — install the corresponding .isl first
; Name: "german";  MessagesFile: "compiler:Languages\German.isl"
; Name: "french";  MessagesFile: "compiler:Languages\French.isl"
; Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"

[CustomMessages]
english.InstallServiceTask=Install and start the Tether background service
english.FirewallTask=Add Windows Firewall rules for Tether (TCP 37123, UDP 37124)
english.LaunchUITask=Launch Tether Desktop UI after installation
english.VaultUninstallPrompt=Tether stores encrypted credentials in HKLM\SOFTWARE\Tether.%n%nDo you want to remove this stored data as well?%n%nChoose No to keep it (recommended if you plan to reinstall).
english.ServiceStarting=Starting {#MyServiceDisplay}...
english.ServiceStopping=Stopping {#MyServiceDisplay}...
english.RegisteredCredProv=Registered Tether credential provider
english.StoppingExisting=Stopping existing Tether service before upgrade...

[Tasks]
Name: "installservice";  Description: "{cm:InstallServiceTask}";   GroupDescription: "Tether components:"; Flags: checkedonce
Name: "firewall";        Description: "{cm:FirewallTask}";         GroupDescription: "Tether components:"; Flags: checkedonce
Name: "launchui";        Description: "{cm:LaunchUITask}";         GroupDescription: "Post-install:";      Flags: unchecked

[Files]
; ---------------------------------------------------------------------------
;  1. App payload → C:\Program Files\Tether
;     Excludes TetherCredentialProvider.dll because that goes to System32.
; ---------------------------------------------------------------------------
Source: "{#PackDir}\*"; DestDir: "{app}"; \
    Excludes: "{#MyCredProvDll}"; \
    Flags: ignoreversion recursesubdirs createallsubdirs

; ---------------------------------------------------------------------------
;  2. Credential Provider DLL → C:\Windows\System32
;     ArchitecturesInstallIn64BitMode makes {sys} resolve to the 64-bit
;     System32 folder, not SysWOW64. The DLL must be signed with a code
;     signing certificate or Windows will refuse to load it at logon.
; ---------------------------------------------------------------------------
Source: "{#PackDir}\{#MyCredProvDll}"; DestDir: "{sys}"; \
    Flags: ignoreversion restartreplace uninsremovereadonly

[Registry]
; ---------------------------------------------------------------------------
;  Credential Provider registration
;  Mirrors the .reg exports provided with the project.
;  uninsdeletekey ensures these are removed on uninstall.
; ---------------------------------------------------------------------------

; CLSID base
Root: HKCR; Subkey: "CLSID\{#MyCredProvGuid}"; \
    ValueType: string; ValueName: ""; ValueData: "{#MyCredProvName}"; \
    Flags: uninsdeletekey

; CLSID InprocServer32
Root: HKCR; Subkey: "CLSID\{#MyCredProvGuid}\InprocServer32"; \
    ValueType: string; ValueName: ""; ValueData: "{sys}\{#MyCredProvDll}"; \
    Flags: uninsdeletekey

Root: HKCR; Subkey: "CLSID\{#MyCredProvGuid}\InprocServer32"; \
    ValueType: string; ValueName: "ThreadingModel"; ValueData: "Apartment"

; Credential Provider registration
Root: HKLM; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{#MyCredProvGuid}"; \
    ValueType: string; ValueName: ""; ValueData: "{#MyCredProvName}"; \
    Flags: uninsdeletekey

; Credential Provider Filter
Root: HKLM; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters\{#MyCredProvGuid}"; \
    ValueType: string; ValueName: ""; ValueData: "{#MyCredProvName}"; \
    Flags: uninsdeletekey

; ---------------------------------------------------------------------------
;  Encrypted credential vault
;  Created empty at install time. Deliberately NOT flagged uninsdeletekey —
;  the uninstaller will ask the user whether to purge it (see [Code]).
; ---------------------------------------------------------------------------
Root: HKLM; Subkey: "SOFTWARE\{#MyAppName}"; Flags: createvalueifdoesntexist

; ---------------------------------------------------------------------------
;  App Paths — lets users type "Tether" in Win+R to launch the Desktop UI
; ---------------------------------------------------------------------------
Root: HKLM; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{#MyDesktopUIExeName}"; \
    ValueType: string; ValueName: ""; ValueData: "{app}\{#MyDesktopUIExeName}"; \
    Flags: uninsdeletekey
Root: HKLM; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{#MyDesktopUIExeName}"; \
    ValueType: string; ValueName: "Path"; ValueData: "{app}"

[Run]
; ---------------------------------------------------------------------------
;  Firewall rules — optional, since Worker.cs also creates them at startup.
;  Running netsh here means the rules exist even before the first service
;  start, which avoids a first-launch hiccup on restrictive networks.
; ---------------------------------------------------------------------------
Filename: "{sys}\netsh.exe"; \
    Parameters: "advfirewall firewall add rule name=""Tether TCP 37123"" dir=in action=allow protocol=TCP localport=37123 profile=any"; \
    Flags: runhidden waituntilterminated; \
    Tasks: firewall; StatusMsg: "Adding Windows Firewall rule (TCP 37123)..."

Filename: "{sys}\netsh.exe"; \
    Parameters: "advfirewall firewall add rule name=""Tether UDP 37124"" dir=in action=allow protocol=UDP localport=37124 profile=any"; \
    Flags: runhidden waituntilterminated; \
    Tasks: firewall; StatusMsg: "Adding Windows Firewall rule (UDP 37124)..."

; ---------------------------------------------------------------------------
;  Service creation
;  Uses sc.exe because it's available everywhere and gives us the exact
;  startup / recovery semantics we want without shipping a service helper.
;
;  Quoting note: Inno uses doubled quotes (""), not backslash escapes, to
;  embed a literal " inside a parameter string. The path needs its own
;  quotes because "C:\Program Files\Tether" contains spaces.
; ---------------------------------------------------------------------------
Filename: "{sys}\sc.exe"; \
    Parameters: "create {#MyServiceName} binPath= ""{app}\{#MyAppExeName}"" start= auto DisplayName= ""{#MyServiceDisplay}"""; \
    Flags: runhidden waituntilterminated; \
    Tasks: installservice; StatusMsg: "{cm:ServiceStarting}"

Filename: "{sys}\sc.exe"; \
    Parameters: "description {#MyServiceName} ""{#MyServiceDesc}"""; \
    Flags: runhidden waituntilterminated; \
    Tasks: installservice

; Restart on 1st, 2nd, 3rd failure; reset failure counter after 24h
Filename: "{sys}\sc.exe"; \
    Parameters: "failure {#MyServiceName} reset= 86400 actions= restart/5000/restart/10000/restart/30000"; \
    Flags: runhidden waituntilterminated; \
    Tasks: installservice

Filename: "{sys}\sc.exe"; \
    Parameters: "start {#MyServiceName}"; \
    Flags: runhidden waituntilterminated; \
    Tasks: installservice; StatusMsg: "{cm:ServiceStarting}"

; ---------------------------------------------------------------------------
;  Optional: launch the Desktop UI at the end
; ---------------------------------------------------------------------------
Filename: "{app}\{#MyDesktopUIExeName}"; \
    Description: "{cm:LaunchUITask}"; \
    Flags: nowait postinstall skipifsilent; \
    Tasks: launchui

[UninstallRun]
; ---------------------------------------------------------------------------
;  Runs BEFORE files are removed.
;  Order matters: stop service → delete service → unregister CP.
; ---------------------------------------------------------------------------
Filename: "{sys}\sc.exe"; \
    Parameters: "stop {#MyServiceName}"; \
    Flags: runhidden waituntilterminated; \
    RunOnceId: "StopTetherService"; \
    StatusMsg: "{cm:ServiceStopping}"

; Give the service a moment to release its file handles
Filename: "{cmd}"; \
    Parameters: "/c ping 127.0.0.1 -n 3 > nul"; \
    Flags: runhidden waituntilterminated; \
    RunOnceId: "WaitForServiceExit"

Filename: "{sys}\sc.exe"; \
    Parameters: "delete {#MyServiceName}"; \
    Flags: runhidden waituntilterminated; \
    RunOnceId: "DeleteTetherService"

; Remove firewall rules — netsh silently ignores "not found"
Filename: "{sys}\netsh.exe"; \
    Parameters: "advfirewall firewall delete rule name=""Tether TCP 37123"""; \
    Flags: runhidden waituntilterminated; \
    RunOnceId: "RemoveTcpFwRule"

Filename: "{sys}\netsh.exe"; \
    Parameters: "advfirewall firewall delete rule name=""Tether UDP 37124"""; \
    Flags: runhidden waituntilterminated; \
    RunOnceId: "RemoveUdpFwRule"

[UninstallDelete]
; ---------------------------------------------------------------------------
;  Explicit cleanup of files Inno doesn't own (log files, state, etc.)
;  The CP DLL in System32 is removed automatically because we installed it
;  via [Files], but we add a safety net here in case Inno's uninstaller
;  can't delete it because LogonUI has it loaded.
; ---------------------------------------------------------------------------
Type: files;          Name: "{sys}\{#MyCredProvDll}"
Type: filesandordirs; Name: "{app}"
Type: filesandordirs; Name: "{commonappdata}\Tether"
Type: filesandordirs; Name: "{commonappdata}\Tether\Logs"

; ============================================================================
;  CODE
; ============================================================================
[Code]

const
  SERVICE_STOPPED          = $00000001;
  SERVICE_START_PENDING    = $00000002;
  SERVICE_STOP_PENDING     = $00000003;
  SERVICE_RUNNING          = $00000004;

  SC_MANAGER_CONNECT       = $0001;
  SERVICE_QUERY_STATUS     = $0004;
  SERVICE_STOP             = $0020;

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

function OpenSCManager(lpMachineName: string;
                       lpDatabaseName: string;
                       dwDesiredAccess: DWORD): THandle;
  external 'OpenSCManagerW@advapi32.dll stdcall';

function OpenService(hSCManager: THandle;
                     lpServiceName: string;
                     dwDesiredAccess: DWORD): THandle;
  external 'OpenServiceW@advapi32.dll stdcall';

function QueryServiceStatus(hService: THandle;
                            var lpServiceStatus: TServiceStatus): BOOL;
  external 'QueryServiceStatus@advapi32.dll stdcall';

function ControlService(hService: THandle;
                        dwControl: DWORD;
                        var lpServiceStatus: TServiceStatus): BOOL;
  external 'ControlService@advapi32.dll stdcall';

function CloseServiceHandle(hSCObject: THandle): BOOL;
  external 'CloseServiceHandle@advapi32.dll stdcall';

procedure SHChangeNotify(wEventId: Integer; uFlags: Cardinal; dwItem1, dwItem2: Cardinal);
  external 'SHChangeNotify@shell32.dll stdcall';

{ ---------------------------------------------------------------------------
  Returns True if the named service exists in the SCM.
  --------------------------------------------------------------------------- }
function ServiceExists(const ServiceName: string): Boolean;
var
  SCM: THandle;
  Svc: THandle;
begin
  Result := False;
  SCM := OpenSCManager('', '', SC_MANAGER_CONNECT);
  if SCM = 0 then Exit;
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

{ ---------------------------------------------------------------------------
  Stops the service if it's running, then waits up to ~30 s for it to stop.
  Returns True on success (or if it wasn't running to begin with).
  --------------------------------------------------------------------------- }
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
    Svc := OpenService(SCM, ServiceName,
                       SERVICE_QUERY_STATUS or SERVICE_STOP);
    if Svc = 0 then Exit;  { service doesn't exist }
    try
      if QueryServiceStatus(Svc, Status) then
      begin
        if (Status.dwCurrentState = SERVICE_RUNNING) or
           (Status.dwCurrentState = SERVICE_START_PENDING) then
        begin
          ControlService(Svc, SERVICE_STOP, Status);
          Waited := 0;
          while (Status.dwCurrentState <> SERVICE_STOPPED) and (Waited < 30) do
          begin
            Sleep(1000);
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

{ ---------------------------------------------------------------------------
  Delete the service using sc.exe (simpler than SCM P/Invoke).
  --------------------------------------------------------------------------- }
procedure DeleteServiceSilently(const ServiceName: string);
var
  ResultCode: Integer;
begin
  Exec(ExpandConstant('{sys}\sc.exe'),
       'delete ' + ServiceName,
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

{ ---------------------------------------------------------------------------
  Pre-install / pre-upgrade hook.
  Stops and deletes any existing Tether service so sc create succeeds.
  --------------------------------------------------------------------------- }
function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  if ServiceExists('{#MyServiceName}') then
  begin
    WizardForm.StatusLabel.Caption := ExpandConstant('{cm:StoppingExisting}');
    StopServiceIfRunning('{#MyServiceName}');
    DeleteServiceSilently('{#MyServiceName}');
    { Give SCM a moment to release the service record }
    Sleep(500);
  end;
end;

{ ---------------------------------------------------------------------------
  Verify the CP DLL exists in the pack folder before starting the install.
  --------------------------------------------------------------------------- }
function InitializeSetup(): Boolean;
var
  PackPath: string;
  CredProvPath: string;
begin
  Result := True;
  PackPath := '{#PackDir}';
  CredProvPath := PackPath + '\{#MyCredProvDll}';

  if not FileExists(CredProvPath) then
  begin
    if MsgBox('Warning: ' + CredProvPath + ' was not found.' + #13#10 +
              'The installer will continue but the credential provider will not be registered.' + #13#10 + #13#10 +
              'Do you want to continue anyway?',
              mbConfirmation, MB_YESNO) = IDNO then
      Result := False;
  end;
end;

{ ---------------------------------------------------------------------------
  Uninstall-time prompt: ask whether to purge the encrypted vault.
  Called before files are removed so we can decide what to delete.
  --------------------------------------------------------------------------- }
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  VaultKey: string;
begin
  if CurUninstallStep = usUninstall then
  begin
    VaultKey := 'SOFTWARE\{#MyAppName}';

    if RegKeyExists(HKLM, VaultKey) then
    begin
      if MsgBox(ExpandConstant('{cm:VaultUninstallPrompt}'),
                mbConfirmation, MB_YESNO) = IDYES then
      begin
        RegDeleteKeyIncludingSubkeys(HKLM, VaultKey);
      end;
    end;
  end;
end;

{ ---------------------------------------------------------------------------
  Friendly status message for the shell-notification refresh.
  --------------------------------------------------------------------------- }
procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    { Notify Windows that file associations / App Paths changed }
    SHChangeNotify($08000000 { SHCNE_ASSOCCHANGED }, $0000, 0, 0);
  end;
end;