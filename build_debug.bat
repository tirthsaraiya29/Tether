@echo off

setlocal EnableExtensions

rem ============================================================================
rem  Tether Debug Build & Local Deploy Script
rem ============================================================================
rem  Usage: build_debug.bat   (run from an elevated prompt)
rem    1. Stops TetherCommService and lingering Tether processes
rem    2. Cleans the Windows solution
rem    3. Builds Tether.slnx (Debug, Any CPU) + Credential Provider (Debug x64)
rem    4. Registers TetherCommService as a Windows service (if not registered)
rem    5. Copies the Credential Provider DLL to System32 and registers it
rem    6. Ensures firewall rules for the Debug CommunicationService binary
rem    7. Starts TetherCommService if the active network profile is Private
rem    8. Builds the Android Debug APK named with the short commit hash
rem ============================================================================

set "SCRIPT_DIR=%~dp0"
set "ROOT_DIR=%SCRIPT_DIR:~0,-1%"
cd /d "%ROOT_DIR%"

echo ============================================================================
echo   Tether - Debug Build and Local Deploy
echo ============================================================================
echo Root directory: "%ROOT_DIR%"
echo.

rem ----------------------------------------------------------------------------
rem  Locate MSBuild
rem ----------------------------------------------------------------------------
set "MSBUILD_EXE="
if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" (
    for /f "usebackq tokens=*" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe 2^>nul`) do (
        if exist "%%i" set "MSBUILD_EXE=%%i"
    )
)
if not defined MSBUILD_EXE if exist "C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD_EXE=C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe"
if not defined MSBUILD_EXE if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD_EXE=C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
if not defined MSBUILD_EXE (
    where msbuild.exe >nul 2>&1
    if not errorlevel 1 set "MSBUILD_EXE=msbuild.exe"
)
if not defined MSBUILD_EXE (
    echo [ERROR] MSBuild.exe could not be found.
    goto :error
)
echo     MSBuild:     %MSBUILD_EXE%

rem ----------------------------------------------------------------------------
rem  Configure Java / Android SDK environment
rem ----------------------------------------------------------------------------
if not defined JAVA_HOME (
    if exist "C:\Program Files\Android\Android Studio\jbr" (
        set "JAVA_HOME=C:\Program Files\Android\Android Studio\jbr"
    )
)
if not defined ANDROID_HOME (
    if exist "%LOCALAPPDATA%\Android\Sdk" (
        set "ANDROID_HOME=%LOCALAPPDATA%\Android\Sdk"
    )
)

rem Short commit hash for output naming
set "COMMIT_HASH="
for /f "delims=" %%h in ('git rev-parse --short=7 HEAD 2^>nul') do set "COMMIT_HASH=%%h"
if not defined COMMIT_HASH set "COMMIT_HASH=unknown"
echo     Commit:      %COMMIT_HASH%
echo.

rem ----------------------------------------------------------------------------
rem  Step 1: Stop Tether service and lingering processes
rem ----------------------------------------------------------------------------
echo ============================================================================
echo  [1/8] Stopping Tether service and processes...
echo ============================================================================
net stop TetherCommService >nul 2>&1
taskkill /F /IM Tether.SessionHelper.exe /T >nul 2>&1
taskkill /F /IM Tether.DesktopUI.exe /T >nul 2>&1
taskkill /F /IM Tether.CommunicationService.exe /T >nul 2>&1
taskkill /F /IM Tether.Updater.exe /T >nul 2>&1

rem ----------------------------------------------------------------------------
rem  Step 2: Clean the Windows solution
rem ----------------------------------------------------------------------------
echo  [2/8] Cleaning Tether.slnx (Debug, Any CPU)...
echo ============================================================================
"%MSBUILD_EXE%" "%ROOT_DIR%\Tether.slnx" /p:Configuration=Debug /p:Platform="Any CPU" /t:Clean /v:q /nologo
powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem -Path 'apps','services','shared' -Recurse -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -in @('bin','obj') } | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue"

rem ----------------------------------------------------------------------------
rem  Step 3: Build solution (Debug, Any CPU) + Credential Provider (Debug x64)
rem ----------------------------------------------------------------------------
echo  [3/8] Building Tether.slnx (Debug, Any CPU)...
echo ============================================================================
"%MSBUILD_EXE%" "%ROOT_DIR%\Tether.slnx" /p:Configuration=Debug /p:Platform="Any CPU" /v:m /nologo
if errorlevel 1 (
    echo [ERROR] Building Tether.slnx in Debug failed.
    goto :error
)

echo.
echo [*] Building native TetherCredentialProvider (Debug x64)...
"%MSBUILD_EXE%" "%ROOT_DIR%\TetherCredentialProvider\TetherCredentialProvider.vcxproj" /p:Configuration=Debug /p:Platform=x64 /v:m /nologo
if errorlevel 1 (
    echo [ERROR] Building TetherCredentialProvider in Debug failed.
    goto :error
)

rem ----------------------------------------------------------------------------
rem  Step 4: Register TetherCommService as a Windows service (if not registered)
rem ----------------------------------------------------------------------------
echo  [4/8] Registering TetherCommService Windows service...
echo ============================================================================
set "COMM_EXE="
for /f "delims=" %%f in ('dir /b /s "%ROOT_DIR%\services\communication-service\Tether.CommunicationService\bin\Debug\Tether.CommunicationService.exe" 2^>nul') do set "COMM_EXE=%%f"
if not defined COMM_EXE (
    echo [ERROR] Tether.CommunicationService.exe (Debug) not found.
    goto :error
)
echo     Service exe: %COMM_EXE%

sc query TetherCommService >nul 2>&1
if errorlevel 1 (
    sc create TetherCommService binPath= "%COMM_EXE%" start= demand DisplayName= "Tether Communication Service" obj= LocalSystem
    if errorlevel 1 (
        echo [ERROR] Failed to create TetherCommService. Run this script as Administrator.
        goto :error
    )
    echo [*] Service TetherCommService created.
) else (
    sc config TetherCommService binPath= "%COMM_EXE%" >nul
    echo [*] Service TetherCommService already registered (binPath updated).
)

rem ----------------------------------------------------------------------------
rem  Step 5: Copy Credential Provider DLL to System32 and register it
rem ----------------------------------------------------------------------------
echo  [5/8] Deploying Credential Provider to System32...
echo ============================================================================
set "CRED_DLL="
if exist "%ROOT_DIR%\TetherCredentialProvider\x64\Debug\TetherCredentialProvider.dll" (
    set "CRED_DLL=%ROOT_DIR%\TetherCredentialProvider\x64\Debug\TetherCredentialProvider.dll"
) else (
    if exist "%ROOT_DIR%\x64\Debug\TetherCredentialProvider.dll" set "CRED_DLL=%ROOT_DIR%\x64\Debug\TetherCredentialProvider.dll"
)
if not defined CRED_DLL (
    echo [ERROR] TetherCredentialProvider.dll (Debug x64) not found.
    goto :error
)

copy /y "%CRED_DLL%" "%SystemRoot%\System32\TetherCredentialProvider.dll" >nul
if errorlevel 1 (
    echo [ERROR] Failed to copy DLL to System32. Run this script as Administrator.
    goto :error
)
reg import "%ROOT_DIR%\TetherCredentialProvider\register.reg" >nul 2>&1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters\{c8c8d282-f4f1-451d-96fc-a8b1f783117b}" /ve /t REG_SZ /d "TetherCredentialProvider" /f >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Failed to register Credential Provider. Run this script as Administrator.
    goto :error
)
echo [*] Credential Provider and Filter copied and registered.

rem ----------------------------------------------------------------------------
rem  Step 6: Ensure firewall rules for the Debug CommunicationService binary
rem ----------------------------------------------------------------------------
echo  [6/8] Ensuring firewall rules...
echo ============================================================================
netsh advfirewall firewall delete rule name="Tether Control (TCP 37123)" >nul 2>&1
netsh advfirewall firewall delete rule name="Tether Discovery (UDP 5353)" >nul 2>&1
netsh advfirewall firewall delete rule name="Tether File Transfer (TCP 37124)" >nul 2>&1
netsh advfirewall firewall delete rule name="Tether File Transfer (UDP 37124)" >nul 2>&1
netsh advfirewall firewall add rule name="Tether Control (TCP 37123)" dir=in action=allow program="%COMM_EXE%" protocol=TCP localport=37123 profile=any remoteip=localsubnet >nul
netsh advfirewall firewall add rule name="Tether Discovery (UDP 5353)" dir=in action=allow program="%COMM_EXE%" protocol=UDP localport=5353 profile=any remoteip=localsubnet >nul
netsh advfirewall firewall add rule name="Tether File Transfer (TCP 37124)" dir=in action=allow program="%COMM_EXE%" protocol=TCP localport=37124 profile=any remoteip=localsubnet >nul
netsh advfirewall firewall add rule name="Tether File Transfer (UDP 37124)" dir=in action=allow program="%COMM_EXE%" protocol=UDP localport=37124 profile=any remoteip=localsubnet >nul
if errorlevel 1 (
    echo [ERROR] Failed to create firewall rules. Run this script as Administrator.
    goto :error
)
echo [*] Firewall rules ensured (LocalSubnet scope across all profiles).

rem ----------------------------------------------------------------------------
rem  Step 7: Start service if the active network profile is Private
rem ----------------------------------------------------------------------------
echo  [7/8] Checking network profile and starting service...
echo ============================================================================
powershell -NoProfile -ExecutionPolicy Bypass -Command "$p = (Get-NetConnectionProfile | Where-Object NetworkCategory -eq 'Private' | Measure-Object).Count; if ($p -gt 0) { Write-Host '[*] Private network detected - starting TetherCommService...'; Start-Service TetherCommService; Write-Host '[*] Service started.' } else { Write-Host '[i] Active network is not Private - service not started.' }"

rem ----------------------------------------------------------------------------
rem  Step 8: Build Android Debug APK, named with the short commit hash
rem ----------------------------------------------------------------------------
echo  [8/8] Building Android Debug APK...
echo ============================================================================
cd /d "%ROOT_DIR%\apps\android-companion"
call gradlew.bat :app:assembleDebug --no-daemon
if errorlevel 1 (
    echo [ERROR] Android debug build failed.
    goto :error
)
cd /d "%ROOT_DIR%"

set "BUILT_DEBUG_APK=%ROOT_DIR%\apps\android-companion\app\build\outputs\apk\debug\app-debug.apk"
if not exist "%BUILT_DEBUG_APK%" (
    for /f "delims=" %%f in ('dir /b /s "%ROOT_DIR%\apps\android-companion\app\build\intermediates\apk\debug\app-debug.apk" 2^>nul') do set "BUILT_DEBUG_APK=%%f"
)
if not exist "%BUILT_DEBUG_APK%" (
    echo [ERROR] Could not find built debug APK.
    goto :error
)

set "FINAL_APK_ROOT=%ROOT_DIR%\Tether_debug_%COMMIT_HASH%.apk"
copy /y "%BUILT_DEBUG_APK%" "%FINAL_APK_ROOT%" >nul
if errorlevel 1 (
    echo [ERROR] Failed to copy debug APK to root.
    goto :error
)

echo.
echo ============================================================================
echo   DEBUG BUILD AND DEPLOY SUCCESSFUL!
echo ============================================================================
echo   Service:       TetherCommService -^> %COMM_EXE%
echo   Credential:    %SystemRoot%\System32\TetherCredentialProvider.dll
echo   Debug APK:     %FINAL_APK_ROOT%
echo ============================================================================
echo.
goto :finish

:error
echo.
echo [!] Debug build pipeline terminated with errors.
echo.
pause
exit /b 1

:finish
echo Done.
pause
exit /b 0
