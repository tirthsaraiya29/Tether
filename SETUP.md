# Tether — End-to-End Setup, Build & Deployment Guide

This guide provides complete instructions for setting up, building, installing, provisioning, and troubleshooting the **Tether** ecosystem on Windows workstations and Android companion devices.

---

## 1. System Requirements & Network Prerequisites

Before deploying Tether, verify that your hardware, operating systems, and local network meet the following criteria:

### Windows Workstation Requirements
* **Operating System**: Windows 10 (Build 19041 or higher) or Windows 11 x64.
* **Architecture**: x64 (AMD64 / Intel 64).
* **Privileges**: Local Administrator privileges are required for service creation, firewall configuration, and Credential Provider registration.
* **Backup Login**: Maintain an active, verified backup login method (Windows Hello PIN, local account password, or Microsoft Account password).

### Android Companion Device Requirements
* **Operating System**: Android 12 (API Level 31) or higher.
* **Hardware Requirements**: Biometric hardware (fingerprint sensor or facial recognition) and Wi-Fi capability.
* **Security Settings**: Device lock screen (PIN, pattern, or password) must be configured.

### Local Network Environment
* Both devices must be connected to the **same local Wi-Fi or Ethernet subnet**.
* **Router Settings**: Client Isolation / AP Isolation must be **DISABLED** on your Wi-Fi router so devices can communicate directly.
* **Firewall Ports**: The following local inbound ports must be allowed on Windows:
  * `TCP 37123`: Control channel (TLS 1.3).
  * `UDP 37124`: Local device discovery.
  * `UDP 5353`: mDNS service advertisement (`_tether._tcp.`).
  * `TCP 37124`: File transfer server (HTTPS).

---

## 2. Windows Environment Setup & Building from Source

### Step 1: Install Development Tools
Install the following software on your Windows development workstation:
1. **Visual Studio 2022 (v17.10+)**: Select workloads:
   * *.NET Desktop Development* (.NET 10 SDK)
   * *Desktop Development with C++* (MSVC v143, C++20, Windows 11 SDK `10.0.22621.0`+)
2. **.NET 10 SDK**: Download and install [.NET 10 SDK](https://dotnet.microsoft.com/).
3. **Inno Setup 6.2+**: Download [Inno Setup](https://jrsoftware.org/isinfo.php) to compile the installer executable.

### Step 2: Clone & Build the Windows Solution
Open Developer PowerShell for Visual Studio as Administrator:

```powershell
# Clone the repository
git clone https://github.com/tirthsaraiya29/Tether.git
cd Tether

# Restore and build C# solution
dotnet restore Tether.slnx
dotnet build Tether.slnx -c Release

# Build native C++ Credential Provider DLL
msbuild TetherCredentialProvider\TetherCredentialProvider.vcxproj /p:Configuration=Release /p:Platform=x64
```

### Step 3: Package the Windows Installer
Run the automated packaging steps to produce `installer\output\Tether-Setup-1.1.2.exe`:

```powershell
# Create staging directory
New-Item -ItemType Directory -Force -Path installer\pack

# Publish Communication Service
dotnet publish services\communication-service\Tether.CommunicationService\Tether.CommunicationService.csproj -c Release -r win-x64 --self-contained false -o installer\pack

# Publish Session Helper
dotnet publish services\communication-service\Tether.SessionHelper\Tether.SessionHelper.csproj -c Release -r win-x64 --self-contained false -o installer\pack

# Publish Desktop UI
dotnet publish apps\desktop-ui\Tether.DesktopUI\Tether.DesktopUI.csproj -c Release -r win-x64 --self-contained false -o installer\pack

# Copy C++ Credential Provider DLL
Copy-Item x64\Release\TetherCredentialProvider.dll installer\pack\

# Compile Installer
& "C:\Program Files (x86)\Inno Setup 6\iscc.exe" installer\Tether.iss
```

The compiled installer will be created at `installer\output\Tether-Setup-1.1.2.exe`.

---

## 3. Manual Windows Service & Credential Provider Registration

If you prefer installing without running the Inno Setup installer executable:

### 1. Create the Windows Background Service
Open PowerShell as Administrator:

```powershell
# Stop service if existing
Stop-Service TetherCommService -ErrorAction SilentlyContinue

# Register Windows Service
sc.exe create TetherCommService binPath= "C:\Program Files\Tether\Tether.CommunicationService.exe" DisplayName= "Tether Communication Service" start= auto

sc.exe description TetherCommService "Tether background communication service: discovery, TLS transport, session orchestration."

# Start service
Start-Service TetherCommService
```

### 2. Register the Native Win32 Credential Provider
Register `TetherCredentialProvider.dll` in the Windows Registry:

```powershell
# Register COM Class ID
reg.exe add "HKLM\SOFTWARE\Classes\CLSID\{c8c8d282-f4f1-451d-96fc-a8b1f783117b}" /ve /t REG_SZ /d "TetherCredentialProvider" /f
reg.exe add "HKLM\SOFTWARE\Classes\CLSID\{c8c8d282-f4f1-451d-96fc-a8b1f783117b}\InprocServer32" /ve /t REG_SZ /d "C:\Program Files\Tether\TetherCredentialProvider.dll" /f
reg.exe add "HKLM\SOFTWARE\Classes\CLSID\{c8c8d282-f4f1-451d-96fc-a8b1f783117b}\InprocServer32" /v "ThreadingModel" /t REG_SZ /d "Apartment" /f

# Register with Windows Credential Providers
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{c8c8d282-f4f1-451d-96fc-a8b1f783117b}" /ve /t REG_SZ /d "TetherCredentialProvider" /f
```

### 3. Add Windows Firewall Rules
```powershell
netsh advfirewall firewall add rule name="Tether Control (TCP-In 37123)" dir=in action=allow protocol=TCP localport=37123
netsh advfirewall firewall add rule name="Tether Discovery (UDP-In 37124)" dir=in action=allow protocol=UDP localport=37124
netsh advfirewall firewall add rule name="Tether mDNS (UDP-In 5353)" dir=in action=allow protocol=UDP localport=5353
netsh advfirewall firewall add rule name="Tether File Transfer (TCP-In 37124)" dir=in action=allow protocol=TCP localport=37124
```

---

## 4. Android Companion Setup & Building

### Step 1: Open in Android Studio
1. Launch Android Studio.
2. Open project folder `apps/android-companion`.
3. Allow Gradle sync to download Jetpack Compose and AndroidX dependencies.

### Step 2: Build & Deploy via ADB
Connect your Android device via USB with USB Debugging enabled:

```bash
cd apps/android-companion

# Assemble Debug APK
./gradlew assembleDebug

# Install on connected Android device
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

---

## 5. Provisioning & Pairing Walkthrough

Follow these steps to establish initial cryptographic pairing between Windows and Android:

### 1. Launch Applications
* On Windows: Open **Tether Desktop UI** from Start Menu or `C:\Program Files\Tether\Tether.DesktopUI.exe`.
* On Android: Open the **Tether** app.

### 2. Grant Android Runtime Permissions
In the Tether Android app, open the **Permissions** screen and grant:
* Nearby Wi-Fi / Location permissions (required for local device discovery).
* Notification permission (required for foreground service status).
* Battery Optimization Exemption (allows background connection persistence).

### 3. Pair Devices
1. On Android, tap **Search for Workstation** or tap your PC name under Local Devices.
2. A 6-digit numeric Pairing Code will appear on **Tether Desktop UI**.
3. Enter the 6-digit code on the Android app.
4. Verify that the generated **SHA-256 Cryptographic Fingerprint** (`XX:XX:...:XX`) matches on both screens.
5. Tap **Confirm Pairing**.

### 4. Store Credentials in DPAPI Vault
On Tether Desktop UI, navigate to **Vault Settings**, enter your current Windows password/PIN, and tap **Save to Vault**. The credential payload will be encrypted using DPAPI system-bound entropy (`Tether_System_Bound_Vault_v1`) and written to `HKLM\SOFTWARE\Tether\Secrets`.

---

## 6. Testing System Capabilities

Once paired, test the primary workflows:

| Workflow | Action | Expected Behavior |
|---|---|---|
| **Remote Unlock** | Lock PC (`Win + L`). Open Android app, tap **Unlock Workstation**, satisfy BiometricPrompt. | Windows Credential Provider receives authenticated pipe signal, decrypts DPAPI credentials, and unlocks desktop. |
| **Emergency Panic** | Tap **PANIC** on Android dashboard. | Immediate workstation lock command is dispatched; active session trust is invalidated. |
| **Trackpad & Input** | Open **Trackpad** tab on Android, swipe finger or tap modifier keys (`Win`, `Ctrl`). | Mouse cursor moves smoothly on Windows; clicks and keystrokes register via `Tether.SessionHelper`. |
| **Audio Volume** | Slide volume control on Android. | Windows master volume adjusts in real time via COM `IAudioEndpointVolume`. |
| **Display Brightness** | Slide brightness control on Android. | Monitor brightness changes via WMI / DXVA2. |
| **System Launcher** | Tap **Terminal**, **Task Manager**, or **Explorer** icon on Android. | Utility application launches inside the active console user desktop. |

---

## 7. Troubleshooting & Error Resolution Matrix

| Issue / Symptom | Root Cause | Resolution |
|---|---|---|
| `HOTSPOT_UNSUPPORTED` | Mobile device is operating in Wi-Fi Hotspot / Access Point mode. | Disable Hotspot. Connect both Windows and Android to the same home/office Wi-Fi router. |
| `DISCOVERY_FAILED` | Router Client Isolation is enabled or UDP ports blocked. | Disable Client Isolation on router settings. Verify Windows Firewall allows UDP `37124` and UDP `5353`. |
| `Connection Timeout` | `TetherCommService` is stopped or TCP `37123` blocked. | Open `services.msc`, start `Tether Communication Service`, and check firewall rules. |
| `TLS Handshake Error` | Stale or mismatched device certificate pinning. | Open Tether Desktop UI, tap **Reset Pairing**, clear stored key on Android, and pair again. |
| `HELPER_NOT_FOUND` | `Tether.SessionHelper.exe` missing from installation path. | Reinstall Tether or verify file exists in `C:\Program Files\Tether\Tether.SessionHelper.exe`. |
| `BIOMETRIC_FAILED` | Fingerprint or facial recognition canceled or unconfigured. | Enroll biometrics in Android System Settings and retry unlock prompt. |
| `Windows Logon Tile Missing` | `TetherCredentialProvider.dll` not registered in Registry. | Re-run registry registration commands from Section 3 or re-run `Tether-Setup-1.1.2.exe`. |
