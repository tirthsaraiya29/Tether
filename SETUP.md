# Tether — End-to-End Setup, Build & Deployment Guide

This guide provides complete instructions for setting up, building, installing, provisioning, and troubleshooting the **Tether** ecosystem on Windows workstations and Android companion devices.

---

## 1. System Requirements & Network Prerequisites

Before deploying Tether, verify that your hardware, operating systems, and local network meet the following criteria:

### Linux Host Requirements
* **Operating System**: Fedora 40+, RHEL 9+, CentOS Stream 9+, Ubuntu 22.04+, Debian 12+, Arch Linux.
* **Architecture**: x64 (AMD64) or ARM64 (aarch64).
* **Init & Supervisor**: systemd (v245+).
* **Kernel Subsystems**: `/dev/uinput` enabled with read/write access for synthetic mouse and keyboard event injection.
* **Privileges**: root / sudo access required for service installation, firewall configuration, and PAM module deployment.
* **PAM Subsystem**: Linux-PAM with PAM development headers (`pam-devel` or `libpam0g-dev`).

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

# Register with Windows Credential Provider Filters
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters\{c8c8d282-f4f1-451d-96fc-a8b1f783117b}" /ve /t REG_SZ /d "TetherCredentialProvider" /f
```

### 3. Add Windows Firewall Rules
```powershell
netsh advfirewall firewall add rule name="Tether Control (TCP-In 37123)" dir=in action=allow protocol=TCP localport=37123 profile=any remoteip=localsubnet
netsh advfirewall firewall add rule name="Tether Discovery (UDP-In 37124)" dir=in action=allow protocol=UDP localport=37124 profile=any remoteip=localsubnet
netsh advfirewall firewall add rule name="Tether mDNS (UDP-In 5353)" dir=in action=allow protocol=UDP localport=5353 profile=any remoteip=localsubnet
netsh advfirewall firewall add rule name="Tether File Transfer (TCP-In 37124)" dir=in action=allow protocol=TCP localport=37124 profile=any remoteip=localsubnet
```

---

## 4. Linux Environment Setup, Building & Automated Installation

### Step 1: Install Development Dependencies

#### Fedora / RHEL / CentOS Stream:
```bash
sudo dnf install -y dotnet-sdk-10.0 gcc pam-devel firewalld
```

#### Ubuntu / Debian:
```bash
sudo apt update
sudo apt install -y dotnet-sdk-10.0 gcc libpam0g-dev ufw
```

#### Arch Linux:
```bash
sudo pacman -S --needed dotnet-sdk gcc pam ufw
```

### Step 2: Automated Installation (Recommended)

Run the automated installer script:

```bash
sudo ./scripts/install-linux.sh
```

The installer performs the following operations:
1. Builds `Tether.LinuxDaemon` in Release mode using .NET 10 SDK and publishes to `/opt/tether/daemon/`.
2. Compiles the native C PAM module `pam_tether.so` with security hardening flags (`-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, `-Wl,-z,relro,-z,now`).
3. Installs `pam_tether.so` into the platform's PAM directory (`/usr/lib64/security/` on RHEL/Fedora or `/lib/x86_64-linux-gnu/security/` on Debian/Ubuntu).
4. Creates the dedicated service user and group `tether:tether`.
5. Deploys `/etc/udev/rules.d/99-tether-uinput.rules` allowing the `tether` group access to `/dev/uinput`.
6. Configures firewall rules (via `firewalld` or `ufw`):
   - `TCP 37123`: Control channel (TLS 1.3).
   - `UDP 37124`: Local discovery probe listener.
   - `TCP 37124`: HTTPS file transfer server.
   - `UDP 5353`: mDNS discovery advertiser.
7. Installs and enables the hardened systemd unit `/etc/systemd/system/tether.service`.
8. Builds and installs `tetherctl` CLI to `/usr/local/bin/tether`.

### Step 3: Manual Step-by-Step Linux Build

If building individual components manually:

```bash
# 1. Publish Linux Daemon
dotnet publish services/communication-service/Tether.LinuxDaemon/Tether.LinuxDaemon.csproj -c Release -o /opt/tether/daemon

# 2. Build Native PAM Module
gcc -fPIC -fstack-protector-strong -D_FORTIFY_SOURCE=2 -shared -O2 \
    -Iservices/pam-tether \
    services/pam-tether/pam_tether.c -lpam \
    -o /usr/lib64/security/pam_tether.so

# 3. Build tetherctl CLI
dotnet publish tools/tetherctl/Tether.Cli.csproj -c Release -o /usr/local/bin
ln -sf /usr/local/bin/tetherctl /usr/local/bin/tether

# 4. Enable and start systemd service
sudo systemctl daemon-reload
sudo systemctl enable --now tether.service
```

### Step 4: Configuring PAM for Lock Screen Unlock

To enable mobile biometric unlock for lock screens (e.g. GDM or screen lockers), add `pam_tether.so` as `sufficient` at the top of the `auth` section in the appropriate PAM configuration:

In `/etc/pam.d/password-auth` or `/etc/pam.d/system-auth`:
```pam
# Tether mobile biometric unlock module
auth        sufficient    pam_tether.so
```

When an unlock request is confirmed on the Android companion, `Tether.LinuxDaemon` writes a short-lived unlock grant to its secure socket (`/run/tether/auth.sock`). When `pam_tether.so` is invoked by the lock screen, it connects via UNIX domain socket, cryptographically verifies the grant with the daemon, and completes authentication without requiring manual password entry.

### Step 5: Managing the Linux Service with `tetherctl`

```bash
# Display overall daemon status, hardware metrics, and active session
tether status

# List paired Android devices
tether devices

# Unpair a device by fingerprint
tether unpair <FINGERPRINT>

# Lock the workstation immediately
tether lock

# Arm a 30-second mobile unlock grant
sudo tether unlock

# Restart the daemon service
sudo tether restart

# View live daemon logs
tether logs -f
```

---

## 5. Android Companion Setup & Building

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

## 6. Provisioning & Pairing Walkthrough

Follow these steps to establish initial cryptographic pairing between Linux/Windows and Android:

### 1. Launch Applications
* On Linux: Ensure `tether.service` is active (`tether status`).
* On Windows: Open **Tether Desktop UI** from Start Menu or `C:\Program Files\Tether\Tether.DesktopUI.exe`.
* On Android: Open the **Tether** app.

### 2. Grant Android Runtime Permissions
In the Tether Android app, open the **Permissions** screen and grant:
* Nearby Wi-Fi / Location permissions (required for local device discovery).
* Notification permission (required for foreground service status).
* Battery Optimization Exemption (allows background connection persistence).

### 3. Pair Devices
1. On Android, tap **Search for Workstation** or tap your PC/laptop name under Local Devices.
2. A 6-digit numeric Pairing Code will appear on the workstation (in desktop notification / `tetherctl` logs on Linux, or on **Tether Desktop UI** on Windows).
3. Enter the 6-digit code on the Android app.
4. Verify that the generated **SHA-256 Cryptographic Fingerprint** (`XX:XX:...:XX`) matches on both screens.
5. Tap **Confirm Pairing**.

### 4. Workstation Authentication Configuration
* **On Linux**: Configure PAM with `pam_tether.so` as described in Section 4. Test unlock by running `sudo tether unlock`.
* **On Windows**: On Tether Desktop UI, navigate to **Vault Settings**, enter your current Windows password/PIN, and tap **Save to Vault**. The credential payload will be encrypted using DPAPI system-bound entropy (`Tether_System_Bound_Vault_v1`) and written to `HKLM\SOFTWARE\Tether\Secrets`.

---

## 7. Testing System Capabilities

Once paired, test the primary workflows:

| Workflow | Action | Expected Behavior (Linux / Windows) |
|---|---|---|
| **Remote Unlock** | Lock PC (`loginctl lock-session` or `Win + L`). Open Android app, tap **Unlock Workstation**, satisfy BiometricPrompt. | Dispatches authenticated unlock challenge; `pam_tether.so` on Linux or `TetherCredentialProvider` on Windows completes unlock. |
| **Emergency Panic** | Tap **PANIC** on Android dashboard. | Immediate workstation lock command is dispatched; active session trust is invalidated. |
| **Trackpad & Input** | Open **Trackpad** tab on Android, swipe finger or tap modifier keys (`Win`, `Ctrl`). | Mouse cursor moves smoothly; clicks and keystrokes register via `/dev/uinput` on Linux or `Tether.SessionHelper` on Windows. |
| **Audio Volume** | Slide volume control on Android. | Master volume adjusts in real time via PipeWire/amixer on Linux or COM `IAudioEndpointVolume` on Windows. |
| **Display Brightness** | Slide brightness control on Android. | Monitor brightness changes via `/sys/class/backlight` on Linux or WMI / DXVA2 on Windows. |
| **System Launcher** | Tap **Terminal**, **Task Manager**, or **Files** icon on Android. | Desktop application or shell launches inside the active desktop session. |

---

## 8. Troubleshooting & Error Resolution Matrix

| Issue / Symptom | Root Cause | Resolution |
|---|---|---|
| `DISCOVERY_FAILED` | Router Client Isolation is enabled or UDP ports blocked. | Disable Client Isolation on router settings. Verify firewall allows UDP `37124` and UDP `5353`. On hotspot, verify laptop is connected to phone hotspot. |
| `Connection Timeout` | Daemon or Service is stopped, or TCP `37123` blocked. | On Linux: check `tether status` or `sudo systemctl restart tether`. On Windows: check `services.msc` for `Tether Communication Service`. Verify firewall allows TCP `37123`. |
| `TLS Handshake Error` | Stale or mismatched device certificate pinning. | On Linux: `tether unpair <FINGERPRINT>`. On Windows: Tap **Reset Pairing** in Desktop UI. Clear stored key in Android app and re-pair. |
| `Linux Uinput Permission Denied` | User lacks permission to open `/dev/uinput`. | Verify `/etc/udev/rules.d/99-tether-uinput.rules` exists with `KERNEL=="uinput", MODE="0660", GROUP="tether"`. Run `sudo udevadm control --reload-rules && sudo udevadm trigger`. |
| `Linux PAM Auth Failed` | Socket `/run/tether/auth.sock` missing or permission error. | Verify `tether.service` is active (`tether status`). Ensure `pam_tether.so` is placed in `/usr/lib64/security/` (or `/lib/x86_64-linux-gnu/security/`). |
| `HELPER_NOT_FOUND` | `Tether.SessionHelper.exe` missing from installation path. | Reinstall Tether or verify file exists in `C:\Program Files\Tether\Tether.SessionHelper.exe`. |
| `BIOMETRIC_FAILED` | Fingerprint or facial recognition canceled or unconfigured. | Enroll biometrics in Android System Settings and retry unlock prompt. |
| `Windows Logon Tile Missing` | `TetherCredentialProvider.dll` not registered in Registry. | Re-run registry registration commands from Section 3 or re-run `Tether-Setup-1.1.2.exe`. |
