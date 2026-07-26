# Tether

> Adaptive personal trust and security system for Windows and Android.

Tether is a high-security personal trust platform focused on adaptive authentication, phone-based trust validation, panic lockdown systems, and layered recovery mechanisms.

The system creates a secure trust relationship between a Windows machine and an Android device, where the phone acts as a continuously validated trust anchor.

---

> **⚠️ BETA DEVELOPMENT STATUS**
>
> This software is under active development.
> It should **not** be relied upon for production-critical security environments.
> See [Security Notice](#security-notice) for details.

---

# Features

## Android Trust Anchor

- Secure device pairing
- Phone-based trust validation
- Recovery device support
- Proximity authentication

## Panic Mode

- Instant lockdown triggering
- Trust revocation
- Session invalidation
- Emergency isolation workflows

## Continuous Trust Validation

- Connection integrity monitoring
- Trusted device verification
- Secure channel validation
- Trust continuity checks

## Recovery Systems

- Multi-layer recovery mechanisms
- Safe fallback procedures
- Recovery hardening logic

---

# Architecture

## Windows Components

- Core Service (`Tether.CommunicationService`)
- Authentication Engine (`TetherCredentialProvider`)
- Overlay UI (`Tether.OverlayUI`)
- Desktop Configuration UI (`Tether.DesktopUI`)
- Trust State Manager
- Recovery Manager
- Secure Communication Layer

## Android Components

- Trust Companion App (`apps/android-companion/app`)
- Secure Pairing System
- Proximity Validation
- Panic Trigger Interface

## Shared Components

- Event Bus
- Shared DTOs
- Shared Constants
- IPC Constants
- Logging

---

# Tech Stack

## Windows

- C# (.NET 8)
- WPF / XAML
- C++
- Windows Credential Provider API
- Windows Security APIs
- DPAPI (`CryptProtectData`)
- Named Pipes (IPC)

## Android

- Kotlin
- Jetpack Compose
- Android SDK (API 33+)
- Bluetooth Low Energy (BLE)
- Android Keystore / StrongBox

## Communication

- BLE (GATT)
- RSA + AES encrypted communication
- Named Pipes
- Global Event Handles

---

# Prerequisites

## Windows Development

Install:

- Visual Studio 2022
  - Desktop Development with C++
  - .NET Desktop Development
  - Windows SDK 10.0.22621.0 or later
- .NET 8 SDK
- Git

## Android Development

Install:

- Android Studio (latest)
- JDK 17+
- Android SDK API 33+
- Physical Android 12+ device for BLE testing

## Build Tools

- CMake
- MSBuild

---

# Getting the Source

```bash
git clone https://github.com/your-org/Tether.git
cd Tether
```

---

# Build Instructions

## 1. Build the Communication Service

```bash
cd services/communication-service/Tether.CommunicationService

dotnet restore
dotnet build --configuration Release

dotnet publish \
    --configuration Release \
    --runtime win-x64 \
    --self-contained true
```

Output:

```
bin/Release/net8.0-windows10.0.22621.0/win-x64/
```

---

## 2. Build the Credential Provider

Open:

```
TetherCredentialProvider.vcxproj
```

in Visual Studio 2022

or build from the command line:

```bash
msbuild TetherCredentialProvider.vcxproj ^
    /p:Configuration=Release ^
    /p:Platform=x64
```

Output:

```
x64/Release/TetherCredentialProvider.dll
```

> The credential provider must be registered before Windows will load it.

---

## 3. Build the Desktop UI

```bash
cd apps/desktop-ui/Tether.DesktopUI

dotnet restore
dotnet build --configuration Release
```

Output:

```
bin/Release/net8.0-windows/
```

---

## 4. Build the Overlay UI

```bash
cd Tether.OverlayUI

dotnet restore
dotnet build --configuration Release
```

Output:

```
bin/Release/net8.0-windows/
```

---

## 5. Build the Android Companion

```bash
cd apps/android-companion

./gradlew assembleRelease
```

Output:

```
app/build/outputs/apk/release/app-release.apk
```

For development:

```bash
./gradlew assembleDebug
```

---

## 6. Build Shared Libraries

```bash
cd shared/Tether.Shared

dotnet restore
dotnet build --configuration Release
```

```bash
cd services/event-bus/Tether.EventBus

dotnet restore
dotnet build --configuration Release
```

All .NET projects reference these through `ProjectReference`, so build order is handled automatically.

---

# Installation

## 1. Install the Windows Service

```powershell
sc.exe create "TetherCommService" `
    binPath= "C:\Dev\Tether\services\communication-service\Tether.CommunicationService\bin\Release\net8.0-windows10.0.22621.0\win-x64\Tether.CommunicationService.exe" `
    start= auto
```

Start it:

```powershell
sc.exe start "TetherCommService"
```

Verify:

```powershell
sc.exe query "TetherCommService"
```

The service requires:

- SYSTEM privileges
- BLE access
- Registry access
- Named Pipe creation

---

## 2. Register the Credential Provider

```cmd
regsvr32.exe C:\Dev\Tether\x64\Release\TetherCredentialProvider.dll
```

or

```cmd
regedit.exe /s TetherCredentialProvider\register.reg
```

Registry location:

```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\
Authentication\Credential Providers\
{c8c8d282-f4f1-451d-96fc-a8b1f783117b}
```

To unregister:

```cmd
regsvr32.exe /u C:\Dev\Tether\x64\Release\TetherCredentialProvider.dll

regedit.exe /s TetherCredentialProvider\unregister.reg
```

---

## 3. Credential Provider Configuration

Registry:

```
HKLM\SOFTWARE\Tether\CredentialProvider
```

| Value | Type | Description |
|--------|------|-------------|
| `EncryptedPassword` | `REG_BINARY` | DPAPI-encrypted Windows password |
| `PasswordHash` | `REG_SZ` | SHA-256 hash of password + salt |
| `PasswordSalt` | `REG_BINARY` | 64-byte random salt |
| `TrustedPhonePublicKey` | `REG_SZ` | Base64 X.509 public key |
| `Provisioned` | `REG_DWORD` | `1` if paired |

Automatically configured by:

- `Tether.DesktopUI`
- `Tether.CommunicationService`

---

## 4. Pair a Phone

1. Open the Android app.
2. Display the QR code or public key.
3. Open `Tether.DesktopUI`.
4. Paste the public key into **PHONE PAIRING PROFILE**.
5. Select **PAIR PROVISIONED PHONE**.

---

## 5. Configure the Password Vault

1. Open `Tether.DesktopUI`.
2. Navigate to **CRYPTOGRAPHIC VAULT CONFIGURATION**.
3. Enter the Windows password.
4. Select **COMMIT CRYPTOGRAPHIC LSA VAULT**.

The password is encrypted using machine DPAPI before being stored in the registry.

---

# Quick Test

1. Start `Tether.CommunicationService`.
2. Launch `Tether.DesktopUI`.
3. Lock Windows (`Win + L`).
4. Open the Android companion.
5. Ensure Bluetooth is enabled.
6. Tap **Unlock**.

If provisioning is correct, Windows should unlock automatically.

---

# Development Tips

## Logs

Windows Service:

```
C:\ProgramData\Tether\Logs\
```

Credential Provider:

- DebugView
- Event Viewer
- OutputDebugString

Android:

```
Logcat
Tag: TetherBle
```

---

## Registry

```cmd
regedit.exe
```

Navigate to:

```
HKLM\SOFTWARE\Tether\CredentialProvider
```

---

## Named Pipe Testing

```bash
cd tests/PipeTest

dotnet run -- "PHONE_UNLOCKED"
```

---

## Rebuild Everything

```powershell
dotnet build Tether.slnx --configuration Release
```

```powershell
msbuild TetherCredentialProvider\TetherCredentialProvider.vcxproj `
    /p:Configuration=Release `
    /p:Platform=x64
```

```bash
cd apps/android-companion

./gradlew assembleRelease
```

---

# Debugging the Credential Provider

The credential provider executes inside:

```
LogonUI.exe
```

Recommended workflow:

1. Attach Visual Studio to `LogonUI.exe`.
2. Run Visual Studio as SYSTEM (or equivalent elevated context).
3. Set breakpoints in `TetherCredential.cpp`.
4. Lock the workstation.

Alternatively:

- Use `OutputDebugString()`
- Capture output using **DebugView**

---

# Security Notice

Tether is under active development and should **not** be considered production-ready.

Before deployment, review the project's security assessment and threat model.

---

# Contributing

1. Fork the repository.
2. Create a feature branch.
3. Follow the project's `.editorconfig`.
4. Run tests.
5. Submit a pull request.

---

# Author

**Tirth Saraiya**
