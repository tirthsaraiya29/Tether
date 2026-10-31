# Tether — Developer & Contributor Guide

Welcome to the **Tether** project! Tether is an open-source, local-first adaptive personal trust and workstation security system bridging Windows 10/11 workstations with Android companion devices.

This guide provides technical contributors with architecture standards, codebase conventions, build workflows, and contribution guidelines for both the Windows (.NET 10 / Win32 C++) and Android (Kotlin / Jetpack Compose) stacks.

---

## 1. Project Governance & Engineering Philosophy

Tether adheres to five core architectural principles:

1. **Zero-Cloud & Local-First Security**: Tether operates strictly within local network boundaries (Wi-Fi/LAN). Cloud relays, external telemetry, and third-party SaaS dependencies are strictly prohibited in runtime paths.
2. **Hardware-Backed Cryptography**: Cryptographic identity keys must be bound to hardware enclaves (AndroidKeyStore with StrongBox / Trusted Execution Environment on mobile, DPAPI with system-bound entropy on Windows).
3. **Defense-in-Depth & Privileged Isolation**: Windows services operate in Session 0 with minimal privilege elevation. Interactive desktop actions are strictly delegated to a dedicated Session Helper running within active console user sessions (`WTSQueryUserToken` + `CreateProcessAsUser`).
4. **Resilient Protocol Design**: All network communication requires TLS 1.3 over TCP, strict monotonic request sequence validation, ephemeral nonces, and zero-trust payload verification.
5. **Quality & Zero-Slop Standard**: Code contributions must be idiomatic, deterministic, well-typed, and maintain strict memory and resource management standards across both C#/.NET, C++20, and Kotlin.

---

## 2. Architecture & Monorepo Structure

The repository is structured as a unified monorepo containing Windows services, a native Win32 DLL, a WPF management desktop UI, shared C# libraries, and an Android Jetpack Compose companion app:

```text
Tether/
├── Tether.slnx                    # Unified Visual Studio Solution
├── TetherCredentialProvider/       # Native C++ Win32 Credential Provider DLL
├── apps/
│   ├── android-companion/          # Kotlin / Jetpack Compose Android App
│   └── desktop-ui/                 # Windows WPF Desktop Configuration UI
├── services/
│   ├── communication-service/      # Tether.CommunicationService & Tether.SessionHelper
│   ├── enforcement-engine/         # Policy enforcement logic
│   ├── event-bus/                  # Decoupled in-memory pub-sub event bus
│   ├── panic-engine/               # Workstation emergency panic lockdown engine
│   ├── recovery-engine/            # Fail-safe trust recovery engine
│   └── trust-engine/               # Dynamic trust state machine
├── shared/
│   └── Tether.Shared/              # Cross-service DTOs, events, and IPC constants
├── installer/                      # Inno Setup installer script (Tether.iss)
└── tests/                          # Integration and pipe test utilities
```

### Component Overview

| Layer | Component | Path | Language / Stack |
|---|---|---|---|
| **Windows Logon** | `TetherCredentialProvider` | `TetherCredentialProvider/` | C++20 / Win32 COM APIs |
| **Service Host** | `Tether.CommunicationService` | `services/communication-service/...` | C# .NET 10 Worker Service |
| **Session Bridge** | `Tether.SessionHelper` | `services/communication-service/...` | C# .NET 10 Win32 Interop |
| **Desktop UI** | `Tether.DesktopUI` | `apps/desktop-ui/...` | C# .NET 10 / WPF Fluent UI |
| **Trust Engines** | `Tether.TrustEngine`, `PanicEngine` | `services/...` | C# .NET 10 Library |
| **Shared Contracts**| `Tether.Shared` | `shared/Tether.Shared/` | C# .NET 10 Library |
| **Android Client** | `android-companion` | `apps/android-companion/` | Kotlin / Jetpack Compose / M3 |

---

## 3. Development Prerequisites

To set up your local development environment, verify that your workstation meets the following prerequisites:

### Windows Workstation Requirements
* **Operating System**: Windows 10 (Build 19041+) or Windows 11 x64.
* **IDE**: Visual Studio 2022 (v17.10 or newer) with workloads:
  * *.NET Desktop Development* (.NET 10 SDK v10.0.100+)
  * *Desktop Development with C++* (MSVC v143 toolset, C++20 standard, Windows 11 SDK `10.0.22621.0`+)
* **Build Tools**:
  * `.NET 10 SDK` installed and available in `PATH`.
  * `Inno Setup 6.2+` (for compiling the Windows installer via `iscc.exe`).
* **System Privileges**: Administrative access required for service installation and Credential Provider registry registration.

### Android Development Requirements
* **IDE**: Android Studio Jellyfish (2023.3.1) or Koala (2024.1.1)+.
* **JDK**: Java Development Kit 17 (bundled with Android Studio).
* **Android SDK**:
  * `compileSdk`: 35
  * `targetSdk`: 35
  * `minSdk`: 31 (Android 12)
* **Physical Device or Emulator**: Android 12+ physical device recommended for testing biometric authentication, Wi-Fi discovery, and hardware KeyStore integration.

---

## 4. Development & Build Workflows

### 4.1 Building the Windows Stack
Open a PowerShell terminal as Administrator or Developer PowerShell for Visual Studio:

1. **Restore dependencies & build C# projects**:
   ```powershell
   dotnet restore Tether.slnx
   dotnet build Tether.slnx -c Release
   ```

2. **Build C++ Credential Provider**:
   ```powershell
   msbuild TetherCredentialProvider\TetherCredentialProvider.vcxproj /p:Configuration=Release /p:Platform=x64
   ```

3. **Run Unit & Integration Tests**:
   ```powershell
   dotnet test Tether.slnx --configuration Release
   ```

4. **Package Windows Installer**:
   Staging published artifacts into `installer\pack\` and compiling via Inno Setup:
   ```powershell
   # Publish Communication Service
   dotnet publish services\communication-service\Tether.CommunicationService\Tether.CommunicationService.csproj -c Release -r win-x64 --self-contained false -o installer\pack

   # Publish Session Helper
   dotnet publish services\communication-service\Tether.SessionHelper\Tether.SessionHelper.csproj -c Release -r win-x64 --self-contained false -o installer\pack

   # Publish Desktop UI
   dotnet publish apps\desktop-ui\Tether.DesktopUI\Tether.DesktopUI.csproj -c Release -r win-x64 --self-contained false -o installer\pack

   # Copy Credential Provider DLL
   Copy-Item x64\Release\TetherCredentialProvider.dll installer\pack\

   # Build Installer executable
   & "C:\Program Files (x86)\Inno Setup 6\iscc.exe" installer\Tether.iss
   ```

### 4.2 Building the Android Stack
Navigate to `apps/android-companion` in terminal or open in Android Studio:

1. **Assemble Debug APK**:
   ```bash
   ./gradlew assembleDebug
   ```

2. **Run Unit Tests**:
   ```bash
   ./gradlew test
   ```

3. **Install Debug APK on Device via ADB**:
   ```bash
   adb install -r app/build/outputs/apk/debug/app-debug.apk
   ```

4. **Assemble Release APK**:
   ```bash
   ./gradlew assembleRelease
   ```

---

## 5. Coding Standards & Guidelines

### 5.1 C# / .NET 10 Conventions
* **Nullable Reference Types**: `<Nullable>enable</Nullable>` is enforced. Annotate all method parameters and return types accurately.
* **File-Scoped Namespaces**: Always use file-scoped namespaces (e.g., `namespace Tether.CommunicationService.Transport;`).
* **Async & Cancellation**: Asynchronous methods must accept a `CancellationToken ct = default` and check `ct.ThrowIfCancellationRequested()` in loops.
* **Logging**: Use `ITetherLogger` or `ILogger<T>` for structured logging. Never print sensitive values (passwords, tokens, nonces, raw key material) in log strings.
* **IPC Channel Security**: Named pipes (`TetherPipe`, `TetherUiPipe`, `Tether.InputPipe`) must mandate authenticated user SID validation and strict ACLs.

### 5.2 C++ / Win32 Credential Provider Conventions
* **Language Standard**: Strict C++20 (`/std:c++20`).
* **COM Lifecycle**: Implement `AddRef()` / `Release()` cleanly using `std::atomic<ULONG>` or ATL smart pointers. Always call `DllAddRef()` and `DllRelease()`.
* **Zeroing Memory**: Any memory buffer holding password hashes, credentials, or decryption keys must be cleared using `SecureZeroMemory()` before deallocation.
* **Unicode Enforcement**: Use wide-character Win32 APIs (`wchar_t`, `L"..."`, `std::wstring`).
* **Exception Boundaries**: C++ exceptions MUST NOT leak across COM interface boundaries (`ICredentialProvider`, `ICredentialProviderCredential2`). Catch all exceptions inside interface methods and return an appropriate `HRESULT` (e.g., `E_FAIL`, `E_UNEXPECTED`).

### 5.3 Kotlin / Android Conventions
* **Coroutines & Scopes**: Structured concurrency is enforced. Long-running network and crypto tasks must execute on `Dispatchers.IO`. UI state manipulation must run on `Dispatchers.Main`.
* **Jetpack Compose State**: Use `StateFlow` and immutable data classes (`@Immutable`) for UI state representation in `MainScreens.kt`, `RemoteInputScreen.kt`, and `FileTransferScreen.kt`.
* **KeyStore Security**: Private keys must be generated inside `AndroidKeyStore` (`TetherIdentityKey_v1`) using `KeyGenParameterSpec` with `KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY`. Sensitive configuration must be stored in AES-256-GCM encrypted SharedPreferences via `ProductionSecurityEngine`.

---

## 6. Git Workflow & Commit Policy

We follow a structured Git branching and commit workflow:

### Branch Naming Conventions
* `feature/<short-description>`: New system capabilities, UI additions, or platform support.
* `fix/<bug-description>`: Bug fixes and stability improvements.
* `sec/<vulnerability-description>`: Security hardening and vulnerability remediation.
* `refactor/<module-name>`: Architectural cleanups without behavior changes.

### Conventional Commits Format
Every commit message must follow the Conventional Commits specification:

```text
<type>(<scope>): <short summary>

[optional body explaining reason and technical context]
```

**Valid Types**:
* `feat`: A new feature for the user or platform.
* `fix`: A bug fix.
* `sec`: Security enhancement or patch.
* `refactor`: A code change that neither fixes a bug nor adds a feature.
* `docs`: Documentation changes.
* `test`: Adding missing tests or correcting existing tests.
* `build`: Changes that affect the build system or external dependencies.

---

## 7. Security & Vulnerability Reporting

Security is central to Tether. If you discover a security vulnerability in Tether:

1. **Do NOT open a public GitHub issue.**
2. Send a detailed report to the repository maintainers via private security advisory or direct contact.
3. Include step-by-step reproduction instructions, affected platform details, and potential impact.
4. Allow up to 90 days for investigation and patch deployment before public disclosure.

---

## 8. License

By contributing to Tether, you agree that your contributions will be licensed under the **GNU General Public License v3.0** (`GPL-3.0-only`). See the [`LICENSE`](LICENSE) file for complete details.
