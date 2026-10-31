# Tether — AI Agent & Automation Developer Instructions

This document provides explicit instructions, architectural constraints, security invariants, and execution protocols for AI Coding Agents (e.g., Claude Code, Gemini CLI, Cursor, Copilot, Codex) operating on the Tether codebase.

---

## 1. System Role & Project Context

You are operating on **Tether**, a local-first, zero-cloud personal trust and security ecosystem spanning **Windows 10/11** (.NET 10, C++20 Win32 Credential Provider, WPF) and **Android 12+** (Kotlin, Jetpack Compose, Material 3, AndroidKeyStore).

### Primary System Goal
To establish a secure, low-latency cryptographic trust link over local Wi-Fi/LAN (TCP 37123 / TLS 1.3) using an Android device as a hardware-backed trust anchor for Windows workstation unlock, emergency panic lockdown, system telemetry, and remote input injection.

---

## 2. Codebase Map & Boundary Navigation

When fulfilling user requests or modifying code, locate files according to this component map:

### Windows Stack (`.NET 10` & `C++ Win32`)
* **Service Host**: `services/communication-service/Tether.CommunicationService/`
  * `Worker.cs`: Service entry point, firewall rule management, event subscriptions.
  * `Transport/TetherTcpServer.cs`: Dual-mode IPv6/IPv4 TLS 1.3 server listener (Port 37123).
  * `Transport/TetherSession.cs`: Individual authenticated device communication session.
  * `Protocol/PacketRouter.cs`: Handshake, capability checks, and command frame dispatch.
  * `Pairing/PairingManager.cs`: ECDSA/RSA key exchange and pairing code verification.
  * `Trust/TrustStore.cs`: DPAPI/Registry-backed persistent device identity store (`HKLM\SOFTWARE\Tether\Secrets`).
  * `Capabilities/HardwareExecutor.cs` & `LaptopStateCollector.cs`: Volume, display brightness, system apps, power state integrations.
* **Session Bridge**: `services/communication-service/Tether.SessionHelper/`
  * `Program.cs`: Interactive user-session daemon spawned by Session 0 service via `CreateProcessAsUser`.
  * `InputInjector.cs`: Windows Synthetic Input Injection (`SendInput` for mouse/keyboard).
  * `AudioController.cs` & `WallpaperReader.cs`: Session-bound Win32 API calls (`IAudioEndpointVolume`).
* **Win32 Credential Provider**: `TetherCredentialProvider/`
  * `TetherProvider.cpp`: `ICredentialProvider` implementation for Windows logon UI.
  * `TetherCredential.cpp`: `ICredentialProviderCredential2` implementation. Handles tile layout, event synchronization (`_hAppEvent`, `_hScreenEvent`), pipe signal listening, and DPAPI password serialization.
* **Desktop Configuration UI**: `apps/desktop-ui/Tether.DesktopUI/`
  * `MainWindow.xaml.cs`: Fluent WPF interface, SCM service control, IPC diagnostics stream, vault controls.
* **Shared & Engines**: `shared/Tether.Shared/`, `services/trust-engine/`, `services/panic-engine/`, `services/event-bus/`
  * `TetherEvent.cs`, `IpcConstants.cs`, `InMemoryEventBus.cs`, `TrustStateManager.cs`, `PanicManager.cs`.

### Android Stack (`Kotlin` & `Jetpack Compose`)
* **Companion Root**: `apps/android-companion/app/src/main/java/com/tether/phone/`
  * `TetherLanService.kt`: Foreground service managing Wi-Fi state, TLS socket client, heartbeat, and remote command processing.
  * `ProductionSecurityEngine.kt`: AndroidKeyStore EC key generator (`TetherIdentityKey_v1`), AES-256-GCM storage key (`TetherStorageKey_v2`), BiometricPrompt, SHA-256 fingerprinting.
  * `TetherDiscoveryManager.kt`: mDNS (`_tether._tcp.`) and UDP broadcast (Port 37124) discovery engine.
  * `TetherPairingManager.kt`: Mobile-side cryptographic pairing state machine.
  * `DeviceIntegrityRegistry.kt`: System integrity auditor (root check, developer options, biometric status).
  * `RemoteInputEngine.kt`: Trackpad gesture and modifier key packet generator.
  * `FileTransferClient.kt`: Encrypted file transfer client (HTTPS on Port 37124 with public key pinning).
  * `ui/screens/MainScreens.kt`: Jetpack Compose main dashboard and control center.
  * `ui/screens/RemoteInputScreen.kt`: Remote trackpad, scroll canvas, and keyboard interface.
  * `ui/screens/PermissionsScreen.kt`: Runtime permissions dashboard and grant manager.

---

## 3. Strict Security Invariants & Agent Guardrails

AI Coding Agents MUST strictly obey these security invariants when reading, editing, or generating code. **Violations will break system integrity and create critical vulnerabilities.**

### 🛑 INVARIANT 1: Zero Cloud & Local Boundary
* NEVER add cloud API calls, remote HTTP telemetry endpoints, or external cloud relays.
* Communication must strictly remain within local subnet boundaries (TCP 37123 / TLS 1.3).

### 🛑 INVARIANT 2: Windows Session 0 Isolation
* Windows services (`Tether.CommunicationService.exe`) run in **Session 0**. Session 0 CANNOT directly interact with desktop windows, UI elements, or user audio sessions.
* NEVER invoke GUI APIs, `SendInput`, or user-session Core Audio methods directly inside `Tether.CommunicationService`.
* Interactive session tasks MUST be delegated to `Tether.SessionHelper.exe`, spawned into the active console session via `WTSQueryUserToken` + `CreateProcessAsUser`.

### 🛑 INVARIANT 3: Credential Provider Exception & Memory Safety
* C++ code inside `TetherCredentialProvider` MUST NOT allow C++ exceptions to cross COM interface boundaries (`ICredentialProvider`, `ICredentialProviderCredential2`). Always wrap method bodies in `try { ... } catch (...) { return E_UNEXPECTED; }`.
* Sensitive memory buffers containing passwords, PINs, or decrypt keys MUST be cleared immediately after use using `SecureZeroMemory()` or `RtlSecureZeroMemory()`.
* NEVER output plain-text credentials, raw hashes, or DPAPI master entropy strings to logs (`WriteDebugLog`).

### 🛑 INVARIANT 4: DPAPI Cryptographic Entropy
* Data Protection API (`CryptProtectData` / `CryptUnprotectData`) calls for local credential storage MUST pass the system-bound entropy string `Tether_System_Bound_Vault_v1`.
* Registry secrets reside in `HKLM\SOFTWARE\Tether\Secrets` with strict ACLs (`VaultDaclVersion=2`).

### 🛑 INVARIANT 5: Android KeyStore Hardware Binding
* Android private keys MUST remain inside `AndroidKeyStore` under alias `TetherIdentityKey_v1`.
* Key material MUST NEVER be exported as raw bytes or written to unencrypted disk storage.
* AES-256-GCM secret keys (`TetherStorageKey_v2`) MUST be used for local SharedPreferences encryption in `ProductionSecurityEngine`.

### 🛑 INVARIANT 6: Input & Command Injection Sanitization
* Hardware execution commands (e.g., launching apps in `HardwareExecutor.cs` or `Program.cs`) MUST sanitize file paths and process names.
* NEVER use `cmd.exe /c` or `powershell.exe -Command` with unparsed string concatenation from incoming network payloads.

---

## 4. Code Modification & Formatting Guidelines

When making edits to the codebase:

1. **Use Built-in IDE Tools**: Use `replace_file_content` or `multi_replace_file_content` for surgical edits. Avoid shell scripts (`sed`, `perl`, `echo >`) that bypass IDE buffers.
2. **Preserve Language Idioms**:
   * **C#**: Use pattern matching, file-scoped namespaces, nullable annotations, `using` declarations, and async/await with `CancellationToken`.
   * **C++**: Use C++20 standard, wide strings (`std::wstring`), COM smart pointers, and explicit `HRESULT` error checking (`SUCCEEDED()` / `FAILED()`).
   * **Kotlin**: Use idiomatic Kotlin, immutable data classes (`data class`), Jetpack Compose best practices, and Kotlin Coroutines/Flow.
3. **Comment Hygiene (Anti-Slop Standard)**:
   * DO NOT add trivial, redundant comments (e.g., `// Increment i by 1` or `// Constructor`).
   * DO add concise technical comments explaining complex Win32 interop, Session 0 token duplication, thread synchronization, or cryptographic invariants.

---

## 5. Automated Build & Verification Commands

Agents should verify their changes using these standard commands:

### Windows Build Verification
```powershell
# Build entire solution
dotnet build Tether.slnx -c Debug

# Run unit tests
dotnet test Tether.slnx --configuration Debug
```

### Android Build Verification
```bash
# Navigate to Android project directory
cd apps/android-companion

# Assemble debug build
./gradlew assembleDebug

# Run unit tests
./gradlew test
```

---

## 6. Pre-Flight Verification Checklist for Agents

Before reporting a task as complete, verify:

- [ ] Build compiles cleanly without errors on affected platforms.
- [ ] No plain-text secrets, passwords, or keys are written to log files.
- [ ] All new public methods specify nullability annotations and parameter validation.
- [ ] Session 0 isolation constraints are preserved for Windows service code.
- [ ] Android background tasks run on `Dispatchers.IO` and UI updates on `Dispatchers.Main`.
- [ ] Unit test suite passes without regressions.
