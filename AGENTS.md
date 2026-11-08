# Tether — Unified AI Agent & System Directives

This specification defines the non-negotiable architectural constraints, security invariants, repository topology, and execution profiles for AI Coding Agents operating on the Tether codebase.

---

## 1. System Invariants & Security Boundaries (STRICT)

All agents must strictly enforce the following security and architectural invariants. Any modification violating these constraints will destabilize the system or introduce severe privilege escalation vulnerabilities:

* **Zero-Cloud & Local Network Boundary:**
* Tether operates exclusively over local Wi-Fi/LAN (TCP 37123 for TLS 1.3 control; TCP 37124 for HTTPS file transfer; UDP 37124 and UDP 5353 for discovery).

* Never introduce external cloud SDKs, third-party authentication endpoints, remote telemetry beacons, or external relay servers.

* Mobile hotspot / AP mode is explicitly unsupported.

* **Session 0 Privileged Isolation (Windows):**
* `Tether.CommunicationService` runs as `NT AUTHORITY\SYSTEM` in Session 0.

* Session 0 cannot interact with the desktop or run user-space GUI/Audio APIs.

* Never invoke `SendInput`, Core Audio (`IAudioEndpointVolume`), or window management directly from `Tether.CommunicationService`.

* Interactive operations must be delegated to `Tether.SessionHelper.exe`, spawned into the active console session (`WTSGetActiveConsoleSessionId`) via `WTSQueryUserToken` + `DuplicateTokenEx` + `CreateProcessAsUser`.

* **Native Credential Provider Memory & Exception Safety (C++ Win32):**
* `TetherCredentialProvider.dll` is an in-process COM component loaded by `Winlogon.exe` / Logon UI.

* COM interface methods (`ICredentialProvider`, `ICredentialProviderCredential2`) must never leak C++ exceptions across COM boundaries. Every method body must be wrapped in `try { ... } catch (...) { return E_UNEXPECTED; }`.

* Buffers containing cleartext credentials, PINs, or DPAPI master entropy must be wiped immediately after use via `SecureZeroMemory()` or `RtlSecureZeroMemory()`.

* Never write plain-text credentials, raw keys, or cryptographic nonces to debug logs (`WriteDebugLog`).

* **Cryptographic Vault & DPAPI Hardening:**
* Windows workstation credentials must be protected via DPAPI (`CryptProtectData` / `CryptUnprotectData`) using the exact system-bound entropy string `Tether_System_Bound_Vault_v1`.

* Stored in `HKLM\SOFTWARE\Tether\Secrets` with strict Discretionary Access Control Lists (`VaultDaclVersion=2`) restricted to LocalSystem and Administrators.

* **Android KeyStore Hardware Binding:**
* Android identity keys must be generated inside the hardware enclave (`AndroidKeyStore` with StrongBox / TEE) under key alias `TetherIdentityKey_v1` using ECDSA P-256 for `SHA256withECDSA` signing.

* Private key material must never be exported as raw bytes or written to storage.

* Local SharedPreferences encryption requires AES-256-GCM (`TetherStorageKey_v2`).

* **Named Pipe IPC ACLs:**
* Named pipes (`TetherPipe`, `TetherUiPipe`, `Tether.InputPipe`) must mandate authenticated user SID validation and strict access-control lists (ACLs) to block unprivileged local hijacking.

---

## 2. Codebase Topology & File Mapping

Locate target components using the map below to avoid broad filesystem scans:

| Subsystem | Primary Path | Technology / Core Files |
| --- | --- | --- |
| **Windows Service Host** | `services/communication-service/Tether.CommunicationService/` | C# .NET 10 (`Worker.cs`, `TetherTcpServer.cs`, `PacketRouter.cs`, `TrustStore.cs`, `WindowsAdminManager.cs`, `AutomationEngine.cs`, `FileTransferServer.cs`) |
| **Interactive Session Bridge** | `services/communication-service/Tether.SessionHelper/` | C# .NET 10 (`Program.cs`, `InputInjector.cs`, `ScreenCaptureEngine.cs`, `AdvancedAudioController.cs`, `MediaSessionController.cs`, `ClipboardController.cs`, `NotificationController.cs`, `TerminalSessionManager.cs`, `ApplicationManager.cs`) |
| **Win32 Credential Provider** | `TetherCredentialProvider/` | C++20 Win32 COM (`TetherProvider.cpp`, `TetherCredential.cpp`, `core.h`) |
| **Desktop Management UI** | `apps/desktop-ui/Tether.DesktopUI/` | C# .NET 10 WPF (`MainWindow.xaml.cs`, `Themes/FluentTheme.xaml`) |
| **Core Engines & Shared** | `services/`, `shared/Tether.Shared/` | `TrustEngine/`, `PanicEngine/`, `EnforcementEngine/`, `EventBus/`, `IpcConstants.cs` |
| **Android Companion App** | `apps/android-companion/app/src/main/java/com/tether/phone/` | Kotlin / Jetpack Compose (`TetherLanService.kt`, `ProductionSecurityEngine.kt`, `FileTransferClient.kt`, `TetherNotificationListenerService.kt`, `ui/screens/*.kt`) |
| **Installer Packaging** | `installer/` | Inno Setup script (`Tether.iss`) compiling `Tether-Setup-*.exe` |

---

## 3. General Engineering Standards (Ponytail & Anti-Slop)

* **Minimalist Architecture (Ponytail):**
* Write the minimal code necessary to satisfy the requirement.

* Do not create premature abstraction layers, unnecessary interfaces, or factory wrappers for single-use classes.

* Prefer standard library APIs (.NET BCL, Win32 APIs, AndroidX/Java standard libraries) over pulling in external dependencies.

* Use surgical string replacements; do not reformat or modify lines adjacent to the change.

* **Zero AI Slop & Direct Output:**
* Eliminate conversational preamble, pleasantries, apologies, and self-evident narrative explanations.

* Do not output trivial comments (e.g., `// Constructor`, `// Increment counter`, `// Set variable`).

* Add technical comments solely for complex Win32 interop, Session 0 token duplication, COM reference counting, or cryptographic edge cases.

* Limit terminal summaries to 1–3 dense, technical sentences stating only modified files and verification results.

---

## 4. Agent-Specific Execution Profiles

### 4.1 Pi Agent Execution Profile

Optimized for Pi Agent’s native toolset (`read`, `edit`, `write`, `bash`) to minimize working memory payload:

* **Tool-Specific Constraints:**
* **`edit` Tool Exclusivity:** Always use `edit` for code modifications using unique 2-to-3 line anchor blocks. Never use `write` to overwrite existing files. Reserve `write` strictly for new file creation.

* **Bounded `read` Operations:** Always provide `offset` and `limit` parameters (max 100 lines) when inspecting unfamiliar classes. Never read unbounded source files into working memory.

* **Targeted Search via `bash`:** Execute search queries via `rg -m 10 --no-heading` or `git grep -n`. Never run unconstrained directory listings or recursive tree printouts.

* **Execution Flow:**
1. Identify exact line ranges using bounded `read` or `rg`.

2. Apply precise edits with `edit`.

3. Validate through quiet compilation commands via `bash`.

4. Immediately conclude turn without narrative filler.

### 4.2 Claude Code (CC) Execution Profile

Optimized to prevent conversation history bloat, terminal output duplication, and token explosion:

* **Token Preservation & Output Restraints:**
* **Zero Full-File Rewrites:** Use localized `Edit` / `str_replace` tools with no more than 3 lines of preceding and succeeding context.

* **Terminal Output Containment:** Suppress build and test output using quiet flags (`-v q --nologo`). Never pipe full file contents via `cat` or PowerShell `Get-Content`.

* **Search Truncation:** Limit ripgrep searches using `rg -m 10` or git grep.

* **Git Hygiene:** Use short status output (`git status -s`).

* **Context Window Discipline:**
* Enforce `/autocompact 75k` at session startup to prevent unpruned terminal history from growing beyond 75k tokens.
* Trigger `/compact` immediately upon completing discrete sub-tasks.
* Keep tool responses under 3 sentences. Focus strictly on tool calls and execution status.

### 4.3 Antigravity Execution Profile

Optimized for the Google Shared Agent Harness and structured sandbox environment:

* **AST & Symbol Navigation First:**
* Prioritize AST and symbol discovery tools (`view_file_outline`, `view_symbol`) before reading raw code blocks to avoid loading entire source files into context.
* Use targeted slice viewing (`view_file_segment`) constrained to specific functions.

* **Sandbox Terminal Governance:**
* Run builds with strict silent switches. Never dump raw compilation object lists or intermediate build artifacts into the persistent sandbox history.
* Terminate execution turns immediately once validation succeeds. Do not launch unprompted verification passes or speculative exploratory loops.

* **Multi-Turn Scoping:**
* Address tasks within a single focused turn wherever possible. Avoid multi-turn discovery chains when a targeted grep or symbol query can locate the target in one pass.

### 4.4 Codex, Qwen Code, Hermes Agent & dsh Execution Profile

Optimized for headless, single-pass instruction completion and strict syntax correctness:

* **Deterministic Single-Pass Diffs:**
* Generate compact search/replace blocks or standard unified diffs with exact line matching.

* Preserve native line endings: CRLF for Windows C# (`.cs`) and C++ (`.cpp`, `.h`), LF for Android Kotlin (`.kt`) and shell scripts (`.sh`, `.gradle`).

* **Strict Type Safety & Language Idioms:**
* **C# .NET 10:** File-scoped namespaces, nullable reference types enabled, explicit `CancellationToken` propagation, pattern matching, no unconstrained allocations.

* **C++20:** Wide Win32 APIs (`wchar_t`, `std::wstring`), COM smart pointers, explicit `HRESULT` validation via `SUCCEEDED()` / `FAILED()`, explicit `try/catch` wrapping at COM boundaries.

* **Kotlin:** Structured concurrency on `Dispatchers.IO`, immutable UI state models, AndroidX KeyStore security APIs.

* **Fail-Fast Policy:**
* If a compilation step produces errors, address only the primary compiler diagnostic. Do not execute speculative multi-file edits across unaffected subsystems.

---

## 5. Token-Optimized Build & Test Verification

Agents must run the following quiet commands to verify changes without filling the context window with build output:

```powershell
# Windows: Build entire solution quietly
dotnet build Tether.slnx -c Release -v q --nologo

# Windows: Run C# unit tests quietly
dotnet test Tether.slnx -c Release -v q --nologo --logger "console;verbosity=minimal"

# Windows: Build C++ Credential Provider quietly
msbuild TetherCredentialProvider\TetherCredentialProvider.vcxproj /p:Configuration=Release /p:Platform=x64 /v:q /nologo

# Android: Assemble debug APK quietly
cd apps/android-companion && ./gradlew assembleDebug -q

# Android: Run unit tests quietly
./gradlew test -q

```

---

## 6. Pre-Commit Verification Gate

Before signaling task completion, verify:

1. The modified component compiles with zero errors under quiet build flags.

2. No plain-text secrets, passwords, nonces, or master keys are printed to logs.

3. Session 0 isolation constraints are intact (no desktop/GUI calls in Windows services).

4. COM interface boundaries in `TetherCredentialProvider` catch all exceptions and clear memory via `SecureZeroMemory()`.

5. Edits are minimal and surgical, with zero extraneous files touched.
