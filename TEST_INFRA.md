# Tether Test Infrastructure & Architecture Specification

## 1. Test Philosophy & Principles

Tether is a local-first, zero-cloud Windows workstation companion system. Because security boundaries and system invariants (Session 0 isolation, Win32 handle hygiene, DPAPI encryption, detached cryptographic manifest verification, TOCTOU-free file promotions, and cross-device session isolation) are critical to system integrity, the test suite adheres strictly to the following principles:

1. **Opaque-Box & Requirement-Driven:**
   Tests are derived directly from user requirements (`ORIGINAL_REQUEST.md`) and the project architectural specification (`PROJECT.md`). Tests assert against observable behaviors, interface contracts, return codes, and cryptographic boundaries without coupling to ephemeral internal state.

2. **Deterministic & Self-Contained:**
   Every test creates and isolates its own test artifacts, cryptographic keys, tokens, or temporary files. No test relies on order of execution, shared mutable static state, or network access. All temporary resources are cleaned up deterministically via `try / finally` or `IDisposable`.

3. **Adversarial & Fail-Closed Invariants:**
   Tests explicitly exercise edge conditions: forged signatures, tampered byte streams, expired tokens, path traversal payloads (`..`, alternate data streams, UNC paths, reserved DOS device names), reparse-point directories, unsolicited unlock confirmations, and unauthorized cross-device commands. In all adversarial conditions, the system must fail closed.

4. **Zero-Slop & Zero-Facade Integrity:**
   No facade tests that pass unconditionally. Assertions strictly verify functional and security guarantees.

---

## 2. Feature Inventory Matrix (R1 - R5)

| Feature ID | Feature Name | Target Component | Security / Functional Invariant Tested | Tiers Covered |
|---|---|---|---|---|
| **R1 (F1.1 - F1.5)** | Android Companion & Biometric Unlock Security | `PacketRouter.cs`, `HardwareExecutor.cs`, `CapabilityManager.cs` | Biometric unlock authorization, unique requestId binding, 30s timestamp window, rejection of forged/unsolicited confirmations, lock guard invariance, `Global\TetherPhoneAppUnlocked` ACL verification. | T1, T2, T3, T4 |
| **R2 (F2.1 - F2.5)** | Updater, Manifest Auth & Authenticode Pinning | `AuthenticodeVerifier.cs`, `UpdateWatcherService.cs`, `Tether.Updater/Program.cs` | Detached ECDSA P-256 signature verification on raw bytes, rejection of tampered/unauthenticated payloads, hash pre-verification, pinned publisher identity, fail-closed staging ACLs and reparse-point rejection. | T1, T2, T3, T4 |
| **R3 (F3.1 - F3.4)** | File Transfer TOCTOU Elimination & Promotion Integrity | `FileTransferServer.cs`, `TokenStore.cs`, `FileTransferAuthMiddleware.cs` | Handle-locked verification, atomic promotion without cross-volume copy fallbacks, reparse point rejection, ADS/UNC/DOS name blocking, cross-user profile boundary enforcement, resumable transfer tokens. | T1, T2, T3, T4 |
| **R4 (F4.1 - F4.4)** | Terminal Handle Inheritance & Cross-Device Isolation | `TerminalSessionManager.cs`, `PacketRouter.cs` | Mandatory `ownerDeviceId` enforcement, cross-device isolation (foreign devices cannot read, input to, or terminate sessions), administrative command restrictions (`runas`, `sudo`, `bcdedit`), handle inheritance safety. | T1, T2, T3, T4 |
| **R5 (F5.1 - F5.5)** | System Hardening & Boundary Defect Elimination | `App.xaml.cs`, `HardwareExecutor.cs`, `ScreenCaptureEngine.cs`, `CapabilityManager.cs` | Desktop UI single-instance pipe security descriptor (NetworkSid deny, currentUser allow), Session 0 fail-closed execution without shell fallback, multi-monitor virtual screen coordinate mapping, role-based capability boundaries. | T1, T2, T3, T4 |

---

## 3. Test Architecture & Runner Setup

### 3.1 Technology Stack
- **Framework:** .NET 10 (`net10.0-windows10.0.22621.0`)
- **Test Runner:** xUnit v2.9.2 with Microsoft.NET.Test.Sdk 17.12.0
- **Runner Configuration:** Release build, quiet output (`-v q --nologo`), zero slop
- **Primary Test Project:** `tests/Tether.FileTransfer.Tests/Tether.FileTransfer.Tests.csproj`

### 3.2 Subsystem Linkages
The test project links directly to all solution assemblies:
- `Tether.CommunicationService.csproj` (Windows Session 0 Service Host, Protocol Router, File Server, Capabilities)
- `Tether.SessionHelper.csproj` (Console Session Bridge, Terminal Sessions, Screen Capture, Input Injection)
- `Tether.DesktopUI.csproj` (WPF Desktop UI, Single-Instance Pipe Server, Update Banner)
- `Tether.Shared.csproj` (Authenticode Verifier, Event Bus, Shared Constants & Protocols)
- `Tether.Updater.csproj` (Elevated Updater, Manifest Verification, Staging ACL Lockdown)

### 3.3 Test Execution Command
```powershell
dotnet test tests/Tether.FileTransfer.Tests/Tether.FileTransfer.Tests.csproj -c Release -v q --nologo --logger "console;verbosity=minimal"
```

---

## 4. Tier Coverage Summary

### Tier 1: Feature Coverage (>=5 test cases per feature across R1-R5)
Comprehensive coverage verifying the core operational and security behaviors of every subsystem under nominal conditions:
- **R1:** Biometric unlock protocol confirmation, capability checking (`SYSTEM_CONTROL`), unprivileged rejection, unlock event creation/signaling, ownership verification, and lock state consistency.
- **R2:** Detached ECDSA manifest signature verification, tampered payload rejection, untrusted key rejection, update manifest serialization/deserialization, Authenticode verifier with unsigned/corrupt binary rejection.
- **R3:** Cryptographically secure token generation, device fingerprint binding, path validation for allowed user files, Public profile access, system directory blocking, and volume recycle bin blocking.
- **R4:** Mandatory owner device ID checking, cross-device input isolation, cross-device session termination blocking, cross-device history isolation, owner-filtered session listing, and maximum capacity enforcement.
- **R5:** Session 0 fail-closed handling without console session, named pipe ACL network denial and user grant, multi-monitor virtual screen negative offset handling, unprivileged power command blocking, and automation capability gating.

### Tier 2: Boundary & Corner Cases (>=5 test cases per feature)
Adversarial and extreme boundary testing:
- **R1:** Empty and whitespace request IDs, expired timestamps (>30s), future timestamp skew, empty command strings, null session/device handling, extreme-length IDs.
- **R2:** Zero-length manifest payload, zero-length signature, single-bit signature corruption, extreme payload size, reparse-point binaries, whitespace staging directory paths.
- **R3:** Path traversal sequences (`..\..\`), alternate data streams (`test.txt:stream`), UNC double-slash paths (`\\server\share`), DOS reserved names (`CON`, `NUL`, `AUX`, `COM1`), expired token rejection, victim profile isolation.
- **R4:** Directory traversal characters in custom session IDs, custom IDs exceeding 32 characters, restricted admin command detection (`runas`, `sudo`, `bcdedit`, `diskpart`, `net localgroup`, `takeown`), empty and whitespace input handling.
- **R5:** Null device/command objects, malformed capability strings, invalid automation condition thresholds, unknown condition types, extreme coordinate overflow clamping, untrusted security descriptor ownership rejection.

### Tier 3: Cross-Feature Combinations (Pairwise Interactions)
Pairwise matrix testing interacting features across auth, transfer, terminal, and lock boundaries:
- App lock state interaction with file transfer upload and delete endpoints.
- App lock state interaction with remote terminal invocation.
- App lock state interaction with authorized biometric unlock flow.
- Token invalidation across simultaneous file and terminal subsystems.
- Partitioning between Device A terminal sessions and Device B file transfer tokens.
- Local UI token privilege restriction preventing remote admin / filesystem access.
- Power elevated privileges unable to bypass detached manifest signature validation.
- Simultaneous file transfers and terminal streams under resource throttling.
- Dynamic device trust revocation immediately cutting off active tokens and sessions.
- Multi-monitor capture under locked screen returning secure deterministic frames.
- Updater staging directory isolation preventing leakage into file transfer accessible trees.
- Cross-device replay of unlock confirmations failing across distinct device identifiers.

### Tier 4: Real-World Application Scenarios (End-to-End Workflows)
End-to-end simulations of actual user and system lifecycles:
1. Full Device Pairing -> Biometric Authentication -> Unlock Lifecycle.
2. Chunked, Resumable Encrypted File Transfer with Token Binding and Boundary Protection.
3. Multi-Turn Interactive Remote Terminal Session (Spawn -> Command -> Output -> Terminate).
4. Elevated Background Updater Execution (Manifest Verification -> Staging Lockdown -> File Verification).
5. Multi-Device Partitioned Concurrency (Simultaneous distinct device workflows).
6. Remote Hardware Telemetry & Power Management under Granular Capabilities.
7. Desktop UI Single-Instance Pipe Handoff with Strict Access Control.
8. Adversarial Escape Attempt: Compound Attack Chain Neutralization.
