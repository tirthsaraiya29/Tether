# Project: Tether Hardening & Release Verification

## Architecture
Tether is a local-first, zero-cloud Windows workstation companion system communicating over local LAN with an Android companion device.
- **Windows Service Host (`Tether.CommunicationService`)**: Runs as `NT AUTHORITY\SYSTEM` in Session 0. Handles TLS 1.3 control server (port 37123), HTTPS file transfer server (port 37124), packet routing, and update monitoring.
- **Interactive Session Bridge (`Tether.SessionHelper`)**: Runs in the active user console session (Session 1+). Handles terminal sessions, screen capture, audio control, and input injection.
- **Desktop UI (`Tether.DesktopUI`)**: WPF client running in user session. Manages pairing, settings, and update banners.
- **Native Credential Provider (`TetherCredentialProvider`)**: C++20 Win32 COM dll loaded by `winlogon.exe` in LogonUI.
- **Android Companion App**: Kotlin Jetpack Compose app communicating via encrypted TLS 1.3 sockets.

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| F1.1 | Biometric Unlock Deadlock Fix | Decouple authorized biometric unlock flow from `isAppLocked.value` drops; safely initiate unlock over TLS while locked | M1 | Survey (Explorer 1) / R1 |
| F1.2 | Normal Action Lock Guard Invariance | Preserve lock guards for all general LAN actions (power, terminal, files, clipboard, admin) when app is locked | M1 | Survey (Explorer 1) / R1 |
| F1.3 | Cryptographic Unlock Correlation | Generate, track, and bind unique `requestId` for unlock requests across Android client and Windows `PacketRouter.cs` `CONFIRM_COMMAND` | M1 | Survey (Explorer 1) / R1 |
| F1.4 | Anti-Replay & Confirmation Verification | Reject unsolicited, stale (>30s), duplicate, or mismatched confirmations in `TetherLanService.kt` | M1 | Survey (Explorer 1) / R1 |
| F1.5 | UI Lock & Biometric Lifecycle Consistency | Fix `UnlockActionReceiver` biometric requirement and `PowerEventActivity` `BiometricPrompt` `CryptoObject` config | M1 | Survey (Explorer 1) / R1 |
| F2.1 | Raw Manifest Detached Signature Check | Verify detached ECDSA P-256 signature against pinned key before JSON deserialization across all updater paths | M2 | Survey (Explorer 2) / R2 |
| F2.2 | Fail-Closed Manifest Handling | Abort elevated updater execution and UI prompts if manifest signature is missing, invalid, or tampered | M2 | Survey (Explorer 2) / R2 |
| F2.3 | Staged Payload Hash Pre-Verification | Verify SHA-256 hash of staged payload zip against authenticated manifest before extraction/execution | M2 | Survey (Explorer 2) / R2 |
| F2.4 | Pinned Authenticode Publisher Verification | Replace loose substring `subject.Contains("Tether")` with strict pinned publisher identity failing closed | M2 | Survey (Explorer 2) / R2 |
| F2.5 | Code Signing Prerequisites Documentation | Document production code signing prerequisites / hardware token constraints | M2 | Survey (Explorer 2) / R2 |
| F3.1 | Handle-Locked TOCTOU Elimination | Hold exclusive verified handle during SHA-512 check and promote atomically via `SetFileInformationByHandle(FileRenameInfo)` | M3 | Survey (Explorer 2) / R3 |
| F3.2 | Cross-Volume Fallback Removal | Remove unsafe `MOVEFILE_COPY_ALLOWED` and `File.Move(..., overwrite: true)` copy fallbacks from file promotion paths | M3 | Survey (Explorer 2) / R3 |
| F3.3 | Reparse-Point & Path-Traversal Defense | Reject reparse points, symlinks, and path traversal attempts on both source and destination | M3 | Survey (Explorer 2) / R3 |
| F3.4 | Resumable & Simultaneous Transfer Preservation | Ensure chunked, resumable, and simultaneous encrypted LAN transfers remain fully functional | M3 | Survey (Explorer 2) / R3 |
| F4.1 | Native Handle Return Checking | Check return values for all `SetHandleInformation` calls in `TerminalSessionManager.cs` | M4 | Survey (Explorer 3) / R4 |
| F4.2 | Strict Handle Inheritance & Cleanup | Clean up all pipe handles on failure paths in `TrySpawnLimitedProcess` to prevent handle inheritance leaks | M4 | Survey (Explorer 3) / R4 |
| F4.3 | Cross-Device Terminal Session Isolation | Ensure authenticated `deviceId` binds to terminal sessions and foreign devices cannot enumerate, attach, or kill sessions | M4 | Survey (Explorer 3) / R4 |
| F4.4 | Remote Shell Security & Command Filtering | Preserve remote shell functionality while enforcing restricted token execution | M4 | Survey (Explorer 3) / R4 |
| F5.1 | Desktop UI Single-Instance Pipe ACLs | Enforce strict user SID ACLs via `NamedPipeServerStreamAcl.Create` on `TetherDesktopUIInstancePipe` | M5 | Survey (Explorer 3) / R5 |
| F5.2 | Session 0 Fallback Elimination | Remove unsafe `Process.Start(..., UseShellExecute = true)` fallback in `HardwareExecutor.LaunchInUserSession`; fail closed | M5 | Survey (Explorer 3) / R5 |
| F5.3 | Multi-Monitor Input Coordinate Calculation | Fix `InputInjector.HandleAbsoluteMove` to calculate fallback coordinates using `SystemInformation.VirtualScreen` | M5 | Survey (Explorer 3) / R5 |
| F5.4 | Compiler & Analyzer Warning Resolution | Resolve `MSB3270` and `CS8625` warnings in `Tether.FileTransfer.Tests.csproj` and test files | M5 | Survey (Explorer 3) / R5 |
| F5.5 | Release Verification & Repository Cleanliness | Ensure clean Release/Debug builds and all unit tests passing, document architecture, prepare clean git commit | M5 | Survey (Explorer 3) / R5 |
| F6.1 | E2E Test Suite Pass (Tiers 1-4) | Pass 100% of the opaque-box requirement-driven E2E test suite across all features | M6 | E2E Testing Track |
| F6.2 | Adversarial Coverage Hardening (Tier 5) | White-box adversarial testing and gap elimination | M6 | E2E Testing Track |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Android Biometric Unlock & Cryptographic Binding | F1.1, F1.2, F1.3, F1.4, F1.5 | none | PLANNED |
| M2 | Updater, Manifest Auth & Authenticode Pinning | F2.1, F2.2, F2.3, F2.4, F2.5 | none | PLANNED |
| M3 | File Transfer TOCTOU Elimination & Atomic Promotion | F3.1, F3.2, F3.3, F3.4 | none | PLANNED |
| M4 | Terminal Handle Inheritance & Session Isolation | F4.1, F4.2, F4.3, F4.4 | none | PLANNED |
| M5 | System-Wide Hardening & Build Baseline Cleanliness | F5.1, F5.2, F5.3, F5.4, F5.5 | none | PLANNED |
| M6 | Final Milestone: 100% E2E Pass & Adversarial Hardening | F6.1, F6.2 | M1, M2, M3, M4, M5, TEST_READY.md | PLANNED |

## Interface Contracts

### Android Companion <-> Windows PacketRouter
- **Packet `COMMAND_EXECUTE`**:
  ```json
  {
    "type": "COMMAND_EXECUTE",
    "requestId": "<uuid-v4>",
    "command": "unlock",
    "timestamp": 1731151200000
  }
  ```
- **Packet `CONFIRM_COMMAND`**:
  ```json
  {
    "type": "CONFIRM_COMMAND",
    "requestId": "<echoed-uuid-v4>",
    "confirmedCommand": "unlock",
    "success": true,
    "reason": "OK"
  }
  ```
- Android `TetherLanService` verifies:
  1. `requestId` matches an active pending request in `pendingUnlockRequests`.
  2. `confirmedCommand == "unlock"`.
  3. `timestamp` within 30-second window.
  4. Response received on authenticated TLS connection with paired server.
- On match, request entry removed (no replay) and app unlock finalized.

### Updater Manifest <-> Authenticode Verifier
- Manifest format: raw JSON bytes accompanied by detached signature file (`update-manifest.json.sig` or detached payload field).
- Verification function:
  `AuthenticodeVerifier.VerifyManifestSignature(byte[] rawManifestBytes, byte[] signatureBytes, ECDsa publisherKey)`
- Authenticode function:
  `AuthenticodeVerifier.VerifyFileAuthenticode(string filePath, string? pinnedThumbprint = null, string? pinnedPublicKey = null)`
  - Replaces substring check with exact match: `CN=Tether Project, O=Tether, C=US` or pinned public key / thumbprint. Fails closed.

### File Transfer Promotion Contract
- In `FileTransferServer.cs`:
  - `partPath` resides on the same volume as `fullPath` (`fullPath + ".tether_part"`).
  - An exclusive read/write handle (`FileAccess.ReadWrite`, `FileShare.None`) is opened.
  - Verification: SHA-512 is computed from the open handle.
  - Promotion: `SetFileInformationByHandle` with `FileRenameInfo` (ReplaceIfExists = TRUE) atomically renames the open handle to `fullPath`.
  - Handle closed.
  - Zero cross-volume copy fallbacks. Reparse points rejected on both source handle and target path.

## Code Layout
- `apps/android-companion/app/src/main/java/com/tether/phone/`: Android companion implementation (`MainActivity.kt`, `TetherLanService.kt`, `PowerEventActivity.kt`, `UnlockActionReceiver.kt`).
- `services/communication-service/Tether.CommunicationService/`: Windows service host (`PacketRouter.cs`, `FileTransfer/FileTransferServer.cs`, `Capabilities/HardwareExecutor.cs`, `Services/UpdateWatcherService.cs`).
- `services/communication-service/Tether.SessionHelper/`: Interactive session helper (`TerminalSessionManager.cs`, `InputInjector.cs`).
- `apps/updater/Tether.Updater/`: Standalone elevated updater (`Program.cs`).
- `apps/desktop-ui/Tether.DesktopUI/`: WPF desktop UI (`App.xaml.cs`, `Updates/UpdateBannerControl.xaml.cs`).
- `shared/Tether.Shared/`: Shared contracts and utilities (`Security/AuthenticodeVerifier.cs`).
- `tests/`: Solution unit and regression tests (`Tether.FileTransfer.Tests/`).
