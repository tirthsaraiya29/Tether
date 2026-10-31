# Tether — System Architecture & Security Design Specification

This specification documents the complete architectural design, cryptographic threat model, communication protocol, and subsystem breakdown for the **Tether** ecosystem across Windows and Android platforms.

---

## 1. System Goals & Design Philosophy

Tether is built to provide an adaptive personal trust and security framework linking an Android mobile device with a Windows 10/11 workstation.

### Key Architectural Pillars
1. **Local-First & Zero-Cloud Dependency**: Tether operates completely within local Wi-Fi/LAN networks. No cloud services, external identity providers, or third-party relays are used.
2. **Hardware-Backed Identity Enclaves**: Cryptographic key pairs are generated inside hardware security enclaves (`AndroidKeyStore` with StrongBox / TEE on Android, DPAPI system-bound entropy on Windows).
3. **Session 0 Privileged Isolation**: Windows background services operate in isolated Session 0, delegating interactive user operations to an ephemeral Session Helper inside active user desktop sessions.
4. **Instant Panic & Trust Revocation**: Workstation trust state can be dynamically downgraded or completely revoked instantly from the mobile companion app or Windows system events.

---

## 2. Threat Model & Security Invariants

Tether is designed to defend against network eavesdropping, local workstation tampering, relay attacks, and privilege escalation.

### Threat Matrix & Mitigations

| Threat Vector | Attack Scenario | Architectural Mitigation |
|---|---|---|
| **Local Network Interception** | Eavesdropping or MitM attacks on local Wi-Fi. | Mandatory **TLS 1.3** transport on direct TCP socket. Public keys pinned after initial pairing. |
| **Replay Attacks** | Capturing command frames and replaying them later. | Monotonically increasing `requestId`, UTC timestamp drift validation ($\le 30\text{s}$ window), and ephemeral nonces. |
| **Session 0 Privilege Escalation** | Rogue local processes attempting to hijack service IPC. | Named pipes (`TetherPipe`, `TetherUiPipe`, `Tether.InputPipe`) enforce strict Security Descriptors (ACLs) restricting access to Local System and authenticated user SIDs. |
| **Local Registry Secret Theft** | Unprivileged local malware reading stored credentials. | Credentials stored in `HKLM\SOFTWARE\Tether\Secrets` with `VaultDaclVersion=2` DACL restriction and encrypted via **DPAPI** using system-bound entropy (`Tether_System_Bound_Vault_v1`). |
| **Compromised Mobile Device** | Rooted Android device or malware attempting unauthorized unlock. | `DeviceIntegrityRegistry` performs hardware root checks (`su` binary, `test-keys`), audits developer options, and mandates **BiometricPrompt** cryptographic challenge. |
| **Credential Provider Exception Crashing** | Malicious input causing logon UI crashes in Winlogon. | Native C++ COM interface methods (`ICredentialProvider`, `ICredentialProviderCredential2`) catch all exceptions, log diagnostic errors, and clear secrets via `SecureZeroMemory()`. |

---

## 3. Communication Protocol & Network Architecture

Tether employs a dual-channel network architecture for control and high-throughput data transfer over local TCP/UDP.

```
+-----------------------------------------------------------------------+
|                       ANDROID COMPANION DEVICE                        |
|                                                                       |
|  +--------------------+   +-------------------+   +----------------+  |
|  |  Jetpack Compose   |   | ProductionSecurity|   | TetherLanSvc   |  |
|  |  MainScreens / UI  |   | Engine (KeyStore) |   | TLS Client     |  |
|  +---------+----------+   +---------+---------+   +-------+--------+  |
+------------|------------------------|---------------------|-----------+
             |                        |                     |
             | Local Wi-Fi / LAN      |                     |
             | TCP 37123 (TLS 1.3)    | UDP 37124 / 5353    | TCP 37124 (File HTTPS)
             v                        v                     v
+-----------------------------------------------------------------------+
|                         WINDOWS WORKSTATION                           |
|                                                                       |
|  +-----------------------------------------------------------------+  |
|  | Tether.CommunicationService (Worker Service - Session 0)        |  |
|  |                                                                 |  |
|  |  +----------------+  +-----------------+  +------------------+  |  |
|  |  | TetherTcpServer|  | UdpDiscovery /  |  | TrustStore /     |  |  |
|  |  | (TLS 1.3 37123)|  | MdnsAdvertiser  |  | DeviceManager    |  |  |
|  |  +-------+--------+  +-----------------+  +--------+---------+  |  |
|  |          |                                         |            |  |
|  |          +--------------------+--------------------+            |  |
|  |                               |                                 |  |
|  |                               v                                 |  |
|  |                   PacketRouter & Event Bus                      |  |
|  +-----------+---------------------------------------+-------------+  |
|              |                                       |                |
|              | Named Pipe (Tether.InputPipe)         | Pipe (TetherPipe)
|              v                                       v                |
|  +-----------------------+               +-------------------------+  |
|  | Tether.SessionHelper  |               | Tether.DesktopUI        |  |
|  | Active User Session   |               | WPF Management App      |  |
|  | (SendInput / Audio)   |               | (Telemetry & Settings)  |  |
|  +-----------------------+               +-------------------------+  |
|                                                                       |
|  +-----------------------------------------------------------------+  |
|  | TetherCredentialProvider (Win32 DLL in Winlogon / Logon UI)    |  |
|  +-----------------------------------------------------------------+  |
+-----------------------------------------------------------------------+
```

### Protocol Specifications
* **Control Channel**: TCP Port `37123` (Dual-stack IPv6/IPv4). Enforces TLS 1.3 with mutual public key pinning.
* **Discovery Channels**:
  * **mDNS**: Advertises service type `_tether._tcp.` over UDP Port `5353`.
  * **UDP Broadcast**: Port `37124` for instant peer discovery on local subnets.
* **File Transfer Channel**: TCP Port `37124`. Driven by Kestrel HTTPS server with `FileTransferAuthMiddleware`, `TokenStore` short-lived token authorization, 4GB size limits, Win32 handle resolution to prevent symlink escape, and public key certificate pinning (`TetherPinnedTrustManager`).

### Frame Structure & Packet Codec
Network payloads are framed using length-prefixed binary encoding (`FrameCodec.cs`):

```text
+-----------------------+-----------------------+-------------------------------+
|  Length (4 Bytes)     |  Opcode (2 Bytes)     |  Payload JSON (UTF-8 Encoded) |
|  Big-Endian UInt32    |  Big-Endian UInt16    |  Command or Event Payload     |
+-----------------------+-----------------------+-------------------------------+
```

### Pairing Handshake Lifecycle
1. **Discovery**: Android discovers Windows workstation via mDNS or UDP broadcast.
2. **Session Initiation**: Android opens TCP TLS connection to Port `37123`.
3. **Short Authentication String (SAS)**: A 6-digit numeric pairing code is displayed on `Tether.DesktopUI`.
4. **Key Exchange & Signing**: Android sends its EC public key (`TetherIdentityKey_v1`). Windows verifies the SAS code, verifies its self-signed ECDSA P-256 identity certificate (`CN=Tether Windows Identity`), signs the handshake nonce, and stores the trusted device record in `TrustStore`.
5. **Fingerprint Verification**: Both devices compute and display a SHA-256 public key fingerprint formatted as `XX:XX:XX:...:XX`.

---

## 4. Windows Subsystem Architecture

### 4.1 Communication Service (`Tether.CommunicationService`)
The primary background Windows service (`TetherCommService`), running as `NT AUTHORITY\SYSTEM` in Session 0:
* **`Worker.cs`**: Orchestrates service lifecycle, firewall rule management via `netsh advfirewall`, and system power event integration (`PowerEventWatcher.cs`).
* **`TetherTcpServer.cs`**: Handles dual-mode TCP sockets, limits concurrent sessions (max 16), and instantiates `TetherSession` objects.
* **`PacketRouter.cs`**: Validates request sequence IDs, parses JSON packet frames, checks required capabilities (`CapabilityManager.cs`), and routes execution to `HardwareExecutor.cs` or the internal `InMemoryEventBus`.
* **`TrustStore.cs`**: Persists paired device records, public keys, and trust state to `HKLM\SOFTWARE\Tether\Secrets` with DPAPI system-bound protection (`Tether_System_Bound_Vault_v1`).

### 4.2 Interactive Session Helper (`Tether.SessionHelper`)
Because Session 0 is isolated from user desktop sessions:
* When an active console user session is detected (`WTSGetActiveConsoleSessionId`), `Tether.CommunicationService` obtains the user token (`WTSQueryUserToken`), duplicates it (`DuplicateTokenEx`), and spawns `Tether.SessionHelper.exe` using `CreateProcessAsUser`.
* `SessionHelper` listens on named pipe `Tether.InputPipe` to perform:
  * **Synthetic Input Injection**: `InputInjector.cs` calls Win32 `SendInput` for mouse pointer movement, clicks, scrolling, and keyboard keystrokes.
  * **Core Audio Control**: `AudioController.cs` uses COM `IAudioEndpointVolume` for master volume adjustment.
  * **Display Brightness**: WMI / DXVA2 monitor brightness controls.
  * **Lock Detection**: Registers for session notification (`WTSRegisterSessionNotification`) to monitor workstation lock/unlock transitions.

### 4.3 Native Credential Provider (`TetherCredentialProvider`)
A native C++ Win32 COM DLL registered in `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{c8c8d282-f4f1-451d-96fc-a8b1f783117b}`:
* Implements `ICredentialProvider` and `ICredentialProviderCredential2`.
* Enumerates a custom logon tile on the Windows logon/unlock screen.
* Listens on named pipe signal events (`_hAppEvent`, `_hScreenEvent`).
* When an authenticated unlock command is received from the paired Android device, the provider decrypts the DPAPI-protected user credentials, populates `KERB_INTERACTIVE_UNLOCK_LOGON` structures, and serializes the credential to Winlogon for seamless desktop unlock.

---

## 5. Android Companion Architecture

### 5.1 Architecture & Layers
The Android companion app follows the modern Android architecture guidance:

```text
+-----------------------------------------------------------------+
|                       JETPACK COMPOSE UI                        |
|   MainScreens.kt | RemoteInputScreen.kt | PermissionsScreen.kt  |
+--------------------------------+--------------------------------+
                                 |
                                 v
+-----------------------------------------------------------------+
|                      VIEW MODEL & STATE                         |
|           UpdateViewModel.kt | LaptopState.kt                   |
+--------------------------------+--------------------------------+
                                 |
                                 v
+-----------------------------------------------------------------+
|                    FOREGROUND SERVICE & CORE                    |
|  TetherLanService.kt | ProductionSecurityEngine.kt | Discovery  |
+--------------------------------+--------------------------------+
                                 |
                                 v
+-----------------------------------------------------------------+
|                    ANDROID HARDWARE ENCLAVE                     |
|        AndroidKeyStore | StrongBox | BiometricPrompt            |
+-----------------------------------------------------------------+
```

### 5.2 Key Subsystems
* **`TetherLanService.kt`**: A foreground service with a persistent notification channel. Maintains background Wi-Fi connectivity, TLS TCP connection, keepalive heartbeats, and processes power/lock commands.
* **`ProductionSecurityEngine.kt`**:
  * Identity Key: Generates EC 256-bit key pair (`TetherIdentityKey_v1`) in `AndroidKeyStore`.
  * Storage Key: Generates AES-256-GCM key (`TetherStorageKey_v2`) for local storage encryption.
  * Signing & Verification: Signs handshake nonces using `SHA256withECDSA`.
  * Biometric Authentication: Wraps AES-GCM cipher in `BiometricPrompt.CryptoObject` for biometric-gated workstation unlock.
* **`DeviceIntegrityRegistry.kt`**: Audits mobile device security status before allowing sensitive operations:
  * Detects root binaries (`/system/xbin/su`, `/system/app/Superuser.apk`).
  * Checks for `test-keys` build tags.
  * Verifies hardware biometric availability and developer settings state.
* **`RemoteInputEngine.kt`**: Captures multi-touch trackpad gestures, two-finger scrolling, left/right clicks, and modifier keys (`Ctrl`, `Alt`, `Shift`, `Win`), packing them into binary frames for immediate transmission to Windows.

---

## 6. Visual Design System & UX Standards

Tether implements platform-native, highly responsive visual design systems on both Windows and Android:

### Design Dials
* **ENERGY: 1 (Calm & Professional)**: Clean, purposeful security dashboard aesthetic without unnecessary visual clutter or distracting animations.
* **RHYTHM: 2 (Structured Platform-Native)**: Clear information hierarchy, structured card containers, and standard platform navigation models.
* **MOTION: 1 (Subtle & Purposeful)**: Micro-interactions and subtle transitions indicating connection status, trust level shifts, and active input streams.

### Windows Desktop Theme (`Fluent UI`)
* Dark theme styled via `Themes/FluentTheme.xaml` and `Themes/ControlStyles.xaml`.
* Custom controls for real-time IPC telemetry log streaming, system audio/brightness sliders, and service status toggles.

### Android Companion Theme (`Material 3`)
* Dark theme defined in `ui/theme/Color.kt`, `Theme.kt`, and `Type.kt`.
* Dynamic atmospheric background canvas (`AtmosphericCanvas.kt`) providing subtle visual feedback for device connection state.
