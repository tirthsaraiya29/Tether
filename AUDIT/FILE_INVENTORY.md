# TETHER CODEBASE INVENTORY

**Audit Date:** 2026-11-23  
**Total Tracked Files:** 371  
**Detailed Matrix:** See [`AUDIT/FILE_REVIEW_MATRIX.csv`](file:///home/tether/Tether/AUDIT/FILE_REVIEW_MATRIX.csv)

---

## 1. Classification Breakdown

| Component Group | Tracked File Count | Primary Languages | Security Relevance |
| :--- | :--- | :--- | :--- |
| **Linux Daemon & Services** (`Tether.LinuxDaemon`, `tetherctl`) | 38 | C# (.NET 10) | **CRITICAL** (Root service, PAM, IPC, Auth) |
| **Linux PAM Native Module** (`pam-tether`) | 4 | C, Makefile | **CRITICAL** (Login auth stack, SO_PEERCRED) |
| **Linux Deployment & Hardening** (`installer/linux`) | 7 | Bash, systemd, SELinux TE | **HIGH** (System privileges, PAM files) |
| **Linux Tests** (`Tether.LinuxTests`) | 14 | C# (xUnit) | **MEDIUM** (Security and unit verification) |
| **Shared Protocol & Primitives** (`Tether.Shared`) | 24 | C# (.NET 10) | **HIGH** (Crypto, models, serialization) |
| **Core Engines** (`Trust`, `Enforcement`, `Panic`, `Recovery`, `EventBus`) | 46 | C# (.NET 10) | **HIGH** (Attestation, panic locks, events) |
| **Android Companion App** (`apps/android-companion`) | 125 | Kotlin, Compose, Gradle | **HIGH** (TLS 1.3, pairing, biometric UI) |
| **Windows Services & CP** (`CommunicationService`, `SessionHelper`, `CP`) | 62 | C#, C++ COM | **HIGH** (Reference implementation) |
| **Desktop UI & Updater** (`apps/desktop-ui`, `apps/updater`) | 32 | C# (WPF, XAML) | **MEDIUM** |
| **Documentation & Project Infrastructure** | 19 | Markdown, Git, Slime | **LOW** |

---

## 2. Key Linux Implementation Paths Audited

### A. Authentication & Host Security
- [`services/pam-tether/pam_tether.c`](file:///home/tether/Tether/services/pam-tether/pam_tether.c): Native C PAM module (`pam_sm_authenticate`).
- [`services/communication-service/Tether.LinuxDaemon/Security/LinuxPamAuthServer.cs`](file:///home/tether/Tether/services/communication-service/Tether.LinuxDaemon/Security/LinuxPamAuthServer.cs): Domain socket listener `/run/tether/pam.sock`.
- [`services/communication-service/Tether.LinuxDaemon/Trust/LinuxTrustStore.cs`](file:///home/tether/Tether/services/communication-service/Tether.LinuxDaemon/Trust/LinuxTrustStore.cs): HKDF master key derivation, AES-256-GCM encryption, fingerprint verification.

### B. Networking, Pairing & Protocol Dispatch
- [`services/communication-service/Tether.LinuxDaemon/Transport/LinuxTcpServer.cs`](file:///home/tether/Tether/services/communication-service/Tether.LinuxDaemon/Transport/LinuxTcpServer.cs): TLS 1.3 listener on port 51443 with self-signed SPKI certificate.
- [`services/communication-service/Tether.LinuxDaemon/Pairing/LinuxPairingManager.cs`](file:///home/tether/Tether/services/communication-service/Tether.LinuxDaemon/Pairing/LinuxPairingManager.cs): 6-digit PIN SAS pairing, cryptographic handshake.
- [`services/communication-service/Tether.LinuxDaemon/Protocol/LinuxPacketRouter.cs`](file:///home/tether/Tether/services/communication-service/Tether.LinuxDaemon/Protocol/LinuxPacketRouter.cs): Command routing, rate limiting, capability enforcement (`LOCK`, `POWER_ELEVATED`, `INPUT`, `FILES`, `TERMINAL`).

### C. File Transfer & Remote Desktop
- [`services/communication-service/Tether.LinuxDaemon/FileTransfer/LinuxFileTransferServer.cs`](file:///home/tether/Tether/services/communication-service/Tether.LinuxDaemon/FileTransfer/LinuxFileTransferServer.cs): Kestrel HTTPS listener on port 51444.
- [`services/communication-service/Tether.LinuxDaemon/FileTransfer/LinuxTokenStore.cs`](file:///home/tether/Tether/services/communication-service/Tether.LinuxDaemon/FileTransfer/LinuxTokenStore.cs): Ephemeral bearer token management.

### D. System Interaction & Capabilities
- [`services/communication-service/Tether.LinuxDaemon/Input/LinuxUinputInjector.cs`](file:///home/tether/Tether/services/communication-service/Tether.LinuxDaemon/Input/LinuxUinputInjector.cs): `/dev/uinput` mouse and keyboard event synthesis.
- [`services/communication-service/Tether.LinuxDaemon/Terminal/LinuxTerminalManager.cs`](file:///home/tether/Tether/services/communication-service/Tether.LinuxDaemon/Terminal/LinuxTerminalManager.cs): POSIX PTY allocation (`openpty`, `fork`, `execve`).
- [`services/communication-service/Tether.LinuxDaemon/Capabilities/LinuxHardwareExecutor.cs`](file:///home/tether/Tether/services/communication-service/Tether.LinuxDaemon/Capabilities/LinuxHardwareExecutor.cs): Volume, brightness, system suspend/lock/shutdown.
- [`services/communication-service/Tether.LinuxDaemon/Capabilities/LinuxLaptopStateCollector.cs`](file:///home/tether/Tether/services/communication-service/Tether.LinuxDaemon/Capabilities/LinuxLaptopStateCollector.cs): `/sys/class/power_supply` battery and power state reader.
