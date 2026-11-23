# TETHER LINUX THREAT MODEL & STRIDE ANALYSIS

**Audit Date:** 2026-11-23  
**Auditor:** Principal Security & Systems Engineer  
**Methodology:** STRIDE Model, Least Privilege Principles, Privilege Separation Analysis  

---

## 1. System Assets & Sensitivity

1. **System Authentication Authority:** The ability to authenticate local user sessions, grant workstation unlock, or elevate permissions.
2. **Device Cryptographic Keys & Trust Store:**
   - Linux Host EC P-256 private key (`identity.pfx` / in-memory).
   - Linux Trust Store Master Key (`trust.key`, mode `0600`).
   - Paired phone SPKI public keys and fingerprints (`trust.json`, mode `0600`, AES-256-GCM encrypted).
3. **Session Data & Streams:**
   - Video frames of the active desktop (confidentiality: HIGH).
   - Terminal input/output streams (confidentiality & integrity: CRITICAL).
   - Filesystem contents within user home directories.
4. **Kernel Input Injection Subsystem:**
   - Synthetic mouse/keyboard event injection via `/dev/uinput` (integrity: CRITICAL).
5. **PAM Authentication IPC Channel:**
   - UNIX domain socket `/run/tether/auth.sock`.

---

## 2. Threat Actors & Capabilities

- **Remote LAN Attacker:** Located on the same Wi-Fi / LAN network. Can capture or inject packets, attempt rogue TLS handshakes, attempt brute-forcing PINs, or spoof discovery.
- **Local Unprivileged User:** A local user account on the same Linux host (e.g. guest or student account). Attempts to escalate privileges to root or impersonate other users via Tether's IPC or daemon endpoints.
- **Malicious / Compromised Companion Phone:** A paired or previously paired Android device attempting unauthorized actions (e.g. attempting desktop streaming without capability, replay attacks).
- **Physical Attacker with Laptop Access:** Attempts to unlock the workstation without the paired phone or exploit greeter vulnerabilities.

---

## 3. STRIDE Analysis & Control Evaluation

| STRIDE Category | Threat Description | Existing Control | Residual Risk / Flaw | Planned Remediation |
| :--- | :--- | :--- | :--- | :--- |
| **Spoofing** | Rogue device claims to be paired phone. | SPKI public key pinning & ECDSA proof-of-possession. | None on TLS control channel; HTTP file transfer missing client-proof verification (`TETH-SEC-LNX-003`). | Implement signed client-proof verification in `LinuxFileTransferServer`. |
| **Tampering** | Local user alters `trust.json` to inject untrusted public key. | AES-256-GCM encryption with HKDF-derived key; SHA-256 fingerprint verification on load. | Low. Master key stored in `0600` root file. | Maintain strict filesystem permissions (`0600` on `/var/lib/tether/trust.key`). |
| **Repudiation** | Client claims action was not performed. | Structured logging of commands and pairing events. | Diagnostic logs must avoid secret leakage (PINs). | Ensure pairing PINs are excluded from persistent system logs. |
| **Information Disclosure** | Desktop screen scraped by unauthorized process. | Token authentication with capability check (`FILES` / `DESKTOP`). | Desktop capture not yet implemented on Linux. | Ensure desktop streaming requires authenticated token with `DESKTOP` capability. |
| **Denial of Service** | Process flooding PAM socket or TLS control port. | 5000ms socket timeouts, rate limits (500 events/sec), 16 listener backlog. | Medium. | Enforce per-client connection limits and strict request size caps (4 KB). |
| **Elevation of Privilege** | Attacker consumes unlock grant via `ssh` or `sudo`. | `LinuxPamAuthServer` verifies `SO_PEERCRED`. | **CRITICAL:** `LinuxPamAuthServer` ignores `service` attribute (`TETH-SEC-LNX-001`). | Restrict PAM grant consumption strictly to authorized display managers and screen lockers. |

---

## 4. Privilege Boundary & Sandboxing Architecture

### Current Daemon Architecture
`tether.service` runs as `root` with `SupplementaryGroups=tether`.
- **Justification for Root Privileges:**
  1. Opening `/run/tether/auth.sock` accessible by display manager (`gdm` or `root`).
  2. Spawning user terminal sessions with `runuser -u <user>`.
  3. Reading system power state (`/sys/class/power_supply`) and invoking `loginctl lock-session`.
- **Systemd Sandboxing Hardening:**
  - `ProtectSystem=full`
  - `PrivateTmp=true`
  - `ProtectKernelTunables=true`
  - `ProtectKernelModules=true`
  - `ProtectControlGroups=true`
  - `DeviceAllow=/dev/uinput rw`
  - `DeviceAllow=char-input rw`
  - `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK`
