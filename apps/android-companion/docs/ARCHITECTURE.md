# Tether Local Network Connection & Security Architecture

This document describes the peer-to-peer local network architecture for Tether across Windows and Android, hardened with TLS 1.3, hardware-backed AndroidKeyStore / Windows Certificate Store identity, Out-of-Band Short Authentication String (SAS) 6-digit PIN commitment pairing, persistent logical device management, capability-based authorization, and strict protocol framing.

---

## 1. Overview & Security Philosophy

Tether operates as a direct peer-to-peer system on local area networks (LAN) without requiring central cloud servers, internet connectivity, or manual network reconfigurations (e.g., port forwarding or static IP setup).

> **Core Security Principle:** The local network is treated as completely untrusted and hostile.

Being on the same Wi-Fi network grants **zero trust**. All authentication and authorization rely on cryptographic asymmetric key identity, explicit human 6-digit PIN authorization, and TLS 1.3 transport security.

---

## 2. Discovery Layer

- **Service Type:** `_tether._tcp.local.`
- **Implementation:** Native Android `NsdManager` and Windows `Makaretu.Dns` mDNS / DNS-SD.
- **Untrusted Discovery Metadata (TXT Records):**
  - `v`: Protocol version (`"2.0"`)
  - `id`: Long-lived device SHA-256 identity fingerprint
  - `name`: Display name (e.g., `Tether-Android-Pixel`)
  - `caps`: Capability string (`CLIPBOARD,FILES,NOTIFICATIONS,MEDIA,TERMINAL,POWER_ELEVATED`)

Discovery packets carry no secrets. An attacker observing or spoofing mDNS can at most advertise an endpoint; they cannot authenticate or obtain session control.

---

## 3. Secure Transport Layer

- **Protocol:** TLS 1.3 direct TCP connection on port `37123`.
- **Windows Engine:** .NET 8 `SslStream` backed by Windows Schannel / CNG.
- **Android Engine:** Android platform `SSLSocket` / Conscrypt.
- **Cipher Suites:** Enforces TLS 1.3 cipher suites (`TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1805_SHA256`). Disables weak/obsolete TLS versions.
- **Properties:** End-to-end confidentiality, integrity, replay protection, and forward secrecy.

---

## 4. Device Identity & Persistent Trust Storage

- **Windows Identity:** Self-signed ECDSA P-256 X.509 certificate stored in `LocalMachine\My` certificate store. Private key is machine-bound and non-exportable.
- **Windows Trust Store:** `C:\ProgramData\Tether\trust.json` protected by NTFS Access Control Lists (ACLs) restricted to `NT AUTHORITY\SYSTEM` and `BUILTIN\Administrators`.
- **Android Identity:** Hardware-backed EC key pair (`secp256r1`) generated in `AndroidKeyStore` (`TetherIdentityKey_v1`).
- **Android Pinned Keys:** Pinned host keys encrypted using hardware AES-256 GCM key (`TetherStorageKey_v2`) in `AndroidKeyStore` and saved in application SharedPreferences.

---

## 5. Persistent Device vs Ephemeral Session Model

Tether cleanly separates persistent device identity from ephemeral network sockets:

- **`TetherDevice`**: Represents a logical peer (`DeviceId`, `DisplayName`, `TrustState`, `Capabilities`, `OnlineState`, `LastSeenUtc`, `CurrentSession`).
  - Restored from `TrustStore` on Windows service startup.
  - Survives Wi-Fi loss and system restarts.
- **`TetherSession`**: Represents a single active TCP/TLS 1.3 connection.
  - Handles frame reader/writer, `PING`/`PONG` keepalives, and packet routing.
  - Sockets dropping set `OnlineState = Disconnected` and `CurrentSession = null` on `TetherDevice` without losing device trust or requiring re-pairing.

---

## 6. Out-of-Band 6-Digit PIN SAS Pairing Protocol

To prevent Man-In-The-Middle (MITM) attacks during initial connection without sending plaintext secrets over the network, Tether utilizes a **SHA-512 Out-of-Band SAS Commitment Scheme**:

```
Phone (Android)                                          Windows Service (CommunicationService)
      │                                                                │
      │──────────────────── 1. HANDSHAKE_INIT ────────────────────────►│  (isPairingRequested = true,
      │                                                                │   contains PK_Phone)
      │                                                                │
      │                                                   [ PairingManager ]
      │                                                   - Generates random 6-Digit PIN (e.g. "482910")
      │                                                   - Calculates Commitment_Win = SHA-512(PIN || PK_Win || PK_Phone || ReqId)
      │                                                   - Publishes PAIRING_REQUESTED via IPC
      │                                                                │
      │                                                                ├─── IPC: PAIRING_REQUESTED ──► [ Desktop UI ]
      │                                                                │                                Displays PIN: "482910"
      │                                                                │
      │◄─────────────────── 2. HANDSHAKE_RESPONSE ─────────────────────│  (status = "PAIRING_PENDING",
      │                                                                │   requestId, commitment, PK_Win)
      │                                                                │   *NOTE: Raw PIN is NOT sent!*
[ User Prompts PIN ]                                                   │
  "Enter PIN on PC"                                                    │
  (User types: "482910")                                              │
      │                                                                │
  [ Proof Calculation ]                                                │
  Proof_Phone = SHA-512("482910" || PK_Phone || PK_Win || ReqId)        │
      │                                                                │
      │──────────────────── 3. PAIRING_CONFIRMED ─────────────────────►│
      │                      (requestId, proof = Proof_Phone)          │
      │                                                                │
      │                                                   [ PairingManager Verification ]
      │                                                   - FixedTimeEquals(Expected, Proof_Phone)
      │                                                   - Max 3 failed attempts before request invalidation
      │                                                   - On success: Promotes device to PAIRED in TrustStore
      │                                                                │
      │◄─────────────────── 4. PAIRING_COMPLETE ───────────────────────│
      │                      (status = "OK", proof = Proof_Win)        │
      │                                                                │
[ Verify Proof_Win ]                                                   │
[ Store PK_Win in AndroidKeyStore ]                                    │
      │                                                                │
      │◄─────────────────── Authenticated Session Active ─────────────►│ (Commands, Keepalives)
```

---

## 7. Protocol Framing & Keepalive Policy

### Framing
Every frame consists of:
1. **Length Prefix:** 4-byte big-endian integer specifying payload size.
2. **Payload Limit:** Maximum allowed frame size is **1 MB** (`1024 * 1024` bytes) to prevent buffer overflow and memory exhaustion attacks.
3. **Payload:** UTF-8 encoded JSON string containing `type`, `requestId`, `timestamp`, and command parameters.

### Heartbeat & Keepalive Policy
- **Zero Idle Disconnections**: Healthy connections remain open indefinitely.
- **Application Keepalive**: If no frame is received for 30 seconds, `PING` (`{"type":"PING"}`) is sent.
- **Dead Connection Detection**: If no `PONG` or frame is received within 15 seconds after `PING` (45s total silence), session is terminated.
- **TCP Socket Options**: Enabled with `TcpKeepAliveTime = 15s`, `TcpKeepAliveInterval = 5s`, `TcpKeepAliveRetryCount = 3`, and `NoDelay = true`.

---

## 8. Capability-Based Authorization

Commands are authorized against granted capabilities prior to execution:

| Capability Scope | Granted Actions / Commands | Risk Level |
| :--- | :--- | :--- |
| `MEDIA` | Volume adjustment, brightness, playback control | Low |
| `CLIPBOARD` | Read / write clipboard contents | Low |
| `FILES` | Direct file transfers, file browsing | Medium |
| `NOTIFICATIONS` | Notification mirror & dismissal | Medium |
| `TERMINAL` | Interactive CMD, PowerShell, WSL access | High |
| `POWER_ELEVATED` | Shutdown, Reboot, Sleep, System Halt | High / Critical |

---

## 9. Threat Model Summary

| Threat Scenario | Mitigation Strategy |
| :--- | :--- |
| **Passive Wi-Fi Eavesdropping** | Encrypted over TLS 1.3. Eavesdroppers see zero plaintext data or secrets. |
| **Active MITM Proxy Attack** | Proofs incorporate public keys ($PK_{Phone}$ / $PK_{Win}$). Verification fails if MITM proxies TLS. |
| **Offline PIN Brute-Force** | Raw PIN is never sent. Commitment and proof hashes cannot be reversed without pre-image SHA-512 attack. |
| **Online PIN Guessing** | Windows limits failed attempts to 3 per request ID. Exceeding 3 invalidates pairing request and closes socket. |
| **Key Swap / Impersonation** | Post-pairing key changes trigger `KEY_MISMATCH` alert and immediate fail-closed connection termination. |
