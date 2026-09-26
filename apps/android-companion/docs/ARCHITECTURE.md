# Tether Local Network Connection & Security Architecture

This document describes the KDE Connect-inspired local network architecture for Tether, hardened with TLS 1.3, hardware-backed Android KeyStore identity, Trust-On-First-Use (TOFU) pairing, post-quantum cryptography (PQC) integration, capability-based authorization, and strict protocol framing.

---

## 1. Overview & Security Philosophy

Tether operates as a direct peer-to-peer system on local area networks (LAN) without requiring central cloud servers, internet connectivity, or manual network reconfigurations (e.g., port forwarding or static IP setup).

> **Core Security Principle:** The local network is treated as completely untrusted and hostile.

Being on the same Wi-Fi network grants **zero trust**. All authentication and authorization rely on cryptographic asymmetric key identity, explicit human pairing approval, and TLS 1.3 transport security.

---

## 2. Discovery Layer

- **Service Type:** `_tether._tcp.local.`
- **Implementation:** Native Android `NsdManager` mDNS / DNS-SD.
- **Untrusted Discovery Metadata (TXT Records):**
  - `v`: Protocol version (`"1.0"`)
  - `id`: Long-lived device SHA-256 identity fingerprint
  - `name`: Display name (e.g., `Tether-Android-Pixel`)
  - `caps`: Capability string (`CLIPBOARD,FILES,NOTIFICATIONS,MEDIA,TERMINAL,POWER_ELEVATED`)
  - `pqc`: Hybrid post-quantum support indicator (`true`)

Discovery packets carry no secrets. An attacker observing or spoofing mDNS can at most advertise an endpoint; they cannot authenticate or obtain session control.

---

## 3. Secure Transport Layer

- **Protocol:** TLS 1.3 direct TCP connection on port `37123`.
- **Engine:** Android Conscrypt platform provider with Java `SSLContext` / `SSLSocketFactory`.
- **Cipher Suites:** Enforces TLS 1.3 cipher suites (`TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1805_SHA256`). Disables weak/obsolete TLS versions.
- **Properties:** End-to-end confidentiality, integrity, replay protection, and forward secrecy.

---

## 4. Post-Quantum Cryptography (PQC) Integration

Tether incorporates post-quantum cryptographic primitives available in Android 17 / modern platform security providers and BouncyCastle (`bcprov-jdk18on`):

1. **TLS Key Exchange (Hybrid Post-Quantum KEM):**
   - Utilizes `X25519MLKEM768` / `X25519Kyber768` hybrid post-quantum key exchange in platform TLS 1.3 where supported by Conscrypt / BoringSSL.
2. **Identity & Signature Layer:**
   - Asymmetric long-lived identity keys generated in hardware-backed `AndroidKeyStore` (`secp256r1` / `EC` / `Ed25519`).
   - Integrated with BouncyCastle provider for standard post-quantum signature verification (`ML-DSA-65` / Dilithium) and post-quantum key encapsulation (`ML-KEM-768`).

---

## 5. Device Identity & Key Storage

- **Device Identity:** Persistent non-exportable asymmetric key pair stored in `AndroidKeyStore`.
- **Self-Signed Certificates:** Automatically generated X.509 identity certificates for TLS mutual authentication.
- **Pinned Key Storage:** Pinned Windows host identity public keys are encrypted using a hardware-backed AES-256 GCM key in `AndroidKeyStore` and persisted in secure application storage.

---

## 6. Pairing & TOFU Trust Model

```
Android Phone                                              Windows Desktop UI
     │                                                             │
     │────────────── mDNS Local Discovery ────────────────────────►│
     │                                                             │
     │────────────── Direct TCP Connection ───────────────────────►│
     │                                                             │
     │◄───────────── TLS 1.3 Handshake ───────────────────────────►│
     │                                                             │
     │────────────── HANDSHAKE_INIT (Identity FP) ────────────────►│
     │                                                             │
     │                                                  [ Explicit Human Prompt ]
     │                                                  "Pair with Tirth's Phone?"
     │                                                             │
     │◄───────────── HANDSHAKE_RESPONSE (Status/FP) ───────────────│
     │                                                             │
[ Pin Windows Key ]                                       [ Pin Phone Key ]
     │                                                             │
     │◄───────────── Authenticated Session Ready ─────────────────►│
```

1. **First Connection (Unpaired):**
   - Phone connects to discovered Windows PC over TLS 1.3.
   - Phone sends `HANDSHAKE_INIT` containing its identity fingerprint and public key.
   - Windows Desktop UI displays an explicit user prompt showing the device fingerprint.
   - Upon user approval, both devices pin each other's public key fingerprint into secure storage.
2. **Subsequent Connections (Paired):**
   - Devices authenticate automatically by comparing presented TLS certificates against pinned fingerprints.
   - If a presented key does not match the pinned identity, the system **fails closed** immediately (`KEY_MISMATCH`).

---

## 7. Protocol Framing & State Machine

### Framing
Every frame consists of:
1. **Length Prefix:** 4-byte big-endian integer specifying payload size.
2. **Payload Limit:** Maximum allowed frame size is **1 MB** (`1024 * 1024` bytes) to prevent buffer overflow and memory exhaustion attacks.
3. **Payload:** UTF-8 encoded JSON string containing `type`, `requestId`, `timestamp`, and command parameters.

### Connection State Machine
```
DISCONNECTED ──► DISCOVERED ──► CONNECTING ──► TLS_HANDSHAKE
     ▲                                                │
     │                                                ▼
  CLOSING ◄── CONNECTED ◄── AUTHENTICATED ◄── AUTHENTICATING
                                  ▲                   │
                                  │                   ▼
                           [ PAIRED ]           PAIRING_REQUIRED
```

---

## 8. Capability-Based Authorization

To enforce least-privilege security, Tether mandates scope-based capability checks before executing commands:

| Capability Scope | Granted Actions / Commands | Risk Level |
| :--- | :--- | :--- |
| `MEDIA` | Volume adjustment, brightness, playback control | Low |
| `CLIPBOARD` | Read / write clipboard contents | Low |
| `FILES` | Direct file transfers, file browsing | Medium |
| `NOTIFICATIONS` | Notification mirror & dismissal | Medium |
| `TERMINAL` | Interactive CMD, PowerShell, WSL access | High |
| `POWER_ELEVATED` | Shutdown, Reboot, Sleep, System Halt | High / Critical |

Commands requiring `POWER_ELEVATED` or `TERMINAL` capabilities are denied unless explicitly authorized during capability negotiation.

---

## 9. Threat Model & Self-Review Summary

| Threat Scenario | Mitigation Strategy | Status |
| :--- | :--- | :--- |
| Malicious LAN participant / ARP / DNS spoofing | All communication is encrypted over TLS 1.3; authentication relies on public key fingerprints rather than IP/hostname. | **Mitigated** |
| Stolen IP or impersonated server | Server must prove possession of private key matching pinned identity fingerprint; mismatch causes immediate session rejection. | **Mitigated** |
| Pairing message replay | Nonces, timestamps, and TLS session keys prevent replay of pairing responses. | **Mitigated** |
| Oversized frame / DoS allocation attack | Strict 1 MB maximum length check before allocating buffer in stream parser. | **Mitigated** |
| Unauthorized privilege escalation | Commands strictly checked against `TetherCapabilityManager` authorization matrix prior to execution. | **Mitigated** |
