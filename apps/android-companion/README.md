# Tether Companion App (Canary Branch - Wi-Fi/LAN Transport)

> Tether's **Wi-Fi/LAN-only transport branch** for Android companion and Windows host communication.

## Transport Architecture Overview

The `canary` branch of Tether implements a strict **Wi-Fi/LAN-only transport architecture** for all command, control, state synchronization, and panic lockdown operations between the Android companion app and the Windows Tether service.

```
Android Tether App
│
│ Local Wi-Fi / LAN (AES-256-GCM Encrypted TCP Socket)
▼
Tether Windows Service (Port 37123)
│
▼
Windows APIs / SYSTEM operations

BLE                 → NOT USED FOR COMMAND TRANSPORT
Internet            → NOT REQUIRED
Cloud Relay         → NOT USED
Mobile Hotspot      → SUPPORTED (Transparent SoftAP)
VPN / Port Forward  → NOT SUPPORTED
```

---

## Core Transport Requirements & Network Boundaries

### 1. Supported Network Topologies
- **Same Local Wi-Fi / LAN Infrastructure**: Both the Android device and Windows workstation connected as clients to the same Wi-Fi router or wired local subnet.
- **Android Mobile Hotspot (Direct SoftAP)**: The Android phone acts as the Wi-Fi hotspot access point and the Windows workstation connects directly to that hotspot. Tether discovers and establishes mutual TLS 1.3 connectivity transparently with zero user configuration.
- **Local Network Discovery**: Discovery occurs over local interfaces using Android Network Service Discovery (mDNS `_tether._tcp.`) and UDP broadcast/unicast discovery on port `37124` (including gateway and candidate client unicast probing for hotspot environments where multicast/broadcast is restricted).
- **No Internet Dependency**: Communication is local-only. Internet access is not required, and no third-party cloud servers, external telemetry beacons, or relay services are ever contacted.
- **Unsupported Configurations**:
  - Android on cellular while Windows is on an unrelated Wi-Fi network
  - Android and Windows on separate, non-routed physical subnets
  - Connections routed via public WAN, VPN, or port forwarding
  - Bluetooth command transport / Bluetooth fallback

### 2. Mobile Hotspot Architecture & Gateway Discovery
- Tether provides transparent, production-grade Android Hotspot support. When the Android phone enables mobile hotspot and the Windows laptop joins it, Windows resolves the default gateway (which is the Android phone) and sends discovery announcements directly to the gateway on UDP port `37124`.
- The Android client dynamically monitors Wi-Fi client and AP/tether interface states using standard broadcast intents (`WIFI_AP_STATE_CHANGED`, `TETHER_STATE_CHANGED`) and standard `NetworkInterface` inspection (no hidden API reflection), resolves local subnets, probes candidate DHCP client addresses bounded by actual subnet masks (/16, /24, /28, /30), and receives gateway discovery packets.
- Network isolation strictly excludes cellular (`rmnet*`, `ccmni*`), VPN (`tun*`, `tap*`, `ppp*`), virtual adapters, and CGNAT space (`100.64.0.0/10`).
- Inbound UDP discovery strictly validates payload length (10 to 1024 bytes), source IPs (RFC 1918 private IPv4 only), device fingerprints (`^[a-zA-Z0-9_\-\.:]{1,128}$`), TCP ports (1024..65535), and enforces per-IP rate limiting (5 probes/sec). Probes only trigger rate-limited datagram responses and never spawn unsolicited outbound TCP connections or misleading pairing prompts.
- All communications remain strictly authenticated via hardware-backed ECDSA P-256 keys and encrypted over mutual TLS 1.3. Joining the phone's hotspot never confers automatic trust.

---

## Security Architecture & Session Cryptography

1. **Same Wi-Fi is Location, Not Trust**: Being on the same LAN does NOT confer trust. All TCP command communication is cryptographically authenticated and encrypted.
2. **Mutual RSA Authentication**:
   - Phone and Windows host exchange public keys and 32-byte cryptographically secure random nonces (`phoneNonce` and `windowsNonce`).
   - The Windows host returns an AES-256 session key encrypted with the Phone's hardware-backed RSA public key (`TetherAsymmetricKey_v3` from Android KeyStore) along with an RSA signature over the nonces.
   - Phone verifies the signature using the pinned Windows public key stored in hardware AES storage (`TetherStorageKey_v1`).
3. **AES-256-GCM Encrypted Frame Transport**:
   - All subsequent command frames (`lock_now`, `unlock`, `panic`, `sleep`, `reboot`, `shutdown`, state sync) are encrypted using AES-256-GCM with unique 12-byte IVs.
4. **Replay & Stale Session Protection**:
   - Every command payload contains a unique UUID `requestId`, timestamp, and nonce.
   - Recent request IDs are tracked to reject replayed packets.
   - Stale sessions are immediately invalidated upon network state change, IP change, process restart, or disconnect.

---

## Network Change & Reconnection Behavior

- **Dynamic Network Callback**: `ConnectivityManager.NetworkCallback` monitors Wi-Fi availability and capabilities in real time.
- **Instant Invalidation**: When Wi-Fi disconnects or changes, active TCP sockets are immediately closed and session keys are wiped.
- **Auto-Discovery & Recovery**: When a valid infrastructure Wi-Fi connection is restored, `TetherLanService` automatically resumes NSD discovery and UDP broadcast scan to locate the Windows Tether service and re-establish a secure session.

---

## Supported Directives & Semantics

- `lock_now`: Request instant workstation lock.
- `unlock`: Execute secure unlock after biometric validation.
- `panic`: Execute emergency lockdown and trust revocation.
- `sleep` / `reboot` / `shutdown`: Host power directives (with confirmation prompt).
- `screen_unlock`: Automatic state sync when phone screen unlocks.
- Hardware state sync: Live volume level and brightness level updates.

---

## Known Limitations

- **Windows Service Alignment**: The Windows host service (`Tether.CommunicationService`) must be running the matching LAN socket listener on port `37123` advertising `_tether._tcp.`.
- **Subnet Comparison Non-Certainty**: Network reachability and local mDNS/UDP discovery verify the LAN relationship; client-side IP subnet mask matching alone is not treated as absolute proof of physical L2 identity. Cryptographic host key verification enforces authentic endpoint identity.
