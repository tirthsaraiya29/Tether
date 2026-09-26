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
Mobile Hotspot      → NOT SUPPORTED
VPN / Port Forward  → NOT SUPPORTED
```

---

## Core Transport Requirements & Network Boundaries

### 1. Same Local Wi-Fi / LAN Requirement
- **Local Infrastructure Client**: Both the Android device and Windows host must be connected as Wi-Fi clients on the exact same local Wi-Fi / LAN infrastructure network.
- **Local Network Discovery**: Discovery occurs locally over the active Wi-Fi interface using Android Network Service Discovery (mDNS/NSD service type `_tether._tcp.`) and UDP broadcast scanning on port `37123`.
- **No Internet Dependency**: Communication is local-only. Internet access is not required and no third-party cloud servers or WebSocket relays are involved.
- **Unsupported Configurations**:
  - Android on cellular + Windows on Wi-Fi
  - Android on one Wi-Fi network + Windows on another Wi-Fi network
  - Android connected via mobile hotspot / tethering AP
  - Connections routed via public WAN, VPN, or port forwarding
  - Bluetooth command transport / Bluetooth fallback

### 2. Mobile Hotspot / Tethering Exclusion
- Tether Canary strictly **rejects Mobile Hotspot mode**. Operating the phone as a mobile Wi-Fi Access Point (AP) or tethering hotspot is explicitly classified as an unsupported configuration.
- The Android client checks network capabilities and Wi-Fi AP state. If Mobile Hotspot mode is detected, the transport transitions to `HOTSPOT_UNSUPPORTED` state and refuses socket establishment. Both devices must be clients on an established Wi-Fi infrastructure network.

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
