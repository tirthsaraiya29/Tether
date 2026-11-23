# Tether Linux Login & Greeter Experience

## Overview
The Tether Linux Login and Greeter subsystem provides secure mobile phone authentication for Linux workstations across modern display managers (GDM, SDDM, LightDM) and desktop screen lockers.

It informs the user of phone connectivity, displays paired device status, enables initiating mobile unlock challenges, offers authorized service restart, and seamlessly hands authentication to native Linux password entry (`pam_unix.so`).

---

## Architectural Comparison

| Capability | Windows Credential Provider | Linux Greeter & PAM Architecture |
| :--- | :--- | :--- |
| **UI Integration** | In-process Winlogon COM Tile | Native PAM integration (`pam_tether.so`) + Standalone GTK4/Adwaita Status Tile (`tether-greeter`) |
| **Phone Connectivity** | Live service status query via RPC | Live Unix Domain Socket IPC (`/run/tether/auth.sock`) |
| **Authentication Flow** | Async Kerberos / NTLM credential submission | PAM module (`pam_tether.so`) consuming one-time unlock grant armed by verified phone TLS |
| **Daemon Restart** | Service control manager restart | Secure IPC restart request (`RESTART_REQUEST`) authorized via `SO_PEERCRED` |
| **Native Fallback** | "Sign-in options" tile switch | Seamless `PAM_AUTHINFO_UNAVAIL` return falling through to native password prompt (`pam_unix.so`) |

> [!NOTE]
> Unlike Windows, which supports in-process COM authentication tiles in LogonUI, Linux display managers (especially GNOME GDM / Mutter) do not provide public APIs for third-party in-process login tiles. Tether integrates directly into the standard PAM stack for seamless password-free login upon mobile approval, accompanied by `tether-greeter` for optional visual connectivity status.

---

## Components

### 1. The Greeter Helper (`tether-greeter`)
Located at `tools/tether-greeter/tether-greeter`, the visual helper is written in Python using PyGObject with Libadwaita and GTK4, with an automated fallback to formatted ANSI console output if no graphical display is active.

#### Command-Line Options
```bash
# Check connectivity and print daemon/phone status
tether-greeter --status

# Request unlock authorization challenge to connected phone
tether-greeter --unlock

# Request background daemon restart
tether-greeter --restart

# Launch visual windowed greeter tile
tether-greeter
```

### 2. Live Status & Connectivity Detection
The greeter communicates with the daemon over `/run/tether/auth.sock` via a structured JSON protocol:

**Request:**
```json
{
  "action": "STATUS_REQUEST",
  "user": "alice"
}
```

**Response:**
```json
{
  "status": "ONLINE",
  "version": "2.0-production",
  "daemonRunning": true,
  "phoneConnected": true,
  "connectedDeviceName": "Pixel 9 Pro",
  "connectedDeviceFingerprint": "A1:B2:C3:D4:...",
  "grantActive": false,
  "grantRemainingSeconds": 0,
  "authPromptPending": false,
  "activeUser": "alice",
  "displayServer": "Wayland",
  "timestamp": 1700000000000
}
```

### 3. Requesting Phone Authentication (`REQUEST_PHONE_AUTH`)
When the user clicks "Send Unlock Prompt" or executes `tetherctl unlock`:
1. The client sends `{"action": "REQUEST_PHONE_AUTH", "user": "alice"}`.
2. The daemon validates via `SO_PEERCRED` that the caller UID is root (display manager) or matches the target user's UID.
3. If a paired phone is connected, the daemon sends an unlock challenge packet to the phone over the encrypted TLS channel and marks the prompt pending.
4. When the user approves on their mobile device (via biometric or PIN), the phone delivers a cryptographically-proven `unlock` command over TLS.
5. The daemon arms a single-use, 20-second unlock grant bound to that user and device fingerprint.

> [!IMPORTANT]
> Local IPC callers CANNOT manufacture unlock grants (`ARM_GRANT`). Grants are created exclusively through cryptographically verified mobile authentication over TLS.

### 4. Safe Service Restart IPC (`RESTART_REQUEST`)
When the user clicks "Restart Tether Daemon" or runs `tetherctl restart`:
1. A JSON packet `{"action": "RESTART_REQUEST"}` is sent over `/run/tether/auth.sock`.
2. The daemon checks `SO_PEERCRED` to verify that the caller is root (UID 0), a member of the `tether` group, or the active console session user.
3. The daemon responds with `{"status": "RESTARTING"}` and executes a bounded service restart (`systemctl restart tether.service`).
4. Unauthorized local callers are rejected with `UNAUTHORIZED`.

### 5. Seamless Native Password Fallback
When a user is at the login screen (GDM, SDDM, or LightDM):
1. The display manager PAM stack invokes `pam_tether.so` as `auth sufficient`.
2. `pam_tether.so` queries `/run/tether/auth.sock`.
3. If an active, unexpired grant exists for that user from an authenticated phone, the daemon returns `SUCCESS`, consuming the grant, and the desktop session opens immediately.
4. If no phone unlock was triggered, the daemon returns `NO_GRANT`.
5. `pam_tether.so` translates `NO_GRANT` into `PAM_AUTHINFO_UNAVAIL`.
6. PAM immediately invokes the next module (`gdm-password-auth-substack` / `pam_unix.so`), presenting the normal user password prompt without showing any error or failure indicators.
