# Tether Linux Login & Greeter Experience

## Overview
The Tether Linux Login and Greeter subsystem provides a visual authentication tile comparable in functionality and responsiveness to the Windows Credential Provider tile.

It informs the user of phone connectivity, displays paired device status, offers a one-click daemon restart mechanism, and seamlessly hands authentication to native Linux password entry (`pam_unix.so`).

---

## Architectural Comparison

| Capability | Windows Credential Provider | Linux Greeter & PAM Architecture |
| :--- | :--- | :--- |
| **UI Integration** | In-process Winlogon COM Tile | Libadwaita / GTK4 Greeter Helper (`tether-greeter`) + Display Manager Integration |
| **Phone Connectivity** | Live service status query via RPC | Live Unix Domain Socket IPC (`/run/tether/auth.sock`) |
| **Authentication Flow** | Async Kerberos / NTLM credential submission | PAM module (`pam_tether.so`) consuming one-time unlock grant |
| **Daemon Restart** | Service control manager restart | Secure IPC restart request (`RESTART_REQUEST`) on `/run/tether/auth.sock` |
| **Native Fallback** | "Sign-in options" tile switch | Seamless `PAM_AUTHINFO_UNAVAIL` return falling through to `pam_unix.so` |

---

## Components

### 1. The Greeter Tile (`tether-greeter`)
Located at `tools/tether-greeter/tether-greeter`, the visual tile is written in Python using PyGObject with Libadwaita and GTK4, with an automated fallback to formatted ANSI console output if no X11 or Wayland display is active.

#### Command-Line Options
```bash
# Check connectivity and print daemon/phone status
tether-greeter --status

# Arm a workstation unlock grant for testing
tether-greeter --unlock

# Request background daemon restart
tether-greeter --restart

# Launch visual windowed greeter tile
tether-greeter
```

### 2. Live Status & Connectivity Detection
The greeter communicates with the daemon over `/run/tether/auth.sock` via a lightweight JSON protocol:

**Request:**
```json
{ "action": "STATUS_QUERY" }
```

**Response:**
```json
{
  "status": "RUNNING",
  "activeSessions": 1,
  "pairedDevicesCount": 1,
  "phoneConnected": true,
  "phoneName": "Tether Pixel 9 Pro",
  "unlockArmed": false,
  "armRemainingSeconds": 0
}
```

### 3. Safe Service Restart IPC
When the user clicks "Restart Tether Daemon" or runs `tetherctl restart`:
1. A JSON packet `{"action": "RESTART_REQUEST"}` is sent over `/run/tether/auth.sock`.
2. The daemon checks `SO_PEERCRED` to verify that the request comes from root or the active console session user.
3. The daemon responds with `{"status": "RESTARTING"}` and asynchronously signals systemd (`systemctl restart tether.service`) or re-executes itself.
4. No privilege escalation or sudo password prompt is required for the authorized desktop user.

### 4. Seamless Native Password Fallback
When a user is at the login screen (GDM, SDDM, or LightDM):
1. The display manager PAM stack invokes `pam_tether.so` as `auth sufficient`.
2. `pam_tether.so` queries `/run/tether/auth.sock`.
3. If the user unlocked their workstation via the phone app within the 30-second window, the daemon returns `SUCCESS`, and the desktop opens immediately without a password prompt.
4. If no phone unlock was triggered, the daemon returns `NO_GRANT`.
5. `pam_tether.so` translates `NO_GRANT` into `PAM_AUTHINFO_UNAVAIL`.
6. PAM immediately invokes the next module (`gdm-password-auth-substack` / `pam_unix.so`), presenting the normal user password prompt without showing any error or failure indicators.
