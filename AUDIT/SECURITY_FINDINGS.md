# TETHER FORENSIC SECURITY AUDIT FINDINGS

**Audit Date:** 2026-11-23  
**Auditor:** Principal Security & Systems Engineer  
**Scope:** Full codebase audit (Linux Daemon, PAM Native Module, Installer/Uninstaller scripts, Android Companion, Shared protocols, Windows parity reference).

---

## Executive Summary

| Finding ID | Severity | CWE | Title | Status |
| :--- | :--- | :--- | :--- | :--- |
| **`TETH-SEC-LNX-001`** | **CRITICAL** | CWE-285 | PAM Service Name Unchecked in `LinuxPamAuthServer` | **OPEN (P0)** |
| **`TETH-SEC-LNX-002`** | **HIGH** | CWE-703 | `SO_PEERCRED` Failure Fails Open in `pam_tether.c` | **OPEN (P0)** |
| **`TETH-SEC-LNX-003`** | **HIGH** | CWE-345 | HTTPS Server Missing Cryptographic Client-Proof & Timestamp Validation | **OPEN (P0)** |
| **`TETH-SEC-LNX-004`** | **CRITICAL** | CWE-755 | Uninstaller Deletes PAM Module Without Restoring PAM Configuration | **OPEN (P0)** |
| **`TETH-SEC-LNX-005`** | **MEDIUM** | CWE-379 | Installer Modifies PAM Files Without Backups or Multi-DM Support | **OPEN (P4)** |
| **`TETH-SEC-LNX-006`** | **MEDIUM** | CWE-377 | Blind Socket Deletion and Symlink Race Protection in `LinuxPamAuthServer` | **OPEN (P0)** |
| **`TETH-SEC-LNX-007`** | **HIGH** | CWE-440 | Missing Desktop Streaming Pipeline Endpoints in `LinuxFileTransferServer` | **OPEN (P2)** |

---

## Detailed Vulnerability Reports

### Finding TETH-SEC-LNX-001: PAM Service Name Unchecked in `LinuxPamAuthServer`
- **Severity:** CRITICAL
- **CWE Identifier:** CWE-285 (Improper Authorization) / CWE-287 (Improper Authentication)
- **Affected OS:** Linux
- **File & Line Range:** [`services/communication-service/Tether.LinuxDaemon/Security/LinuxPamAuthServer.cs:223-251`](file:///home/tether/Tether/services/communication-service/Tether.LinuxDaemon/Security/LinuxPamAuthServer.cs#L223-L251)
- **Vulnerable Execution Path:**
  1. Phone sends `unlock` command to daemon -> `LinuxPamAuthServer.ArmUnlockGrant(targetUser, deviceFp, 15)`.
  2. While the grant is active (15-second window), an SSH session (`sshd`), `sudo`, `su`, or screen locker triggers PAM authentication.
  3. If `pam_tether.so` is loaded (e.g. in `/etc/pam.d/system-auth` or `/etc/pam.d/password-auth`), `pam_tether` sends:
     `{"action":"AUTH_REQUEST","user":"<user>","service":"sshd"}`.
  4. `LinuxPamAuthServer.HandlePamClientAsync` extracts `targetUser` and calls `ConsumeGrant(targetUser)` without checking the `service` property!
  5. The server returns `{"status":"SUCCESS"}`.
- **Attacker Prerequisites:** Workstation unlock grant armed by phone; network access to SSH or local access to `sudo`.
- **Realistic Impact:** Privilege escalation or unauthorized remote access (SSH login) using a token intended strictly for physical desktop unlock.
- **Reproduction / Proof:**
  Send `{"action":"AUTH_REQUEST","user":"tether","service":"sshd"}` to `/run/tether/auth.sock` when a grant is armed; the server returns `{"status":"SUCCESS"}`.
- **Recommended Remediation:**
  1. Enforce a strict whitelist of permitted PAM services: `gdm-password`, `sddm`, `lightdm`, `login`, `gnome-screensaver`, `swaylock`, `hyprlock`.
  2. Reject requests with missing, unknown, or prohibited services (`sshd`, `sudo`, `su`, `polkit-1`, `chsh`).
  3. Bind the grant explicitly to the intended local workstation service context.
- **Regression Test Required:** Unit test in `LinuxPamAuthServerTests.cs` verifying that `sshd` and `sudo` service names are rejected even when a grant is active.

---

### Finding TETH-SEC-LNX-002: `SO_PEERCRED` Failure Fails Open in `pam_tether.c`
- **Severity:** HIGH
- **CWE Identifier:** CWE-703 (Improper Check or Handling of Exceptional Conditions) / CWE-287
- **Affected OS:** Linux
- **File & Line Range:** [`services/pam-tether/pam_tether.c:185-195`](file:///home/tether/Tether/services/pam-tether/pam_tether.c#L185-L195)
- **Vulnerable Execution Path:**
  ```c
  struct ucred cred;
  socklen_t cred_len = sizeof(cred);
  if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) == 0) {
      uid_t caller_uid = geteuid();
      if (cred.uid != 0 && cred.uid != caller_uid) {
          ...
          return PAM_AUTHINFO_UNAVAIL;
      }
  }
  ```
  If `getsockopt` fails (returns -1, e.g. due to socket descriptor anomaly or unprivileged namespace restrictions), the entire `if` block is bypassed.
- **Attacker Prerequisites:** Rogue process impersonating daemon socket if socket descriptor is manipulated.
- **Realistic Impact:** Failure of peer credential authentication allows communication with an untrusted or spoofed server socket.
- **Recommended Remediation:**
  Fail closed: If `getsockopt(fd, SOL_SOCKET, SO_PEERCRED, ...)` returns non-zero or `cred_len != sizeof(cred)`, immediately abort with `PAM_AUTHINFO_UNAVAIL`.
- **Regression Test Required:** Native test in `test_pam_tether.c` verifying rejection on simulated `SO_PEERCRED` retrieval failure.

---

### Finding TETH-SEC-LNX-003: HTTPS Server Missing Cryptographic Client-Proof & Timestamp Validation
- **Severity:** HIGH
- **CWE Identifier:** CWE-345 (Insufficient Verification of Data Authenticity) / CWE-294 (Authentication Bypass by Capture-replay)
- **Affected OS:** Linux
- **File & Line Range:** [`services/communication-service/Tether.LinuxDaemon/FileTransfer/LinuxFileTransferServer.cs:76-129`](file:///home/tether/Tether/services/communication-service/Tether.LinuxDaemon/FileTransfer/LinuxFileTransferServer.cs#L76-L129)
- **Vulnerable Execution Path:**
  Android client generates `X-Tether-Client-Proof` and `X-Tether-Client-Timestamp` in `FileTransferClient.kt`.
  Windows validates this in `FileTransferAuthMiddleware.cs` using the phone's EC public key.
  Linux `LinuxFileTransferServer.cs` only checks if the bearer token exists in `LinuxTokenStore` and compares `X-Tether-Device` header without verifying the cryptographic signature or timestamp freshness.
- **Attacker Prerequisites:** Eavesdropped or intercepted bearer token within token TTL.
- **Realistic Impact:** Replay attacks or unauthorized file exfiltration/upload if a token is leaked, bypassing device identity proof.
- **Recommended Remediation:**
  Port the Windows `FileTransferAuthMiddleware` client-proof verification to `LinuxFileTransferServer.cs`:
  1. Verify `X-Tether-Client-Timestamp` is within $\pm 5$ minutes of current UTC time.
  2. Verify `X-Tether-Client-Proof` signature over `$"{token}:{timestamp}:{spki}"` using the paired phone's EC public key from `LinuxTrustStore`.
- **Regression Test Required:** Unit tests in `FileTransferTests.cs` verifying rejection of invalid proofs, expired timestamps, and tampered signatures.

---

### Finding TETH-SEC-LNX-004: Uninstaller Deletes PAM Module Without Restoring PAM Configuration
- **Severity:** CRITICAL
- **CWE Identifier:** CWE-755 (Improper Handling of Exceptional Conditions) / CWE-276
- **Affected OS:** Linux
- **File & Line Range:** [`installer/linux/uninstall.sh:25-28`](file:///home/tether/Tether/installer/linux/uninstall.sh#L25-L28)
- **Vulnerable Execution Path:**
  `uninstall.sh` executes `rm -f /usr/lib64/security/pam_tether.so`.
  However, `/etc/pam.d/gdm-password` still contains:
  `auth     sufficient    pam_tether.so`.
  When a user subsequently attempts to log in at GDM, PAM attempts to dynamically load `pam_tether.so`, fails, and depending on PAM stack flags, may deny authentication or crash the greeter session.
- **Attacker Prerequisites:** Running the official uninstaller script.
- **Realistic Impact:** Permanent lockout of graphical desktop login for local users upon uninstalling Tether.
- **Recommended Remediation:**
  1. In `uninstall.sh`, restore `/etc/pam.d/gdm-password` from verified backup `/etc/pam.d/gdm-password.tether-orig` if present.
  2. If backup is missing, safely remove the line referencing `pam_tether.so` using `sed` or awk.
  3. Test PAM stack integrity before exiting.
- **Regression Test Required:** Installer/uninstaller cycle automated test asserting clean PAM restoration and no leftover references.

---

### Finding TETH-SEC-LNX-005: Installer Modifies PAM Files Without Backups or Multi-DM Support
- **Severity:** MEDIUM
- **CWE Identifier:** CWE-379 (Creation of Temporary File in Directory with Incorrect Permissions) / CWE-703
- **Affected OS:** Linux
- **File & Line Range:** [`installer/linux/install.sh:70-74`](file:///home/tether/Tether/installer/linux/install.sh#L70-L74)
- **Vulnerable Execution Path:**
  Modifies `/etc/pam.d/gdm-password` in-place without saving a `.tether-orig` backup. Fails to configure SDDM or LightDM.
- **Recommended Remediation:**
  Add atomic backups (`.tether-orig`) and add display-manager detection for GDM, SDDM, and LightDM.

---

### Finding TETH-SEC-LNX-006: Blind Socket Deletion and Symlink Race Protection in `LinuxPamAuthServer`
- **Severity:** MEDIUM
- **CWE Identifier:** CWE-377 (Insecure Temporary File) / CWE-59 (Improper Link Resolution Before File Access)
- **Affected OS:** Linux
- **File & Line Range:** [`services/communication-service/Tether.LinuxDaemon/Security/LinuxPamAuthServer.cs:97-104`](file:///home/tether/Tether/services/communication-service/Tether.LinuxDaemon/Security/LinuxPamAuthServer.cs#L97-L104)
- **Vulnerable Execution Path:**
  `File.Delete(sockPath)` is executed without checking whether `sockPath` is a real UNIX socket or a symlink. If `/run/tether` permissions are compromised, an attacker could create a symlink pointing to a critical system file.
- **Recommended Remediation:**
  1. Ensure `/run/tether` is owned by `root:tether` with mode `0750` or `0755` without public write access.
  2. Verify that existing file is not a symlink before unlinking.
- **Regression Test Required:** Test socket initialization in `LinuxPamAuthServerTests.cs`.

---

### Finding TETH-SEC-LNX-007: Missing Desktop Streaming Pipeline Endpoints in `LinuxFileTransferServer`
- **Severity:** HIGH
- **CWE Identifier:** CWE-440 (Expected Behavior Violation)
- **Affected OS:** Linux
- **File & Line Range:** [`services/communication-service/Tether.LinuxDaemon/FileTransfer/LinuxFileTransferServer.cs`](file:///home/tether/Tether/services/communication-service/Tether.LinuxDaemon/FileTransfer/LinuxFileTransferServer.cs)
- **Vulnerable Execution Path:**
  Android companion calls `/api/desktop/stream`, `/api/desktop/screenshot`, and `/api/desktop/windows`.
  Linux host returns HTTP 404. Screen sharing and remote desktop on Linux are completely broken.
- **Recommended Remediation:**
  Implement the full desktop streaming pipeline supporting Wayland (via Portal/PipeWire) and X11 capture, plus window enumeration.
