# Security Policy

## Supported Versions

Tether is currently under active development. Security fixes are prioritized for the latest development version.

| Version / Branch | Supported |
| --- | --- |
| Latest development version (`main`) | ✅ |
| Development branch (`beta`) | ✅ |
| Older releases and unsupported builds | ❌ |

Support for a particular branch does not guarantee that every feature is production-ready or that every known security issue has been resolved.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues or public discussions.**

If you discover a potential security vulnerability in Tether, please report it privately through GitHub's security reporting feature, if enabled for this repository:

1. Open the [Tether repository](https://github.com/tirthsaraiya29/Tether).
2. Navigate to the **Security** tab.
3. Select **Report a vulnerability** under Private vulnerability reporting.
4. Include enough information to reproduce and assess the issue.

Please include, where applicable:

- The affected component (Android app, Windows service, Credential Provider, desktop UI, or communication protocol).
- The affected version, commit, branch, or build.
- A description of the vulnerability and its potential impact.
- Reproduction steps or a proof of concept.
- Any suggested mitigation or remediation.

### What to Expect

- **Acknowledgment:** I aim to acknowledge reports within 7 calendar days.
- **Assessment:** I will investigate the report and may request additional information to validate the finding.
- **Updates:** I aim to provide a status update within 14 calendar days of acknowledgment, with further updates as the investigation progresses.
- **Resolution:** If the vulnerability is confirmed, I will prioritize a fix based on its severity and impact.
- **Disclosure:** Coordinated disclosure will be preferred where practical, allowing time to investigate, develop a fix, and communicate relevant mitigations.

These are response targets, not guaranteed deadlines.

### Scope

Security reports may concern, among other things:

- Authentication, device pairing, authorization, and trust verification.
- TLS configuration, certificate validation, and communication security.
- Command execution and privilege boundaries between Windows components.
- Windows Credential Provider and lock/unlock workflows.
- Android Keystore usage and key management.
- IPC, named pipes, session boundaries, and local privilege escalation.
- File transfers, input handling, replay attacks, and denial-of-service vulnerabilities.

Please test only systems you own or have explicit permission to assess. Avoid accessing other people's data, disrupting services, or conducting destructive testing.

### Out of Scope

The following are generally outside the scope of a security report unless they demonstrate a concrete security impact:

- Vulnerabilities affecting unsupported or substantially outdated builds.
- Issues requiring an already-compromised device or administrator-level access, without a meaningful additional security impact.
- Theoretical concerns without a reproducible attack scenario.
- General feature requests, usability issues, or non-security bugs.

Reports outside these categories may still be considered at the maintainer's discretion.

### Safe Harbor

Good-faith security research conducted within the boundaries described above is welcome. Do not intentionally compromise systems, access or modify data that does not belong to you, or disrupt services. Stop testing and report the issue if you encounter sensitive data.

This policy does not grant permission to test systems you do not own or control, and it does not override applicable laws or third-party policies.

---

## Security Architecture & Technical Controls

Tether enforces defense-in-depth across the Android companion app, Windows service, and Linux daemon:

### 1. Cryptographic Authentication & Proof of Possession
* **Handshake & Reconnect:** Every session reconnection requires mutual cryptographic proof of possession. The daemon issues a fresh 32-byte cryptographically secure random `serverNonce`. The client signs a deterministic transcript (`serverNonce || clientNonce || serverSpki || clientSpki`) using its hardware-backed ECDSA P-256 identity key, returning an RFC 3279 DER sequence signature. Public keys or fingerprints alone are never accepted as proof of identity.
* **Pairing Protocol:** First-time pairing uses high-entropy 6-digit PINs displayed strictly on the active console screen. Cleartext PINs are never logged, never broadcast over IPC, and zeroized from memory immediately after HMAC-SHA256 key derivation (`TETHER-PAIRING-v2`). Failed attempts are strictly limited to 3 tries before request eviction. Raw PIN fallbacks are permanently disabled.

### 2. Privilege Dropping & Session Isolation
* **Windows Remote Shells:** When the interactive helper runs elevated for input injection across UIPI boundaries, remote terminal sessions (`powershell.exe`, `cmd.exe`) explicitly drop privileges using `CreateProcessWithTokenW` to run under the interactive user's medium-integrity token.
* **Linux Remote Shells:** When the Linux daemon executes as root, remote terminal sessions drop root privileges using `su -l <user>` or `runuser -u <user>` to execute strictly under the active unprivileged console user's UID/GID resolved from `loginctl`. Process arguments are constructed with `ProcessStartInfo.ArgumentList` to eliminate shell string injection.
* **Linux Input & Sandboxing:** Input injection is isolated to a dedicated `tether` group (`0660` on `/dev/uinput`). The daemon runs in a hardened systemd sandbox with `ProtectSystem=full`, `ProtectHome=read-only`, `PrivateTmp=true`, `ProtectKernelTunables=true`, and restricted address families.

### 3. Native PAM Module Hardening (`pam_tether`)
* Framed I/O loops (`write_all` and `read_all`) prevent partial read/write desynchronization.
* `parse_auth_status` performs strict JSON status validation, preventing status substring injection attacks.
* Socket caller identity is verified via `SO_PEERCRED`, requiring the authentication server to be root (UID 0).
* JSON strings (such as usernames) are strictly escaped with `json_escape_string`.

### 4. File Transfer Boundary & Token Binding
* File transfer tokens are bound to device fingerprints, enforce single-use / maximum-use counts, and expire in 15 minutes with explicit revocation support.
* Path boundary validation uses native libc `realpath` and .NET link target resolution, verifying that both target files and parent directories reside strictly within authorized roots.
* Direct uploads use atomic promotion from unprivileged temporary sidecars (`0600`) to prevent symlink and TOCTOU races.

### 5. Capability-Based Authorization
* All command execution and packet routing strictly enforce capability permissions (`MEDIA`, `POWER_ELEVATED`, `TERMINAL`, `FILES`, `APP_LAUNCH`, `ADMIN`, `NOTIFICATIONS`). Commands submitted without required capabilities are rejected with immediate failure responses.
