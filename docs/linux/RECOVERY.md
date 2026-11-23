# Tether Linux Recovery & Troubleshooting Guide

## Overview
Tether Linux is architected with strict fail-closed safety guarantees. In the event of a daemon crash, socket deletion, or uninstallation, the system is designed to **never lock the user out** of their machine.

---

## Automatic Fail-Safe Mechanisms

### 1. Seamless Password Fallback
If the Tether daemon is stopped or the mobile phone is not within range:
- `pam_tether.so` attempts to connect to `/run/tether/auth.sock` with a strict 2-second timeout.
- When the socket is unreachable or returns `NO_GRANT`, `pam_tether.so` immediately returns `PAM_AUTHINFO_UNAVAIL`.
- The PAM stack smoothly hands control to the standard password authentication module (`pam_unix.so`).
- The login screen presents the regular password prompt without errors.

---

## Troubleshooting & Recovery Commands

### 1. Check PAM Configuration Health
To inspect whether PAM files and shared libraries are properly configured:
```bash
tetherctl recover
```
Expected output:
```text
=== Tether PAM & Authentication Health Check ===
[OK] Native PAM module found: /usr/lib64/security/pam_tether.so
[INFO] /etc/pam.d/gdm-password: Configured=True, Pristine Backup Present=True
[OK] PAM auth socket present: /run/tether/auth.sock
```

### 2. Restore Pristine PAM Configuration
If you experience any issues with display manager login, you can immediately restore the pristine, pre-Tether PAM configuration files:
```bash
sudo tetherctl recover --restore-pam
```
This restores all `.tether-orig` backups and cleanly removes any `pam_tether.so` lines from `/etc/pam.d/gdm-password`, `/etc/pam.d/sddm`, and `/etc/pam.d/lightdm`.

### 3. Emergency TTY Console Login
If the graphical desktop does not accept input:
1. Press `Ctrl + Alt + F3` (or `F4`, `F5`) to open a virtual console (TTY).
2. Log in using your native username and password (virtual consoles use `/etc/pam.d/login`, which is unaffected by Tether).
3. Run the recovery command:
   ```bash
   sudo tetherctl recover --restore-pam
   ```
4. Restart your display manager:
   ```bash
   sudo systemctl restart gdm # or sddm / lightdm
   ```
5. Return to the graphical screen with `Ctrl + Alt + F1` or `Ctrl + Alt + F2`.

---

## Clean Uninstallation
To completely remove Tether while safely restoring all system PAM configurations:
```bash
sudo ./installer/linux/uninstall.sh
```
The uninstaller will:
- Stop and disable `tether.service`.
- Restore all pristine PAM configuration files from backups.
- Remove `pam_tether.so` and SELinux modules.
- Remove binaries, CLI links, udev rules, and firewall exceptions.
- Preserve paired device keys in `/var/lib/tether` for future reinstallation (or run `sudo rm -rf /var/lib/tether` to purge all keys).
