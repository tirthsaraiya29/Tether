# Tether Linux Installation & Deployment Guide

## System Requirements
- **Operating Systems:** Fedora 39+, RHEL / CentOS Stream 9+, Ubuntu 22.04 LTS+, Debian 12+, Arch Linux.
- **Runtimes:** .NET 10 SDK / Runtime (`dotnet-sdk-10.0`).
- **Toolchain:** `gcc`, `make`, `pam-devel` (or `libpam0g-dev`).
- **Display Managers Supported:** GDM, SDDM, LightDM.
- **Display Servers Supported:** Wayland and X11.

---

## Quick Installation

```bash
# Clone the repository
git clone https://github.com/tirthsaraiya29/tether.git
cd tether

# Run production installer as root
sudo ./installer/linux/install.sh
```

---

## What the Installer Does

1. **Dependency Verification:** Validates presence of .NET 10 and GCC.
2. **Directory Creation & Permissions:**
   - `/opt/tether`: Application binaries and CLI utilities.
   - `/var/lib/tether`: Secure trust store (`trust.json`, mode `0700`).
   - `/run/tether`: Runtime sockets (`auth.sock`, mode `0755 root:root`).
   - `/var/log/tether`: Daemon log files (mode `0700`).
3. **Compilation & Publication:**
   - Publishes `Tether.LinuxDaemon` to `/opt/tether/daemon`.
   - Publishes `tetherctl` CLI to `/opt/tether/cli`.
   - Links binaries to `/usr/local/bin/tether-daemon`, `/usr/local/bin/tetherctl`, `/usr/local/bin/tether`.
   - Installs visual greeter tile to `/usr/local/bin/tether-greeter`.
4. **Native PAM Compilation & Multi-DM Integration:**
   - Compiles native `pam_tether.so` from C source.
   - Installs `pam_tether.so` to `/usr/lib64/security/` or distribution equivalent.
   - Backs up pristine PAM files (`/etc/pam.d/gdm-password.tether-orig`, etc.).
   - Injects `auth sufficient pam_tether.so` into GDM, SDDM, and LightDM PAM stacks.
   - Compiles and loads SELinux policy module (`tether_pam`) if SELinux is active.
5. **Synthetic Input Udev Rules:**
   - Creates `/etc/udev/rules.d/99-tether-uinput.rules` for `/dev/uinput` access.
6. **Firewall Configuration:**
   - Opens TCP 37123 (TLS/HTTPS), UDP 37124 (Discovery), and UDP 5353 (mDNS) via `firewalld` or `ufw`.
7. **Systemd Service Activation:**
   - Installs and starts `tether.service`.

---

## Verifying the Installation

```bash
# Verify daemon service status
sudo systemctl status tether.service

# Check Tether status and active session info
tether status

# Verify PAM health check
tetherctl recover

# Check visual greeter helper
tether-greeter --status
```
