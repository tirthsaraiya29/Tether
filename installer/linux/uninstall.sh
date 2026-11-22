#!/usr/bin/env bash
set -euo pipefail

# Tether Linux Uninstaller

echo "=== Tether Linux Uninstaller ==="

if [[ $EUID -ne 0 ]]; then
   echo "[ERROR] This uninstaller must be run as root. Use: sudo ./uninstall.sh"
   exit 1
fi

echo "[1/5] Stopping and disabling tether.service..."
systemctl stop tether.service >/dev/null 2>&1 || true
systemctl disable tether.service >/dev/null 2>&1 || true
rm -f /etc/systemd/system/tether.service
systemctl daemon-reload

echo "[2/5] Removing installed binaries and symlinks..."
rm -f /usr/local/bin/tether-daemon
rm -f /usr/local/bin/tetherctl
rm -f /usr/local/bin/tether
rm -rf /opt/tether

echo "[3/5] Removing native PAM module..."
rm -f /usr/lib64/security/pam_tether.so
rm -f /lib/x86_64-linux-gnu/security/pam_tether.so
rm -f /usr/lib/security/pam_tether.so

echo "[4/5] Removing udev rules..."
rm -f /etc/udev/rules.d/99-tether-uinput.rules
udevadm control --reload-rules >/dev/null 2>&1 || true

echo "[5/5] Cleaning runtime files..."
rm -rf /run/tether

echo ""
echo "=== Tether Linux Successfully Uninstalled ==="
echo "Note: Paired devices and configuration in /var/lib/tether were preserved."
echo "To purge all data: rm -rf /var/lib/tether /var/log/tether"
