#!/usr/bin/env bash
set -euo pipefail

# Tether Linux Uninstaller

echo "=== Tether Linux Uninstaller ==="

if [[ $EUID -ne 0 ]]; then
   echo "[ERROR] This uninstaller must be run as root. Use: sudo ./uninstall.sh"
   exit 1
fi

echo "[1/6] Stopping and disabling tether.service..."
systemctl stop tether.service >/dev/null 2>&1 || true
systemctl disable tether.service >/dev/null 2>&1 || true
rm -f /etc/systemd/system/tether.service
systemctl daemon-reload

echo "[2/6] Removing installed binaries and symlinks..."
rm -f /usr/local/bin/tether-daemon
rm -f /usr/local/bin/tetherctl
rm -f /usr/local/bin/tether
rm -rf /opt/tether

echo "[3/6] Removing native PAM module..."
rm -f /usr/lib64/security/pam_tether.so
rm -f /lib/x86_64-linux-gnu/security/pam_tether.so
rm -f /usr/lib/security/pam_tether.so

echo "[4/6] Removing udev rules and input permissions..."
rm -f /etc/udev/rules.d/99-tether-uinput.rules
udevadm control --reload-rules >/dev/null 2>&1 || true
udevadm trigger --name-match=uinput >/dev/null 2>&1 || true

echo "[5/6] Cleaning firewall rules..."
if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
    firewall-cmd --permanent --remove-port=37123/tcp >/dev/null 2>&1 || true
    firewall-cmd --permanent --remove-port=37124/udp >/dev/null 2>&1 || true
    firewall-cmd --permanent --remove-port=37124/tcp >/dev/null 2>&1 || true
    firewall-cmd --permanent --remove-port=5353/udp >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
elif command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
    ufw delete allow 37123/tcp >/dev/null 2>&1 || true
    ufw delete allow 37124/udp >/dev/null 2>&1 || true
    ufw delete allow 37124/tcp >/dev/null 2>&1 || true
    ufw delete allow 5353/udp >/dev/null 2>&1 || true
fi

echo "[6/6] Cleaning runtime files..."
rm -rf /run/tether

echo ""
echo "=== Tether Linux Successfully Uninstalled ==="
echo "Note: Paired devices and configuration in /var/lib/tether were preserved."
echo "To purge all data: rm -rf /var/lib/tether /var/log/tether"
