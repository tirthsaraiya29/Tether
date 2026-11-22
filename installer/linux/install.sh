#!/usr/bin/env bash
set -euo pipefail

# Tether Linux Production Installer
# Supported on Fedora, RHEL, CentOS, Ubuntu, Debian, Arch Linux

echo "=== Tether Linux Production Installer ==="

if [[ $EUID -ne 0 ]]; then
   echo "[ERROR] This installer must be run as root. Use: sudo ./install.sh"
   exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

echo "[1/7] Checking dependencies..."
command -v dotnet >/dev/null 2>&1 || { echo "[ERROR] .NET 10 SDK/Runtime is required but not installed."; exit 1; }
command -v gcc >/dev/null 2>&1 || { echo "[ERROR] gcc is required for native PAM compilation."; exit 1; }

# Target directories
OPT_DIR="/opt/tether"
BIN_DIR="/usr/local/bin"
PAM_DIR="/usr/lib64/security"
if [[ ! -d "${PAM_DIR}" ]] && [[ -d "/lib/x86_64-linux-gnu/security" ]]; then
    PAM_DIR="/lib/x86_64-linux-gnu/security"
elif [[ ! -d "${PAM_DIR}" ]] && [[ -d "/usr/lib/security" ]]; then
    PAM_DIR="/usr/lib/security"
fi

DATA_DIR="/var/lib/tether"
RUN_DIR="/run/tether"
LOG_DIR="/var/log/tether"

echo "[2/7] Preparing directory structure..."
mkdir -p "${OPT_DIR}/daemon" "${OPT_DIR}/cli"
mkdir -p "${DATA_DIR}" "${RUN_DIR}" "${LOG_DIR}"
chmod 0700 "${DATA_DIR}" "${LOG_DIR}"
chmod 0755 "${RUN_DIR}"

echo "[3/7] Building Tether Linux Daemon and CLI..."
dotnet publish "${REPO_ROOT}/services/communication-service/Tether.LinuxDaemon/Tether.LinuxDaemon.csproj" \
    -c Release -o "${OPT_DIR}/daemon" --nologo -v q

dotnet publish "${REPO_ROOT}/tools/tetherctl/Tether.Cli.csproj" \
    -c Release -o "${OPT_DIR}/cli" --nologo -v q

# Ensure executables have execute permissions
chmod +x "${OPT_DIR}/daemon/Tether.LinuxDaemon"
chmod +x "${OPT_DIR}/cli/tetherctl"

# Create symlinks
ln -sf "${OPT_DIR}/daemon/Tether.LinuxDaemon" "${BIN_DIR}/tether-daemon"
ln -sf "${OPT_DIR}/cli/tetherctl" "${BIN_DIR}/tetherctl"
ln -sf "${OPT_DIR}/cli/tetherctl" "${BIN_DIR}/tether"

echo "[4/7] Compiling native PAM module..."
make -C "${REPO_ROOT}/services/pam-tether" clean >/dev/null
make -C "${REPO_ROOT}/services/pam-tether" pam_tether.so >/dev/null

mkdir -p "${PAM_DIR}"
cp -f "${REPO_ROOT}/services/pam-tether/pam_tether.so" "${PAM_DIR}/pam_tether.so"
chmod 0755 "${PAM_DIR}/pam_tether.so"

echo "[5/7] Configuring udev rules for synthetic input..."
cat << 'EOF' > /etc/udev/rules.d/99-tether-uinput.rules
KERNEL=="uinput", MODE="0660", GROUP="input"
EOF
udevadm control --reload-rules >/dev/null 2>&1 || true
udevadm trigger --name-match=uinput >/dev/null 2>&1 || true

echo "[6/7] Configuring firewall..."
if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
    firewall-cmd --permanent --add-port=37123/tcp >/dev/null 2>&1 || true
    firewall-cmd --permanent --add-port=37124/udp >/dev/null 2>&1 || true
    firewall-cmd --permanent --add-port=37124/tcp >/dev/null 2>&1 || true
    firewall-cmd --permanent --add-port=5353/udp >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
    echo "  firewalld rules configured."
elif command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
    ufw allow 37123/tcp >/dev/null 2>&1 || true
    ufw allow 37124/udp >/dev/null 2>&1 || true
    ufw allow 37124/tcp >/dev/null 2>&1 || true
    ufw allow 5353/udp >/dev/null 2>&1 || true
    echo "  ufw rules configured."
fi

echo "[7/7] Installing systemd service..."
cat << 'EOF' > /etc/systemd/system/tether.service
[Unit]
Description=Tether Linux Daemon
Documentation=https://github.com/tirthsaraiya29/tether
After=network.target network-online.target dbus.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/tether-daemon
Restart=on-failure
RestartSec=3s
KillMode=control-group
StandardOutput=journal
StandardError=journal

# Security and Sandbox Constraints
ProtectSystem=full
ProtectHome=read-only
ReadWritePaths=/var/lib/tether /run/tether /var/log/tether
DeviceAllow=/dev/uinput rw
DeviceAllow=char-input rw

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now tether.service

echo ""
echo "=== Tether Linux Successfully Installed and Started! ==="
echo "Check daemon status:   tether status"
echo "View daemon logs:      tether logs -f"
echo "CLI utility:           tetherctl --help"
