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

# Stop active service during upgrades to prevent file lock contention
systemctl stop tether.service >/dev/null 2>&1 || true

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

echo "[2/7] Preparing directory structure and service group..."
getent group tether >/dev/null 2>&1 || groupadd -r tether
mkdir -p "${OPT_DIR}/daemon" "${OPT_DIR}/cli"
mkdir -p "${DATA_DIR}" "${RUN_DIR}" "${LOG_DIR}"
chmod 0700 "${DATA_DIR}" "${LOG_DIR}"
chmod 0755 "${RUN_DIR}"

echo "[3/7] Building Tether Linux Daemon, CLI, and Greeter..."
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

# Install tether-greeter visual login helper
if [[ -f "${REPO_ROOT}/tools/tether-greeter/tether-greeter" ]]; then
    cp -f "${REPO_ROOT}/tools/tether-greeter/tether-greeter" "${BIN_DIR}/tether-greeter"
    chmod 0755 "${BIN_DIR}/tether-greeter"
    echo "  Installed tether-greeter helper to ${BIN_DIR}/tether-greeter."
fi

echo "[4/7] Compiling and configuring native PAM module..."
make -C "${REPO_ROOT}/services/pam-tether" clean >/dev/null
make -C "${REPO_ROOT}/services/pam-tether" pam_tether.so >/dev/null

mkdir -p "${PAM_DIR}"
cp -f "${REPO_ROOT}/services/pam-tether/pam_tether.so" "${PAM_DIR}/pam_tether.so"
chmod 0755 "${PAM_DIR}/pam_tether.so"

# Safely configure PAM service files with backup, multi-DM support, and idempotency
configure_pam_service() {
    local pam_name="$1"
    local pam_file="/etc/pam.d/${pam_name}"
    local upstream_file="/usr/lib/pam.d/${pam_name}"
    local backup_file="${pam_file}.tether-orig"

    # If file doesn't exist in /etc/pam.d, check if upstream exists in /usr/lib/pam.d
    if [[ ! -f "${pam_file}" ]] && [[ -f "${upstream_file}" ]]; then
        echo "  Copying upstream ${upstream_file} to ${pam_file}..."
        cp "${upstream_file}" "${pam_file}"
    fi

    if [[ -f "${pam_file}" ]]; then
        if grep -q "pam_tether\.so" "${pam_file}"; then
            echo "  [INFO] pam_tether.so already configured in ${pam_file}."
        else
            echo "  Configuring ${pam_file} for mobile authentication..."
            # Save pristine backup only if not already saved
            if [[ ! -f "${backup_file}" ]]; then
                cp -p "${pam_file}" "${backup_file}"
            fi

            # Determine insertion point before primary password auth substack / common-auth
            if grep -qE "auth.*substack.*(gdm-password-auth-substack|password-auth|system-auth)" "${pam_file}"; then
                sed -i '/auth.*substack.*\(gdm-password-auth-substack\|password-auth\|system-auth\)/i auth     sufficient    pam_tether.so' "${pam_file}"
            elif grep -qE "@include.*common-auth" "${pam_file}"; then
                sed -i '/@include.*common-auth/i auth     sufficient    pam_tether.so' "${pam_file}"
            elif grep -qE "auth.*pam_unix\.so" "${pam_file}"; then
                sed -i '/auth.*pam_unix\.so/i auth     sufficient    pam_tether.so' "${pam_file}"
            else
                sed -i '1i auth     sufficient    pam_tether.so' "${pam_file}"
            fi
            echo "  Successfully configured ${pam_file}."
        fi
    fi
}

# Configure known display managers (GDM, SDDM, LightDM)
configure_pam_service "gdm-password"
configure_pam_service "sddm"
configure_pam_service "lightdm"

# Configure SELinux policy if SELinux is active
if command -v semodule >/dev/null 2>&1 && command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled; then
    echo "  Configuring SELinux policy for PAM unlock..."
    SELINUX_TMP=$(mktemp -d /tmp/tether_selinux.XXXXXX)
    checkmodule -M -m -o "${SELINUX_TMP}/tether_pam.mod" "${REPO_ROOT}/installer/linux/selinux/tether_pam.te" >/dev/null 2>&1 || true
    if [[ -f "${SELINUX_TMP}/tether_pam.mod" ]]; then
        semodule_package -o "${SELINUX_TMP}/tether_pam.pp" -m "${SELINUX_TMP}/tether_pam.mod" >/dev/null 2>&1 || true
        if [[ -f "${SELINUX_TMP}/tether_pam.pp" ]]; then
            semodule -i "${SELINUX_TMP}/tether_pam.pp" >/dev/null 2>&1 || true
            echo "  SELinux tether_pam policy module loaded."
        fi
    fi
    rm -rf "${SELINUX_TMP}"
fi

echo "[5/7] Configuring dedicated udev rules for synthetic input..."
cat << 'EOF' > /etc/udev/rules.d/99-tether-uinput.rules
KERNEL=="uinput", MODE="0660", GROUP="tether"
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
cp -f "${REPO_ROOT}/services/communication-service/Tether.LinuxDaemon/systemd/tether.service" /etc/systemd/system/tether.service

systemctl daemon-reload
systemctl enable --now tether.service

echo ""
echo "=== Tether Linux Successfully Installed and Started! ==="
echo "Check daemon status:   tether status"
echo "View daemon logs:      tether logs -f"
echo "CLI utility:           tetherctl --help"
