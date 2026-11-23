#!/usr/bin/env bash
set -euo pipefail

# Automated Test Suite for Tether Linux Installer and Uninstaller Lifecycle

echo "=== Testing Tether Linux Installer & Uninstaller PAM Lifecycle ==="

TEST_DIR=$(mktemp -d /tmp/tether_pam_test.XXXXXX)
trap 'rm -rf "${TEST_DIR}"' EXIT

MOCK_ETC_PAM="${TEST_DIR}/etc/pam.d"
MOCK_USR_PAM="${TEST_DIR}/usr/lib/pam.d"
mkdir -p "${MOCK_ETC_PAM}" "${MOCK_USR_PAM}"

# 1. Create mock upstream GDM file
cat << 'EOF' > "${MOCK_USR_PAM}/gdm-password"
auth     [success=done ignore=ignore default=bad] pam_selinux_permit.so
auth     substack      gdm-password-auth-substack
-auth    optional      pam_gnome_keyring.so
account  include       password-auth
password substack      gdm-password-auth-substack
session  include       password-auth
EOF

# 2. Create mock existing SDDM file
cat << 'EOF' > "${MOCK_ETC_PAM}/sddm"
auth     include       system-auth
account  include       system-auth
password include       system-auth
session  include       system-auth
EOF

# 3. Create mock existing LightDM file (Debian style with common-auth)
cat << 'EOF' > "${MOCK_ETC_PAM}/lightdm"
@include common-auth
@include common-account
@include common-session
EOF

echo "[Test 1] Configure PAM on mock GDM (copied from upstream)..."
# Simulate install configure_pam_service
configure_pam_service() {
    local pam_name="$1"
    local pam_file="${MOCK_ETC_PAM}/${pam_name}"
    local upstream_file="${MOCK_USR_PAM}/${pam_name}"
    local backup_file="${pam_file}.tether-orig"

    if [[ ! -f "${pam_file}" ]] && [[ -f "${upstream_file}" ]]; then
        cp "${upstream_file}" "${pam_file}"
    fi

    if [[ -f "${pam_file}" ]]; then
        if grep -q "pam_tether\.so" "${pam_file}"; then
            return 0
        fi

        if [[ ! -f "${backup_file}" ]]; then
            cp -p "${pam_file}" "${backup_file}"
        fi

        if grep -qE "auth.*substack.*(gdm-password-auth-substack|password-auth|system-auth)" "${pam_file}"; then
            sed -i '/auth.*substack.*\(gdm-password-auth-substack\|password-auth\|system-auth\)/i auth     sufficient    pam_tether.so' "${pam_file}"
        elif grep -qE "@include.*common-auth" "${pam_file}"; then
            sed -i '/@include.*common-auth/i auth     sufficient    pam_tether.so' "${pam_file}"
        elif grep -qE "auth.*pam_unix\.so" "${pam_file}"; then
            sed -i '/auth.*pam_unix\.so/i auth     sufficient    pam_tether.so' "${pam_file}"
        else
            sed -i '1i auth     sufficient    pam_tether.so' "${pam_file}"
        fi
    fi
}

configure_pam_service "gdm-password"
configure_pam_service "sddm"
configure_pam_service "lightdm"

# Verify all mock files now contain pam_tether.so
grep -q "pam_tether\.so" "${MOCK_ETC_PAM}/gdm-password" || { echo "FAIL: gdm-password missing pam_tether.so"; exit 1; }
grep -q "pam_tether\.so" "${MOCK_ETC_PAM}/sddm" || { echo "FAIL: sddm missing pam_tether.so"; exit 1; }
grep -q "pam_tether\.so" "${MOCK_ETC_PAM}/lightdm" || { echo "FAIL: lightdm missing pam_tether.so"; exit 1; }

# Verify pristine backups exist
[[ -f "${MOCK_ETC_PAM}/gdm-password.tether-orig" ]] || { echo "FAIL: gdm-password.tether-orig missing"; exit 1; }
[[ -f "${MOCK_ETC_PAM}/sddm.tether-orig" ]] || { echo "FAIL: sddm.tether-orig missing"; exit 1; }
[[ -f "${MOCK_ETC_PAM}/lightdm.tether-orig" ]] || { echo "FAIL: lightdm.tether-orig missing"; exit 1; }

# Verify backup does NOT have pam_tether.so
if grep -q "pam_tether\.so" "${MOCK_ETC_PAM}/gdm-password.tether-orig"; then
    echo "FAIL: backup contaminated with pam_tether.so"; exit 1;
fi

echo "  -> Passed: Initial PAM configuration and backup creation."

echo "[Test 2] Idempotency: re-running configure_pam_service must not duplicate lines..."
configure_pam_service "gdm-password"
configure_pam_service "sddm"
configure_pam_service "lightdm"

GDM_COUNT=$(grep -c "pam_tether\.so" "${MOCK_ETC_PAM}/gdm-password" || true)
SDDM_COUNT=$(grep -c "pam_tether\.so" "${MOCK_ETC_PAM}/sddm" || true)
LIGHTDM_COUNT=$(grep -c "pam_tether\.so" "${MOCK_ETC_PAM}/lightdm" || true)

if [[ "${GDM_COUNT}" -ne 1 ]] || [[ "${SDDM_COUNT}" -ne 1 ]] || [[ "${LIGHTDM_COUNT}" -ne 1 ]]; then
    echo "FAIL: Duplicate pam_tether.so entries found! (GDM=${GDM_COUNT}, SDDM=${SDDM_COUNT}, LightDM=${LIGHTDM_COUNT})"; exit 1;
fi
echo "  -> Passed: Idempotency check verified."

echo "[Test 3] Restoration: simulating uninstaller restoring pristine backups..."
restore_pam_service() {
    local pam_name="$1"
    local pam_file="${MOCK_ETC_PAM}/${pam_name}"
    local backup_file="${pam_file}.tether-orig"

    if [[ -f "${backup_file}" ]]; then
        cp -fp "${backup_file}" "${pam_file}"
        rm -f "${backup_file}"
    elif [[ -f "${pam_file}" ]] && grep -q "pam_tether\.so" "${pam_file}"; then
        sed -i '/pam_tether\.so/d' "${pam_file}"
    fi
}

restore_pam_service "gdm-password"
restore_pam_service "sddm"
restore_pam_service "lightdm"

# Verify pam_tether.so is completely gone
if grep -q "pam_tether\.so" "${MOCK_ETC_PAM}/gdm-password" || \
   grep -q "pam_tether\.so" "${MOCK_ETC_PAM}/sddm" || \
   grep -q "pam_tether\.so" "${MOCK_ETC_PAM}/lightdm"; then
    echo "FAIL: pam_tether.so still present after restoration!"; exit 1;
fi

# Verify backup files were cleaned up
if [[ -f "${MOCK_ETC_PAM}/gdm-password.tether-orig" ]] || \
   [[ -f "${MOCK_ETC_PAM}/sddm.tether-orig" ]] || \
   [[ -f "${MOCK_ETC_PAM}/lightdm.tether-orig" ]]; then
    echo "FAIL: Backup files were not removed after restoration!"; exit 1;
fi

# Verify SDDM and LightDM contents match original
grep -q "auth     include       system-auth" "${MOCK_ETC_PAM}/sddm" || { echo "FAIL: SDDM content damaged"; exit 1; }
grep -q "@include common-auth" "${MOCK_ETC_PAM}/lightdm" || { echo "FAIL: LightDM content damaged"; exit 1; }

echo "  -> Passed: Pristine restoration check verified."

echo "[Test 4] Fallback restoration: stripped cleanly even if backup is missing..."
cat << 'EOF' > "${MOCK_ETC_PAM}/sddm"
auth     sufficient    pam_tether.so
auth     include       system-auth
account  include       system-auth
EOF

restore_pam_service "sddm"
if grep -q "pam_tether\.so" "${MOCK_ETC_PAM}/sddm"; then
    echo "FAIL: Fallback strip failed!"; exit 1;
fi
grep -q "auth     include       system-auth" "${MOCK_ETC_PAM}/sddm" || { echo "FAIL: Content damaged during strip"; exit 1; }
echo "  -> Passed: Fallback strip check verified."

echo "=== All Installer & PAM Lifecycle Tests Passed! ==="
