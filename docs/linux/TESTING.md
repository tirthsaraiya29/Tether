# Tether Linux Testing & Quality Assurance Guide

## Overview
Tether Linux is verified through a multi-tiered testing strategy comprising native C PAM tests, .NET 10 xUnit integration tests, cryptographic signature verification tests, and automated installer lifecycle simulation.

---

## Test Suites & Execution

### 1. Native C PAM Module Tests
Located at [`services/pam-tether/test_pam_tether.c`](file:///home/tether/Tether/services/pam-tether/test_pam_tether.c), this suite tests PAM module invariants directly against a mock socket server without requiring GDM or root privileges.

**To Run:**
```bash
make -C services/pam-tether test
```

**Coverage:**
- `PAM_SUCCESS` for authorized user with active grant.
- `PAM_AUTH_ERR` for unauthorized user without grant.
- `PAM_AUTHINFO_UNAVAIL` when socket is missing (fail-closed).
- Socket communication timeouts.
- Strict parser rejecting substring collisions (e.g. `DENIED` with embedded "SUCCESS").
- JSON escaping for usernames with special characters.
- `NO_GRANT` translation to `PAM_AUTHINFO_UNAVAIL` for seamless password fallback.
- `pam_sm_setcred` and `pam_sm_acct_mgmt` lifecycle stubs.

### 2. .NET 10 Linux Integration & Authorization Tests
Located at [`tests/Tether.LinuxTests/`](file:///home/tether/Tether/tests/Tether.LinuxTests/), this suite comprises 107 test cases (99 executed unit/integration tests and 8 live-daemon network tests).

**To Run:**
```bash
dotnet test tests/Tether.LinuxTests/Tether.LinuxTests.csproj
```

**Test Suites:**
- [`LinuxPamAuthServerTests.cs`](file:///home/tether/Tether/tests/Tether.LinuxTests/LinuxPamAuthServerTests.cs): Service whitelisting (`gdm-password`, `sddm`, `lightdm`), rejection of unauthorized services (`sudo`, `sshd`), single-use grant consumption, 30s TTL expiry, symlink rejection on socket path.
- [`FileTransferTests.cs`](file:///home/tether/Tether/tests/Tether.LinuxTests/FileTransferTests.cs): Client proof validation (`X-Tether-Client-Proof`), timestamp skew validation, reject unauthorized streaming/screenshot requests, desktop streaming route registration.
- [`LinuxPacketRouterAuthorizationTests.cs`](file:///home/tether/Tether/tests/Tether.LinuxTests/LinuxPacketRouterAuthorizationTests.cs): Capability enforcement (`MEDIA`, `TERMINAL`, `POWER_ELEVATED`, `ADMIN`, `APP_LAUNCH`), audio device enumeration, microphone controls, request deduplication.
- [`LinuxHardwareExecutorTests.cs`](file:///home/tether/Tether/tests/Tether.LinuxTests/LinuxHardwareExecutorTests.cs): PipeWire / `wpctl` volume level parsing, brightness control, laptop state collection.
- [`LinuxTrustStoreTests.cs`](file:///home/tether/Tether/tests/Tether.LinuxTests/LinuxTrustStoreTests.cs): Atomic storage, JSON corruption recovery, device revocation, key pinning.
- [`LinuxInputTests.cs`](file:///home/tether/Tether/tests/Tether.LinuxTests/LinuxInputTests.cs): Virtual mouse/keyboard event injection, modifier handling, Unicode character translation.
- [`LinuxTerminalTests.cs`](file:///home/tether/Tether/tests/Tether.LinuxTests/LinuxTerminalTests.cs): POSIX PTY session allocation, input forwarding, session termination.

### 3. Installer & Uninstaller PAM Lifecycle Verification
Located at [`installer/linux/test_installer_lifecycle.sh`](file:///home/tether/Tether/installer/linux/test_installer_lifecycle.sh), this automated script tests PAM configuration insertion, backup creation, idempotency, and clean restoration.

**To Run:**
```bash
./installer/linux/test_installer_lifecycle.sh
```

**Scenarios Tested:**
1. Initial installation with pristine backup (`.tether-orig`) creation across GDM, SDDM, and LightDM.
2. Idempotency test verifying that repeated installations do not produce duplicate entries.
3. Clean uninstallation verifying that pristine backups are restored and `.tether-orig` files removed.
4. Fallback restoration verifying that `pam_tether.so` lines are cleanly stripped even if the backup file was accidentally removed.

---

## Negative Security Test Matrix

| Security Scenario | Expected Result | Verified Test Case |
| :--- | :--- | :--- |
| `sudo` requests mobile unlock grant | `SERVICE_DENIED` | `PamAuthServer_RejectsUnauthorizedPamService` |
| Client requests stream without signature | `HTTP 401 Unauthorized` | `DesktopStream_MissingProof_Returns401` |
| Client requests stream with expired timestamp (>300s) | `HTTP 401 Unauthorized` | `DesktopStream_ExpiredTimestamp_Returns401` |
| Client requests stream with signature from unknown device | `HTTP 401 Unauthorized` | `DesktopStream_UntrustedKey_Returns401` |
| Device without `MEDIA` requests audio devices | `CONFIRM_ACTION success=false` | `AudioDevicesGet_RejectedIfLacksMediaCapability` |
| Device without `TERMINAL` requests shell | `TERMINAL_START_RESPONSE success=false` | `TerminalStart_RejectedIfLacksTerminalCapability` |
| Daemon socket path replaced by symlink | Symlink deleted & recreated safely | `PamAuthServer_CreatesHardenedSocket` |
| Mobile unlock grant expired after 30s | `NO_GRANT` -> `PAM_AUTHINFO_UNAVAIL` | `PamAuthServer_ExpiresGrantsAfterTtl` |
| Unlock grant consumed once | Second attempt returns `NO_GRANT` | `PamAuthServer_SingleUseGrant` |
