# Cross-Platform Compatibility Audit

Date: 2026-11-28
Scope: Android companion <-> Windows host <-> Linux host

This document records defects verified against the code on `main` (d3df8bf), not
claims copied from earlier audit snapshots. Earlier snapshots in this directory
are partially stale: Linux file transfer, desktop streaming and client-proof
verification described as missing are in fact implemented.

## Verified defects

### D1 - Linux never grants the admin capability (authorization)
`LinuxPairingManager.FinalizePairing` persists the phone's capabilities without
any admin scope (`ADMIN`, `LINUX_ADMIN` or `WINDOWS_ADMIN`). `HasCapability`
maps `ADMIN` onto `LINUX_ADMIN`/`WINDOWS_ADMIN`, so every admin command is
rejected on Linux:
`ADMIN_TELEMETRY_GET`, `HARDWARE_SPECS_GET`, `BATTERY_HEALTH_GET`,
`POWER_PLANS_GET`, `SET_POWER_PLAN`, `USB_DEVICES_GET`, `SERVICES_GET`,
`SERVICE_*`, `UPDATES_GET`.

`LinuxSession.ServerCapabilities` and the Linux discovery record also omit any
admin scope, so the Android client strips `WINDOWS_ADMIN` during negotiation and
blocks these commands client-side as well. The Linux discovery record
advertises `WINDOWS_ADMIN`, which is a platform mislabel.

### D2 - Linux admin payloads do not match the Android contract (silent zeros)
Both hosts serialize camelCase JSON, so property names are the contract.
`LinuxSystemTelemetry` exposes `usedRamMb/freeDiskGb/totalDiskGb/network*Kbps`
while Android reads `availRamMb/ramUsagePct/disks[]/networks[]/gpuName/
gpuVramMb/cpuCores`. `LinuxHardwareSpecs` exposes `cpuName/cpuCores/
totalRamMb/osVersion` while Android reads `processorName/coreCount/
totalMemoryMb/osDescription`. Result: the Administration page shows zeroes and
blank fields on Linux even when the command succeeds.

### D3 - Fabricated telemetry on Linux
- `GetPowerPlans` invents "Performance"/"Power Saver" entries when no governor
  data exists.
- `GetGpuInfo` reports 4096 MB VRAM for any detected GPU.

Both violate the no-fabrication rule and mislead the UI.

### D4 - Power plan changes report success without applying
`SetPowerPlan` swallows every write failure and returns `true` whenever the
governor sysfs node exists. It also accepts arbitrary unvalidated governor
names.

### D5 - Update checking is dnf-only and shadowed
`GetSystemUpdates` only invokes `dnf`; Debian/Ubuntu, openSUSE and Arch report
"up to date". A second `case "CHECK_UPDATES"` returns `hasUpdates = false`
unconditionally and shadows the real handler, so the client's update check
always reports no updates on Linux.

### D6 - Service control lacks target validation
`ControlService` interpolates the client-supplied service name into a
`systemctl` argument string with no format validation and no protection for
critical units. `systemctl` is not checked for presence.

### D7 - Battery report generation is Windows-only
The router has `BATTERY_REPORT_GENERATE` on Windows but no Linux handler, so
"Generate Report" fails on Linux.

### D8 - Android surfaces Windows-specific labels and dead UI
`SystemAppsScreen` / `AppScreen.SYSTEM_APPS` still exist. `DiskUsageItem`
defaults to `C:`/`NTFS`. The admin screen title and copy assume Windows.

### D9 - Pre-existing failing test
`Tether.LinuxTests.InProcessDaemonIntegrationTests.InProcess_RapidConnectDisconnect_StressTest`
fails on `main`.

## Remediation order
D1 capability grant -> D2 schema -> D3/D4 power -> D5 updates -> D6 services
-> D7 battery report -> D8 Android UI -> D9 test.
