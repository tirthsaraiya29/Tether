# TETHER OPERATING SYSTEM COMPATIBILITY MATRIX

> **Historical snapshot.** This matrix predates the remediation work. Current status and the
> remaining Wayland-capture gap are tracked in `AUDIT/REMEDIATION_PROGRESS.md`.

**Audit Date:** 2026-11-23  
**Auditor:** Principal Security & Systems Engineer  
**Evaluation Standard:** Feature functionality verified against actual code paths, protocol parsers, and integration contracts.

---

## 1. Operating System Feature Parity Matrix

| Feature Area | Subsystem / Feature | Windows Host | Linux Host (Current Baseline) | Android Companion | Status Assessment & Defect Summary |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Daemon Lifecycle** | Background service management | `IMPLEMENTED_AND_TESTED` (Windows Service) | `IMPLEMENTED_AND_TESTED` (systemd unit `tether.service`) | `IMPLEMENTED_AND_TESTED` (Foreground Service) | Parity verified. Systemd unit managed via `systemctl`. |
| **Authentication UI** | Login / Greeter Tile | `IMPLEMENTED_AND_TESTED` (Credential Provider COM DLL) | `BROKEN` (Only raw PAM shared object; lacks graphical greeter status tile) | `IMPLEMENTED_AND_TESTED` (Biometric prompt + Unlock Button) | **P1 Gap:** Linux lacks greeter tile for connection status, restart action, and fallback toggle. |
| **Authentication** | PAM Module & Grant Consumption | `UNSUPPORTED_WITH_REASON` (Windows uses LSA/SSPI) | `PARTIALLY_IMPLEMENTED` (`pam_tether.so` + `LinuxPamAuthServer`) | `IMPLEMENTED_AND_TESTED` (Signs unlock challenge) | **P0 Flaw:** `LinuxPamAuthServer` ignores `service` field; `pam_tether` fails open if `SO_PEERCRED` getsockopt fails. |
| **Authentication** | Local Password / PIN Fallback | `IMPLEMENTED_AND_TESTED` (Tile switch to native Windows Password/Hello) | `BROKEN` (If `pam_tether` fails or service uninstalled without PAM cleanup, GDM fails) | `IMPLEMENTED_AND_TESTED` | **P0 Flaw:** Need safe PAM fallback to `pam_unix` and clean uninstallation restore. |
| **Service Restart** | Safe In-Greeter Restart | `IMPLEMENTED_AND_TESTED` (Restart Service button in CP tile via SCM) | `BROKEN` (Only root can run `systemctl restart`; no greeter IPC/polkit interface) | `UNSUPPORTED_WITH_REASON` (N/A on phone) | **P1 Gap:** Needs secure, narrow IPC command in `tetherctl` / auth socket. |
| **Connection State** | Live Phone & Daemon Status | `IMPLEMENTED_AND_TESTED` (Global Event + SCM polling) | `PARTIALLY_IMPLEMENTED` (`tetherctl status` exists; greeter cannot display live state) | `IMPLEMENTED_AND_TESTED` (LAN/BLE connection status bar) | Greeter needs real-time state reporting. |
| **Screen Capture** | Wayland Capture | `UNSUPPORTED_WITH_REASON` (Windows DXGI/GDI) | `MISSING` (No XDG Desktop Portal / PipeWire capture implementation) | `IMPLEMENTED_AND_TESTED` (Renders MJPEG/H264 stream) | **P2 Gap:** Complete capture pipeline missing in daemon. |
| **Screen Capture** | X11 Capture | `UNSUPPORTED_WITH_REASON` (Windows DXGI/GDI) | `MISSING` (No X11 XShm / XGetImage backend) | `IMPLEMENTED_AND_TESTED` (Renders MJPEG/H264 stream) | **P2 Gap:** X11 capture backend missing. |
| **Desktop Streaming**| `/api/desktop/stream` | `IMPLEMENTED_AND_TESTED` (Windows `FileTransferServer.cs`) | `BROKEN` (Route not mapped in `LinuxFileTransferServer.cs`) | `IMPLEMENTED_AND_TESTED` (`RemoteDesktopScreen.kt`) | **P2 Gap:** Endpoint missing in `LinuxFileTransferServer.cs`. |
| **Desktop Streaming**| `/api/desktop/screenshot` | `IMPLEMENTED_AND_TESTED` (Windows `FileTransferServer.cs`) | `BROKEN` (Route not mapped in `LinuxFileTransferServer.cs`) | `IMPLEMENTED_AND_TESTED` (`RemoteDesktopScreen.kt`) | **P2 Gap:** Endpoint missing in `LinuxFileTransferServer.cs`. |
| **Desktop Streaming**| `/api/desktop/windows` | `IMPLEMENTED_AND_TESTED` (Windows EnumWindows API) | `BROKEN` (Route not mapped in `LinuxFileTransferServer.cs`) | `IMPLEMENTED_AND_TESTED` (`RemoteDesktopScreen.kt`) | **P2 Gap:** Endpoint missing in `LinuxFileTransferServer.cs`. |
| **HTTP Auth** | Client Proof Validation | `IMPLEMENTED_AND_TESTED` (`FileTransferAuthMiddleware.cs`) | `BROKEN` (`LinuxFileTransferServer.cs` ignores `X-Tether-Client-Proof` and timestamps) | `IMPLEMENTED_AND_TESTED` (`FileTransferClient.kt`) | **P0 Flaw:** Linux HTTP server accepts bearer tokens without verifying cryptographic client proof. |
| **Input Forwarding** | Keyboard, Mouse, Scroll | `IMPLEMENTED_AND_TESTED` (`SendInput` Win32 API) | `IMPLEMENTED_AND_TESTED` (`LinuxUinputInjector` via `/dev/uinput` char-input) | `IMPLEMENTED_AND_TESTED` (Trackpad & Key injection) | Fully verified on Linux kernel uinput subsystem. |
| **File Transfer** | Browse, Download, Upload | `IMPLEMENTED_AND_TESTED` (`FileTransferServer.cs`) | `IMPLEMENTED_AND_TESTED` (Path canonicalization, symlink escape checks in `LinuxFileTransferServer`) | `IMPLEMENTED_AND_TESTED` (`FileTransferClient.kt`) | Parity verified for `/api/files/*`. |
| **Terminal** | Remote Interactive Shell | `IMPLEMENTED_AND_TESTED` (Windows ConPTY) | `IMPLEMENTED_AND_TESTED` (`LinuxTerminalManager` with `runuser` drop & POSIX PTY) | `IMPLEMENTED_AND_TESTED` (`TerminalScreen.kt`) | Verified: drops to non-root active session user. |
| **Hardware & Audio** | Volume, Mute, Brightness | `IMPLEMENTED_AND_TESTED` (CoreAudio & WMI) | `IMPLEMENTED_AND_TESTED` (`amixer` non-blocking process with 300ms timeout) | `IMPLEMENTED_AND_TESTED` (Volume & Brightness sliders) | Verified in commit `4c7e8e6`. |
| **Media Controls** | MPRIS2 Play/Pause/Skip | `IMPLEMENTED_AND_TESTED` (Windows Media Transport) | `IMPLEMENTED_AND_TESTED` (`LinuxMediaController` via D-Bus MPRIS2) | `IMPLEMENTED_AND_TESTED` (Now Playing widget) | Verified on D-Bus session bus. |
| **Power Management** | Lock, Suspend, Shutdown | `IMPLEMENTED_AND_TESTED` (LockWorkStation Win32 API) | `IMPLEMENTED_AND_TESTED` (`loginctl lock-session`, systemctl poweroff) | `IMPLEMENTED_AND_TESTED` (Quick Action power tiles) | Verified in `LinuxHardwareExecutor.cs`. |
| **Telemetry** | Battery, CPU, RAM, Disk | `IMPLEMENTED_AND_TESTED` (WMI / PerformanceCounters) | `IMPLEMENTED_AND_TESTED` (`/sys/class/power_supply`, `/proc/meminfo`, `/proc/stat`) | `IMPLEMENTED_AND_TESTED` (Dashboard telemetry card) | Verified in `LinuxLaptopStateCollector.cs`. |
| **Installation** | Deployment & Registration | `IMPLEMENTED_AND_TESTED` (Inno Setup Installer) | `BROKEN` (`install.sh` modifies PAM without backup; `uninstall.sh` fails to restore PAM) | `IMPLEMENTED_AND_TESTED` (Google Play / APK) | **P0 Flaw:** Installer and uninstaller risk PAM corruption. |
