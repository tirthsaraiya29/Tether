# Tether Linux Operating System & Client Compatibility Matrix

## Platform Comparison

| Feature Category | Windows Implementation | Linux Implementation | Android Companion Parity | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Daemon / Service** | Windows Service (`Tether.CommunicationService`) | systemd Service (`Tether.LinuxDaemon`) | Full parity across both | `IMPLEMENTED_AND_TESTED` |
| **Mutual TLS 1.3** | Schannel / CNG ECDSA P-256 | OpenSSL / SslStream ECDSA P-256 | Android KeyStore ECDSA P-256 | `IMPLEMENTED_AND_TESTED` |
| **Discovery** | mDNS + UDP Broadcast (Port 37124) | mDNS + UDP Broadcast (Port 37124) | Dual discovery listener | `IMPLEMENTED_AND_TESTED` |
| **First-Time Pairing** | 6-digit Out-of-Band SAS Commitment | 6-digit Out-of-Band SAS Commitment | Seamless pairing handshake | `IMPLEMENTED_AND_TESTED` |
| **Trust Store** | NTFS ACL `C:\ProgramData\Tether\trust.json` | POSIX `0700 /var/lib/tether/trust.json` | EncryptedSharedPreferences | `IMPLEMENTED_AND_TESTED` |
| **Login Experience** | Windows Credential Provider Tile | Libadwaita Greeter Tile (`tether-greeter`) + PAM (`pam_tether.so`) | Mobile biometric unlock gesture | `IMPLEMENTED_AND_TESTED` |
| **Display Managers** | Winlogon | GDM, SDDM, LightDM | Display agnostic | `IMPLEMENTED_AND_TESTED` |
| **Password Fallback** | Native Password Tile switch | Seamless `PAM_AUTHINFO_UNAVAIL` -> `pam_unix` | Automatic fallback | `IMPLEMENTED_AND_TESTED` |
| **Synthetic Input** | Win32 `SendInput` API | Linux `/dev/uinput` kernel interface | Touchpad, Mouse, Keyboard | `IMPLEMENTED_AND_TESTED` |
| **Screen Streaming** | Desktop Duplication API (DXGI) | MJPEG Stream (`/api/desktop/stream`) over X11/XWayland | `RemoteDesktopScreen` | `IMPLEMENTED` (X11/XWayland). Pure Wayland needs the portal ScreenCast client, not yet implemented; returns 503 |
| **Screen Capture** | GDI / Direct3D JPEG | Snapshot (`/api/desktop/screenshot`) via ffmpeg x11grab | Remote desktop viewer | `IMPLEMENTED` (X11/XWayland) |
| **Window Listing** | Win32 `EnumWindows` | `wmctrl` -l (X11/XWayland only) | `RemoteDesktopScreen` windows list | `IMPLEMENTED` (X11/XWayland; Wayland windows are not enumerable by design) |
| **Window Control** | `SetForegroundWindow` / Close | `wmctrl -i -a` / `wmctrl -i -c` / Process Kill | Close and switch windows | `IMPLEMENTED_AND_TESTED` |
| **Audio Controls** | CoreAudio / WASAPI Endpoints | PipeWire / WirePlumber (`wpctl`) + `pactl` | Master volume, mic gain, mute | `IMPLEMENTED_AND_TESTED` |
| **Audio Devices** | IMMDeviceEnumerator endpoints | `wpctl status` Sinks & Sources | Device selector list | `IMPLEMENTED_AND_TESTED` |
| **Panic Lockdown** | Win32 `LockWorkStation` + Mute | `loginctl lock-session` + `wpctl` Mute | Panic button trigger | `IMPLEMENTED_AND_TESTED` |
| **File Transfer** | HTTPS TLS 1.3 chunked upload/download | HTTPS TLS 1.3 chunked upload/download | Shared file transfer client | `IMPLEMENTED_AND_TESTED` |
| **Remote Terminal** | ConPTY Windows Pseudo-Console | Linux POSIX PTY (`openpty`, `forkpty`, bash) | Terminal screen & keyboard | `IMPLEMENTED_AND_TESTED` |
| **System Telemetry** | WMI / Performance Counters | `/proc`, `/sys/class`, `loginctl` | Battery, CPU, RAM, Network stats | `IMPLEMENTED_AND_TESTED` |

---

## Display Server & Desktop Environment Compatibility

| Desktop Environment | Display Server | Greeter / PAM Support | Screen Capture | Input Injection | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **GNOME 45+** | Wayland | GDM (`gdm-password`) | XWayland windows only | `/dev/uinput` | Input/terminal/audio full; pure-Wayland screen capture requires a portal ScreenCast grant (not implemented) |
| **GNOME 40+** | X11 | GDM (`gdm-password`) | Direct X11 / ffmpeg | `/dev/uinput` | Full support |
| **KDE Plasma 5/6** | Wayland | SDDM (`sddm`) | XWayland windows only | `/dev/uinput` | Input/terminal/audio full; pure-Wayland screen capture requires a portal ScreenCast grant (not implemented) |
| **KDE Plasma 5** | X11 | SDDM (`sddm`) | Direct X11 / ffmpeg | `/dev/uinput` | Full support |
| **XFCE / MATE** | X11 | LightDM (`lightdm`) | Direct X11 / xwd | `/dev/uinput` | Full support on Debian, Mint, Arch |
