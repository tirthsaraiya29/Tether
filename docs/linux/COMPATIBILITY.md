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
| **Screen Streaming** | Desktop Duplication API (DXGI) | MJPEG Stream (`/api/desktop/stream`) | `RemoteDesktopScreen` | `IMPLEMENTED_AND_TESTED` |
| **Screen Capture** | GDI / Direct3D JPEG | Snapshot (`/api/desktop/screenshot`) | Remote desktop viewer | `IMPLEMENTED_AND_TESTED` |
| **Window Listing** | Win32 `EnumWindows` | `wmctrl` / X11 / Wayland Session query | `RemoteDesktopScreen` windows list | `IMPLEMENTED_AND_TESTED` |
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
| **GNOME 45+** | Wayland | GDM (`gdm-password`) | PipeWire / Portal fallback | `/dev/uinput` | Full support on Fedora, RHEL, Ubuntu |
| **GNOME 40+** | X11 | GDM (`gdm-password`) | Direct X11 / ffmpeg | `/dev/uinput` | Full support |
| **KDE Plasma 5/6** | Wayland | SDDM (`sddm`) | PipeWire / Portal fallback | `/dev/uinput` | Full support |
| **KDE Plasma 5** | X11 | SDDM (`sddm`) | Direct X11 / ffmpeg | `/dev/uinput` | Full support |
| **XFCE / MATE** | X11 | LightDM (`lightdm`) | Direct X11 / xwd | `/dev/uinput` | Full support on Debian, Mint, Arch |
