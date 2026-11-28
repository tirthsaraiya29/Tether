# Remediation Progress Log

Branch: `main` (local only; nothing pushed)
Baseline: `d3df8bf`

Verification legend: **unit** = automated test run here; **build** = compiled here;
**code-verified** = reviewed against the implementation, not executed; **not verified** =
no representative environment available.

| # | Phase / change | Commit | Verification |
|---|---|---|---|
| 1 | Cross-platform audit (`AUDIT/CROSS_PLATFORM_GAP_REPORT.md`) | `4f8752b` | code-verified |
| 2 | Linux grants + advertises admin capability; Android maps `LINUX_ADMIN`/`ADMIN`; legacy trust records migrated at load | `714b88c` | unit (Android `CompanionCapabilityTests`, .NET suites) |
| – | Credential provider no longer requires a missing `pch.h` (pre-existing build break) | `6da282c` | build (MSBuild x64) |
| 3 | Linux admin telemetry/specs match the Android JSON contract; no fabricated GPU VRAM/disk/RAM; ACPI/power-profiles-daemon/cpufreq power backend with verified apply; distro-aware update check (apt/dnf/zypper/pacman) and removal of the shadowing `CHECK_UPDATES`; validated + critical-unit-guarded service control; Linux battery report + router handler | `eb1846a` | unit (127 Linux tests), build |
| 4 | Android: System Apps launcher removed; admin UI platform-aware; no `C:`/`NTFS` defaults | `0a7978a` | build (`assembleDebug`) |
| 5 | Android: transfer-token denials surfaced instead of empty-token requests; failed on disconnect; laptop cache keyed to the authenticated peer fingerprint and cleared on Forget | `124520f` | build, unit |
| 6 | Linux: client-supplied audio device / sink-input ids validated before reaching wpctl/pactl | `ac9e7a9` | unit |
| 7 | Linux: pure-Wayland capture refused instead of root KMS bypass; docs corrected | `89da7b7` | build, unit |
| 8 | Linux: capture resolves only root-owned distro ffmpeg paths, drops to the session user via runuser; terminal resolves the user's `/etc/passwd` login shell, validates explicit shells, sets HOME/SHELL/USER | `1306621` | build, unit |
| 9 | Linux: a reconnecting device aborts its replaced session so stale transports stop receiving broadcasts | `15a11a5` | build, unit |
| 10 | Android: remaining Windows-only labels removed from shared UI | `ad0275a` | build, unit |
| 11 | Linux: command dedup cache scoped to the authenticated device; cross-device request-id replay covered | `c85be54` | unit |
| 12 | Linux: transfer tokens accepted only from headers, never URLs; Windows running-window regression tests | `0849f7e` | unit |

## Findings closed
D1–D9 in `AUDIT/CROSS_PLATFORM_GAP_REPORT.md`, except D9: the stress test passed on every
rerun (`5/5` isolated runs plus full-suite runs); the single baseline failure was not reproduced.

## Known limitations / not verified
- No Linux host or Android device was available. Linux behaviour is unit-tested on a Windows
  host with `/proc`, `/sys`, `systemctl`, `wpctl` and `ffmpeg` absent, so the *fallback and
  refusal* paths are exercised; the happy paths (real PipeWire, systemd, apt) are code-verified
  only.
- Pure Wayland screen capture needs an XDG Desktop Portal `ScreenCast` client; not implemented.
- Running-window discovery on Linux uses `wmctrl`, so it only sees X11/XWayland windows.
- Android cache tests need an instrumented `Context`; `claimOwner`/`clearAll` are not unit-tested.
- The 8 `LiveDaemonIntegrationTests` are skipped by design on non-Linux hosts.
- `dotnet build Tether.slnx` cannot build the two `.vcxproj` projects (CLI limitation); they were
  built separately with VS BuildTools MSBuild x64.

## Remaining gaps
- End-to-end transfer matrix and real-desktop window regression need physical Windows/Android hosts.
- Pure-Wayland screen capture still needs an XDG portal ScreenCast client.
- Linux audio/input happy paths remain code-verified only (no Linux host available).
- Performance/soak audit not performed.
- The automated security review flagged two Medium issues in this work (cache ownership fail-open,
  privileged ffmpeg resolution); both were fixed (`3e9d41e`, `1306621`).
