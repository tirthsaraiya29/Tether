# TETHER LINUX FORENSIC BASELINE

**Audit Date:** 2026-11-23  
**Auditor:** Principal Security & Systems Engineer (Autonomous Engineering Mission)  
**Host Environment:** Fedora Linux 45 (Workstation Edition), x86_64, Kernel with systemd, SELinux, PAM  
**Runtime Toolchains:** .NET SDK 10.0.113, GCC 16.2.1 20261029  

---

## 1. Git Repository State

- **Repository Origin URL:** `git@github.com:tirthsaraiya29/Tether.git`
- **Default Branch:** `main`
- **Baseline Commit SHA:** `4c7e8e66ad1166ec200302cc0252a37a88131a73`
- **Working Tree State at Inception:** Clean (`nothing to commit, working tree clean`)
- **Mission Feature Branch:** `feature/linux-production-implementation`

### Remote Configuration & Branches
```text
origin  git@github.com:tirthsaraiya29/Tether.git (fetch)
origin  git@github.com:tirthsaraiya29/Tether.git (push)

Remotes:
  origin/HEAD -> origin/main
  origin/main
  origin/beta
  origin/legacy
```

### Repository Tags
- `v1.0.0` through `v1.2.3`

---

## 2. Recent Linux Engineering Milestones

Top 10 commits prior to the start of this forensic audit:
1. `4c7e8e6` `fix(selinux,hardware): resolve GDM PAM socket denial and eliminate blocking audio process calls`
2. `ac0fe79` `fix(security,daemon): grant POWER_ELEVATED capability to paired devices and alias LOCK capability`
3. `cc57691` `fix(daemon): handle state and volume queries, add audio response stubs`
4. `1febdc5` `fix(pipeline): harden command delivery, rate limit binary input, and support dynamic POSIX shells`
5. `8c0a7f7` `fix(pairing): implement secure Linux discovery, transcript preservation, and user-space prompt dispatch`
6. `694fd90` `docs(security): document security architecture, cryptographic proof-of-possession, and isolation controls`
7. `3c12ecf` `fix(security): enforce capability authorization in Linux packet router and add platform guard to AuthenticodeVerifier`
8. `6a1a429` `fix(tests): eliminate false-positive live daemon tests and add in-process integration suite`
9. `e1236bb` `fix(security): restrict uinput to dedicated tether group and harden systemd sandbox`
10. `b879e85` `fix(security): strengthen Linux trust store with HKDF-derived master key, record fingerprint validation, and atomic backups`

---

## 3. Repository Structure & Project Boundaries

```text
Tether/
├── apps/
│   ├── android-companion/        # Android client application (Jetpack Compose, Kotlin)
│   ├── desktop-ui/               # Windows Desktop UI (.NET WPF)
│   └── updater/                  # Windows updater (.NET)
├── installer/
│   ├── linux/                    # Linux installer, uninstaller, systemd, SELinux policy
│   └── windows/                  # Windows installer (Inno Setup / scripts)
├── services/
│   ├── communication-service/
│   │   ├── Tether.CommunicationService/ # Windows communication daemon (.NET)
│   │   ├── Tether.LinuxDaemon/          # Linux background daemon (.NET Kestrel/TCP/UnixSocket)
│   │   └── Tether.SessionHelper/        # Windows Session Helper (.NET)
│   ├── enforcement-engine/       # Security policy enforcement (.NET)
│   ├── event-bus/                # Internal event messaging (.NET)
│   ├── pam-tether/               # Native Linux PAM module (C / libpam)
│   ├── panic-engine/             # Device panic & emergency lock engine (.NET)
│   ├── recovery-engine/          # Recovery & fallback mechanism (.NET)
│   └── trust-engine/             # Device trust calculation & attestation (.NET)
├── shared/
│   └── Tether.Shared/            # Cross-platform shared protocols, models, encryption (.NET)
├── tests/
│   ├── Tether.LinuxTests/        # Linux-specific unit & integration test suite (xUnit)
│   └── Tether.Tests/             # Shared & Windows test suite (xUnit)
├── tools/
│   └── tetherctl/                # Linux management CLI tool (.NET)
└── TetherCredentialProvider/     # Windows Credential Provider (C++ Native COM DLL)
```

---

## 4. Operational Boundaries

- **Target OS:** Fedora Linux, Ubuntu, Debian, Arch Linux.
- **Display Servers:** Wayland (Primary) and X11 (Fallback).
- **Display Managers:** GDM, SDDM, LightDM.
- **Companion:** Android Companion (Bluetooth / LAN TLS 1.3 / mDNS / UDP Discovery).
