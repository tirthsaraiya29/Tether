# Tether v1.1.2 Release Notes

**Release Title:** v1.1.2 — Streamlined Single Sign-In, Filesystem Sync & Security Hardening

## Overview

Tether v1.1.2 delivers a major hardening and UX refinement across Windows and Android integration. This release introduces a streamlined single sign-in path for Windows Credential Provider, automated local database synchronization between devices, clean architectural refactoring, and comprehensive UI terminology polish.

---

## What's New in v1.1.2

### 1. Streamlined Single Sign-In Windows Unlock
- **Phone-App Unlock Exclusivity:** The native C++ `TetherCredentialProvider` now exclusively enforces phone-app unlock. Manual password boxes, TPM-stored password options, and screen-unlock toggles on the Windows logon tile have been removed to establish a secure single sign-in path.
- **Registry Vault Hardening:** Credential secrets are securely maintained in hardened registry paths protected by strict Discretionary Access Control Lists (`VaultDaclVersion=2`) and DPAPI encryption (`CryptProtectData`).

### 2. Filesystem & Database Auto-Sync
- Implemented robust background database synchronization between the Android companion and Windows workstation filesystem databases, ensuring state consistency across the local network boundary.

### 3. Architecture & Codebase Cleanup
- **File Transfer Removal:** Cleanly removed experimental file transfer features and protocols across Android companion (`TetherFileTransferManager`, etc.) and Windows communication services to keep the core local trust and control plane lightweight and secure.
- **IPC & Transport Refinements:** Streamlined named-pipe IPC and TLS 1.3 direct TCP packet routing.

### 4. UI Terminology & Android Polish
- **Terminology Updates:** Standardized UI labels, status messages, and navigation headers across Android screens and Windows Desktop UI.
- **Permissions & Updates:** Added a dedicated Android permissions dashboard and a background `UpdateCheckService` monitoring GitHub releases.

### 5. Security & Authorization Hardening
- **Pinned Key Verification:** Tightened device authorization checks by strictly verifying peer fingerprints against stored trusted keys.
- **Log Input Sanitization:** Sanitized log inputs and restricted external storage access on Android.

---

## Installation & Upgrade Instructions

### Windows
1. Run `Tether-Setup-1.1.2.exe` as Administrator.
2. The installer registers `TetherCredentialProvider.dll`, configures `Tether.CommunicationService`, and opens port `37123` (control).
3. Launch `Tether Desktop UI`.

### Android
1. Transfer and install `Tether-1.1.2.apk` on your Android device (Android 12+).
2. Grant requested local network and notification permissions.
3. Pair with your Windows workstation via cryptographic QR/pairing code exchange.
