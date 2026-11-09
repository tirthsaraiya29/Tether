# Tether Code Signing, Manifest Detached Signature & Authenticode Architecture

## 1. Overview & Security Invariants

Tether enforces cryptographic authenticity and integrity across all update channels. An update compromises the entire workstation if tampered with because:
1. `Tether.Updater.exe` runs with elevated administrative privileges (`Verb = "runas"` / `requireAdministrator`).
2. The updater overwrites core system binaries and installs the Windows Credential Provider DLL into `%SystemRoot%\System32\TetherCredentialProvider.dll`, which runs directly inside `Winlogon.exe` (Session 0 LogonUI).

To eliminate local privilege escalation (LPE) and remote tampering:
- **Raw Manifest Detached Signature Verification (F2.1):** Every update manifest (`update-manifest.json`) MUST be accompanied by a detached cryptographic signature (`update-manifest.json.sig`). Raw bytes are verified against `AuthenticodeVerifier.PinnedManifestPublicKey` *prior* to JSON deserialization or trusting any manifest entries.
- **Fail-Closed Enforcement (F2.2):** Missing, forged, or invalid signatures abort execution immediately (exit code `14`), preventing any file replacement, service manipulation, or UI prompts.
- **Payload Hash Pre-Verification (F2.3):** Staged payload archives and files are checked for exact SHA-256 match against the authenticated manifest before extraction or execution.
- **Pinned Publisher Identity Verification (F2.4):** PE Authenticode verification enforces exact Distinguished Name / Organization matching (`ExpectedPublisherSubject = "CN=Tether Project, O=Tether, C=US"`) or pinned certificate thumbprint / public key, completely eliminating loose substring matching.

---

## 2. Production Code Signing Prerequisites

For official production releases:

### 2.1 Authenticode Code Signing Certificate
- **Type:** Extended Validation (EV) Code Signing Certificate issued by a Microsoft Trusted Root Certification Authority (e.g., DigiCert, Sectigo).
- **Subject Distinguished Name:**
  - `CN = Tether Project`
  - `O = Tether`
  - `C = US`
  - `ExpectedPublisherSubject = "CN=Tether Project, O=Tether, C=US"`
- **Hardware Security Module (HSM):**
  - EV code signing certificates require private key storage in a FIPS 140-2 Level 2+ physical hardware security module / cryptographic token, or cloud HSM (such as Azure Trusted Signing / Google Cloud KMS).
  - Private keys are non-exportable and never stored on local development disks or in Git.
- **Timestamping Authority:**
  - RFC 3161 compliant timestamp server (e.g., `http://timestamp.digicert.com` or `http://timestamp.sectigo.com`).
  - Algorithm: SHA-256 (`/tr http://timestamp.digicert.com /td sha256`).

### 2.2 Manifest Signing Keypair (ECDSA P-256)
- **Algorithm:** ECDSA with NIST P-256 curve (`SHA256withECDSA`).
- **Pinned Public Key (SPKI Base64):**
  ```
  MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+d23PzDk0hLw5v0fE9W+tqC7F3jV4jA9K3F1uT7wH5s=
  ```
  Embedded in `shared/Tether.Shared/Security/AuthenticodeVerifier.cs` as `PinnedManifestPublicKey`.
- **Private Key Storage:**
  - Kept in secure CI/CD secrets vault or hardware signing enclave.
  - Generates detached signature `update-manifest.json.sig` over raw `update-manifest.json` bytes.

---

## 3. Release Pipeline Signing Procedure

1. **Build Binaries:**
   ```powershell
   dotnet build Tether.slnx -c Release -v q --nologo
   ```
2. **Sign Native and Managed PE Binaries:**
   ```powershell
   signtool sign /sha1 <THUMBPRINT> /tr http://timestamp.digicert.com /td sha256 /fd sha256 `
       bin\Release\net10.0-windows\Tether.DesktopUI.exe `
       bin\Release\net10.0-windows\Tether.Updater.exe `
       bin\Release\net10.0-windows\TetherCredentialProvider.dll
   ```
3. **Assemble Payload Archive:**
   Compress release binaries into `update_payload.zip`. Compute its SHA-256:
   ```powershell
   $payloadHash = (Get-FileHash -Algorithm SHA256 .\update_payload.zip).Hash.ToLowerInvariant()
   ```
4. **Generate `update-manifest.json`:**
   Populate file hashes, file sizes, and top-level `payloadSha256`.
5. **Generate Detached Signature `update-manifest.json.sig`:**
   Sign `update-manifest.json` bytes using ECDSA P-256 private key:
   ```powershell
   # OpenSSL or .NET ECDsa tool
   openssl dgst -sha256 -sign manifest_privkey.pem -out update-manifest.json.sig update-manifest.json
   ```
6. **Publish Release Assets to GitHub:**
   - `update-manifest.json`
   - `update-manifest.json.sig`
   - `update_payload.zip`
   - `Tether-Setup-<version>.exe`

---

## 4. Development & Test Mock Semantics

In developer environments and CI test runners where official EV hardware tokens are physically unavailable:
- **`UpdateEnvironment.IsDebugOrDevEnvironment()`:**
  Detects debug configurations, `TETHER_DEV=1`, `TETHER_DEBUG=1`, `TETHER_SKIP_UPDATES=1`, attached debuggers, or compilation under bin/Debug. In this mode, background update checks are suppressed to prevent interference.
- **Fail-Closed Staging & Pinning Verification:**
  When testing Authenticode or manifest signature verification programmatically:
  - Unit tests use programmatic `ECDsa.Create(ECCurve.NamedCurves.nistP256)` instances to sign test manifests and verify both valid and tampered scenarios (see `SecurityRemediationRegressionTests.cs`).
  - Unit tests pass `pinnedThumbprint` to test `VerifyFileAuthenticode` without requiring public CA trust anchors.
- **External Blocker Note (F2.5):**
  Official Authenticode signing requires the production EV hardware token. Local builds of `Tether.DesktopUI.exe` and `Tether.Updater.exe` remain unsigned during local development. In production deployments, unsigned binaries fail closed.
