# Security Policy

## Supported Versions

Tether is currently under active development. Security fixes are prioritized for the latest development version.

| Version / Branch | Supported |
| --- | --- |
| Latest development version (`main`) | ✅ |
| Development branch (`beta`) | ✅ |
| Older releases and unsupported builds | ❌ |

Support for a particular branch does not guarantee that every feature is production-ready or that every known security issue has been resolved.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues or public discussions.**

If you discover a potential security vulnerability in Tether, please report it privately through GitHub's security reporting feature, if enabled for this repository:

1. Open the [Tether repository](https://github.com/tirthsaraiya29/Tether).
2. Navigate to the **Security** tab.
3. Select **Report a vulnerability** under Private vulnerability reporting.
4. Include enough information to reproduce and assess the issue.

Please include, where applicable:

- The affected component (Android app, Windows service, Credential Provider, desktop UI, or communication protocol).
- The affected version, commit, branch, or build.
- A description of the vulnerability and its potential impact.
- Reproduction steps or a proof of concept.
- Any suggested mitigation or remediation.

### What to Expect

- **Acknowledgment:** I aim to acknowledge reports within 7 calendar days.
- **Assessment:** I will investigate the report and may request additional information to validate the finding.
- **Updates:** I aim to provide a status update within 14 calendar days of acknowledgment, with further updates as the investigation progresses.
- **Resolution:** If the vulnerability is confirmed, I will prioritize a fix based on its severity and impact.
- **Disclosure:** Coordinated disclosure will be preferred where practical, allowing time to investigate, develop a fix, and communicate relevant mitigations.

These are response targets, not guaranteed deadlines.

### Scope

Security reports may concern, among other things:

- Authentication, device pairing, authorization, and trust verification.
- TLS configuration, certificate validation, and communication security.
- Command execution and privilege boundaries between Windows components.
- Windows Credential Provider and lock/unlock workflows.
- Android Keystore usage and key management.
- IPC, named pipes, session boundaries, and local privilege escalation.
- File transfers, input handling, replay attacks, and denial-of-service vulnerabilities.

Please test only systems you own or have explicit permission to assess. Avoid accessing other people's data, disrupting services, or conducting destructive testing.

### Out of Scope

The following are generally outside the scope of a security report unless they demonstrate a concrete security impact:

- Vulnerabilities affecting unsupported or substantially outdated builds.
- Issues requiring an already-compromised device or administrator-level access, without a meaningful additional security impact.
- Theoretical concerns without a reproducible attack scenario.
- General feature requests, usability issues, or non-security bugs.

Reports outside these categories may still be considered at the maintainer's discretion.

### Safe Harbor

Good-faith security research conducted within the boundaries described above is welcome. Do not intentionally compromise systems, access or modify data that does not belong to you, or disrupt services. Stop testing and report the issue if you encounter sensitive data.

This policy does not grant permission to test systems you do not own or control, and it does not override applicable laws or third-party policies.
