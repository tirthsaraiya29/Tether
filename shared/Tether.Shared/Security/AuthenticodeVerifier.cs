using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace Tether.Shared.Security;

/// <summary>
/// Authenticode and publisher trust verification for updater payloads, installers, and update manifests.
/// </summary>
public static class AuthenticodeVerifier
{
    #region WinVerifyTrust Native Interop

    private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOKE_NONE = 0;
    private const uint WTD_REVOKE_WHOLECHAIN = 1;
    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_STATEACTION_IGNORE = 0;
    private const uint WTD_SAFER_FLAG = 0x00000100;

    private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 =
        new Guid("{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}");

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile; // Points to WINTRUST_FILE_INFO
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string? pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern int WinVerifyTrust(
        IntPtr hwnd,
        [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID,
        IntPtr pWVTData);

    #endregion

    /// <summary>
    /// Tether official publisher public key in SubjectPublicKeyInfo (SPKI) Base64 format.
    /// Can also be matched by certificate Subject and Thumbprint or RSA public key.
    /// </summary>
    public const string ExpectedPublisherSubject = "CN=Tether Project, O=Tether, C=US";
    public const string ExpectedPublisherOrganization = "Tether Project";

    // Pinned ECDSA P-256 public key (X9.62 uncompressed 64-byte key or SPKI) used to sign update-manifest.json
    // Public key parameter encoded in PEM/Base64 or ECDsa XML/ECC
    public const string PinnedManifestPublicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+d23PzDk0hLw5v0fE9W+tqC7F3jV4jA9K3F1uT7wH5s=";

    /// <summary>
    /// Verifies the Authenticode signature of a PE file (installer, DLL, EXE).
    /// Enforces:
    /// 1. File exists and is not a reparse point.
    /// 2. Embedded Authenticode digital signature is cryptographically valid and not tampered with.
    /// 3. Certificate chain builds to a trusted root or pinned publisher certificate.
    /// 4. Publisher subject/identity matches the expected Tether publisher.
    /// </summary>
    public static bool VerifyFileAuthenticode(string filePath, string? pinnedThumbprint = null, string? pinnedPublicKey = null)
    {
        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
        {
            return false;
        }

        // Reparse points / symlink protection
        if ((File.GetAttributes(filePath) & FileAttributes.ReparsePoint) != 0)
        {
            return false;
        }

        // 1. Native WinVerifyTrust validation
        var fileInfo = new WINTRUST_FILE_INFO
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
            pcwszFilePath = Path.GetFullPath(filePath),
            hFile = IntPtr.Zero,
            pgKnownSubject = IntPtr.Zero
        };

        IntPtr pFileInfo = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
        IntPtr pWintrustData = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_DATA>());

        try
        {
            Marshal.StructureToPtr(fileInfo, pFileInfo, false);

            var wvtData = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                pPolicyCallbackData = IntPtr.Zero,
                pSIPClientData = IntPtr.Zero,
                dwUIChoice = WTD_UI_NONE,
                fdwRevocationChecks = WTD_REVOKE_NONE,
                dwUnionChoice = WTD_CHOICE_FILE,
                pFile = pFileInfo,
                dwStateAction = WTD_STATEACTION_IGNORE,
                hWVTStateData = IntPtr.Zero,
                pwszURLReference = null,
                dwProvFlags = WTD_SAFER_FLAG,
                dwUIContext = 0,
                pSignatureSettings = IntPtr.Zero
            };

            Marshal.StructureToPtr(wvtData, pWintrustData, false);

            int result = WinVerifyTrust(INVALID_HANDLE_VALUE, WINTRUST_ACTION_GENERIC_VERIFY_V2, pWintrustData);
            if (result != 0) // ERROR_SUCCESS == 0
            {
                return false;
            }
        }
        catch
        {
            return false;
        }
        finally
        {
            if (pFileInfo != IntPtr.Zero) Marshal.FreeHGlobal(pFileInfo);
            if (pWintrustData != IntPtr.Zero) Marshal.FreeHGlobal(pWintrustData);
        }

        // 2. Extract and validate signer certificate chain & publisher identity
        try
        {
#pragma warning disable SYSLIB0057
            using var rawCert = X509Certificate.CreateFromSignedFile(filePath);
            if (rawCert == null) return false;
            using var cert2 = new X509Certificate2(rawCert);

            // Verify certificate dates
            DateTime now = DateTime.UtcNow;
            if (now < cert2.NotBefore.ToUniversalTime() || now > cert2.NotAfter.ToUniversalTime())
            {
                return false;
            }

            // Verify publisher identity against pinned attributes (strict fail-closed, no loose substring matching)
            bool hasPinnedIdentifier = !string.IsNullOrEmpty(pinnedThumbprint) || !string.IsNullOrEmpty(pinnedPublicKey);

            if (!string.IsNullOrEmpty(pinnedThumbprint))
            {
                string cleanPinned = pinnedThumbprint.Replace(":", "").Replace(" ", "");
                if (!string.Equals(cert2.Thumbprint, cleanPinned, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }
            }

            if (!string.IsNullOrEmpty(pinnedPublicKey))
            {
                string pubKeyBase64 = Convert.ToBase64String(cert2.GetPublicKey());
                if (!string.Equals(pubKeyBase64, pinnedPublicKey, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }
            }

            // Strict Subject / Distinguished Name validation against pinned publisher identity
            bool subjectMatches = MatchesExpectedPublisher(cert2);
            if (!hasPinnedIdentifier && !subjectMatches)
            {
                return false;
            }

            // Full X509Chain validation
            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck; // Offline / LAN air-gapped capability
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
            bool chainValid = chain.Build(cert2);
            if (!chainValid)
            {
                // In test environments or self-signed test publisher roots, verify certificate itself
                if (chain.ChainStatus.Length > 0 && 
                    chain.ChainStatus[0].Status == X509ChainStatusFlags.UntrustedRoot &&
                    !string.IsNullOrEmpty(pinnedThumbprint))
                {
                    // If thumbprint is explicitly pinned, untrusted root warning may be accepted
                    return true;
                }
                return false;
            }

            return true;
#pragma warning restore SYSLIB0057
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Strictly verifies that the certificate Subject matches the expected Tether publisher identity.
    /// Replaces loose substring checks with exact Distinguished Name / RDN validation.
    /// Fails closed if the subject does not match ExpectedPublisherSubject or expected components.
    /// </summary>
    public static bool MatchesExpectedPublisher(X509Certificate2 cert)
    {
        if (cert == null) return false;

        string subject = cert.Subject;
        if (string.IsNullOrWhiteSpace(subject)) return false;

        if (string.Equals(subject.Trim(), ExpectedPublisherSubject, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        // Parse Distinguished Name RDN components
        var rdns = ParseDistinguishedName(subject);

        // Common Name (CN) must strictly equal "Tether Project"
        if (!rdns.TryGetValue("CN", out string? cn) ||
            !string.Equals(cn, ExpectedPublisherOrganization, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        // Organization (O) if present must strictly equal "Tether"
        if (rdns.TryGetValue("O", out string? org) &&
            !string.Equals(org, "Tether", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        // Country (C) if present must strictly equal "US"
        if (rdns.TryGetValue("C", out string? country) &&
            !string.Equals(country, "US", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return true;
    }

    private static Dictionary<string, string> ParseDistinguishedName(string dn)
    {
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(dn)) return dict;

        var parts = dn.Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries);
        foreach (var part in parts)
        {
            int eqIdx = part.IndexOf('=');
            if (eqIdx > 0 && eqIdx < part.Length - 1)
            {
                string key = part.Substring(0, eqIdx).Trim();
                string val = part.Substring(eqIdx + 1).Trim().Trim('"', '\'');
                dict[key] = val;
            }
        }
        return dict;
    }

    /// <summary>
    /// Creates an ECDsa instance initialized with the pinned manifest public key.
    /// </summary>
    public static ECDsa CreatePinnedManifestPublicKey(string? spkiBase64 = null)
    {
        var ecdsa = ECDsa.Create();
        ecdsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(spkiBase64 ?? PinnedManifestPublicKey), out _);
        return ecdsa;
    }

    /// <summary>
    /// Verifies the detached ECDSA signature of update-manifest.json raw bytes against the pinned manifest public key.
    /// Fails closed if manifest bytes or signature bytes are missing, corrupted, or signature verification fails.
    /// </summary>
    public static bool VerifyManifestSignature(byte[] manifestBytes, byte[] signatureBytes, string? pinnedPublicKeySpki = null)
    {
        if (manifestBytes == null || manifestBytes.Length == 0 || signatureBytes == null || signatureBytes.Length == 0)
        {
            return false;
        }

        try
        {
            using var ecdsa = CreatePinnedManifestPublicKey(pinnedPublicKeySpki);
            return VerifyManifestSignature(manifestBytes, signatureBytes, ecdsa);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Verifies the detached ECDSA signature of update-manifest.json against a provided ECDsa public key.
    /// Supports raw DER/IEEE-P1363 signatures as well as Base64/Hex-encoded detached signature payloads.
    /// </summary>
    public static bool VerifyManifestSignature(byte[] manifestBytes, byte[] signatureBytes, ECDsa publisherKey)
    {
        if (manifestBytes == null || manifestBytes.Length == 0 || signatureBytes == null || signatureBytes.Length == 0 || publisherKey == null)
        {
            return false;
        }

        try
        {
            // 1. Direct signature verification (raw binary signature)
            if (publisherKey.VerifyData(manifestBytes, signatureBytes, HashAlgorithmName.SHA256))
            {
                return true;
            }

            // 2. Base64/Hex string decoding if signature was stored as text
            string sigText = Encoding.UTF8.GetString(signatureBytes).Trim();
            if (!string.IsNullOrEmpty(sigText))
            {
                try
                {
                    byte[] decoded = Convert.FromBase64String(sigText);
                    if (decoded.Length > 0 && publisherKey.VerifyData(manifestBytes, decoded, HashAlgorithmName.SHA256))
                    {
                        return true;
                    }
                }
                catch (FormatException) { }

                try
                {
                    byte[] hexDecoded = Convert.FromHexString(sigText);
                    if (hexDecoded.Length > 0 && publisherKey.VerifyData(manifestBytes, hexDecoded, HashAlgorithmName.SHA256))
                    {
                        return true;
                    }
                }
                catch (FormatException) { }
            }

            return false;
        }
        catch
        {
            return false;
        }
    }
}
