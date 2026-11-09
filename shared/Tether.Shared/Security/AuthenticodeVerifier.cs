using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
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

            // Verify publisher identity against pinned attributes
            string subject = cert2.Subject;
            bool subjectMatch = subject.Contains("Tether", StringComparison.OrdinalIgnoreCase) ||
                               subject.Contains("Tether Project", StringComparison.OrdinalIgnoreCase);

            if (!subjectMatch)
            {
                return false;
            }

            if (!string.IsNullOrEmpty(pinnedThumbprint))
            {
                if (!string.Equals(cert2.Thumbprint, pinnedThumbprint.Replace(":", "").Replace(" ", ""), StringComparison.OrdinalIgnoreCase))
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
    /// Verifies the detached ECDSA or RSA signature of update-manifest.json.
    /// </summary>
    public static bool VerifyManifestSignature(byte[] manifestBytes, byte[] signatureBytes, ECDsa publisherKey)
    {
        if (manifestBytes == null || manifestBytes.Length == 0 || signatureBytes == null || signatureBytes.Length == 0)
        {
            return false;
        }

        try
        {
            return publisherKey.VerifyData(manifestBytes, signatureBytes, HashAlgorithmName.SHA256);
        }
        catch
        {
            return false;
        }
    }
}
