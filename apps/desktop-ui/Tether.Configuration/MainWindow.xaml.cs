using Microsoft.Win32;
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Windows;

namespace Tether.Configuration
{
    public partial class MainWindow : Window
    {
        // ========================================================================
        // Win32 P/Invoke Declarations
        // ========================================================================

        [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool CryptProtectData(
            ref DATA_BLOB pDataIn,
            string szDataDescr,
            ref DATA_BLOB pOptionalEntropy,
            IntPtr pvReserved,
            IntPtr pPromptStruct,
            uint dwFlags,
            ref DATA_BLOB pDataOut);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool LogonUser(
            string lpszUsername,
            string lpszDomain,
            string lpszPassword,
            int dwLogonType,
            int dwLogonProvider,
            out IntPtr phToken);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("secur32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetUserNameEx(
            int nameFormat,
            StringBuilder lpNameBuffer,
            ref uint lpnSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr LocalFree(IntPtr hMem);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct DATA_BLOB
        {
            public int cbData;
            public IntPtr pbData;
        }

        // ========================================================================
        // Constants
        // ========================================================================

        private const uint CRYPTPROTECT_UI_FORBIDDEN = 0x1;
        private const uint CRYPTPROTECT_LOCAL_MACHINE = 0x4;

        private const int LOGON32_LOGON_INTERACTIVE = 2;
        private const int LOGON32_LOGON_NETWORK = 3;
        private const int LOGON32_PROVIDER_DEFAULT = 0;

        private enum EXTENDED_NAME_FORMAT
        {
            NameUnknown = 0,
            NameFullyQualifiedDN = 1,
            NameSamCompatible = 2,
            NameDisplay = 3,
            NameUniqueId = 6,
            NameCanonical = 7,
            NameUserPrincipal = 8
        }

        // ========================================================================
        // Constructor
        // ========================================================================

        public MainWindow()
        {
            InitializeComponent();
            SetUserTypeDisplay();
        }

        // ========================================================================
        // User Type Detection
        // ========================================================================

        private void SetUserTypeDisplay()
        {
            string upn = GetCurrentUserPrincipalName();
            bool isMicrosoft = !string.IsNullOrEmpty(upn) && upn.Contains('@');

            TxtUserType.Text = isMicrosoft
                ? $"✓ Current user type: Microsoft Account ({upn})"
                : "✓ Current user type: Local / Domain account";
        }

        private string GetCurrentUserPrincipalName()
        {
            uint size = 256;
            StringBuilder sb = new StringBuilder((int)size);

            if (GetUserNameEx((int)EXTENDED_NAME_FORMAT.NameUserPrincipal, sb, ref size))
            {
                return sb.ToString();
            }

            // Fallback: try SamCompatible (DOMAIN\User)
            size = 256;
            sb.Clear();
            if (GetUserNameEx((int)EXTENDED_NAME_FORMAT.NameSamCompatible, sb, ref size))
            {
                return sb.ToString();
            }

            return Environment.UserName;
        }

        // ========================================================================
        // Password Verification (Supports Both Local & Microsoft Accounts)
        // ========================================================================

        private bool VerifyWindowsPassword(string password)
        {
            string upn = GetCurrentUserPrincipalName();
            string domain = Environment.UserDomainName;
            string username = Environment.UserName;
            string computerName = Environment.MachineName;

            IntPtr token;
            bool success = false;

            // Try multiple logon types for each combination

            // 1. Try UPN (user@domain) - works for Microsoft Accounts
            if (!string.IsNullOrEmpty(upn) && upn.Contains('@'))
            {
                // Interactive logon with domain = null
                success = LogonUser(upn, null, password,
                                    LOGON32_LOGON_INTERACTIVE,
                                    LOGON32_PROVIDER_DEFAULT,
                                    out token);
                if (success) { CloseHandle(token); return true; }

                // Network logon (less restrictive)
                success = LogonUser(upn, null, password,
                                    LOGON32_LOGON_NETWORK,
                                    LOGON32_PROVIDER_DEFAULT,
                                    out token);
                if (success) { CloseHandle(token); return true; }

                // Try with domain extracted from UPN
                string upnDomain = upn.Substring(upn.IndexOf('@') + 1);
                success = LogonUser(upn, upnDomain, password,
                                    LOGON32_LOGON_INTERACTIVE,
                                    LOGON32_PROVIDER_DEFAULT,
                                    out token);
                if (success) { CloseHandle(token); return true; }

                success = LogonUser(upn, upnDomain, password,
                                    LOGON32_LOGON_NETWORK,
                                    LOGON32_PROVIDER_DEFAULT,
                                    out token);
                if (success) { CloseHandle(token); return true; }
            }

            // 2. Try domain\username
            success = LogonUser(username, domain, password,
                                LOGON32_LOGON_INTERACTIVE,
                                LOGON32_PROVIDER_DEFAULT,
                                out token);
            if (success) { CloseHandle(token); return true; }

            success = LogonUser(username, domain, password,
                                LOGON32_LOGON_NETWORK,
                                LOGON32_PROVIDER_DEFAULT,
                                out token);
            if (success) { CloseHandle(token); return true; }

            // 3. Try computer\username (local accounts)
            success = LogonUser(username, computerName, password,
                                LOGON32_LOGON_INTERACTIVE,
                                LOGON32_PROVIDER_DEFAULT,
                                out token);
            if (success) { CloseHandle(token); return true; }

            success = LogonUser(username, computerName, password,
                                LOGON32_LOGON_NETWORK,
                                LOGON32_PROVIDER_DEFAULT,
                                out token);
            if (success) { CloseHandle(token); return true; }

            // 4. Final fallback: just username with no domain
            success = LogonUser(username, null, password,
                                LOGON32_LOGON_INTERACTIVE,
                                LOGON32_PROVIDER_DEFAULT,
                                out token);
            if (success) { CloseHandle(token); return true; }

            success = LogonUser(username, null, password,
                                LOGON32_LOGON_NETWORK,
                                LOGON32_PROVIDER_DEFAULT,
                                out token);
            if (success) { CloseHandle(token); return true; }

            return false;
        }

        // ========================================================================
        // Registry Management
        // ========================================================================

        private void ClearRegistryKeys()
        {
            try
            {
                using RegistryKey? key = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Tether\CredentialProvider",
                    true);

                if (key == null) return;

                // Get all value names
                string[] valueNames = key.GetValueNames();

                foreach (string name in valueNames)
                {
                    // Don't delete PhonePublicKeyBase64 - it's managed by BLE auto-pairing
                    if (name == "PhonePublicKeyBase64") continue;
                    key.DeleteValue(name);
                }

                System.Diagnostics.Debug.WriteLine("Registry keys cleared (except PhonePublicKeyBase64)");
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Failed to clear registry: {ex.Message}");
            }
        }

        // ========================================================================
        // DPAPI Encryption Helpers
        // ========================================================================

        private bool StoreEncryptedPassword(string cleartextPassword)
        {
            try
            {
                byte[] rawPlainBytes = Encoding.Unicode.GetBytes(cleartextPassword ?? string.Empty);

                DATA_BLOB dataIn = new DATA_BLOB();
                DATA_BLOB dataOut = new DATA_BLOB();
                DATA_BLOB entropy = new DATA_BLOB();

                dataIn.cbData = rawPlainBytes.Length;
                dataIn.pbData = Marshal.AllocHGlobal(rawPlainBytes.Length);
                Marshal.Copy(rawPlainBytes, 0, dataIn.pbData, rawPlainBytes.Length);

                try
                {
                    bool success = CryptProtectData(
                        ref dataIn,
                        "TetherCredentialProviderSecret",
                        ref entropy,
                        IntPtr.Zero,
                        IntPtr.Zero,
                        CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE,
                        ref dataOut);

                    if (success)
                    {
                        byte[] encryptedPayload = new byte[dataOut.cbData];
                        Marshal.Copy(dataOut.pbData, encryptedPayload, 0, dataOut.cbData);

                        using RegistryKey? key = Registry.LocalMachine.CreateSubKey(
                            @"SOFTWARE\Tether\CredentialProvider",
                            true);

                        if (key == null)
                        {
                            throw new InvalidOperationException("Failed to create/open registry key.");
                        }

                        key.SetValue("EncryptedPassword", encryptedPayload, RegistryValueKind.Binary);
                        return true;
                    }

                    int lastError = Marshal.GetLastWin32Error();
                    System.Diagnostics.Debug.WriteLine($"CryptProtectData failed with error: {lastError}");
                    return false;
                }
                finally
                {
                    if (dataIn.pbData != IntPtr.Zero)
                        Marshal.FreeHGlobal(dataIn.pbData);

                    if (dataOut.pbData != IntPtr.Zero)
                        LocalFree(dataOut.pbData);
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"StoreEncryptedPassword exception: {ex.Message}");
                MessageBox.Show($"Encryption error: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return false;
            }
        }

        // ========================================================================
        // Event Handlers
        // ========================================================================

        private void BtnSave_Click(object sender, RoutedEventArgs e)
        {
            if (TxtPassword.SecurePassword.Length == 0)
            {
                MessageBox.Show("Password entry field cannot be empty.",
                    "Validation Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                return;
            }

            IntPtr passwordPointer = IntPtr.Zero;
            string cleartextPassword = string.Empty;

            try
            {
                // Convert SecureString to plaintext (temporarily)
                passwordPointer = Marshal.SecureStringToGlobalAllocUnicode(TxtPassword.SecurePassword);
                cleartextPassword = Marshal.PtrToStringUni(passwordPointer) ?? string.Empty;

                // Try to verify the password
                bool verified = VerifyWindowsPassword(cleartextPassword);

                if (!verified)
                {
                    // Verification failed – ask user if they want to proceed anyway
                    MessageBoxResult result = MessageBox.Show(
                        "We couldn't verify your password with the system.\n\n" +
                        "This can happen with Microsoft accounts or certain domain configurations.\n" +
                        "If you are 100% sure the password is correct, you can proceed.\n\n" +
                        "Do you want to store this password anyway?",
                        "Password Verification Failed",
                        MessageBoxButton.YesNo,
                        MessageBoxImage.Warning);

                    if (result != MessageBoxResult.Yes)
                    {
                        return; // User chose not to store
                    }
                }

                // ✅ CLEAR PREVIOUS REGISTRY ENTRIES BEFORE WRITING
                ClearRegistryKeys();

                // Generate random salt (16 bytes)
                byte[] salt = new byte[16];
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(salt);
                }

                // Compute salted hash (SHA-256)
                byte[] passwordBytes = Encoding.UTF8.GetBytes(cleartextPassword);
                byte[] combined = new byte[salt.Length + passwordBytes.Length];
                Buffer.BlockCopy(salt, 0, combined, 0, salt.Length);
                Buffer.BlockCopy(passwordBytes, 0, combined, salt.Length, passwordBytes.Length);

                byte[] hashBytes;
                using (SHA256 sha = SHA256.Create())
                {
                    hashBytes = sha.ComputeHash(combined);
                }

                string hashHex = BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();

                // Store salt and hash in registry
                using RegistryKey? key = Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Tether\CredentialProvider",
                    true);

                if (key == null)
                {
                    throw new InvalidOperationException("Failed to create/open registry key.");
                }

                key.SetValue("PasswordHash", hashHex, RegistryValueKind.String);
                key.SetValue("PasswordSalt", salt, RegistryValueKind.Binary);

                // Encrypt the cleartext password with DPAPI (machine scope)
                bool storedSecurely = StoreEncryptedPassword(cleartextPassword);

                if (storedSecurely)
                {
                    MessageBox.Show(
                        "✓ Password stored successfully!\n\n" +
                        "The salted hash and encrypted password have been saved to the registry.\n" +
                        "Reboot your computer for changes to take effect.",
                        "Success",
                        MessageBoxButton.OK,
                        MessageBoxImage.Information);
                }
                else
                {
                    MessageBox.Show(
                        "DPAPI data protection framework fault encountered.",
                        "Storage Error",
                        MessageBoxButton.OK,
                        MessageBoxImage.Error);
                }

                TxtPassword.Clear();
            }
            catch (UnauthorizedAccessException)
            {
                MessageBox.Show(
                    "Elevated contextual rights required.\n\n" +
                    "Please restart the application as Administrator.",
                    "Permissions Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    $"Critical error: {ex.Message}",
                    "Exception Trace",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
            finally
            {
                if (passwordPointer != IntPtr.Zero)
                {
                    Marshal.ZeroFreeGlobalAllocUnicode(passwordPointer);
                }
                // Clear the plaintext from memory
                if (!string.IsNullOrEmpty(cleartextPassword))
                {
                    Array.Clear(cleartextPassword.ToCharArray(), 0, cleartextPassword.Length);
                }
            }
        }

        private void BtnSavePhoneKey_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(TxtPhonePublicKey.Text))
            {
                MessageBox.Show("Public key cannot be empty.",
                    "Validation Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                return;
            }

            try
            {
                using RegistryKey? key = Registry.LocalMachine.CreateSubKey(
                    @"SOFTWARE\Tether\CredentialProvider",
                    true);

                if (key == null)
                {
                    throw new InvalidOperationException("Failed to create/open registry key.");
                }

                key.SetValue("PhonePublicKeyBase64", TxtPhonePublicKey.Text.Trim(), RegistryValueKind.String);

                MessageBox.Show(
                    "Phone public key stored successfully.\n\n" +
                    "Restart the Tether Communication Service for changes to take effect.",
                    "Success",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }
            catch (UnauthorizedAccessException)
            {
                MessageBox.Show(
                    "You need administrator privileges to write to the registry.\n\n" +
                    "Please restart the application as Administrator.",
                    "Access Denied",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    $"Failed to store phone key: {ex.Message}",
                    "Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }
    }
}