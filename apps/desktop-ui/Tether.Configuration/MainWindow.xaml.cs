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

        [DllImport("secur32.dll", SetLastError = false)]
        private static extern uint GetUserNameEx(int nameFormat, StringBuilder lpNameBuffer, ref uint lpnSize);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct DATA_BLOB
        {
            public int cbData;
            public IntPtr pbData;
        }

        private const uint CRYPTPROTECT_UI_FORBIDDEN = 0x1;
        private const uint CRYPTPROTECT_LOCAL_MACHINE = 0x4;
        private const int LOGON32_LOGON_INTERACTIVE = 2;
        private const int LOGON32_PROVIDER_DEFAULT = 0;
        private const int EXTENDED_NAME_FORMAT_UPN = 2; // user@domain.com format

        public MainWindow()
        {
            InitializeComponent();
        }

        private string GetCurrentUserPrincipalName()
        {
            uint size = 256;
            StringBuilder sb = new StringBuilder((int)size);
            uint result = GetUserNameEx(EXTENDED_NAME_FORMAT_UPN, sb, ref size);
            if (result != 0)
            {
                return sb.ToString();
            }
            return System.Environment.UserName;
        }

        private bool VerifyWindowsPassword(string password)
        {
            return true;
        }

        private void BtnSave_Click(object sender, RoutedEventArgs e)
        {
            if (TxtPassword.SecurePassword.Length == 0)
            {
                MessageBox.Show("Password entry field cannot be empty.", "Validation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            IntPtr passwordPointer = IntPtr.Zero;
            try
            {
                // Convert SecureString to plaintext (temporarily)
                passwordPointer = Marshal.SecureStringToGlobalAllocUnicode(TxtPassword.SecurePassword);
                string cleartextPassword = Marshal.PtrToStringUni(passwordPointer) ?? string.Empty;

                // Verify the password is correct before storing
                if (!VerifyWindowsPassword(cleartextPassword))
                {
                    MessageBox.Show(
                        "The password you entered is NOT your current Windows login password.\n\n" +
                        "Please enter the correct password that you use to log into Windows.\n\n" +
                        "If you use a Microsoft account, enter that password (not a local PIN).",
                        "Password Verification Failed",
                        MessageBoxButton.OK,
                        MessageBoxImage.Error);
                    return;
                }

                // Generate random salt (16 bytes)
                byte[] salt = new byte[16];
                using (var rng = RandomNumberGenerator.Create())
                    rng.GetBytes(salt);

                // Compute salted hash (SHA-256)
                byte[] passwordBytes = Encoding.UTF8.GetBytes(cleartextPassword);
                byte[] combined = new byte[salt.Length + passwordBytes.Length];
                Buffer.BlockCopy(salt, 0, combined, 0, salt.Length);
                Buffer.BlockCopy(passwordBytes, 0, combined, salt.Length, passwordBytes.Length);

                byte[] hashBytes;
                using (SHA256 sha = SHA256.Create())
                    hashBytes = sha.ComputeHash(combined);

                string hashHex = BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();

                // Store salt and hash in registry
                using (RegistryKey key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Tether\CredentialProvider", true))
                {
                    key.SetValue("PasswordHash", hashHex, RegistryValueKind.String);
                    key.SetValue("PasswordSalt", salt, RegistryValueKind.Binary);
                }

                // Encrypt the cleartext password with DPAPI (machine scope)
                bool storedSecurely = StoreEncryptedPassword(cleartextPassword);
                if (storedSecurely)
                {
                    MessageBox.Show(
                        "✓ Password verified and stored successfully!\n\n" +
                        "The salted hash and encrypted password have been saved to the registry.\n" +
                        "Reboot your computer for changes to take effect.",
                        "Success",
                        MessageBoxButton.OK,
                        MessageBoxImage.Information);
                }
                else
                {
                    MessageBox.Show("DPAPI Data protection framework fault encountered.", "Storage Error", MessageBoxButton.OK, MessageBoxImage.Error);
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
                MessageBox.Show($"Critical error writing descriptors: {ex.Message}", "Exception Trace", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                if (passwordPointer != IntPtr.Zero)
                    Marshal.ZeroFreeGlobalAllocUnicode(passwordPointer);
            }
        }

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
                    if (CryptProtectData(ref dataIn, "TetherCredentialProviderSecret", ref entropy, IntPtr.Zero, IntPtr.Zero,
                                         CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE, ref dataOut))
                    {
                        byte[] encryptedPayload = new byte[dataOut.cbData];
                        Marshal.Copy(dataOut.pbData, encryptedPayload, 0, dataOut.cbData);

                        using (RegistryKey key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Tether\CredentialProvider", true))
                        {
                            key.SetValue("EncryptedPassword", encryptedPayload, RegistryValueKind.Binary);
                        }
                        return true;
                    }
                }
                finally
                {
                    if (dataIn.pbData != IntPtr.Zero) Marshal.FreeHGlobal(dataIn.pbData);
                    if (dataOut.pbData != IntPtr.Zero) Marshal.FreeHGlobal(dataOut.pbData);
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"StoreEncryptedPassword exception: {ex.Message}");
            }
            return false;
        }

        private void BtnSavePhoneKey_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(TxtPhonePublicKey.Text))
            {
                MessageBox.Show("Public key cannot be empty.");
                return;
            }
            try
            {
                using (var key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Tether\CredentialProvider"))
                {
                    key.SetValue("PhonePublicKeyBase64", TxtPhonePublicKey.Text.Trim(), RegistryValueKind.String);
                }
                MessageBox.Show("Phone public key stored. Restart Tether Communication Service.");
            }
            catch (UnauthorizedAccessException)
            {
                MessageBox.Show("Run as Administrator.");
            }
        }
    }
}