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
        // Native Win32 Data Protection API Interop Setup
        [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool CryptProtectData(
            ref DATA_BLOB pDataIn,
            string szDataDescr,
            ref DATA_BLOB pOptionalEntropy,
            IntPtr pvReserved,
            IntPtr pPromptStruct,
            uint dwFlags,
            ref DATA_BLOB pDataOut);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct DATA_BLOB
        {
            public int cbData;
            public IntPtr pbData;
        }

        private const uint CRYPTPROTECT_UI_FORBIDDEN = 0x1;

        public MainWindow()
        {
            InitializeComponent();
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
                int passwordLength = TxtPassword.SecurePassword.Length;
                byte[] rawBytes = new byte[passwordLength * 2]; // WCHAR mapping footprint

                // Unmarshal SecureString data down to unmanaged system buffer structures safely
                passwordPointer = Marshal.SecureStringToGlobalAllocUnicode(TxtPassword.SecurePassword);
                Marshal.Copy(passwordPointer, rawBytes, 0, rawBytes.Length);

                // Calculate cryptographic SHA-256 validation signatures
                byte[] dynamicHashBytes = SHA256.HashData(rawBytes);
                StringBuilder hexStringBuilder = new StringBuilder(dynamicHashBytes.Length * 2);
                foreach (byte b in dynamicHashBytes)
                {
                    hexStringBuilder.AppendFormat("{0:02x}", b);
                }
                string computedHexHash = hexStringBuilder.ToString();

                // Safe local machine storage registration block
                using (RegistryKey standardKey = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Tether\CredentialProvider", true))
                {
                    standardKey.SetValue("PasswordHash", computedHexHash, RegistryValueKind.String);
                }

                // Call local isolated store routine instead of cross-referencing external classes
                string cleartextPassword = new System.Net.NetworkCredential(string.Empty, TxtPassword.SecurePassword).Password;
                bool storedSecurely = StoreCredentialsLocal(cleartextPassword);

                if (storedSecurely)
                {
                    MessageBox.Show("Fallback authentication profile successfully committed to system storage.", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                else
                {
                    MessageBox.Show("DPAPI Data protection framework fault encountered.", "Storage Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }

                // Instantly scrub sensitive application buffer memory fragments
                Array.Clear(rawBytes, 0, rawBytes.Length);
                Array.Clear(dynamicHashBytes, 0, dynamicHashBytes.Length);
                TxtPassword.Clear();
            }
            catch (UnauthorizedAccessException)
            {
                MessageBox.Show("Elevated contextual rights required. Restart application as an Administrator.", "Permissions Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Critical error writing descriptors: {ex.Message}", "Exception Trace", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                if (passwordPointer != IntPtr.Zero)
                {
                    // Zero out structural memory regions allocated outside managed garbage collector spaces
                    Marshal.ZeroFreeGlobalAllocUnicode(passwordPointer);
                }
            }
        }

        private bool StoreCredentialsLocal(string cleartextPassword)
        {
            try
            {
                byte[] rawPlainBytes = Encoding.Unicode.GetBytes(cleartextPassword);
                DATA_BLOB dataIn = new DATA_BLOB();
                DATA_BLOB dataOut = new DATA_BLOB();
                DATA_BLOB entropy = new DATA_BLOB();

                dataIn.cbData = rawPlainBytes.Length;
                dataIn.pbData = Marshal.AllocHGlobal(rawPlainBytes.Length);
                Marshal.Copy(rawPlainBytes, 0, dataIn.pbData, rawPlainBytes.Length);

                try
                {
                    if (CryptProtectData(ref dataIn, "TetherCredentialProviderSecret", ref entropy, IntPtr.Zero, IntPtr.Zero, CRYPTPROTECT_UI_FORBIDDEN, ref dataOut))
                    {
                        byte[] encryptedPayload = new byte[dataOut.cbData];
                        Marshal.Copy(dataOut.pbData, encryptedPayload, 0, dataOut.cbData);

                        using (RegistryKey key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Tether\CredentialProvider", true))
                        {
                            if (key != null)
                            {
                                key.SetValue("EncryptedPassword", encryptedPayload, RegistryValueKind.Binary);
                            }
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
            catch { }
            return false;
        }
    }
}