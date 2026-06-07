using System;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using Microsoft.Win32;

namespace Tether.Configuration
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private void BtnSave_Click(object sender, RoutedEventArgs e)
        {
            string rawPassword = TxtPassword.Password;

            if (string.IsNullOrWhiteSpace(rawPassword))
            {
                MessageBox.Show("Password entry field cannot be left blank.", "Validation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            try
            {
                // Compute SHA-256 string signature to match C++ Verification Routine
                byte[] rawBytes = Encoding.Unicode.GetBytes(rawPassword); // WCHAR matching
                byte[] dynamicHashBytes = SHA256.HashData(rawBytes);

                StringBuilder hexStringBuilder = new StringBuilder(dynamicHashBytes.Length * 2);
                foreach (byte b in dynamicHashBytes)
                {
                    hexStringBuilder.AppendFormat("{0:02x}", b);
                }
                string computedHexHash = hexStringBuilder.ToString();

                // Commit parameters to Local Machine System Architecture
                using (RegistryKey standardKey = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Tether\CredentialProvider", true))
                {
                    standardKey.SetValue("PasswordHash", computedHexHash, RegistryValueKind.String);
                }

                MessageBox.Show("Fallback authentication profile successfully committed to the system storage platform.", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
                TxtPassword.Clear();
            }
            catch (UnauthorizedAccessException)
            {
                MessageBox.Show("Elevated context permissions required. Please restart application context running explicitly as an Administrator.", "Execution Fault", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed writing deployment descriptors: {ex.Message}", "Critical Execution Exception", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }
}