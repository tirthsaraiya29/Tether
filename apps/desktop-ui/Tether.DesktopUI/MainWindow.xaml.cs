using Microsoft.Win32;
using System;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media;
using Tether.Shared.Events;
using Tether.Shared.IPC;

namespace Tether.DesktopUI
{
    public partial class MainWindow : Window
    {
        private bool _isListening = true;

        // ========================================================================
        // Native Win32 P/Invoke Integrations
        // ========================================================================
        [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool CryptProtectData(
            ref DATA_BLOB pDataIn, string szDataDescr, ref DATA_BLOB pOptionalEntropy,
            IntPtr pvReserved, IntPtr pPromptStruct, uint dwFlags, ref DATA_BLOB pDataOut);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool LogonUser(
            string lpszUsername, string lpszDomain, string lpszPassword,
            int dwLogonType, int dwLogonProvider, out IntPtr phToken);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("secur32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool GetUserNameEx(int nameFormat, StringBuilder lpNameBuffer, ref uint lpnSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr LocalFree(IntPtr hMem);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct DATA_BLOB
        {
            public int cbData;
            public IntPtr pbData;
        }

        private const uint CRYPTPROTECT_UI_FORBIDDEN = 0x1;
        private const uint CRYPTPROTECT_LOCAL_MACHINE = 0x4;
        private const int LOGON32_LOGON_INTERACTIVE = 2;
        private const int LOGON32_LOGON_NETWORK = 3;
        private const int LOGON32_PROVIDER_DEFAULT = 0;

        public MainWindow()
        {
            InitializeComponent();
            ResolveUserContext();
            _ = RunTelemetryListenerAsync();
        }

        // ========================================================================
        // Telemetry Monitor & Named Pipe Consumer Engine
        // ========================================================================
        private async Task RunTelemetryListenerAsync()
        {
            while (_isListening)
            {
                try
                {
                    using var server = new NamedPipeServerStream(
                        IpcConstants.UiPipeName,
                        PipeDirection.In,
                        NamedPipeServerStream.MaxAllowedServerInstances,
                        PipeTransmissionMode.Message,
                        PipeOptions.Asynchronous);

                    await server.WaitForConnectionAsync();

                    var buffer = new byte[IpcConstants.PipeBufferSize];
                    int readBytes = await server.ReadAsync(buffer, 0, buffer.Length);

                    if (readBytes > 0)
                    {
                        string json = Encoding.UTF8.GetString(buffer, 0, readBytes);
                        var telemetryEvent = JsonSerializer.Deserialize<TetherEvent>(json);

                        if (telemetryEvent != null)
                        {
                            Dispatcher.Invoke(() => HandleIncomingSignal(telemetryEvent));
                        }
                    }
                }
                catch
                {
                    await Task.Delay(1000);
                }
            }
        }

        private void HandleIncomingSignal(TetherEvent evt)
        {
            switch (evt.EventType)
            {
                case TetherEventType.PHONE_CONNECTED:
                    TxtStatus.Text = "CRYPTOGRAPHIC LINK ENFORCED";
                    IndicatorNode.Fill = new SolidColorBrush(Color.FromRgb(0x00, 0xFF, 0x66));
                    break;

                case TetherEventType.PHONE_DISCONNECTED:
                    TxtStatus.Text = "HARDWARE NODE OFFLINE";
                    IndicatorNode.Fill = new SolidColorBrush(Color.FromRgb(0xFF, 0x00, 0x55));
                    TxtRssi.Text = "RSSI: -- dBm";
                    break;

                case TetherEventType.TRUST_DEGRADED:
                    if (!string.IsNullOrEmpty(evt.PayloadJson))
                    {
                        try
                        {
                            using var document = JsonDocument.Parse(evt.PayloadJson);
                            if (document.RootElement.TryGetProperty("Rssi", out var rssiProp))
                            {
                                double rssiValue = rssiProp.GetDouble();
                                TxtRssi.Text = $"RSSI: {rssiValue:F0} dBm";
                                TxtStatus.Text = "SIGNAL DEGRADED - MONITORING PARADIGM";
                                IndicatorNode.Fill = new SolidColorBrush(Color.FromRgb(0x00, 0xF0, 0xFF));
                            }
                        }
                        catch { }
                    }
                    break;
            }
        }

        // ========================================================================
        // Security Credential Processing Engine (DPAPI Vault Insertion)
        // ========================================================================
        private void BtnCommitVault_Click(object sender, RoutedEventArgs e)
        {
            if (TxtPassword.SecurePassword.Length == 0)
            {
                MessageBox.Show("Password entry field cannot be empty.", "Validation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            IntPtr passwordPointer = IntPtr.Zero;
            string cleartextPassword = string.Empty;

            try
            {
                passwordPointer = Marshal.SecureStringToGlobalAllocUnicode(TxtPassword.SecurePassword);
                cleartextPassword = Marshal.PtrToStringUni(passwordPointer) ?? string.Empty;

                if (!VerifyWindowsPassword(cleartextPassword))
                {
                    MessageBoxResult result = MessageBox.Show(
                        "We couldn't verify your password with the system.\n" +
                        "If you are 100% sure the password is correct, you can proceed anyway.\n\n" +
                        "Do you want to store this password?",
                        "Password Verification Warning", MessageBoxButton.YesNo, MessageBoxImage.Warning);

                    if (result != MessageBoxResult.Yes) return;
                }

                ClearPasswordKeys();

                byte[] salt = new byte[16];
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(salt);
                }

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

                using RegistryKey? key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Tether\CredentialProvider", true);
                if (key == null) throw new InvalidOperationException("Failed to access system registry.");

                key.SetValue("PasswordHash", hashHex, RegistryValueKind.String);
                key.SetValue("PasswordSalt", salt, RegistryValueKind.Binary);

                if (StoreEncryptedPasswordBlob(cleartextPassword))
                {
                    MessageBox.Show("✓ Vault initialization completed successfully.\nReboot workstation context to apply updates.", "Vault Enforced", MessageBoxButton.OK, MessageBoxImage.Information);
                    TxtPassword.Clear();
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Critical security mapping failure: {ex.Message}", "Fatal Exception", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                if (passwordPointer != IntPtr.Zero) Marshal.ZeroFreeGlobalAllocUnicode(passwordPointer);
                if (!string.IsNullOrEmpty(cleartextPassword)) cleartextPassword = new string('\0', cleartextPassword.Length);
            }
        }

        private bool StoreEncryptedPasswordBlob(string cleartextPassword)
        {
            IntPtr allocatedInputMemory = IntPtr.Zero;
            IntPtr allocatedOutputMemory = IntPtr.Zero;
            try
            {
                byte[] rawPlainBytes = Encoding.Unicode.GetBytes(cleartextPassword);
                allocatedInputMemory = Marshal.AllocHGlobal(rawPlainBytes.Length);
                Marshal.Copy(rawPlainBytes, 0, allocatedInputMemory, rawPlainBytes.Length);

                DATA_BLOB dataIn = new DATA_BLOB { cbData = rawPlainBytes.Length, pbData = allocatedInputMemory };
                DATA_BLOB dataOut = new DATA_BLOB();
                DATA_BLOB entropy = new DATA_BLOB();

                bool success = CryptProtectData(
                    ref dataIn, "TetherCredentialProviderSecret", ref entropy, IntPtr.Zero, IntPtr.Zero,
                    CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE, ref dataOut);

                if (success)
                {
                    allocatedOutputMemory = dataOut.pbData;
                    byte[] encryptedPayload = new byte[dataOut.cbData];
                    Marshal.Copy(dataOut.pbData, encryptedPayload, 0, dataOut.cbData);

                    using RegistryKey? key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Tether\CredentialProvider", true);
                    key?.SetValue("EncryptedPassword", encryptedPayload, RegistryValueKind.Binary);
                    return true;
                }
                return false;
            }
            catch
            {
                return false;
            }
            finally
            {
                if (allocatedInputMemory != IntPtr.Zero) Marshal.FreeHGlobal(allocatedInputMemory);
                if (allocatedOutputMemory != IntPtr.Zero) LocalFree(allocatedOutputMemory);
            }
        }

        private bool VerifyWindowsPassword(string password)
        {
            string domain = Environment.UserDomainName;
            string username = Environment.UserName;
            IntPtr token;

            bool success = LogonUser(username, domain, password, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, out token);
            if (success) { CloseHandle(token); return true; }

            success = LogonUser(username, domain, password, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, out token);
            if (success) { CloseHandle(token); return true; }

            return false;
        }

        private void ClearPasswordKeys()
        {
            using RegistryKey? key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Tether\CredentialProvider", true);
            if (key == null) return;
            try { key.DeleteValue("PasswordHash"); } catch { }
            try { key.DeleteValue("PasswordSalt"); } catch { }
            try { key.DeleteValue("EncryptedPassword"); } catch { }
        }

        private void ResolveUserContext()
        {
            uint size = 256;
            StringBuilder sb = new StringBuilder((int)size);
            if (GetUserNameEx(8, sb, ref size))
            {
                TxtUserType.Text = $"✓ AUTHENTICATED REALM: MICROSOFT SERVICE NODES ({sb})";
            }
            else
            {
                TxtUserType.Text = $"✓ AUTHENTICATED REALM: LOCAL DOMAIN WORKSTATION ({Environment.UserDomainName}\\{Environment.UserName})";
            }
        }

        private async void DispatchManualCommand(TetherEventType commandType)
        {
            try
            {
                var outboundEvent = new TetherEvent { EventType = commandType, Source = "DesktopUI" };
                string json = JsonSerializer.Serialize(outboundEvent);
                byte[] bytes = Encoding.UTF8.GetBytes(json);

                using var client = new NamedPipeClientStream(".", IpcConstants.PipeName, PipeDirection.Out);
                await client.ConnectAsync(250);
                await client.WriteAsync(bytes, 0, bytes.Length);
                await client.FlushAsync();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Command Pipeline Error: {ex.Message}", "IPC Node Missing", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private void BtnUnlockOverride_Click(object sender, RoutedEventArgs e) => DispatchManualCommand(TetherEventType.PHONE_UNLOCKED);
        private void BtnLockdownOverride_Click(object sender, RoutedEventArgs e) => DispatchManualCommand(TetherEventType.PANIC_TRIGGERED);

        protected override void OnClosed(EventArgs e)
        {
            _isListening = false;
            base.OnClosed(e);
        }
    }
}