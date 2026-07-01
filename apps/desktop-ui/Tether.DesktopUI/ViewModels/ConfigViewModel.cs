using Microsoft.Win32;
using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Windows.Input;

namespace Tether.DesktopUI.ViewModels;

public class ConfigViewModel : INotifyPropertyChanged
{
    private string _userTypeDisplay = string.Empty;
    private string _phonePublicKey = string.Empty;

    public string UserTypeDisplay
    {
        get => _userTypeDisplay;
        set { _userTypeDisplay = value; OnPropertyChanged(); }
    }

    public string PhonePublicKey
    {
        get => _phonePublicKey;
        set { _phonePublicKey = value; OnPropertyChanged(); }
    }

    public ICommand SavePasswordCommand { get; }
    public ICommand SavePhoneKeyCommand { get; }

    public ConfigViewModel()
    {
        SavePasswordCommand = new RelayCommand(ExecuteSavePassword);
        SavePhoneKeyCommand = new RelayCommand(ExecuteSavePhoneKey);
        SetUserTypeDisplay();
    }

    // --------------------------------------------------------------------
    // User Type Detection
    // --------------------------------------------------------------------
    private void SetUserTypeDisplay()
    {
        string upn = GetCurrentUserPrincipalName();
        bool isMicrosoft = !string.IsNullOrEmpty(upn) && upn.Contains('@');
        UserTypeDisplay = isMicrosoft
            ? $"✓ Current user type: Microsoft Account ({upn})"
            : "✓ Current user type: Local / Domain account";
    }

    private string GetCurrentUserPrincipalName()
    {
        // P/Invoke for GetUserNameEx
        const int NameUserPrincipal = 8;
        uint size = 256;
        StringBuilder sb = new StringBuilder((int)size);
        if (GetUserNameEx(NameUserPrincipal, sb, ref size))
            return sb.ToString();

        // Fallback: SamCompatible
        const int NameSamCompatible = 2;
        size = 256;
        sb.Clear();
        if (GetUserNameEx(NameSamCompatible, sb, ref size))
            return sb.ToString();

        return Environment.UserName;
    }

    [DllImport("secur32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool GetUserNameEx(int nameFormat, StringBuilder lpNameBuffer, ref uint lpnSize);

    // --------------------------------------------------------------------
    // Password Verification (copied from original)
    // --------------------------------------------------------------------
    private bool VerifyWindowsPassword(string password)
    {
        string upn = GetCurrentUserPrincipalName();
        string domain = Environment.UserDomainName;
        string username = Environment.UserName;
        string computerName = Environment.MachineName;

        IntPtr token;
        bool success = false;

        // Try multiple logon types
        if (!string.IsNullOrEmpty(upn) && upn.Contains('@'))
        {
            success = LogonUser(upn, null, password, 2, 0, out token);
            if (success) { CloseHandle(token); return true; }
            success = LogonUser(upn, null, password, 3, 0, out token);
            if (success) { CloseHandle(token); return true; }

            string upnDomain = upn.Substring(upn.IndexOf('@') + 1);
            success = LogonUser(upn, upnDomain, password, 2, 0, out token);
            if (success) { CloseHandle(token); return true; }
            success = LogonUser(upn, upnDomain, password, 3, 0, out token);
            if (success) { CloseHandle(token); return true; }
        }

        success = LogonUser(username, domain, password, 2, 0, out token);
        if (success) { CloseHandle(token); return true; }
        success = LogonUser(username, domain, password, 3, 0, out token);
        if (success) { CloseHandle(token); return true; }

        success = LogonUser(username, computerName, password, 2, 0, out token);
        if (success) { CloseHandle(token); return true; }
        success = LogonUser(username, computerName, password, 3, 0, out token);
        if (success) { CloseHandle(token); return true; }

        success = LogonUser(username, null, password, 2, 0, out token);
        if (success) { CloseHandle(token); return true; }
        success = LogonUser(username, null, password, 3, 0, out token);
        if (success) { CloseHandle(token); return true; }

        return false;
    }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LogonUser(string lpszUsername, string lpszDomain, string lpszPassword,
        int dwLogonType, int dwLogonProvider, out IntPtr phToken);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    // --------------------------------------------------------------------
    // Registry helpers
    // --------------------------------------------------------------------
    private void ClearRegistryKeys()
    {
        try
        {
            using RegistryKey? key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Tether\CredentialProvider", true);
            if (key == null) return;
            foreach (string name in key.GetValueNames())
            {
                if (name == "PhonePublicKeyBase64") continue;
                key.DeleteValue(name);
            }
        }
        catch { }
    }

    private bool StoreEncryptedPassword(string cleartextPassword)
    {
        try
        {
            byte[] rawPlainBytes = Encoding.Unicode.GetBytes(cleartextPassword ?? string.Empty);
            DATA_BLOB dataIn = new DATA_BLOB { cbData = rawPlainBytes.Length, pbData = Marshal.AllocHGlobal(rawPlainBytes.Length) };
            Marshal.Copy(rawPlainBytes, 0, dataIn.pbData, rawPlainBytes.Length);
            DATA_BLOB dataOut = new DATA_BLOB();
            DATA_BLOB entropy = new DATA_BLOB();

            bool success = CryptProtectData(ref dataIn, "TetherCredentialProviderSecret", ref entropy,
                IntPtr.Zero, IntPtr.Zero, 0x1 | 0x4, ref dataOut);

            if (success)
            {
                byte[] encryptedPayload = new byte[dataOut.cbData];
                Marshal.Copy(dataOut.pbData, encryptedPayload, 0, dataOut.cbData);
                using RegistryKey? key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Tether\CredentialProvider", true);
                if (key != null)
                {
                    key.SetValue("EncryptedPassword", encryptedPayload, RegistryValueKind.Binary);
                    return true;
                }
            }
            return false;
        }
        catch
        {
            return false;
        }
    }

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern bool CryptProtectData(ref DATA_BLOB pDataIn, string szDataDescr, ref DATA_BLOB pOptionalEntropy,
        IntPtr pvReserved, IntPtr pPromptStruct, uint dwFlags, ref DATA_BLOB pDataOut);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    private struct DATA_BLOB { public int cbData; public IntPtr pbData; }

    // --------------------------------------------------------------------
    // Command Executions
    // --------------------------------------------------------------------
    private void ExecuteSavePassword(object parameter)
    {
        var passwordBox = parameter as System.Windows.Controls.PasswordBox;
        if (passwordBox == null || passwordBox.SecurePassword.Length == 0)
        {
            MessageBox.Show("Password cannot be empty.", "Validation Error",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        IntPtr ptr = Marshal.SecureStringToGlobalAllocUnicode(passwordBox.SecurePassword);
        string cleartext = Marshal.PtrToStringUni(ptr) ?? string.Empty;
        Marshal.ZeroFreeGlobalAllocUnicode(ptr);

        try
        {
            bool verified = VerifyWindowsPassword(cleartext);
            if (!verified)
            {
                var result = MessageBox.Show(
                    "We couldn't verify your password with the system.\n\n" +
                    "This can happen with Microsoft accounts or certain domain configurations.\n" +
                    "If you are 100% sure the password is correct, you can proceed.\n\n" +
                    "Do you want to store this password anyway?",
                    "Password Verification Failed",
                    MessageBoxButton.YesNo, MessageBoxImage.Warning);
                if (result != MessageBoxResult.Yes)
                    return;
            }

            ClearRegistryKeys();

            byte[] salt = new byte[16];
            using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(salt);

            byte[] passwordBytes = Encoding.UTF8.GetBytes(cleartext);
            byte[] combined = new byte[salt.Length + passwordBytes.Length];
            Buffer.BlockCopy(salt, 0, combined, 0, salt.Length);
            Buffer.BlockCopy(passwordBytes, 0, combined, salt.Length, passwordBytes.Length);
            byte[] hashBytes;
            using (SHA256 sha = SHA256.Create()) hashBytes = sha.ComputeHash(combined);
            string hashHex = BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();

            using RegistryKey? key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Tether\CredentialProvider", true);
            if (key == null) throw new InvalidOperationException("Cannot create registry key.");
            key.SetValue("PasswordHash", hashHex, RegistryValueKind.String);
            key.SetValue("PasswordSalt", salt, RegistryValueKind.Binary);

            bool stored = StoreEncryptedPassword(cleartext);
            if (stored)
            {
                MessageBox.Show("✓ Password stored successfully!\n\n" +
                    "The salted hash and encrypted password have been saved to the registry.\n" +
                    "Reboot your computer for changes to take effect.",
                    "Success", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            else
            {
                MessageBox.Show("DPAPI data protection failed.", "Storage Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
            passwordBox.Clear();
        }
        catch (UnauthorizedAccessException)
        {
            MessageBox.Show("Administrator rights required.", "Permissions Error",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            Array.Clear(cleartext.ToCharArray(), 0, cleartext.Length);
        }
    }

    private void ExecuteSavePhoneKey(object parameter)
    {
        if (string.IsNullOrWhiteSpace(PhonePublicKey))
        {
            MessageBox.Show("Public key cannot be empty.", "Validation Error",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        try
        {
            using RegistryKey? key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Tether\CredentialProvider", true);
            if (key == null) throw new InvalidOperationException("Cannot create registry key.");
            key.SetValue("PhonePublicKeyBase64", PhonePublicKey.Trim(), RegistryValueKind.String);
            MessageBox.Show("Phone public key stored successfully.", "Success",
                MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (UnauthorizedAccessException)
        {
            MessageBox.Show("Administrator rights required.", "Access Denied",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string name = null!) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}