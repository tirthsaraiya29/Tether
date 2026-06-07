using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;
using Microsoft.Win32;

namespace Tether.Communication
{
    public class BleManager : IDisposable
    {
        // Marked as nullable to completely resolve warning CS8618
        private EventWaitHandle? _appEvent;
        private EventWaitHandle? _screenEvent;
        private readonly object _lockObject = new object();
        private bool _isDisposed = false;

        private static readonly string LogDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Tether", "Logs");
        private static readonly string LogFilePath = Path.Combine(LogDirectory, "BleManager.log");

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

        public BleManager()
        {
            EnsureLogDirectoryExists();
            LogInfo("BleManager service layer initialized component sub-system successfully.");
        }

        /// <summary>
        /// Uses Windows ACL creation factory engines to resolve missing constructor errors.
        /// </summary>
        public void InitializeIPCHandles()
        {
            lock (_lockObject)
            {
                try
                {
                    LogInfo("Configuring security descriptors for cross-session Windows global synchronization events...");

                    var securityDescriptor = new EventWaitHandleSecurity();
                    var everyoneSid = new SecurityIdentifier(WellKnownSidType.WorldSid, null);

                    securityDescriptor.AddAccessRule(new EventWaitHandleAccessRule(
                        everyoneSid,
                        EventWaitHandleRights.FullControl,
                        AccessControlType.Allow
                    ));

                    // Fixed: Using EventWaitHandleAcl to handle 5-argument initialization setups in .NET Core+
                    _appEvent = EventWaitHandleAcl.Create(
                        false,
                        EventResetMode.ManualReset,
                        @"Global\TetherPhoneAppUnlocked",
                        out bool createdAppNew,
                        securityDescriptor
                    );
                    LogInfo($"Event handle 'Global\\TetherPhoneAppUnlocked' accessed. Created new system token: {createdAppNew}");

                    _screenEvent = EventWaitHandleAcl.Create(
                        false,
                        EventResetMode.ManualReset,
                        @"Global\TetherPhoneScreenUnlocked",
                        out bool createdScreenNew,
                        securityDescriptor
                    );
                    LogInfo($"Event handle 'Global\\TetherPhoneScreenUnlocked' accessed. Created new system token: {createdScreenNew}");
                }
                catch (Exception ex)
                {
                    LogError("Fatal error encountered during initialization loop of low-integrity security descriptors.", ex);
                    throw;
                }
            }
        }

        public void ResetIPCHandles()
        {
            lock (_lockObject)
            {
                CheckDisposed();
                try
                {
                    _appEvent?.Reset();
                    _screenEvent?.Reset();
                    LogInfo("Global security synchronization flags cleanly reset to default non-signaled state.");
                }
                catch (Exception ex)
                {
                    LogError("Error encountered while resetting system state flags.", ex);
                }
            }
        }

        public void ProcessIncomingBleSignal(string characteristicUuid, byte[]? payload)
        {
            if (string.IsNullOrEmpty(characteristicUuid))
            {
                LogWarning("Received Bluetooth characteristic callback data block with an invalid or empty UUID string.");
                return;
            }

            lock (_lockObject)
            {
                CheckDisposed();
                try
                {
                    string normalizedUuid = characteristicUuid.ToLowerInvariant().Trim();
                    string payloadPreview = payload != null ? BitConverter.ToString(payload).Replace("-", "") : "NULL";
                    LogInfo($"Inbound transmission processing - UUID: {normalizedUuid} | Payload Length: {payload?.Length ?? 0} | Bytes: {payloadPreview}");

                    if (normalizedUuid == "00001234-0000-1000-8000-00805f9b34fb")
                    {
                        _appEvent?.Set();
                        LogInfo("[MATCH] Condition met: Phone verification app triggered signaling event successfully.");
                    }
                    else if (normalizedUuid == "00005678-0000-1000-8000-00805f9b34fb")
                    {
                        _screenEvent?.Set();
                        LogInfo("[MATCH] Condition met: Mobile device screen-lock confirmation triggered signaling event successfully.");
                    }
                }
                catch (Exception ex)
                {
                    LogError("Unexpected tracking fault processing inbound characteristic block updates.", ex);
                }
            }
        }

        public static bool StoreCredentialsSecurely(string cleartextPassword)
        {
            if (cleartextPassword == null)
            {
                StaticLogError("Aborting encryption loop: target string matches a null data parameter reference.", null);
                return false;
            }

            try
            {
                StaticLogInfo("Initiating local storage sequence for target user credential tokens...");

                using (var sha256 = System.Security.Cryptography.SHA256.Create())
                {
                    byte[] passwordBytes = Encoding.UTF8.GetBytes(cleartextPassword);
                    byte[] hashBytes = sha256.ComputeHash(passwordBytes);

                    var sb = new StringBuilder();
                    foreach (byte b in hashBytes)
                    {
                        sb.Append(b.ToString("x2"));
                    }

                    using (RegistryKey? key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Tether\CredentialProvider"))
                    {
                        if (key != null)
                        {
                            key.SetValue("PasswordHash", sb.ToString(), RegistryValueKind.String);
                        }
                    }
                }

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

                        using (RegistryKey? key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Tether\CredentialProvider"))
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
            catch (Exception ex)
            {
                StaticLogError("Unexpected systemic exception block hit while persisting data storage values.", ex);
            }

            return false;
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_isDisposed)
            {
                if (disposing)
                {
                    lock (_lockObject)
                    {
                        _appEvent?.Dispose();
                        _screenEvent?.Dispose();
                    }
                }
                _isDisposed = true;
            }
        }

        private void CheckDisposed()
        {
            if (_isDisposed)
            {
                throw new ObjectDisposedException(nameof(BleManager));
            }
        }

        private void EnsureLogDirectoryExists()
        {
            try { if (!Directory.Exists(LogDirectory)) Directory.CreateDirectory(LogDirectory); } catch { }
        }

        private void LogInfo(string message) => WriteToFile("INFO", message);
        private void LogWarning(string message) => WriteToFile("WARN", message);
        // Changed exception type to nullable to fully fix CS8625
        private void LogError(string message, Exception? ex) => WriteToFile("ERROR", $"{message} {(ex != null ? ex.ToString() : "")}");

        private static void StaticLogInfo(string message) => StaticWriteToFile("INFO", message);
        private static void StaticLogError(string message, Exception? ex) => StaticWriteToFile("ERROR", $"{message} {(ex != null ? ex.ToString() : "")}");

        private void WriteToFile(string level, string message)
        {
            try { File.AppendAllText(LogFilePath, $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] [{level}] {message}{Environment.NewLine}", Encoding.UTF8); } catch { }
        }

        private static void StaticWriteToFile(string level, string message)
        {
            try
            {
                if (!Directory.Exists(LogDirectory)) Directory.CreateDirectory(LogDirectory);
                File.AppendAllText(LogFilePath, $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] [{level}] [STATIC] {message}{Environment.NewLine}", Encoding.UTF8);
            }
            catch { }
        }
    }
}