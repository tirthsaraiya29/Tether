using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;
using Microsoft.Win32;

namespace Tether.CommunicationService
{
    public partial class BleManager
    {
        // Internal tracking synchronization primitives
        private EventWaitHandle? _appEvent;
        private EventWaitHandle? _screenEvent;
        private readonly object _ipcLockObject = new object();

        private static readonly string IpcLogDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Tether", "Logs");
        private static readonly string IpcLogFilePath = Path.Combine(IpcLogDirectory, "BleManager_Ipc.log");

        // Native Win32 DPAPI Struct & Library Interop Bindings
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

        /// <summary>
        /// Configures loose security descriptors on Windows Global Wait Handles to allow Session 0 interoperability.
        /// </summary>
        public void InitializeIPCHandles()
        {
            lock (_ipcLockObject)
            {
                try
                {
                    IpcLogInfo("Configuring security descriptors for cross-session Windows global synchronization events...");

                    var securityDescriptor = new EventWaitHandleSecurity();
                    var everyoneSid = new SecurityIdentifier(WellKnownSidType.WorldSid, null);

                    securityDescriptor.AddAccessRule(new EventWaitHandleAccessRule(
                        everyoneSid,
                        EventWaitHandleRights.FullControl,
                        AccessControlType.Allow
                    ));

                    _appEvent = EventWaitHandleAcl.Create(
                        false,
                        EventResetMode.ManualReset,
                        @"Global\TetherPhoneAppUnlocked",
                        out bool createdAppNew,
                        securityDescriptor
                    );
                    IpcLogInfo($"Event handle 'Global\\TetherPhoneAppUnlocked' established. New Token: {createdAppNew}");

                    _screenEvent = EventWaitHandleAcl.Create(
                        false,
                        EventResetMode.ManualReset,
                        @"Global\TetherPhoneScreenUnlocked",
                        out bool createdScreenNew,
                        securityDescriptor
                    );
                    IpcLogInfo($"Event handle 'Global\\TetherPhoneScreenUnlocked' established. New Token: {createdScreenNew}");
                }
                catch (Exception ex)
                {
                    IpcLogError("Fatal error encountered during initialization of low-integrity security descriptors.", ex);
                    throw;
                }
            }
        }

        public void ResetIPCHandles()
        {
            lock (_ipcLockObject)
            {
                try
                {
                    _appEvent?.Reset();
                    _screenEvent?.Reset();
                    IpcLogInfo("Global security synchronization flags cleanly reset to default non-signaled state.");
                }
                catch (Exception ex)
                {
                    IpcLogError("Error encountered while resetting system state flags.", ex);
                }
            }
        }

        /// <summary>
        /// Call this method inside your existing BLE characteristic write notification handler loop 
        /// to pass down the UUID signals from your OTA pairing logic.
        /// </summary>
        public void ProcessIncomingBleSignal(string characteristicUuid, byte[]? payload)
        {
            if (string.IsNullOrEmpty(characteristicUuid)) return;

            lock (_ipcLockObject)
            {
                try
                {
                    string normalizedUuid = characteristicUuid.ToLowerInvariant().Trim();

                    if (normalizedUuid == "00001234-0000-1000-8000-00805f9b34fb")
                    {
                        _appEvent?.Set();
                        IpcLogInfo("[MATCH] Condition met: Phone verification app triggered signaling event successfully.");
                    }
                    else if (normalizedUuid == "00005678-0000-1000-8000-00805f9b34fb")
                    {
                        _screenEvent?.Set();
                        IpcLogInfo("[MATCH] Condition met: Mobile device screen-lock confirmation triggered signaling event successfully.");
                    }
                }
                catch (Exception ex)
                {
                    IpcLogError("Unexpected tracking fault processing inbound characteristic block updates.", ex);
                }
            }
        }

        /// <summary>
        /// Performs local system machine scoped DPAPI preservation for secure automated background authentication.
        /// </summary>
        public static bool StoreCredentialsSecurely(string cleartextPassword)
        {
            if (cleartextPassword == null) return false;

            try
            {
                using (var sha256 = System.Security.Cryptography.SHA256.Create())
                {
                    byte[] passwordBytes = Encoding.UTF8.GetBytes(cleartextPassword);
                    byte[] hashBytes = sha256.ComputeHash(passwordBytes);

                    var sb = new StringBuilder();
                    foreach (byte b in hashBytes) sb.Append(b.ToString("x2"));

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
                System.Diagnostics.Debug.WriteLine($"DPAPI local persistence operational fault: {ex}");
            }

            return false;
        }

        private void IpcLogInfo(string message) => WriteToIpcFile("INFO", message);
        private void IpcLogError(string message, Exception ex) => WriteToIpcFile("ERROR", $"{message} {ex}");

        private void WriteToIpcFile(string level, string message)
        {
            try
            {
                if (!Directory.Exists(IpcLogDirectory)) Directory.CreateDirectory(IpcLogDirectory);
                File.AppendAllText(IpcLogFilePath, $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] [{level}] [IPC] {message}{Environment.NewLine}", Encoding.UTF8);
            }
            catch { }
        }
    }
}