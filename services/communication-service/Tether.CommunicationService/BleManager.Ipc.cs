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
        private EventWaitHandle? _appEvent;
        private EventWaitHandle? _screenEvent;
        private readonly object _ipcLockObject = new object();

        private static readonly string IpcLogDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Tether", "Logs");
        private static readonly string IpcLogFilePath = Path.Combine(IpcLogDirectory, "BleManager_Ipc.log");

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

        public void InitializeIPCHandles()
        {
            lock (_ipcLockObject)
            {
                try
                {
                    IpcLogInfo("Configuring restricted security descriptors for cross-session Windows global synchronization events...");

                    var security = new EventWaitHandleSecurity();

                    // Allow SYSTEM full control
                    security.AddAccessRule(new EventWaitHandleAccessRule(
                        new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null),
                        EventWaitHandleRights.Synchronize,
                        AccessControlType.Allow));

                    // Allow the current service account (NETWORK SERVICE or LOCAL SERVICE)
                    var selfSid = WindowsIdentity.GetCurrent().User;
                    if (selfSid != null)
                    {
                        security.AddAccessRule(new EventWaitHandleAccessRule(
                            selfSid,
                            EventWaitHandleRights.FullControl,
                            AccessControlType.Allow));
                    }

                    // Allow Authenticated Users to only modify/signal (no full control)
                    security.AddAccessRule(new EventWaitHandleAccessRule(
                        new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null),
                        EventWaitHandleRights.Synchronize | EventWaitHandleRights.Modify,
                        AccessControlType.Allow));

                    // Do NOT add WorldSid – prevents spoofing

                    _appEvent = EventWaitHandleAcl.Create(
                        false,
                        EventResetMode.ManualReset,
                        @"Global\TetherPhoneAppUnlocked",
                        out bool createdAppNew,
                        security);

                    IpcLogInfo($"Event handle 'Global\\TetherPhoneAppUnlocked' established. New: {createdAppNew}");

                    _screenEvent = EventWaitHandleAcl.Create(
                        false,
                        EventResetMode.ManualReset,
                        @"Global\TetherPhoneScreenUnlocked",
                        out bool createdScreenNew,
                        security);

                    IpcLogInfo($"Event handle 'Global\\TetherPhoneScreenUnlocked' established. New: {createdScreenNew}");
                }
                catch (Exception ex)
                {
                    IpcLogError("Fatal error initializing security descriptors.", ex);
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
                    IpcLogInfo("Global security flags reset to non-signaled state.");
                }
                catch (Exception ex)
                {
                    IpcLogError("Error resetting system state flags.", ex);
                }
            }
        }

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
                        IpcLogInfo("Phone app verification triggered.");
                    }
                    else if (normalizedUuid == "00005678-0000-1000-8000-00805f9b34fb")
                    {
                        _screenEvent?.Set();
                        IpcLogInfo("Phone screen unlock triggered.");
                    }
                }
                catch (Exception ex)
                {
                    IpcLogError("Error processing BLE signal.", ex);
                }
            }
        }

        private void IpcLogInfo(string message) => WriteToIpcFile("INFO", message);
        private void IpcLogError(string message, Exception ex) => WriteToIpcFile("ERROR", $"{message} {ex}");

        private void WriteToIpcFile(string level, string message)
        {
            try
            {
                if (!Directory.Exists(IpcLogDirectory)) Directory.CreateDirectory(IpcLogDirectory);
                File.AppendAllText(IpcLogFilePath, $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] [{level}] {message}{Environment.NewLine}", Encoding.UTF8);
            }
            catch { }
        }
    }
}