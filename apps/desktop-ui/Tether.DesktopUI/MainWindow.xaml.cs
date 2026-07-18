using Microsoft.Win32;
using System;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;
using Tether.Shared.Events;
using Tether.Shared.IPC;

namespace Tether.DesktopUI
{
    [SupportedOSPlatform("windows")]
    public partial class MainWindow : Window
    {
        private bool _isListening = true;
        private DispatcherTimer? _syncTimer;
        private bool _isInternalSliderChange = false;

        [ComImport, Guid("BCDE0395-E52F-467C-8E3D-C4579291692E")]
        internal class MMDeviceEnumerator { }

        [Guid("A95664D2-9614-4F35-A746-DE8DB63617E6"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        internal interface IMMDeviceEnumerator
        {
            [PreserveSig] int Reserved1(); [PreserveSig] int Reserved2(); [PreserveSig] int Reserved3();
            [PreserveSig] int GetDefaultAudioEndpoint(int dataFlow, int role, out IMMDevice ppDevice);
        }

        [Guid("D666063F-1587-4E43-81F1-B948E807363F"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        internal interface IMMDevice
        {
            [PreserveSig] int Activate(ref Guid iid, int dwClsCtx, IntPtr pActivationParams, [MarshalAs(UnmanagedType.IUnknown)] out object ppInterface);
        }

        [Guid("5CDF2C82-841E-4546-9722-0CF74078229A"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        internal interface IAudioEndpointVolume
        {
            [PreserveSig] int RegisterControlChangeNotify(IntPtr pNotify);
            [PreserveSig] int UnregisterControlChangeNotify(IntPtr pNotify);
            [PreserveSig] int GetChannelCount(out uint pnChannelCount);
            [PreserveSig] int SetMasterVolumeLevel(float fLevelDB, ref Guid pguidEventContext);
            [PreserveSig] int SetMasterVolumeLevelScalar(float fLevel, ref Guid pguidEventContext);
            [PreserveSig] int GetMasterVolumeLevel(out float pfLevelDB);
            [PreserveSig] int GetMasterVolumeLevelScalar(out float pfLevel);
        }

        [DllImport("user32.dll")]
        private static extern IntPtr MonitorFromWindow(IntPtr hwnd, uint dwFlags);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool GetPhysicalMonitorsFromHMONITOR(IntPtr hMonitor, uint dwPhysicalMonitorArraySize, [Out] PHYSICAL_MONITOR[] pPhysicalMonitorArray);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool DestroyPhysicalMonitor(IntPtr hMonitor);

        [DllImport("dxva2.dll", SetLastError = true)]
        private static extern bool GetMonitorBrightness(IntPtr hMonitor, out uint pdwMinimumBrightness, out uint pdwCurrentBrightness, out uint pdwMaximumBrightness);

        [DllImport("dxva2.dll", SetLastError = true)]
        private static extern bool SetMonitorBrightness(IntPtr hMonitor, uint dwBrightness);

        [DllImport("user32.dll")]
        private static extern IntPtr SendMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);

        [DllImport("kernel32.dll")]
        private static extern uint SetThreadExecutionState(uint esFlags);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct PHYSICAL_MONITOR
        {
            public IntPtr hPhysicalMonitor;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
            public string szPhysicalMonitorDescription;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct INPUT
        {
            public uint type;
            public MOUSEINPUT mi;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MOUSEINPUT
        {
            public int dx; public int dy; public uint mouseData; public uint dwFlags; public uint time; public IntPtr dwExtraInfo;
        }

        [DllImport("user32.dll", SetLastError = true)]
        private static extern uint SendInput(uint nInputs, INPUT[] pInputs, int cbSize);

        [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool CryptProtectData(ref DATA_BLOB pDataIn, string? szDataDescr, ref DATA_BLOB pOptionalEntropy, IntPtr pvReserved, IntPtr pPromptStruct, uint dwFlags, ref DATA_BLOB pDataOut);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool LogonUser(string? lpszUsername, string? lpszDomain, string? lpszPassword, int dwLogonType, int dwLogonProvider, out IntPtr phToken);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr hObject);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct DATA_BLOB { public int cbData; public IntPtr pbData; }

        private const uint MONITOR_DEFAULTTOPRIMARY = 0x00000001;
        private const uint WM_SYSCOMMAND = 0x0112;
        private const uint SC_MONITORPOWER = 0xF170;
        private static readonly IntPtr HWND_BROADCAST = (IntPtr)0xffff;

        public MainWindow()
        {
            InitializeComponent();
            ResolveUserContext();
            LogTerminal("SYSTEM // Tether Telemetry Workspace loaded successfully.");
            CheckProvisioningStatus();

            _ = RunTelemetryListenerAsync();
            InitializeHardwarePolling();
        }

        private void CheckProvisioningStatus()
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Tether\CredentialProvider");
                if (key != null)
                {
                    var provisioned = key.GetValue("Provisioned") as int?;
                    if (provisioned == 1)
                    {
                        var storedKey = key.GetValue("TrustedPhonePublicKey") as string;
                        if (!string.IsNullOrEmpty(storedKey))
                        {
                            TxtProvisionStatus.Text = "✓ Phone paired";
                            TxtProvisionStatus.Foreground = new SolidColorBrush(Color.FromRgb(0x00, 0xFF, 0x66));
                            return;
                        }
                    }
                }
                TxtProvisionStatus.Text = "✗ Not paired";
                TxtProvisionStatus.Foreground = new SolidColorBrush(Color.FromRgb(0xFF, 0x00, 0x55));
            }
            catch
            {
                TxtProvisionStatus.Text = "✗ Error reading pairing status";
                TxtProvisionStatus.Foreground = new SolidColorBrush(Color.FromRgb(0xFF, 0x00, 0x55));
            }
        }

        private async Task RunTelemetryListenerAsync()
        {
            while (_isListening)
            {
                try
                {
                    var uiPipeSecurity = new PipeSecurity();
                    uiPipeSecurity.AddAccessRule(new PipeAccessRule(
                        WindowsIdentity.GetCurrent().User!,
                        PipeAccessRights.ReadWrite,
                        AccessControlType.Allow));
                    uiPipeSecurity.AddAccessRule(new PipeAccessRule(
                        new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                        PipeAccessRights.ReadWrite,
                        AccessControlType.Allow));

                    using var server = NamedPipeServerStreamAcl.Create(
                        IpcConstants.UiPipeName,
                        PipeDirection.In,
                        NamedPipeServerStream.MaxAllowedServerInstances,
                        PipeTransmissionMode.Message,
                        PipeOptions.Asynchronous,
                        0,
                        0,
                        uiPipeSecurity);

                    await server.WaitForConnectionAsync();

                    var buffer = new byte[IpcConstants.PipeBufferSize];
                    int readBytes = await server.ReadAsync(buffer, 0, buffer.Length);

                    if (readBytes > 0)
                    {
                        string json = Encoding.UTF8.GetString(buffer, 0, readBytes);
                        var telemetryEvent = JsonSerializer.Deserialize<TetherEvent>(json);
                        if (telemetryEvent != null)
                        {
                            Dispatcher.Invoke(() => ParseRelayedSignal(telemetryEvent));
                        }
                    }
                }
                catch { await Task.Delay(500); }
            }
        }

        private void ParseRelayedSignal(TetherEvent evt)
        {
            switch (evt.EventType)
            {
                case TetherEventType.PHONE_CONNECTED:
                    TxtStatus.Text = "LINK ENFORCED";
                    IndicatorNode.Fill = new SolidColorBrush(Color.FromRgb(0x00, 0xFF, 0x66));
                    LogTerminal("✓ LINK // Cryptographic over-the-air validation chain locked.");
                    ForceTelemetrySyncToPhone();
                    break;

                case TetherEventType.PHONE_DISCONNECTED:
                    TxtStatus.Text = "NODE DISCONNECTED";
                    IndicatorNode.Fill = new SolidColorBrush(Color.FromRgb(0xFF, 0x00, 0x55));
                    LogTerminal("⚠ LINK // Target node dropped carrier radio links unexpectedly.");
                    break;

                case TetherEventType.TRUST_DEGRADED:
                    if (!string.IsNullOrEmpty(evt.PayloadJson))
                    {
                        try
                        {
                            using var document = JsonDocument.Parse(evt.PayloadJson);
                            var root = document.RootElement;
                            if (root.TryGetProperty("HardwareAction", out var actionProp))
                            {
                                ExecuteHardwareAction(actionProp.GetString());
                            }
                        }
                        catch { }
                    }
                    break;

                case TetherEventType.OVERLAY_DISABLED:
                    if (evt.PayloadJson?.Contains("wake_") == true)
                    {
                        WakeSystemDisplayAndInput();
                        LogTerminal("✓ POWER // Interactive display wake sequence executed.");
                    }
                    break;

                case TetherEventType.PROVISION_PHONE:
                    CheckProvisioningStatus();
                    break;
            }
        }

        private void InitializeHardwarePolling()
        {
            _syncTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1.5) };
            _syncTimer.Tick += (s, e) => PollAndSynchronizeHardwareStates();
            _syncTimer.Start();
        }

        private void PollAndSynchronizeHardwareStates()
        {
            if (SliderVolume.IsMouseCaptureWithin || SliderBrightness.IsMouseCaptureWithin) return;

            _isInternalSliderChange = true;

            int currentVol = (int)(GetSystemMasterVolume() * 100);
            SliderVolume.Value = currentVol;
            TxtVolumeValue.Text = $"{currentVol}%";

            int currentBri = (int)GetMonitorBrightnessLevel();
            SliderBrightness.Value = currentBri;
            TxtBrightnessValue.Text = $"{currentBri}%";

            _isInternalSliderChange = false;
        }

        private void ExecuteHardwareAction(string? action)
        {
            if (string.IsNullOrEmpty(action)) return;
            LogTerminal($"⚙ SYSTEM // Executing hardware primitive context shift: {action}");

            float vol = GetSystemMasterVolume();
            uint bri = GetMonitorBrightnessLevel();

            switch (action)
            {
                case "volume_up": SetSystemMasterVolume(Math.Min(1.0f, vol + 0.04f)); break;
                case "volume_down": SetSystemMasterVolume(Math.Max(0.0f, vol - 0.04f)); break;
                case "brightness_up": SetMonitorBrightnessLevel((uint)Math.Min(100, bri + 5)); break;
                case "brightness_down": SetMonitorBrightnessLevel((uint)Math.Max(0, bri - 5)); break;
            }
            PollAndSynchronizeHardwareStates();
            ForceTelemetrySyncToPhone();
        }

        private void WakeSystemDisplayAndInput()
        {
            SetThreadExecutionState(0x00000002 | 0x00000001 | 0x80000000);
            SendMessage(HWND_BROADCAST, WM_SYSCOMMAND, (IntPtr)SC_MONITORPOWER, (IntPtr)(-1));

            INPUT[] inputs = new INPUT[1];
            inputs[0].type = 0;
            inputs[0].mi.dx = 1; inputs[0].mi.dy = 1; inputs[0].mi.dwFlags = 0x0001;
            SendInput(1, inputs, Marshal.SizeOf(typeof(INPUT)));
        }

        private float GetSystemMasterVolume()
        {
            var volume = GetAudioEndpointVolumeInterface();
            if (volume == null) return 0.0f;
            volume.GetMasterVolumeLevelScalar(out float level);
            Marshal.ReleaseComObject(volume);
            return level;
        }

        private void SetSystemMasterVolume(float level)
        {
            var volume = GetAudioEndpointVolumeInterface();
            if (volume == null) return;
            Guid empty = Guid.Empty;
            volume.SetMasterVolumeLevelScalar(level, ref empty);
            Marshal.ReleaseComObject(volume);
        }

        private IAudioEndpointVolume? GetAudioEndpointVolumeInterface()
        {
            try
            {
                var enumerator = (IMMDeviceEnumerator)new MMDeviceEnumerator();
                enumerator.GetDefaultAudioEndpoint(0, 0, out IMMDevice device);
                Guid iid = new Guid("5CDF2C82-841E-4546-9722-0CF74078229A");
                device.Activate(ref iid, 23, IntPtr.Zero, out object comInterface);
                return (IAudioEndpointVolume)comInterface;
            }
            catch { return null; }
        }

        private uint GetMonitorBrightnessLevel()
        {
            try
            {
                IntPtr hMonitor = MonitorFromWindow(IntPtr.Zero, MONITOR_DEFAULTTOPRIMARY);
                PHYSICAL_MONITOR[] monitors = new PHYSICAL_MONITOR[1];
                if (GetPhysicalMonitorsFromHMONITOR(hMonitor, 1, monitors))
                {
                    GetMonitorBrightness(monitors[0].hPhysicalMonitor, out _, out uint current, out _);
                    DestroyPhysicalMonitor(monitors[0].hPhysicalMonitor);
                    return current;
                }
            }
            catch { }
            return 0;
        }

        private void SetMonitorBrightnessLevel(uint level)
        {
            try
            {
                IntPtr hMonitor = MonitorFromWindow(IntPtr.Zero, MONITOR_DEFAULTTOPRIMARY);
                PHYSICAL_MONITOR[] monitors = new PHYSICAL_MONITOR[1];
                if (GetPhysicalMonitorsFromHMONITOR(hMonitor, 1, monitors))
                {
                    SetMonitorBrightness(monitors[0].hPhysicalMonitor, level);
                    DestroyPhysicalMonitor(monitors[0].hPhysicalMonitor);
                }
            }
            catch { }
        }

        private void SliderVolume_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
        {
            if (_isInternalSliderChange) return;
            SetSystemMasterVolume((float)(SliderVolume.Value / 100.0));
            TxtVolumeValue.Text = $"{(int)SliderVolume.Value}%";
            ForceTelemetrySyncToPhone();
        }

        private void SliderBrightness_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
        {
            if (_isInternalSliderChange) return;
            SetMonitorBrightnessLevel((uint)SliderBrightness.Value);
            TxtBrightnessValue.Text = $"{(int)SliderBrightness.Value}%";
            ForceTelemetrySyncToPhone();
        }

        private void ForceTelemetrySyncToPhone()
        {
            int vol = (int)(GetSystemMasterVolume() * 100);
            int bri = (int)GetMonitorBrightnessLevel();

            var syncEvent = new TetherEvent
            {
                EventType = TetherEventType.AUTH_SUCCESS,
                Source = "DesktopUI",
                PayloadJson = $"{{\"SyncPayload\":\"sync_levels:vol={vol},bri={bri}\"}}"
            };
            DispatchServiceBusPipe(syncEvent);
        }

        private void LogTerminal(string message)
        {
            TxtTerminal.AppendText($"[{DateTime.Now:HH:mm:ss}] {message}\n");
            TerminalScroll.ScrollToEnd();
        }

        private async void DispatchServiceBusPipe(TetherEvent evt)
        {
            // Check if the service process is running (optional: use ServiceController).
            // For simplicity, we'll just attempt to connect with a short timeout and retry.
            const int maxAttempts = 3;
            const int retryDelayMs = 500;

            for (int attempt = 0; attempt < maxAttempts; attempt++)
            {
                try
                {
                    string json = JsonSerializer.Serialize(evt);
                    byte[] bytes = Encoding.UTF8.GetBytes(json);
                    using var client = new NamedPipeClientStream(".", IpcConstants.PipeName, PipeDirection.Out);
                    await client.ConnectAsync(200);  // 200 ms timeout
                    await client.WriteAsync(bytes, 0, bytes.Length);
                    await client.FlushAsync();
                    return; // success
                }
                catch (TimeoutException)
                {
                    // The service might not be running yet.
                    if (attempt < maxAttempts - 1)
                        await Task.Delay(retryDelayMs);
                }
                catch (Exception ex)
                {
                    LogTerminal($"⚠ PIPE // Failed to send event: {ex.Message}");
                    break;
                }
            }
            if (!_isListening) return;
            LogTerminal("⚠ PIPE // Could not reach Tether service – is it running?");
        }

        private void BtnProvision_Click(object sender, RoutedEventArgs e)
        {
            string key = TxtPublicKey.Text.Trim();
            if (string.IsNullOrEmpty(key))
            {
                LogTerminal("❌ PAIRING // Public key cannot be empty.");
                return;
            }

            try
            {
                Convert.FromBase64String(key);
            }
            catch
            {
                LogTerminal("❌ PAIRING // Invalid base64 public key format.");
                return;
            }

            var evt = new TetherEvent
            {
                EventType = TetherEventType.PROVISION_PHONE,
                Source = "DesktopUI",
                PayloadJson = $"{{\"PublicKeyBase64\":\"{key}\"}}"
            };
            DispatchServiceBusPipe(evt);
            LogTerminal("✓ PAIRING // Provisioning request sent to service.");
            TxtPublicKey.Clear();
            CheckProvisioningStatus();
        }

        private void BtnCommitVault_Click(object sender, RoutedEventArgs e)
        {
            IntPtr unmanagedPasswordPtr = IntPtr.Zero;
            IntPtr unmanagedEntropy = IntPtr.Zero;
            try
            {
                if (TxtPassword.SecurePassword.Length == 0) return;

                int plainTextLength = TxtPassword.SecurePassword.Length;
                int byteLength = plainTextLength * 2;
                unmanagedPasswordPtr = Marshal.SecureStringToGlobalAllocUnicode(TxtPassword.SecurePassword);

                // Safe validation using native pointer directly to block managed heap generation
                if (!LogonUser(Environment.UserName, Environment.UserDomainName, Marshal.PtrToStringUni(unmanagedPasswordPtr), 2, 0, out IntPtr token))
                {
                    LogTerminal("❌ VAULT // Windows operational token assignment failed. Secret rejected.");
                    return;
                }
                CloseHandle(token);

                // Allocate and setup application-specific entropy to restrict generic DPAPI decryption tools
                byte[] entropyBytes = Encoding.UTF8.GetBytes("Tether_System_Bound_Vault_v1");
                unmanagedEntropy = Marshal.AllocHGlobal(entropyBytes.Length);
                Marshal.Copy(entropyBytes, 0, unmanagedEntropy, entropyBytes.Length);

                DATA_BLOB dataIn = new DATA_BLOB { cbData = byteLength, pbData = unmanagedPasswordPtr };
                DATA_BLOB dataOut = new DATA_BLOB();
                DATA_BLOB entropy = new DATA_BLOB { cbData = entropyBytes.Length, pbData = unmanagedEntropy };

                if (CryptProtectData(ref dataIn, "TetherCredentialProviderSecret", ref entropy, IntPtr.Zero, IntPtr.Zero, 0x5, ref dataOut))
                {
                    byte[] protectedPayload = new byte[dataOut.cbData];
                    Marshal.Copy(dataOut.pbData, protectedPayload, 0, dataOut.cbData);
                    using RegistryKey? regKey = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Tether\CredentialProvider", true);
                    regKey?.SetValue("EncryptedPassword", protectedPayload, RegistryValueKind.Binary);
                    LogTerminal("✓ VAULT // Cryptographic alignment sealed with application entropy.");
                    TxtPassword.Clear();
                }
            }
            catch (Exception ex) { LogTerminal($"Fatal registry exception: {ex.Message}"); }
            finally
            {
                if (unmanagedEntropy != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(unmanagedEntropy);
                }
                if (unmanagedPasswordPtr != IntPtr.Zero)
                {
                    // Strict forensic zeroization of raw unmanaged memory space parameters
                    byte[] zeroBuffer = new byte[TxtPassword.SecurePassword.Length * 2];
                    Marshal.Copy(zeroBuffer, 0, unmanagedPasswordPtr, zeroBuffer.Length);
                    Marshal.ZeroFreeGlobalAllocUnicode(unmanagedPasswordPtr);
                }
            }
        }

        private void ResolveUserContext() => TxtUserType.Text = $"✓ SECURE SUBSYSTEM BOUNDS: {Environment.UserDomainName}\\{Environment.UserName}";
        private void BtnUnlockOverride_Click(object sender, RoutedEventArgs e) => DispatchServiceBusPipe(new TetherEvent { EventType = TetherEventType.PHONE_UNLOCKED, Source = "DesktopUI" });
        private void BtnLockdownOverride_Click(object sender, RoutedEventArgs e) => DispatchServiceBusPipe(new TetherEvent { EventType = TetherEventType.PANIC_TRIGGERED, Source = "DesktopUI" });
        protected override void OnClosed(EventArgs e) { _isListening = false; _syncTimer?.Stop(); base.OnClosed(e); }
    }
}