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
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Animation;
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
        private DispatcherTimer? _telemetryDebounceTimer;
        private bool _isInternalSliderChange = false;
        private bool _isClosingAnimated = false;
        private uint _cachedBrightness = 50;

        // =====================================================================
        // COREAUDIO COM INTEROP
        // =====================================================================
        [ComImport, Guid("BCDE0395-E52F-467C-8E3D-C4579291692E")]
        internal class MMDeviceEnumerator { }

        [Guid("A95664D2-9614-4F35-A746-DE8DB63617E6"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        internal interface IMMDeviceEnumerator
        {
            [PreserveSig] int EnumAudioEndpoints(int dataFlow, int dwStateMask, out IntPtr ppDevices);
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

        // =====================================================================
        // WINDOWS DWM BACKDROP API
        // =====================================================================
        [DllImport("dwmapi.dll", PreserveSig = true)]
        private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int attrValue, int attrSize);

        [DllImport("dwmapi.dll", PreserveSig = true)]
        private static extern int DwmExtendFrameIntoClientArea(IntPtr hWnd, ref MARGINS pMarInset);

        [StructLayout(LayoutKind.Sequential)]
        private struct MARGINS
        {
            public int cxLeftWidth;
            public int cxRightWidth;
            public int cyTopHeight;
            public int cyBottomHeight;
        }

        private const int DWMWA_USE_IMMERSIVE_DARK_MODE = 20;
        private const int DWMWA_WINDOW_CORNER_PREFERENCE = 33;
        private const int DWMWA_SYSTEMBACKDROP_TYPE = 38;
        private const int DWMWCP_ROUND = 2;
        private const int DWMSBT_MAINWINDOW = 2;
        private const int DWMSBT_TRANSIENTWINDOW = 3;

        // =====================================================================
        // WIN32 POWER SETTING API (INTERNAL DISPLAY BACKLIGHT)
        // =====================================================================
        [DllImport("powrprof.dll", SetLastError = true)]
        private static extern uint PowerGetActiveScheme(IntPtr UserRootPowerKey, out IntPtr ActivePolicyGuid);

        [DllImport("powrprof.dll", SetLastError = true)]
        private static extern uint PowerSetActiveScheme(IntPtr UserRootPowerKey, ref Guid SchemeGuid);

        [DllImport("powrprof.dll", SetLastError = true)]
        private static extern uint PowerWriteACValueIndex(IntPtr RootPowerKey, ref Guid SchemeGuid, ref Guid SubGroupOfPowerSettingsGuid, ref Guid PowerSettingGuid, uint AcValueIndex);

        [DllImport("powrprof.dll", SetLastError = true)]
        private static extern uint PowerWriteDCValueIndex(IntPtr RootPowerKey, ref Guid SchemeGuid, ref Guid SubGroupOfPowerSettingsGuid, ref Guid PowerSettingGuid, uint DcValueIndex);

        [DllImport("powrprof.dll", SetLastError = true)]
        private static extern uint PowerReadACValueIndex(IntPtr RootPowerKey, ref Guid SchemeGuid, ref Guid SubGroupOfPowerSettingsGuid, ref Guid PowerSettingGuid, out uint AcValueIndex);

        private static readonly Guid GUID_VIDEO_SUBGROUP = new Guid("7516b95f-f776-4464-8c53-06167f40cc99");
        private static readonly Guid GUID_DEVICE_POWER_POLICY_VIDEO_BRIGHTNESS = new Guid("aded5e82-b909-4619-9949-f5d71dac0bcb");

        // =====================================================================
        // DXVA2 DDC/CI API (EXTERNAL MONITORS)
        // =====================================================================
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

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct PHYSICAL_MONITOR
        {
            public IntPtr hPhysicalMonitor;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
            public string szPhysicalMonitorDescription;
        }

        // =====================================================================
        // GDI HARDWARE GAMMA RAMP API (UNIVERSAL HARDWARE FALLBACK)
        // =====================================================================
        [DllImport("gdi32.dll")]
        private static extern bool SetDeviceGammaRamp(IntPtr hDC, ref RAMP lpRamp);

        [DllImport("gdi32.dll")]
        private static extern bool GetDeviceGammaRamp(IntPtr hDC, ref RAMP lpRamp);

        [DllImport("user32.dll")]
        private static extern IntPtr GetDC(IntPtr hWnd);

        [DllImport("user32.dll")]
        private static extern int ReleaseDC(IntPtr hWnd, IntPtr hDC);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        private struct RAMP
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
            public ushort[] Red;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
            public ushort[] Green;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
            public ushort[] Blue;
        }

        // =====================================================================
        // SYSTEM WAKE & INPUT SYNTHESIS
        // =====================================================================
        [DllImport("user32.dll")]
        private static extern IntPtr SendMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);

        [DllImport("kernel32.dll")]
        private static extern uint SetThreadExecutionState(uint esFlags);

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

        // =====================================================================
        // DPAPI VAULT API
        // =====================================================================
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

        protected override void OnSourceInitialized(EventArgs e)
        {
            base.OnSourceInitialized(e);
            ApplyDwmGlassBackdrop();
        }

        private void ApplyDwmGlassBackdrop()
        {
            try
            {
                IntPtr hwnd = new WindowInteropHelper(this).Handle;
                if (hwnd == IntPtr.Zero) return;

                var hwndSource = HwndSource.FromHwnd(hwnd);
                if (hwndSource?.CompositionTarget != null)
                {
                    hwndSource.CompositionTarget.BackgroundColor = Colors.Transparent;
                }

                MARGINS margins = new MARGINS { cxLeftWidth = -1, cxRightWidth = -1, cyTopHeight = -1, cyBottomHeight = -1 };
                DwmExtendFrameIntoClientArea(hwnd, ref margins);

                int darkMode = 1;
                DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, ref darkMode, sizeof(int));

                int cornerPreference = DWMWCP_ROUND;
                DwmSetWindowAttribute(hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, ref cornerPreference, sizeof(int));

                int backdropType = Environment.OSVersion.Version.Build >= 22621
                    ? DWMSBT_TRANSIENTWINDOW
                    : DWMSBT_MAINWINDOW;

                int hr = DwmSetWindowAttribute(hwnd, DWMWA_SYSTEMBACKDROP_TYPE, ref backdropType, sizeof(int));
                if (hr != 0)
                {
                    int micaFallback = DWMSBT_MAINWINDOW;
                    DwmSetWindowAttribute(hwnd, DWMWA_SYSTEMBACKDROP_TYPE, ref micaFallback, sizeof(int));
                }
            }
            catch { }
        }

        private void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            var entranceStoryboard = new Storyboard();

            var scaleXAnim = new DoubleAnimation(0.96, 1.0, new Duration(TimeSpan.FromSeconds(0.35))) { DecelerationRatio = 0.9 };
            Storyboard.SetTarget(scaleXAnim, WindowScale);
            Storyboard.SetTargetProperty(scaleXAnim, new PropertyPath(ScaleTransform.ScaleXProperty));

            var scaleYAnim = new DoubleAnimation(0.96, 1.0, new Duration(TimeSpan.FromSeconds(0.35))) { DecelerationRatio = 0.9 };
            Storyboard.SetTarget(scaleYAnim, WindowScale);
            Storyboard.SetTargetProperty(scaleYAnim, new PropertyPath(ScaleTransform.ScaleYProperty));

            var translateAnim = new DoubleAnimation(20.0, 0.0, new Duration(TimeSpan.FromSeconds(0.35))) { DecelerationRatio = 0.9 };
            Storyboard.SetTarget(translateAnim, WindowTranslate);
            Storyboard.SetTargetProperty(translateAnim, new PropertyPath(TranslateTransform.YProperty));

            var opacityAnim = new DoubleAnimation(0.0, 1.0, new Duration(TimeSpan.FromSeconds(0.25)));
            Storyboard.SetTarget(opacityAnim, this);
            Storyboard.SetTargetProperty(opacityAnim, new PropertyPath(Window.OpacityProperty));

            entranceStoryboard.Children.Add(scaleXAnim);
            entranceStoryboard.Children.Add(scaleYAnim);
            entranceStoryboard.Children.Add(translateAnim);
            entranceStoryboard.Children.Add(opacityAnim);

            entranceStoryboard.Begin();
        }

        private void BtnMinimize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;

        private void BtnMaximize_Click(object sender, RoutedEventArgs e) =>
            WindowState = (WindowState == WindowState.Maximized) ? WindowState.Normal : WindowState.Maximized;

        private void BtnClose_Click(object sender, RoutedEventArgs e) => Close();

        protected override void OnClosing(System.ComponentModel.CancelEventArgs e)
        {
            if (!_isClosingAnimated)
            {
                e.Cancel = true;
                _isClosingAnimated = true;

                var fadeOut = new DoubleAnimation(1.0, 0.0, new Duration(TimeSpan.FromSeconds(0.2)));
                var scaleX = new DoubleAnimation(1.0, 0.96, new Duration(TimeSpan.FromSeconds(0.25)));
                var scaleY = new DoubleAnimation(1.0, 0.96, new Duration(TimeSpan.FromSeconds(0.25)));
                var translate = new DoubleAnimation(0.0, 20.0, new Duration(TimeSpan.FromSeconds(0.25)));

                fadeOut.Completed += (s, ev) => Close();

                WindowScale.BeginAnimation(ScaleTransform.ScaleXProperty, scaleX);
                WindowScale.BeginAnimation(ScaleTransform.ScaleYProperty, scaleY);
                WindowTranslate.BeginAnimation(TranslateTransform.YProperty, translate);
                BeginAnimation(OpacityProperty, fadeOut);
            }
            else
            {
                _isListening = false;
                _syncTimer?.Stop();
                _telemetryDebounceTimer?.Stop();
                base.OnClosing(e);
            }
        }

        private SolidColorBrush GetFluentStatusBrush(string key, Color fallbackColor)
        {
            if (Application.Current != null)
            {
                if (Application.Current.TryFindResource(key) is SolidColorBrush resolvedBrush)
                {
                    return resolvedBrush;
                }
            }
            return new SolidColorBrush(fallbackColor);
        }

        private void CheckProvisioningStatus() { }

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
                    IndicatorNode.Fill = GetFluentStatusBrush("StatusHealthyBrush", Color.FromRgb(106, 237, 126));
                    LogTerminal("✓ LINK // Cryptographic over-the-air validation chain locked.");
                    ForceTelemetrySyncToPhone();
                    break;

                case TetherEventType.PHONE_DISCONNECTED:
                    TxtStatus.Text = "NODE DISCONNECTED";
                    IndicatorNode.Fill = GetFluentStatusBrush("StatusCriticalBrush", Color.FromRgb(255, 153, 164));
                    LogTerminal("⚠ LINK // Target node dropped carrier radio links unexpectedly.");
                    break;

                case TetherEventType.PAIRING_REQUESTED:
                    if (!string.IsNullOrEmpty(evt.PayloadJson))
                    {
                        try
                        {
                            using var document = JsonDocument.Parse(evt.PayloadJson);
                            var root = document.RootElement;
                            string pin = root.TryGetProperty("pin", out var p) ? p.GetString() ?? "" : "";
                            string devName = root.TryGetProperty("displayName", out var d) ? d.GetString() ?? "Phone" : "Phone";
                            LogTerminal($"⚠ PAIRING REQUEST // PIN: {pin} for device '{devName}'");
                            MessageBox.Show(
                                this,
                                $"Pairing Request from {devName}\n\nEnter this 6-digit PIN on your phone:\n\n      {pin}      \n",
                                "Tether — Device Pairing",
                                MessageBoxButton.OK,
                                MessageBoxImage.Information);
                        }
                        catch { }
                    }
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
            DebounceTelemetrySync();
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

        // =====================================================================
        // AUDIO ENDPOINT IMPLEMENTATION
        // =====================================================================
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
                int hr = enumerator.GetDefaultAudioEndpoint(0, 0, out IMMDevice device);
                if (hr != 0 || device == null) return null;

                Guid iid = new Guid("5CDF2C82-841E-4546-9722-0CF74078229A");
                device.Activate(ref iid, 23, IntPtr.Zero, out object comInterface);
                Marshal.ReleaseComObject(device);
                return (IAudioEndpointVolume)comInterface;
            }
            catch { return null; }
        }

        // =====================================================================
        // MULTI-TIERED BRIGHTNESS CONTROLLER
        // Tier 1: Windows Power Setting API (Internal Displays / Native Slider)
        // Tier 2: DXVA2 DDC/CI (External Hardware Displays)
        // Tier 3: GDI Hardware Gamma Ramp (Universal Fallback)
        // =====================================================================
        private uint GetMonitorBrightnessLevel()
        {
            // Tier 1: Query Windows Native Power Scheme
            try
            {
                if (PowerGetActiveScheme(IntPtr.Zero, out IntPtr activeGuidPtr) == 0 && activeGuidPtr != IntPtr.Zero)
                {
                    Guid activeScheme = Marshal.PtrToStructure<Guid>(activeGuidPtr);
                    Guid subgroup = GUID_VIDEO_SUBGROUP;
                    Guid setting = GUID_DEVICE_POWER_POLICY_VIDEO_BRIGHTNESS;

                    if (PowerReadACValueIndex(IntPtr.Zero, ref activeScheme, ref subgroup, ref setting, out uint val) == 0)
                    {
                        if (val <= 100)
                        {
                            _cachedBrightness = val;
                            return val;
                        }
                    }
                }
            }
            catch { }

            // Tier 2: DXVA2 DDC/CI
            try
            {
                IntPtr hMonitor = MonitorFromWindow(IntPtr.Zero, MONITOR_DEFAULTTOPRIMARY);
                PHYSICAL_MONITOR[] monitors = new PHYSICAL_MONITOR[1];
                if (GetPhysicalMonitorsFromHMONITOR(hMonitor, 1, monitors))
                {
                    bool success = GetMonitorBrightness(monitors[0].hPhysicalMonitor, out _, out uint current, out _);
                    DestroyPhysicalMonitor(monitors[0].hPhysicalMonitor);
                    if (success && current <= 100)
                    {
                        _cachedBrightness = current;
                        return current;
                    }
                }
            }
            catch { }

            return _cachedBrightness;
        }

        private void SetMonitorBrightnessLevel(uint level)
        {
            level = Math.Clamp(level, 0, 100);
            _cachedBrightness = level;
            bool hardwareControlled = false;

            // Tier 1: Apply to Windows Native Power Scheme (Controls Laptop Backlight + Settings Slider)
            try
            {
                if (PowerGetActiveScheme(IntPtr.Zero, out IntPtr activeGuidPtr) == 0 && activeGuidPtr != IntPtr.Zero)
                {
                    Guid activeScheme = Marshal.PtrToStructure<Guid>(activeGuidPtr);
                    Guid subgroup = GUID_VIDEO_SUBGROUP;
                    Guid setting = GUID_DEVICE_POWER_POLICY_VIDEO_BRIGHTNESS;

                    uint resAc = PowerWriteACValueIndex(IntPtr.Zero, ref activeScheme, ref subgroup, ref setting, level);
                    uint resDc = PowerWriteDCValueIndex(IntPtr.Zero, ref activeScheme, ref subgroup, ref setting, level);

                    if (resAc == 0 || resDc == 0)
                    {
                        PowerSetActiveScheme(IntPtr.Zero, ref activeScheme);
                        hardwareControlled = true;
                    }
                }
            }
            catch { }

            // Tier 2: Apply to External Monitors via DXVA2 DDC/CI
            try
            {
                IntPtr hMonitor = MonitorFromWindow(IntPtr.Zero, MONITOR_DEFAULTTOPRIMARY);
                PHYSICAL_MONITOR[] monitors = new PHYSICAL_MONITOR[1];
                if (GetPhysicalMonitorsFromHMONITOR(hMonitor, 1, monitors))
                {
                    if (SetMonitorBrightness(monitors[0].hPhysicalMonitor, level))
                    {
                        hardwareControlled = true;
                    }
                    DestroyPhysicalMonitor(monitors[0].hPhysicalMonitor);
                }
            }
            catch { }

            // Tier 3: Universal Hardware Gamma Ramp Fallback
            // If the monitor lacks DDC/CI or Windows power plan doesn't directly adjust luminescence,
            // modulating the video LUT ensures the screen visually brightens/dims reliably.
            if (!hardwareControlled)
            {
                ApplyHardwareGammaRamp(level);
            }
        }

        private void ApplyHardwareGammaRamp(uint level)
        {
            try
            {
                IntPtr hDC = GetDC(IntPtr.Zero);
                if (hDC == IntPtr.Zero) return;

                RAMP ramp = new RAMP
                {
                    Red = new ushort[256],
                    Green = new ushort[256],
                    Blue = new ushort[256]
                };

                // Map 0-100% brightness to gamma multipliers (minimum 10% luminance to prevent total blackout)
                double factor = Math.Max(0.10, level / 100.0);

                for (int i = 0; i < 256; i++)
                {
                    int value = (int)(i * 256.0 * factor);
                    ushort clampedValue = (ushort)Math.Clamp(value, 0, 65535);
                    ramp.Red[i] = clampedValue;
                    ramp.Green[i] = clampedValue;
                    ramp.Blue[i] = clampedValue;
                }

                SetDeviceGammaRamp(hDC, ref ramp);
                ReleaseDC(IntPtr.Zero, hDC);
            }
            catch { }
        }

        private void SliderVolume_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
        {
            if (_isInternalSliderChange || TxtVolumeValue == null) return;
            SetSystemMasterVolume((float)(SliderVolume.Value / 100.0));
            TxtVolumeValue.Text = $"{(int)SliderVolume.Value}%";
            DebounceTelemetrySync();
        }

        private void SliderBrightness_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
        {
            if (_isInternalSliderChange || TxtBrightnessValue == null) return;
            SetMonitorBrightnessLevel((uint)SliderBrightness.Value);
            TxtBrightnessValue.Text = $"{(int)SliderBrightness.Value}%";
            DebounceTelemetrySync();
        }

        private void DebounceTelemetrySync()
        {
            if (_telemetryDebounceTimer == null)
            {
                _telemetryDebounceTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(200) };
                _telemetryDebounceTimer.Tick += (s, e) =>
                {
                    _telemetryDebounceTimer.Stop();
                    ForceTelemetrySyncToPhone();
                };
            }
            _telemetryDebounceTimer.Stop();
            _telemetryDebounceTimer.Start();
        }

        private void ForceTelemetrySyncToPhone()
        {
            int vol = (int)SliderVolume.Value;
            int bri = (int)SliderBrightness.Value;

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
            const int maxAttempts = 3;
            const int retryDelayMs = 300;

            for (int attempt = 0; attempt < maxAttempts; attempt++)
            {
                try
                {
                    string json = JsonSerializer.Serialize(evt);
                    byte[] bytes = Encoding.UTF8.GetBytes(json);
                    using var client = new NamedPipeClientStream(".", IpcConstants.PipeName, PipeDirection.Out);
                    await client.ConnectAsync(800);
                    await client.WriteAsync(bytes, 0, bytes.Length);
                    await client.FlushAsync();
                    return;
                }
                catch (TimeoutException)
                {
                    if (attempt < maxAttempts - 1)
                        await Task.Delay(retryDelayMs);
                }
                catch (Exception ex)
                {
                    LogTerminal($"⚠ PIPE // Dispatch failed: {ex.Message}");
                    break;
                }
            }
            if (!_isListening) return;
            LogTerminal("⚠ PIPE // Could not reach Tether service – verify service process status.");
        }

        private void BtnUnlockOverride_Click(object sender, RoutedEventArgs e)
        {
            WakeSystemDisplayAndInput();

            TxtStatus.Text = "INTERLOCK OVERRIDDEN";
            IndicatorNode.Fill = GetFluentStatusBrush("StatusHealthyBrush", Color.FromRgb(106, 237, 126));

            var evt = new TetherEvent
            {
                EventType = TetherEventType.PHONE_UNLOCKED,
                Source = "DesktopUI"
            };
            DispatchServiceBusPipe(evt);
            LogTerminal("✓ OVERRIDE // Manual interlock bypass dispatched and display input awakened.");
        }

        private void BtnLockdownOverride_Click(object sender, RoutedEventArgs e)
        {
            var evt = new TetherEvent
            {
                EventType = TetherEventType.PANIC_TRIGGERED,
                Source = "DesktopUI"
            };
            DispatchServiceBusPipe(evt);
            LogTerminal("⚠ OVERRIDE // System lockdown event dispatched.");
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

                if (!LogonUser(Environment.UserName, Environment.UserDomainName, Marshal.PtrToStringUni(unmanagedPasswordPtr), 2, 0, out IntPtr token))
                {
                    LogTerminal("❌ VAULT // Windows operational token assignment failed. Secret rejected.");
                    return;
                }
                CloseHandle(token);

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
                    byte[] zeroBuffer = new byte[TxtPassword.SecurePassword.Length * 2];
                    Marshal.Copy(zeroBuffer, 0, unmanagedPasswordPtr, zeroBuffer.Length);
                    Marshal.ZeroFreeGlobalAllocUnicode(unmanagedPasswordPtr);
                }
            }
        }

        private void ResolveUserContext() => TxtUserType.Text = $"{Environment.UserDomainName}\\{Environment.UserName}";
    }
}