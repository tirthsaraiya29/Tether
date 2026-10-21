using Microsoft.Win32;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
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
        private const int MaxTerminalEntries = 250;
        private readonly ObservableCollection<string> _terminalLogs = new();
        private PipeSecurity? _cachedPipeSecurity;

        private bool _isListening = true;
        private DispatcherTimer? _syncTimer;
        private DispatcherTimer? _telemetryDebounceTimer;
        private bool _isInternalSliderChange = false;
        private bool _isClosingAnimated = false;
        private uint _cachedBrightness = 50;
        private bool _supportsPowerSchemeBrightness = true;
        private string _activeTransferId = "";

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

        [DllImport("dwmapi.dll", PreserveSig = true)]
        private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int attrValue, int attrSize);

        [DllImport("dwmapi.dll", PreserveSig = true)]
        private static extern int DwmExtendFrameIntoClientArea(IntPtr hWnd, ref MARGINS pMarInset);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool LockWorkStation();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetProcessWorkingSetSize(IntPtr hProcess, IntPtr dwMinimumWorkingSetSize, IntPtr dwMaximumWorkingSetSize);

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

        [DllImport("powrprof.dll", SetLastError = true)]
        private static extern uint PowerGetActiveScheme(IntPtr UserRootPowerKey, out IntPtr ActivePolicyGuid);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr LocalFree(IntPtr hMem);

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

        [DllImport("user32.dll")]
        private static extern IntPtr MonitorFromWindow(IntPtr hwnd, uint dwFlags);

        [DllImport("dxva2.dll", SetLastError = true)]
        private static extern bool GetPhysicalMonitorsFromHMONITOR(IntPtr hMonitor, uint dwPhysicalMonitorArraySize, [Out] PHYSICAL_MONITOR[] pPhysicalMonitorArray);

        [DllImport("dxva2.dll", SetLastError = true)]
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

        [DllImport("gdi32.dll")]
        private static extern bool SetDeviceGammaRamp(IntPtr hDC, ref RAMP lpRamp);

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

        [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool CryptProtectData(ref DATA_BLOB pDataIn, string? szDataDescr, ref DATA_BLOB pOptionalEntropy, IntPtr pvReserved, IntPtr pPromptStruct, uint dwFlags, ref DATA_BLOB pDataOut);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool LogonUser(string? lpszUsername, string? lpszDomain, string? lpszPassword, int dwLogonType, int dwLogonProvider, out IntPtr phToken);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr hObject);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct DATA_BLOB { public int cbData; public IntPtr pbData; }

        [StructLayout(LayoutKind.Sequential)]
        private struct SERVICE_STATUS
        {
            public uint dwServiceType;
            public uint dwCurrentState;
            public uint dwControlsAccepted;
            public uint dwWin32ExitCode;
            public uint dwServiceSpecificExitCode;
            public uint dwCheckPoint;
            public uint dwWaitHint;
        }

        private const uint SC_MANAGER_CONNECT = 0x0001;
        private const uint SERVICE_QUERY_STATUS = 0x0004;
        private const uint SERVICE_START = 0x0010;
        private const uint SERVICE_STOP = 0x0020;

        private const uint SERVICE_CONTROL_STOP = 0x00000001;
        private const uint SERVICE_STOPPED = 0x00000001;
        private const int ERROR_SERVICE_ALREADY_RUNNING = 1056;
        private const string CommServiceName = "TetherCommService";

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr OpenSCManager(string? lpMachineName, string? lpDatabaseName, uint dwDesiredAccess);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr OpenService(IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool QueryServiceStatus(IntPtr hService, out SERVICE_STATUS lpServiceStatus);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool ControlService(IntPtr hService, uint dwControl, ref SERVICE_STATUS lpServiceStatus);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool StartService(IntPtr hService, int dwNumServiceArgs, string[]? lpServiceArgVectors);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CloseServiceHandle(IntPtr hSCObject);

        private const uint MONITOR_DEFAULTTOPRIMARY = 0x00000001;
        private const uint WM_SYSCOMMAND = 0x0112;
        private const uint SC_MONITORPOWER = 0xF170;
        private static readonly IntPtr HWND_BROADCAST = (IntPtr)0xffff;

        public MainWindow()
        {
            InitializeComponent();
            TerminalList.ItemsSource = _terminalLogs;

            ResolveUserContext();
            LogTerminal("Tether is ready.");
            EnsureVaultDaclArchitecture();
            UpdateDownloadFolderBtnText();
            LoadExplorerDirectory(GetCurrentDownloadFolder());

            StateChanged += MainWindow_StateChanged;

            _ = RunTelemetryListenerAsync();
            InitializeHardwarePolling();
        }

        private void MainWindow_StateChanged(object? sender, EventArgs e)
        {
            if (WindowState == WindowState.Minimized)
            {
                _syncTimer?.Stop();
                TrimProcessWorkingSet();
            }
            else
            {
                PollAndSynchronizeHardwareStates();
                _syncTimer?.Start();
            }
        }

        private static void TrimProcessWorkingSet()
        {
            try
            {
                using var currentProcess = Process.GetCurrentProcess();
                SetProcessWorkingSetSize(currentProcess.Handle, (IntPtr)(-1), (IntPtr)(-1));
            }
            catch { }
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
            catch (Exception ex)
            {
                Debug.WriteLine($"ApplyDwmGlassBackdrop warning: {ex.Message}");
            }
        }

        private void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            PollAndSynchronizeHardwareStates();
            var opacityAnim = new DoubleAnimation(0.0, 1.0, new Duration(TimeSpan.FromMilliseconds(160)));
            opacityAnim.Completed += (_, _) => BeginAnimation(OpacityProperty, null);
            BeginAnimation(OpacityProperty, opacityAnim);
        }

        private void NavRailList_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (CardPipeline == null || CardHardware == null || CardVault == null || CardFileTransfer == null) return;
            CardPipeline.Visibility = Visibility.Visible;
            CardHardware.Visibility = Visibility.Visible;
            CardVault.Visibility = Visibility.Visible;
            CardFileTransfer.Visibility = Visibility.Visible;
            LeftScrollViewer?.ScrollToTop();
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

                var fadeOut = new DoubleAnimation(1.0, 0.0, new Duration(TimeSpan.FromMilliseconds(120)));
                fadeOut.Completed += (s, ev) => Close();
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

        private Brush GetFluentBrush(string key, Color fallbackColor)
        {
            if (Application.Current?.TryFindResource(key) is Brush resolvedBrush)
            {
                return resolvedBrush;
            }
            var brush = new SolidColorBrush(fallbackColor);
            brush.Freeze();
            return brush;
        }

        private PipeSecurity GetOrCreatePipeSecurity()
        {
            if (_cachedPipeSecurity != null) return _cachedPipeSecurity;

            var uiPipeSecurity = new PipeSecurity();
            uiPipeSecurity.AddAccessRule(new PipeAccessRule(
                WindowsIdentity.GetCurrent().User!,
                PipeAccessRights.ReadWrite,
                AccessControlType.Allow));
            uiPipeSecurity.AddAccessRule(new PipeAccessRule(
                new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                PipeAccessRights.ReadWrite,
                AccessControlType.Allow));

            _cachedPipeSecurity = uiPipeSecurity;
            return _cachedPipeSecurity;
        }

        private async Task RunTelemetryListenerAsync()
        {
            var pipeSecurity = GetOrCreatePipeSecurity();

            while (_isListening)
            {
                byte[]? rentedBuffer = null;
                try
                {
                    using var server = NamedPipeServerStreamAcl.Create(
                        IpcConstants.UiPipeName,
                        PipeDirection.In,
                        NamedPipeServerStream.MaxAllowedServerInstances,
                        PipeTransmissionMode.Byte,
                        PipeOptions.Asynchronous,
                        0,
                        0,
                        pipeSecurity);

                    await server.WaitForConnectionAsync();

                    rentedBuffer = ArrayPool<byte>.Shared.Rent(IpcConstants.PipeBufferSize);
                    int readBytes = await server.ReadAsync(rentedBuffer, 0, IpcConstants.PipeBufferSize);

                    if (readBytes > 0)
                    {
                        string json = Encoding.UTF8.GetString(rentedBuffer, 0, readBytes);
                        var telemetryEvent = JsonSerializer.Deserialize<TetherEvent>(json);
                        if (telemetryEvent != null)
                        {
                            _ = Dispatcher.BeginInvoke(DispatcherPriority.Normal, new Action(() => ParseRelayedSignal(telemetryEvent)));
                        }
                    }
                }
                catch
                {
                    await Task.Delay(500);
                }
                finally
                {
                    if (rentedBuffer != null)
                    {
                        ArrayPool<byte>.Shared.Return(rentedBuffer);
                    }
                }
            }
        }

        private void ParseRelayedSignal(TetherEvent evt)
        {
            switch (evt.EventType)
            {
                case TetherEventType.PHONE_CONNECTED:
                    TxtStatus.Text = "LINK ENFORCED";
                    IndicatorNode.Fill = GetFluentBrush("StatusHealthyBrush", Color.FromRgb(52, 211, 153));
                    IndicatorHalo.Fill = GetFluentBrush("HealthyHaloBrush", Color.FromArgb(90, 52, 211, 153));
                    LogTerminal("Phone connected.");
                    ForceTelemetrySyncToPhone();
                    break;

                case TetherEventType.PHONE_DISCONNECTED:
                    TxtStatus.Text = "NODE DISCONNECTED";
                    IndicatorNode.Fill = GetFluentBrush("StatusCriticalBrush", Color.FromRgb(251, 113, 133));
                    IndicatorHalo.Fill = GetFluentBrush("CriticalHaloBrush", Color.FromArgb(90, 251, 113, 133));
                    LogTerminal("Phone disconnected.");
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
                            LogTerminal($"Pairing request from {devName}. Enter PIN {pin} on your phone.");

                            string msg = $"Pairing Request from {devName}\n\nEnter this 6-digit PIN on your phone:\n\n      {pin}      \n";
                            _ = Task.Run(() =>
                            {
                                MessageBox.Show(
                                    msg,
                                    "Tether — Device Pairing",
                                    MessageBoxButton.OK,
                                    MessageBoxImage.Information,
                                    MessageBoxResult.OK,
                                    MessageBoxOptions.DefaultDesktopOnly);
                            });
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
                        LogTerminal("Screen woken.");
                    }
                    break;

                case TetherEventType.FILE_TRANSFER_PROGRESS:
                    if (!string.IsNullOrEmpty(evt.PayloadJson))
                    {
                        try
                        {
                            using var doc = JsonDocument.Parse(evt.PayloadJson);
                            var root = doc.RootElement;
                            string transferId = root.GetProperty("TransferId").GetString() ?? "";
                            string fileName = root.GetProperty("FileName").GetString() ?? "file";
                            long fileSize = root.GetProperty("FileSize").GetInt64();
                            long bytesTransferred = root.GetProperty("BytesTransferred").GetInt64();
                            double speedBytesPerSec = root.GetProperty("SpeedBytesPerSec").GetDouble();
                            string peerName = root.GetProperty("PeerName").GetString() ?? "";

                            _activeTransferId = transferId;
                            int pct = fileSize > 0 ? (int)((double)bytesTransferred / fileSize * 100.0) : 0;
                            double speedMb = speedBytesPerSec / (1024.0 * 1024.0);

                            Dispatcher.InvokeAsync(() =>
                            {
                                TxtTransferFileName.Text = $"Receiving: {fileName} (from {peerName})";
                                TransferProgressBar.Value = Math.Clamp(pct, 0, 100);
                                TxtTransferSpeed.Text = $"{speedMb:F1} MB/s";
                                TxtTransferMeta.Text = $"{bytesTransferred / (1024 * 1024)} / {fileSize / (1024 * 1024)} MB ({pct}%)";
                                BtnCancelActiveTransfer.Visibility = Visibility.Visible;
                            });
                        }
                        catch { }
                    }
                    break;

                case TetherEventType.FILE_TRANSFER_COMPLETED:
                    if (!string.IsNullOrEmpty(evt.PayloadJson))
                    {
                        try
                        {
                            using var doc = JsonDocument.Parse(evt.PayloadJson);
                            var root = doc.RootElement;
                            string fileName = root.GetProperty("FileName").GetString() ?? "file";
                            string destPath = root.TryGetProperty("DestinationPath", out var dp) ? dp.GetString() ?? "" : "";

                            Dispatcher.InvokeAsync(() =>
                            {
                                TxtTransferFileName.Text = $"Completed: {fileName}";
                                TransferProgressBar.Value = 100;
                                TxtTransferSpeed.Text = "Verified";
                                TxtTransferMeta.Text = string.IsNullOrEmpty(destPath) ? "Saved to Downloads/Tether" : $"Saved to {destPath}";
                                BtnCancelActiveTransfer.Visibility = Visibility.Collapsed;
                                LogTerminal($"Received '{fileName}'.");
                            });
                        }
                        catch { }
                    }
                    break;

                case TetherEventType.FILE_TRANSFER_FAILED:
                case TetherEventType.FILE_TRANSFER_CANCELLED:
                    if (!string.IsNullOrEmpty(evt.PayloadJson))
                    {
                        try
                        {
                            using var doc = JsonDocument.Parse(evt.PayloadJson);
                            var root = doc.RootElement;
                            string fileName = root.GetProperty("FileName").GetString() ?? "file";
                            string errMsg = root.TryGetProperty("ErrorMessage", out var em) ? em.GetString() ?? "Stopped" : "Stopped";

                            Dispatcher.InvokeAsync(() =>
                            {
                                TxtTransferFileName.Text = $"Stopped: {fileName}";
                                TransferProgressBar.Value = 0;
                                TxtTransferSpeed.Text = "Stopped";
                                TxtTransferMeta.Text = errMsg;
                                BtnCancelActiveTransfer.Visibility = Visibility.Collapsed;
                                LogTerminal($"Transfer of '{fileName}' stopped: {errMsg}");
                            });
                        }
                        catch { }
                    }
                    break;
            }
        }

        private void InitializeHardwarePolling()
        {
            _syncTimer = new DispatcherTimer(DispatcherPriority.Background)
            {
                Interval = TimeSpan.FromSeconds(2.5)
            };
            _syncTimer.Tick += (s, e) => PollAndSynchronizeHardwareStates();
            _syncTimer.Start();
        }

        private void PollAndSynchronizeHardwareStates()
        {
            if (WindowState == WindowState.Minimized) return;
            if (SliderVolume.IsMouseCaptureWithin || SliderBrightness.IsMouseCaptureWithin) return;

            _isInternalSliderChange = true;

            int currentVol = (int)Math.Round(GetSystemMasterVolume() * 100);
            if ((int)SliderVolume.Value != currentVol)
            {
                SliderVolume.Value = currentVol;
                TxtVolumeValue.Text = $"{currentVol}%";
            }

            int currentBri = (int)GetMonitorBrightnessLevel();
            if ((int)SliderBrightness.Value != currentBri)
            {
                SliderBrightness.Value = currentBri;
                TxtBrightnessValue.Text = $"{currentBri}%";
            }

            _isInternalSliderChange = false;
        }

        private void ExecuteHardwareAction(string? action)
        {
            if (string.IsNullOrEmpty(action)) return;

            float vol = GetSystemMasterVolume();
            uint bri = GetMonitorBrightnessLevel();

            string actionLower = action.ToLowerInvariant();
            if (actionLower.StartsWith("brightness_set:") || actionLower.StartsWith("set_brightness:") || actionLower.StartsWith("bright_set:"))
            {
                var parts = action.Split(':');
                if (parts.Length > 1 && uint.TryParse(parts[1], out uint level))
                {
                    SetMonitorBrightnessLevel(Math.Min(100u, level));
                }
            }
            else if (actionLower.StartsWith("volume_set:") || actionLower.StartsWith("set_volume:") || actionLower.StartsWith("vol_set:"))
            {
                var parts = action.Split(':');
                if (parts.Length > 1 && float.TryParse(parts[1], out float level))
                {
                    SetSystemMasterVolume(Math.Clamp(level / 100.0f, 0.0f, 1.0f));
                }
            }
            else
            {
                switch (actionLower)
                {
                    case "volume_up": case "vol_up": SetSystemMasterVolume(Math.Min(1.0f, vol + 0.04f)); break;
                    case "volume_down": case "vol_down": SetSystemMasterVolume(Math.Max(0.0f, vol - 0.04f)); break;
                    case "brightness_up": case "bright_up": SetMonitorBrightnessLevel(Math.Min(100u, bri + 5)); break;
                    case "brightness_down": case "bright_down": SetMonitorBrightnessLevel((uint)Math.Max(0, (int)bri - 5)); break;
                }
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
            SendInput(1, inputs, Marshal.SizeOf<INPUT>());
        }

        private float GetSystemMasterVolume()
        {
            var volume = GetAudioEndpointVolumeInterface();
            if (volume == null) return 0.0f;
            try
            {
                volume.GetMasterVolumeLevelScalar(out float level);
                return level;
            }
            finally
            {
                Marshal.ReleaseComObject(volume);
            }
        }

        private void SetSystemMasterVolume(float level)
        {
            var volume = GetAudioEndpointVolumeInterface();
            if (volume == null) return;
            try
            {
                Guid empty = Guid.Empty;
                volume.SetMasterVolumeLevelScalar(level, ref empty);
            }
            finally
            {
                Marshal.ReleaseComObject(volume);
            }
        }

        private IAudioEndpointVolume? GetAudioEndpointVolumeInterface()
        {
            IMMDeviceEnumerator? enumerator = null;
            IMMDevice? device = null;
            try
            {
                enumerator = (IMMDeviceEnumerator)new MMDeviceEnumerator();
                int hr = enumerator.GetDefaultAudioEndpoint(0, 0, out device);
                if (hr != 0 || device == null) return null;

                Guid iid = new Guid("5CDF2C82-841E-4546-9722-0CF74078229A");
                device.Activate(ref iid, 23, IntPtr.Zero, out object comInterface);
                return (IAudioEndpointVolume)comInterface;
            }
            catch
            {
                return null;
            }
            finally
            {
                if (device != null) Marshal.ReleaseComObject(device);
                if (enumerator != null) Marshal.ReleaseComObject(enumerator);
            }
        }

        private uint GetMonitorBrightnessLevel()
        {
            IntPtr activeGuidPtr = IntPtr.Zero;
            try
            {
                if (PowerGetActiveScheme(IntPtr.Zero, out activeGuidPtr) == 0 && activeGuidPtr != IntPtr.Zero)
                {
                    Guid activeScheme = Marshal.PtrToStructure<Guid>(activeGuidPtr);
                    Guid subgroup = GUID_VIDEO_SUBGROUP;
                    Guid setting = GUID_DEVICE_POWER_POLICY_VIDEO_BRIGHTNESS;

                    if (PowerReadACValueIndex(IntPtr.Zero, ref activeScheme, ref subgroup, ref setting, out uint val) == 0 && val <= 100)
                    {
                        _cachedBrightness = val;
                        _supportsPowerSchemeBrightness = true;
                        return val;
                    }
                }
            }
            catch { }
            finally
            {
                if (activeGuidPtr != IntPtr.Zero) LocalFree(activeGuidPtr);
            }

            if (!_supportsPowerSchemeBrightness) return _cachedBrightness;

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
                _supportsPowerSchemeBrightness = false;
            }
            catch
            {
                _supportsPowerSchemeBrightness = false;
            }

            return _cachedBrightness;
        }

        private void SetMonitorBrightnessLevel(uint level)
        {
            level = Math.Clamp(level, 0, 100);
            _cachedBrightness = level;
            bool hardwareControlled = false;

            IntPtr activeGuidPtr = IntPtr.Zero;
            try
            {
                if (PowerGetActiveScheme(IntPtr.Zero, out activeGuidPtr) == 0 && activeGuidPtr != IntPtr.Zero)
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
            finally
            {
                if (activeGuidPtr != IntPtr.Zero) LocalFree(activeGuidPtr);
            }

            if (!hardwareControlled)
            {
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
            }

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

                double factor = Math.Max(0.10, level / 100.0);

                for (int i = 0; i < 256; i++)
                {
                    ushort clampedValue = (ushort)Math.Clamp((int)(i * 256.0 * factor), 0, 65535);
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
                _telemetryDebounceTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(220) };
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
            string entry = $"[{DateTime.Now:HH:mm:ss}] {message}";
            _terminalLogs.Add(entry);
            while (_terminalLogs.Count > MaxTerminalEntries)
            {
                _terminalLogs.RemoveAt(0);
            }

            if (TerminalList.Items.Count > 0)
            {
                TerminalList.ScrollIntoView(TerminalList.Items[^1]);
            }
        }

        private void BtnClearLogs_Click(object sender, RoutedEventArgs e)
        {
            _terminalLogs.Clear();
            LogTerminal("Log cleared.");
        }

        private void BtnCopyLogs_Click(object sender, RoutedEventArgs e)
        {
            if (_terminalLogs.Count == 0) return;
            Clipboard.SetText(string.Join(Environment.NewLine, _terminalLogs));
            LogTerminal("Log copied to clipboard.");
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
                    Debug.WriteLine($"Dispatch failed: {ex.Message}");
                    LogTerminal("Could not reach the Tether service. Retrying…");
                    break;
                }
            }
            if (!_isListening) return;
            LogTerminal("Tether service is not running. Click 'Restart Service' to try again.");
        }

        private void BtnLockdownOverride_Click(object sender, RoutedEventArgs e)
        {
            LockWorkStation();
            var evt = new TetherEvent
            {
                EventType = TetherEventType.PANIC_TRIGGERED,
                Source = "DesktopUI"
            };
            DispatchServiceBusPipe(evt);
            LogTerminal("System locked.");
        }

        private async void BtnRestartService_Click(object sender, RoutedEventArgs e)
        {
            BtnRestartService.IsEnabled = false;
            try
            {
                LogTerminal("Restarting the Tether service…");
                await RestartCommServiceAsync();
            }
            finally
            {
                BtnRestartService.IsEnabled = true;
            }
        }

        private bool TryStartStandaloneCommService()
        {
            try
            {
                LogTerminal("Starting the Tether service directly…");
                string appDir = AppDomain.CurrentDomain.BaseDirectory;
                string serviceExePath = Path.Combine(appDir, "Tether.CommunicationService.exe");

                if (!File.Exists(serviceExePath))
                {
                    string solutionDir = Path.GetFullPath(Path.Combine(appDir, "..", "..", "..", "..", ".."));
                    serviceExePath = Path.Combine(solutionDir, "services", "communication-service", "Tether.CommunicationService", "bin", "Debug", "net10.0-windows", "Tether.CommunicationService.exe");
                }

                if (File.Exists(serviceExePath))
                {
                    var psi = new ProcessStartInfo
                    {
                        FileName = serviceExePath,
                        UseShellExecute = true,
                        CreateNoWindow = false
                    };
                    Process.Start(psi);
                    LogTerminal("Tether service started.");
                    return true;
                }
                else
                {
                    LogTerminal("Could not find the Tether service program.");
                    return false;
                }
            }
            catch (Exception ex)
            {
                LogTerminal($"Could not start the Tether service: {ex.Message}");
                return false;
            }
        }

        private async Task<bool> RestartCommServiceAsync()
        {
            IntPtr scmHandle = IntPtr.Zero;
            IntPtr serviceHandle = IntPtr.Zero;

            try
            {
                scmHandle = OpenSCManager(null, null, SC_MANAGER_CONNECT);
                if (scmHandle == IntPtr.Zero)
                {
                    return TryStartStandaloneCommService();
                }

                serviceHandle = OpenService(scmHandle, CommServiceName,
                    SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP);

                if (serviceHandle == IntPtr.Zero)
                {
                    return TryStartStandaloneCommService();
                }

                if (!QueryServiceStatus(serviceHandle, out SERVICE_STATUS status))
                {
                    LogTerminal("Could not read the Tether service status.");
                    return false;
                }

                if (status.dwCurrentState != SERVICE_STOPPED)
                {
                    SERVICE_STATUS stopStatus = default;
                    if (!ControlService(serviceHandle, SERVICE_CONTROL_STOP, ref stopStatus))
                    {
                        LogTerminal("Could not stop the Tether service.");
                        return false;
                    }

                    LogTerminal("Stopping the Tether service…");

                    var sw = Stopwatch.StartNew();
                    while (sw.ElapsedMilliseconds < 15000)
                    {
                        await Task.Delay(400);
                        if (!QueryServiceStatus(serviceHandle, out status)) break;
                        if (status.dwCurrentState == SERVICE_STOPPED) break;
                    }

                    if (status.dwCurrentState != SERVICE_STOPPED)
                    {
                        LogTerminal("The Tether service did not stop in time.");
                        return false;
                    }
                }

                if (!StartService(serviceHandle, 0, null))
                {
                    int err = Marshal.GetLastWin32Error();
                    if (err != ERROR_SERVICE_ALREADY_RUNNING)
                    {
                        LogTerminal("Could not start the Tether service.");
                        return false;
                    }
                }

                LogTerminal("Tether service restarted.");
                return true;
            }
            catch (Exception ex)
            {
                LogTerminal($"Could not restart the Tether service: {ex.Message}");
                return false;
            }
            finally
            {
                if (serviceHandle != IntPtr.Zero) CloseServiceHandle(serviceHandle);
                if (scmHandle != IntPtr.Zero) CloseServiceHandle(scmHandle);
            }
        }

        private void EnsureVaultDaclArchitecture()
        {
            try
            {
                using var rootKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Tether\CredentialProvider", true)
                    ?? Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Tether\CredentialProvider", true);

                if (rootKey == null) return;

                object? marker = rootKey.GetValue("VaultDaclVersion");
                int currentVersion = marker is int v ? v : 0;

                if (currentVersion < 2)
                {
                    try { rootKey.DeleteValue("EncryptedPassword", false); } catch { }

                    var rs = new RegistrySecurity();
                    var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
                    var adminsSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
                    var usersSid = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);

                    rs.AddAccessRule(new RegistryAccessRule(systemSid, RegistryRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
                    rs.AddAccessRule(new RegistryAccessRule(adminsSid, RegistryRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
                    rs.AddAccessRule(new RegistryAccessRule(usersSid, RegistryRights.ReadKey, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));

                    using (var secretsKey = rootKey.CreateSubKey("Secrets", RegistryKeyPermissionCheck.Default, rs))
                    {
                        var secretsSecurity = secretsKey?.GetAccessControl();
                        if (secretsSecurity != null)
                        {
                            secretsSecurity.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
                            secretsSecurity.AddAccessRule(new RegistryAccessRule(systemSid, RegistryRights.FullControl, AccessControlType.Allow));
                            secretsSecurity.AddAccessRule(new RegistryAccessRule(adminsSid, RegistryRights.FullControl, AccessControlType.Allow));
                            secretsKey?.SetAccessControl(secretsSecurity);
                        }
                    }

                    rootKey.SetValue("VaultDaclVersion", 2, RegistryValueKind.DWord);
                    LogTerminal("Password storage upgraded. Please re-enter your Windows password.");
                }
            }
            catch (Exception ex)
            {
                LogTerminal($"Password setup notice: {ex.Message}");
            }
        }

        public sealed class ExplorerItemModel
        {
            public required string Name { get; init; }
            public required string FullPath { get; init; }
            public required bool IsDirectory { get; init; }
            public long FileSize { get; init; }
            public string FormattedSize => IsDirectory ? "<DIR>" : $"{FileSize / 1024.0:F1} KB";
            public string FormattedDate { get; init; } = "";
        }

        private string _currentExplorerDir = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        private void LoadExplorerDirectory(string path)
        {
            try
            {
                if (!Directory.Exists(path)) return;
                _currentExplorerDir = path;
                TxtCurrentExplorerPath.Text = path;

                var items = new List<ExplorerItemModel>();
                var dirInfo = new DirectoryInfo(path);

                foreach (var d in dirInfo.GetDirectories())
                {
                    if ((d.Attributes & FileAttributes.Hidden) != 0) continue;
                    items.Add(new ExplorerItemModel
                    {
                        Name = $"📁 {d.Name}",
                        FullPath = d.FullName,
                        IsDirectory = true,
                        FileSize = 0,
                        FormattedDate = d.LastWriteTime.ToString("yyyy-MM-dd HH:mm")
                    });
                }

                foreach (var f in dirInfo.GetFiles())
                {
                    if ((f.Attributes & FileAttributes.Hidden) != 0) continue;
                    items.Add(new ExplorerItemModel
                    {
                        Name = f.Name,
                        FullPath = f.FullName,
                        IsDirectory = false,
                        FileSize = f.Length,
                        FormattedDate = f.LastWriteTime.ToString("yyyy-MM-dd HH:mm")
                    });
                }

                LstFileExplorer.ItemsSource = items;
            }
            catch (Exception ex)
            {
                LogTerminal($"Could not list directory: {ex.Message}");
            }
        }

        private void BtnNavUp_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var parent = Directory.GetParent(_currentExplorerDir);
                if (parent != null)
                {
                    LoadExplorerDirectory(parent.FullName);
                }
            }
            catch { }
        }

        private void LstFileExplorer_MouseDoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            if (LstFileExplorer.SelectedItem is ExplorerItemModel selected && selected.IsDirectory)
            {
                LoadExplorerDirectory(selected.FullPath);
            }
        }

        private void BtnSendExplorerSelected_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var selectedItems = LstFileExplorer.SelectedItems.Cast<ExplorerItemModel>().Select(i => i.FullPath).ToArray();
                if (selectedItems.Length > 0)
                {
                    App.ProcessLaunchArgs(selectedItems);
                    LogTerminal($"Queued {selectedItems.Length} item(s) for transfer.");
                }
            }
            catch (Exception ex)
            {
                LogTerminal($"Could not send selected items: {ex.Message}");
            }
        }

        private void BtnEnqueueFiles_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var dialog = new Microsoft.Win32.OpenFileDialog
                {
                    Title = "Select Files to Send to Phone",
                    Multiselect = true
                };

                if (dialog.ShowDialog() == true && dialog.FileNames.Length > 0)
                {
                    App.ProcessLaunchArgs(dialog.FileNames);
                    LogTerminal($"Queued {dialog.FileNames.Length} file(s) for transfer.");
                }
            }
            catch (Exception ex)
            {
                LogTerminal($"Could not queue files: {ex.Message}");
            }
        }

        private void BtnOpenDownloadsFolder_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string targetFolder = GetCurrentDownloadFolder();
                if (!Directory.Exists(targetFolder))
                {
                    Directory.CreateDirectory(targetFolder);
                }
                Process.Start("explorer.exe", targetFolder);
            }
            catch (Exception ex)
            {
                LogTerminal($"Could not open the Downloads folder: {ex.Message}");
            }
        }

        private void MenuItem_ChangeDownloadFolder_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var dialog = new Microsoft.Win32.OpenFolderDialog
                {
                    Title = "Select Default Download Folder for Tether",
                    InitialDirectory = GetCurrentDownloadFolder()
                };

                if (dialog.ShowDialog() == true)
                {
                    string newPath = dialog.FolderName;
                    string settingsDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Tether");
                    Directory.CreateDirectory(settingsDir);
                    string settingsFile = Path.Combine(settingsDir, "settings.json");

                    string json = "{}";
                    if (File.Exists(settingsFile)) json = File.ReadAllText(settingsFile);

                    var doc = JsonNode.Parse(json)?.AsObject() ?? new JsonObject();
                    doc["DownloadPath"] = newPath;

                    File.WriteAllText(settingsFile, doc.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));

                    UpdateDownloadFolderBtnText();
                    LogTerminal($"Download folder set to {newPath}.");
                }
            }
            catch (Exception ex)
            {
                LogTerminal($"Could not change the download folder: {ex.Message}");
            }
        }

        private string GetCurrentDownloadFolder()
        {
            try
            {
                string settingsFile = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Tether", "settings.json");
                if (File.Exists(settingsFile))
                {
                    var doc = JsonDocument.Parse(File.ReadAllText(settingsFile));
                    if (doc.RootElement.TryGetProperty("DownloadPath", out var pathProp))
                    {
                        string customPath = pathProp.GetString() ?? "";
                        if (!string.IsNullOrWhiteSpace(customPath) && Directory.Exists(customPath))
                        {
                            return customPath;
                        }
                    }
                }
            }
            catch { }
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads", "Tether");
        }

        private void UpdateDownloadFolderBtnText()
        {
            string current = GetCurrentDownloadFolder();
            TxtDownloadFolderBtn.Text = $"Open {new DirectoryInfo(current).Name}";
        }

        private void BtnCancelActiveTransfer_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(_activeTransferId)) return;

            var cancelEvt = new TetherEvent
            {
                EventType = TetherEventType.FILE_TRANSFER_CANCEL_REQUESTED,
                Timestamp = DateTime.UtcNow,
                Source = "DesktopUI",
                PayloadJson = JsonSerializer.Serialize(new { transferId = _activeTransferId })
            };

            DispatchServiceBusPipe(cancelEvt);
            LogTerminal("Cancelling transfer…");
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
                    LogTerminal("Could not verify password. Please check your Windows password and try again.");
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
                    try
                    {
                        byte[] protectedPayload = new byte[dataOut.cbData];
                        Marshal.Copy(dataOut.pbData, protectedPayload, 0, dataOut.cbData);

                        try
                        {
                            EnsureVaultDaclArchitecture();

                            using (RegistryKey? secretsKey = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Tether\CredentialProvider\Secrets", true))
                            {
                                secretsKey?.SetValue("EncryptedPassword", protectedPayload, RegistryValueKind.Binary);
                            }

                            using (RegistryKey? rootKey = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Tether\CredentialProvider", true))
                            {
                                rootKey?.SetValue("VaultDaclVersion", 2, RegistryValueKind.DWord);
                            }

                            LogTerminal("Password saved successfully.");
                            TxtPassword.Clear();
                        }
                        catch (UnauthorizedAccessException)
                        {
                            try
                            {
                                string hexPayload = Convert.ToHexString(protectedPayload);
                                string exePath = Environment.ProcessPath ?? System.Reflection.Assembly.GetExecutingAssembly().Location;

                                var startInfo = new ProcessStartInfo
                                {
                                    FileName = exePath,
                                    Arguments = $"--commit-vault-payload \"{hexPayload}\"",
                                    Verb = "runas",
                                    UseShellExecute = true
                                };

                                Process.Start(startInfo);
                                LogTerminal("Password saved successfully.");
                                TxtPassword.Clear();
                            }
                            catch (Exception ex)
                            {
                                LogTerminal($"Could not save password: {ex.Message}");
                            }
                        }
                    }
                    finally
                    {
                        if (dataOut.pbData != IntPtr.Zero) LocalFree(dataOut.pbData);
                    }
                }
            }
            catch (Exception ex) { LogTerminal($"Could not save password: {ex.Message}"); }
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