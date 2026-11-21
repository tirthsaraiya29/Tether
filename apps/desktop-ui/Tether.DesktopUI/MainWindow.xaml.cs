using Tether.DesktopUI.Updates;
﻿using Microsoft.Win32;
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
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
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
using Tether.Shared.Network;
using Tether.Shared.Security;
using ValidationResult = Tether.Shared.Security.ValidationResult;

namespace Tether.DesktopUI
{
    [SupportedOSPlatform("windows")]
    public class PairedDeviceViewModel
    {
        public string DeviceId { get; set; } = "";
        public string DisplayName { get; set; } = "";
        public string Fingerprint { get; set; } = "";
        public string FingerprintPreview => !string.IsNullOrEmpty(Fingerprint) && Fingerprint.Length > 16
            ? $"SHA256:{Fingerprint[..8]}...{Fingerprint[^6..]}"
            : (Fingerprint ?? "");
        public DateTime? LastSeen { get; set; }
    }

    public partial class MainWindow : Window
    {
        private readonly UpdateWatcherService _updateWatcher = new UpdateWatcherService();
        private const int MaxTerminalEntries = 250;
        public ObservableCollection<PairedDeviceViewModel> PairedDevices { get; } = new();
        private static readonly object _persistentLogLock = new();

        private static void WritePersistentLog(string line)
        {
            try
            {
                string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                string logDir = Path.Combine(localAppData, "Tether", "logs");
                Directory.CreateDirectory(logDir);
                string logPath = Path.Combine(logDir, "desktop-ui.log");

                lock (_persistentLogLock)
                {
                    var fi = new FileInfo(logPath);
                    if (fi.Exists && fi.Length > 5 * 1024 * 1024)
                    {
                        string oldPath = Path.Combine(logDir, "desktop-ui.old.log");
                        File.Move(logPath, oldPath, true);
                    }
                    File.AppendAllText(logPath, line + Environment.NewLine);
                }
            }
            catch { }
        }

        private void UpdatePairedUi()
        {
            if (TxtPairedCount != null)
            {
                TxtPairedCount.Text = $"{PairedDevices.Count} PAIRED";
            }
            if (TxtNoPairedDevices != null)
            {
                TxtNoPairedDevices.Visibility = PairedDevices.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            }
        }

        private void BtnDismissPairing_Click(object sender, RoutedEventArgs e)
        {
            if (CardPairing != null) CardPairing.Visibility = Visibility.Collapsed;
        }

        private void BtnUnpairDevice_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is string fingerprint && !string.IsNullOrEmpty(fingerprint))
            {
                var dev = PairedDevices.FirstOrDefault(d => string.Equals(d.Fingerprint, fingerprint, StringComparison.OrdinalIgnoreCase));
                string name = dev?.DisplayName ?? "device";

                var result = MessageBox.Show(
                    $"Are you sure you want to unpair and revoke '{name}'?\n\nThis phone will no longer be able to unlock this PC or connect.",
                    "Tether — Revoke Paired Device",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Warning);

                if (result == MessageBoxResult.Yes)
                {
                    var evt = new TetherEvent
                    {
                        EventType = TetherEventType.FORGET_PHONE,
                        Source = "DesktopUI",
                        PayloadJson = JsonSerializer.Serialize(new { fingerprint })
                    };
                    DispatchServiceBusPipe(evt);

                    if (dev != null)
                    {
                        PairedDevices.Remove(dev);
                        UpdatePairedUi();
                    }
                    LogTerminal($"Revoked pairing for {name}.");
                }
            }
        }

        private void BtnCopyFingerprint_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is string fingerprint && !string.IsNullOrEmpty(fingerprint))
            {
                try
                {
                    Clipboard.SetText(fingerprint);
                    TxtStatus.Text = "Fingerprint copied to clipboard";
                }
                catch { }
            }
        }

        private void MainWindow_PreviewKeyDown(object sender, System.Windows.Input.KeyEventArgs e)
        {
            if (e.Key == System.Windows.Input.Key.F5)
            {
                try
                {
                    LoadLocalFiles(TxtLocalPath?.Text ?? "");
                    if (!string.IsNullOrEmpty(TxtRemotePath?.Text))
                    {
                        LoadRemoteFiles(TxtRemotePath.Text);
                    }
                    TxtStatus.Text = "Refreshed";
                }
                catch { }
                e.Handled = true;
            }
            else if (e.Key == System.Windows.Input.Key.Escape)
            {
                if (CardPairing != null && CardPairing.Visibility == Visibility.Visible)
                {
                    CardPairing.Visibility = Visibility.Collapsed;
                    e.Handled = true;
                }
            }
        }

        private readonly ObservableCollection<string> _terminalLogs = new();
        private readonly ObservableCollection<DesktopNotification> _activeNotifications = new();
        private PipeSecurity? _cachedPipeSecurity;

        private readonly CancellationTokenSource _closingCts = new();
        private CancellationTokenSource? _loadRemoteFilesCts;
        private bool _isListening = true;
        private DispatcherTimer? _syncTimer;
        private DispatcherTimer? _telemetryDebounceTimer;
        private DispatcherTimer? _phoneUnlockPollTimer;
        private bool _phoneUnlockConfirmed = false;
        private bool _isInternalSliderChange = false;
        private bool _isClosingAnimated = false;
        private uint _cachedBrightness = 50;
        private bool _supportsPowerSchemeBrightness = true;

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

        public static bool IsElevated
        {
            get
            {
                using var identity = WindowsIdentity.GetCurrent();
                return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
            }
        }

        /// <summary>Relaunches this exe elevated with the given arg (UAC prompt). Returns false if declined/unavailable.</summary>
        public static bool RunElevatedSelf(string argument)
        {
            string exePath = Environment.ProcessPath ?? System.Reflection.Assembly.GetExecutingAssembly().Location;
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = exePath,
                    Arguments = argument,
                    UseShellExecute = true,
                    Verb = "runas"
                });
                return true;
            }
            catch
            {
                return false;
            }
        }

        private const uint MONITOR_DEFAULTTOPRIMARY = 0x00000001;
        private const uint WM_SYSCOMMAND = 0x0112;
        private const uint SC_MONITORPOWER = 0xF170;
        private static readonly IntPtr HWND_BROADCAST = (IntPtr)0xffff;

        public MainWindow()
        {
            InitializeComponent();
            if (NotificationItemsControl != null) NotificationItemsControl.ItemsSource = _activeNotifications;
            UpdateNotificationVisibility();
            LoadFallbackAuthConfig();
            if (PairedDevicesList != null) PairedDevicesList.ItemsSource = PairedDevices;
            UpdatePairedUi();

            ResolveUserContext();
            LogTerminal("Tether is ready.");
            EnsureVaultDaclArchitecture();

            // Ask the running service for current phone state so a UI launched after the
            // service already shows CONNECTED / paired devices instead of waiting for an event.
            DispatchServiceBusPipe(new TetherEvent
            {
                EventType = TetherEventType.TELEMETRY_SYNC_REQUESTED,
                Source = "DesktopUI"
            });

            StateChanged += MainWindow_StateChanged;

            _ = RunTelemetryListenerAsync();
            InitializeHardwarePolling();

            _updateWatcher.UpdateDetected += result =>
            {
                Dispatcher.Invoke(() =>
                {
                    AppUpdateBanner?.BindUpdateResult(result);
                    WindowsNotificationHelper.ShowHighPriorityUpdateNotification(result.LatestVersion, result.ReleaseNotes);
                });
            };
            AppUpdateBanner.RequestShutdownForUpdate += () => Close();
            _updateWatcher.Start();
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
            var source = HwndSource.FromHwnd(new WindowInteropHelper(this).Handle);
            source?.AddHook(WndProc);
        }

        private IntPtr WndProc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
        {
            const int WM_QUERYENDSESSION = 0x0011;
            const int WM_ENDSESSION = 0x0016;

            if (msg == WM_QUERYENDSESSION || msg == WM_ENDSESSION)
            {
                bool isLogoff = (lParam.ToInt64() & 0x80000000) != 0;
                var evt = new TetherEvent
                {
                    EventType = isLogoff ? TetherEventType.POWER_EVENT_DETECTED : TetherEventType.SHUTDOWN_INITIATED,
                    Source = "DesktopUI.WM_QUERYENDSESSION",
                    PayloadJson = isLogoff ? "{\"eventType\":\"LOGOFF\"}" : "{\"eventType\":\"SHUTDOWN\"}"
                };
                DispatchServiceBusPipe(evt);
            }
            return IntPtr.Zero;
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
            if (CardPipeline == null || CardHardware == null || CardVault == null || FilesContainer == null || LeftScrollViewer == null || RightColumnGrid == null) return;

            var selected = (ListBoxItem)NavRailList.SelectedItem;
            string tag = selected?.Tag as string ?? "";

            if (tag == "Files")
            {
                if (TxtWorkspaceTitle != null) TxtWorkspaceTitle.Text = "File Transfer";
                LeftScrollViewer.Visibility = Visibility.Collapsed;
                RightColumnGrid.Visibility = Visibility.Collapsed;
                FilesContainer.Visibility = Visibility.Visible;
                LoadLocalFiles(TxtLocalPath.Text);
                LoadRemoteFiles(TxtRemotePath.Text);
            }
            else
            {
                if (TxtWorkspaceTitle != null) TxtWorkspaceTitle.Text = "Dashboard";
                FilesContainer.Visibility = Visibility.Collapsed;
                LeftScrollViewer.Visibility = Visibility.Visible;
                RightColumnGrid.Visibility = Visibility.Visible;
                LeftScrollViewer?.ScrollToTop();
            }
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
                try { _closingCts.Cancel(); } catch { }
                _loadRemoteFilesCts?.Cancel();
                _loadRemoteFilesCts?.Dispose();
                _syncTimer?.Stop();
                _telemetryDebounceTimer?.Stop();
                _updateWatcher?.Dispose();
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

            while (_isListening && !_closingCts.IsCancellationRequested)
            {
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

                    await server.WaitForConnectionAsync(_closingCts.Token);

                    using var ms = new MemoryStream();
                    byte[] rented = ArrayPool<byte>.Shared.Rent(4096);
                    try
                    {
                        int bytesRead;
                        while ((bytesRead = await server.ReadAsync(rented, 0, rented.Length, _closingCts.Token)) > 0)
                        {
                            ms.Write(rented, 0, bytesRead);
                        }
                    }
                    finally
                    {
                        ArrayPool<byte>.Shared.Return(rented);
                    }

                    if (ms.Length > 0)
                    {
                        ms.Position = 0;
                        var telemetryEvent = await JsonSerializer.DeserializeAsync<TetherEvent>(ms, cancellationToken: _closingCts.Token);
                        if (telemetryEvent != null)
                        {
                            _ = Dispatcher.BeginInvoke(DispatcherPriority.Normal, new Action(() => ParseRelayedSignal(telemetryEvent)));
                        }
                    }
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch
                {
                    if (!_closingCts.IsCancellationRequested)
                    {
                        try { await Task.Delay(500, _closingCts.Token); } catch { break; }
                    }
                }
            }
        }

        private void ParseRelayedSignal(TetherEvent evt)
        {
            switch (evt.EventType)
            {
                case TetherEventType.PHONE_CONNECTED:
                    var healthyBrush = GetFluentBrush("StatusHealthyBrush", Color.FromRgb(16, 185, 129));
                    TxtStatus.Text = "CONNECTED";
                    if (TxtStatusSub != null) TxtStatusSub.Text = $"Active ({DateTime.Now:HH:mm:ss})";
                    if (TxtHeaderNodeBadge != null)
                    {
                        TxtHeaderNodeBadge.Text = "CONNECTED";
                        TxtHeaderNodeBadge.Foreground = healthyBrush;
                    }
                    if (HeaderIndicatorDot != null) HeaderIndicatorDot.Fill = healthyBrush;
                    IndicatorNode.Fill = healthyBrush;
                    IndicatorHalo.Fill = GetFluentBrush("HealthyHaloBrush", Color.FromArgb(90, 16, 185, 129));
                    LogTerminal("Phone connected.");
                    ForceTelemetrySyncToPhone();
                    break;

                case TetherEventType.PHONE_DISCONNECTED:
                    var criticalBrush = GetFluentBrush("StatusCriticalBrush", Color.FromRgb(244, 63, 94));
                    TxtStatus.Text = "NOT CONNECTED";
                    if (TxtStatusSub != null) TxtStatusSub.Text = "Looking for phone...";
                    if (TxtHeaderNodeBadge != null)
                    {
                        TxtHeaderNodeBadge.Text = "DISCONNECTED";
                        TxtHeaderNodeBadge.Foreground = criticalBrush;
                    }
                    if (HeaderIndicatorDot != null) HeaderIndicatorDot.Fill = criticalBrush;
                    IndicatorNode.Fill = criticalBrush;
                    IndicatorHalo.Fill = GetFluentBrush("CriticalHaloBrush", Color.FromArgb(90, 244, 63, 94));
                    LogTerminal("Phone disconnected.");
                    break;

                case TetherEventType.PHONE_UNLOCKED:
                    _phoneUnlockConfirmed = true;
                    UpdateForgotPhoneUi(true);
                    LogTerminal("Phone unlock command confirmed.");
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
                            if (!string.IsNullOrEmpty(pin))
                            {
                                LogTerminal($"Pairing request from {devName}. Enter PIN {pin} on your phone.");
                                if (CardPairing != null)
                                {
                                    CardPairing.Visibility = Visibility.Visible;
                                    if (TxtPairingDeviceTitle != null) TxtPairingDeviceTitle.Text = $"Pairing with {devName}";
                                    if (TxtPairingPin != null)
                                    {
                                        string formattedPin = pin.Length == 6 ? $"{pin[..3]} {pin[3..]}" : pin;
                                        TxtPairingPin.Text = formattedPin;
                                    }
                                }
                            }
                            else
                            {
                                LogTerminal($"Pairing request from {devName}. Enter the PIN displayed on your screen.");
                            }
                        }
                        catch { }
                    }
                    break;

                case TetherEventType.PAIRING_DECISION:
                case TetherEventType.PAIRING_INVALIDATED:
                    if (CardPairing != null) CardPairing.Visibility = Visibility.Collapsed;
                    ForceTelemetrySyncToPhone();
                    break;

                case TetherEventType.PROVISION_PHONE:
                    if (!string.IsNullOrEmpty(evt.PayloadJson))
                    {
                        try
                        {
                            var list = JsonSerializer.Deserialize<List<PairedDeviceViewModel>>(evt.PayloadJson, new JsonSerializerOptions
                            {
                                PropertyNameCaseInsensitive = true
                            });
                            if (list != null)
                            {
                                PairedDevices.Clear();
                                foreach (var d in list) PairedDevices.Add(d);
                                UpdatePairedUi();
                            }
                        }
                        catch { }
                    }
                    break;

                case TetherEventType.HARDWARE_SYNC_REQUESTED:
                    if (!string.IsNullOrEmpty(evt.PayloadJson))
                    {
                        try
                        {
                            using var document = JsonDocument.Parse(evt.PayloadJson);
                            var root = document.RootElement;
                            if (root.TryGetProperty("vol", out var volProp))
                            {
                                int v = volProp.GetInt32();
                                if (v >= 0)
                                {
                                    _isInternalSliderChange = true;
                                    SliderVolume.Value = v;
                                    TxtVolumeValue.Text = $"{v}%";
                                    _isInternalSliderChange = false;
                                }
                            }
                            if (root.TryGetProperty("bri", out var briProp))
                            {
                                int b = briProp.GetInt32();
                                if (b >= 0)
                                {
                                    _isInternalSliderChange = true;
                                    SliderBrightness.Value = b;
                                    TxtBrightnessValue.Text = $"{b}%";
                                    _isInternalSliderChange = false;
                                }
                            }
                        }
                        catch { }
                    }
                    break;

                case TetherEventType.TRUST_DEGRADED:
                    LogTerminal("Warning: Device trust state degraded.");
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
                            var progress = JsonSerializer.Deserialize<FileTransferProgressPayload>(evt.PayloadJson, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                            if (progress != null)
                            {
                                UpdateTransferProgressUi(progress);
                            }
                        }
                        catch { }
                    }
                    break;

                case TetherEventType.FILE_TRANSFER_COMPLETED:
                    if (!string.IsNullOrEmpty(evt.PayloadJson))
                    {
                        try
                        {
                            var progress = JsonSerializer.Deserialize<FileTransferProgressPayload>(evt.PayloadJson, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                            if (progress != null)
                            {
                                UpdateTransferCompletedUi(progress);
                            }
                        }
                        catch { }
                    }
                    break;

                case TetherEventType.FILE_TRANSFER_FAILED:
                    if (!string.IsNullOrEmpty(evt.PayloadJson))
                    {
                        try
                        {
                            var progress = JsonSerializer.Deserialize<FileTransferProgressPayload>(evt.PayloadJson, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                            if (progress != null)
                            {
                                UpdateTransferFailedUi(progress);
                            }
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
                EventType = TetherEventType.HARDWARE_SYNC_REQUESTED,
                Source = "DesktopUI",
                PayloadJson = JsonSerializer.Serialize(new { vol = vol, bri = bri })
            };
            DispatchServiceBusPipe(syncEvent);
        }

        private void ShowNotification(string title, string message, NotificationType type = NotificationType.Info)
        {
            Dispatcher.Invoke(() =>
            {
                var notif = new DesktopNotification(title, message, type);
                _activeNotifications.Insert(0, notif);
                while (_activeNotifications.Count > 100)
                {
                    _activeNotifications.RemoveAt(_activeNotifications.Count - 1);
                }
                UpdateNotificationVisibility();
            });
        }

        private void UpdateNotificationVisibility()
        {
            if (PnlNoNotifications != null)
            {
                PnlNoNotifications.Visibility = _activeNotifications.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            }
        }

        private void LogTerminal(string message)
        {
            string entry = $"[{DateTime.Now:HH:mm:ss}] {message}";
            WritePersistentLog(entry);
            _terminalLogs.Add(entry);
            while (_terminalLogs.Count > MaxTerminalEntries)
            {
                _terminalLogs.RemoveAt(0);
            }

            if (TxtLogCount != null)
            {
                TxtLogCount.Text = $"{_terminalLogs.Count} / {MaxTerminalEntries}";
            }

            // Derive semantic styling and category matching Android verification styling
            NotificationType type = NotificationType.Info;
            string title = "Session";
            if (message.Contains("error", StringComparison.OrdinalIgnoreCase) ||
                message.Contains("failed", StringComparison.OrdinalIgnoreCase) ||
                message.Contains("declined", StringComparison.OrdinalIgnoreCase) ||
                message.Contains("corrupted", StringComparison.OrdinalIgnoreCase) ||
                message.Contains("incorrect", StringComparison.OrdinalIgnoreCase))
            {
                type = NotificationType.Error;
                title = "Security Alert";
            }
            else if (message.Contains("warning", StringComparison.OrdinalIgnoreCase) ||
                     message.Contains("degraded", StringComparison.OrdinalIgnoreCase) ||
                     message.Contains("disconnected", StringComparison.OrdinalIgnoreCase) ||
                     message.Contains("retrying", StringComparison.OrdinalIgnoreCase))
            {
                type = NotificationType.Warning;
                title = "Status Warning";
            }
            else if (message.Contains("connected", StringComparison.OrdinalIgnoreCase) ||
                     message.Contains("saved", StringComparison.OrdinalIgnoreCase) ||
                     message.Contains("ready", StringComparison.OrdinalIgnoreCase) ||
                     message.Contains("unlocked", StringComparison.OrdinalIgnoreCase) ||
                     message.Contains("sent", StringComparison.OrdinalIgnoreCase) ||
                     message.Contains("downloaded", StringComparison.OrdinalIgnoreCase))
            {
                type = NotificationType.Success;
                title = "Verification Success";
            }

            ShowNotification(title, message, type);
        }

        private void BtnClearLogs_Click(object sender, RoutedEventArgs e)
        {
            _terminalLogs.Clear();
            _activeNotifications.Clear();
            UpdateNotificationVisibility();
            ShowNotification("Notice", "Activity log cleared.", NotificationType.Info);
        }

        private void BtnCopyLogs_Click(object sender, RoutedEventArgs e)
        {
            if (_terminalLogs.Count == 0) return;
            Clipboard.SetText(string.Join(Environment.NewLine, _terminalLogs));
            ShowNotification("Success", "Activity log copied to clipboard.", NotificationType.Success);
        }

        private async Task<bool> DispatchServiceBusPipeAsync(TetherEvent evt)
        {
            const int maxAttempts = 3;
            const int retryDelayMs = 300;

            for (int attempt = 0; attempt < maxAttempts; attempt++)
            {
                try
                {
                    string json = JsonSerializer.Serialize(evt);
                    byte[] bytes = Encoding.UTF8.GetBytes(json);
                    using var client = new NamedPipeClientStream(
                        serverName: ".",
                        pipeName: IpcConstants.PipeName,
                        direction: PipeDirection.InOut,
                        options: PipeOptions.Asynchronous,
                        impersonationLevel: TokenImpersonationLevel.Impersonation);
                    await client.ConnectAsync(800);
                    await client.WriteAsync(bytes, 0, bytes.Length);
                    await client.FlushAsync();
                    return true;
                }
                catch (TimeoutException)
                {
                    if (attempt < maxAttempts - 1)
                        await Task.Delay(retryDelayMs);
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Dispatch failed: {ex.Message}");
                    if (attempt < maxAttempts - 1)
                    {
                        await Task.Delay(retryDelayMs);
                    }
                    else
                    {
                        LogTerminal("Could not reach the Tether service. Retrying…");
                    }
                }
            }
            if (_isListening)
            {
                LogTerminal("Tether service is not running. Click 'Restart Tether Service' to try again.");
            }
            return false;
        }

        private void DispatchServiceBusPipe(TetherEvent evt)
        {
            _ = DispatchServiceBusPipeAsync(evt);
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
            LogTerminal("PC locked.");
        }

        private void BtnRestartService_Click(object sender, RoutedEventArgs e)
        {
            BtnRestartService.IsEnabled = false;
            try
            {
                LogTerminal("Restarting the Tether service…");
                int result = ServiceControl.Restart(LogTerminal);
                if (result == 1)
                {
                    // Non-admin: relaunch self elevated (UAC) to perform the restart.
                    if (RunElevatedSelf("--restart-service"))
                        LogTerminal("Administrator approval requested to restart the service.");
                    else
                        LogTerminal("Administrator approval was declined. Service not restarted.");
                }
                else if (result == 2)
                {
                    LogTerminal("Could not restart the Tether service.");
                }
            }
            finally
            {
                BtnRestartService.IsEnabled = true;
            }
        }

        private void EnsureVaultDaclArchitecture()
        {
            if (!IsElevated) return;
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

        private async void BtnCommitVault_Click(object sender, RoutedEventArgs e)
        {
            IntPtr unmanagedPasswordPtr = IntPtr.Zero;
            IntPtr unmanagedEntropy = IntPtr.Zero;
            try
            {
                if (TxtPassword.SecurePassword.Length == 0) return;

                int plainTextLength = TxtPassword.SecurePassword.Length;
                int byteLength = plainTextLength * 2;
                unmanagedPasswordPtr = Marshal.SecureStringToGlobalAllocUnicode(TxtPassword.SecurePassword);

                if (!LogonUser(Environment.UserName, Environment.UserDomainName, Marshal.PtrToStringUni(unmanagedPasswordPtr), 2, 0, out IntPtr token) &&
                    !LogonUser(Environment.UserName, ".", Marshal.PtrToStringUni(unmanagedPasswordPtr), 2, 0, out token) &&
                    !LogonUser(Environment.UserName, null, Marshal.PtrToStringUni(unmanagedPasswordPtr), 2, 0, out token))
                {
                    if (TxtVaultBadge != null) TxtVaultBadge.Text = "INCORRECT PASSWORD";
                    LogTerminal("Incorrect password. Please enter your valid Windows password.");
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

                        string hexPayload = Convert.ToHexString(protectedPayload);
                        bool saved = false;

                        if (IsElevated)
                        {
                            WriteVaultToRegistry(protectedPayload);
                            saved = true;
                        }
                        else
                        {
                            // Try saving via the background service over authenticated named pipe
                            var vaultEvt = new TetherEvent
                            {
                                EventType = TetherEventType.VAULT_UPDATE,
                                Source = "DesktopUI",
                                PayloadJson = JsonSerializer.Serialize(new
                                {
                                    hexPayload = hexPayload,
                                    username = Environment.UserName,
                                    domain = Environment.UserDomainName
                                })
                            };
                            saved = await DispatchServiceBusPipeAsync(vaultEvt);

                            if (!saved)
                            {
                                // Non-elevated: HKLM is not writable and service unreachable — relaunch self elevated to commit.
                                if (!RunElevatedSelf($"--commit-vault-payload {hexPayload}"))
                                {
                                    LogTerminal("Administrator approval was declined. Password not saved.");
                                    return;
                                }
                                saved = true;
                            }
                        }

                        if (saved)
                        {
                            if (TxtVaultBadge != null) TxtVaultBadge.Text = "PASSWORD SAVED";
                            LogTerminal("Windows password saved securely.");
                            TxtPassword.Clear();
                        }
                        else
                        {
                            if (TxtVaultBadge != null) TxtVaultBadge.Text = "FAILED TO SAVE";
                            LogTerminal("Could not save Windows password.");
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

        private void WriteVaultToRegistry(byte[] protectedPayload)
        {
            EnsureVaultDaclArchitecture();
            using (RegistryKey? secretsKey = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Tether\CredentialProvider\Secrets", true))
            {
                secretsKey?.SetValue("EncryptedPassword", protectedPayload, RegistryValueKind.Binary);
                secretsKey?.SetValue("TargetUsername", Environment.UserName, RegistryValueKind.String);
                using var id = WindowsIdentity.GetCurrent();
                if (id.User != null)
                {
                    secretsKey?.SetValue("TargetUserSid", id.User.Value, RegistryValueKind.String);
                }
            }
            using (RegistryKey? rootKey = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Tether\CredentialProvider", true))
            {
                rootKey?.SetValue("VaultDaclVersion", 2, RegistryValueKind.DWord);
            }
        }

        private void TxtPassword_KeyDown(object sender, System.Windows.Input.KeyEventArgs e)
        {
            if (e.Key == System.Windows.Input.Key.Enter)
            {
                e.Handled = true;
                BtnCommitVault_Click(sender, e);
            }
        }

        private void LoadFallbackAuthConfig()
        {
            try
            {
                int authType = 0;

                // 1. Check system-wide root config key (accessible by all users)
                try
                {
                    using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
                    using var rootKey = baseKey.OpenSubKey(@"SOFTWARE\Tether\CredentialProvider", false);
                    if (rootKey != null)
                    {
                        var val = rootKey.GetValue("FallbackAuthType") ?? rootKey.GetValue("MasterAuthType");
                        if (val is int i && (i == 1 || i == 2)) authType = i;
                    }
                }
                catch { }

                // 2. Check current user hive (accessible without UAC)
                if (authType == 0)
                {
                    try
                    {
                        using var hkcu = Registry.CurrentUser.OpenSubKey(@"Software\Tether", false);
                        if (hkcu != null)
                        {
                            var val = hkcu.GetValue("FallbackAuthType") ?? hkcu.GetValue("MasterAuthType");
                            if (val is int i && (i == 1 || i == 2)) authType = i;
                        }
                    }
                    catch { }
                }

                // 3. Check secrets key if running elevated
                if (authType == 0)
                {
                    try
                    {
                        using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
                        using var secretsKey = baseKey.OpenSubKey(@"SOFTWARE\Tether\CredentialProvider\Secrets", false);
                        if (secretsKey != null)
                        {
                            var val = secretsKey.GetValue("FallbackAuthType") ?? secretsKey.GetValue("MasterAuthType");
                            if (val is int i && (i == 1 || i == 2)) authType = i;
                        }
                    }
                    catch { }
                }

                if (authType == (int)FallbackAuthType.Pin || authType == (int)FallbackAuthType.Password)
                {
                    string modeStr = authType == (int)FallbackAuthType.Pin ? "PIN" : "PASSWORD";
                    if (TxtFallbackAuthBadge != null)
                    {
                        TxtFallbackAuthBadge.Text = $"✔ ACTIVE: {modeStr}";
                        TxtFallbackAuthBadge.Foreground = (Brush)FindResource("StatusHealthyBrush");
                    }
                    if (PillFallbackAuthBadge != null)
                    {
                        PillFallbackAuthBadge.BorderBrush = (Brush)FindResource("StatusHealthyBrush");
                    }
                    if (PnlFallbackActiveSummary != null) PnlFallbackActiveSummary.Visibility = Visibility.Visible;
                    if (PnlFallbackConfig != null) PnlFallbackConfig.Visibility = Visibility.Collapsed;
                    if (PnlForgotPasswordRecovery != null) PnlForgotPasswordRecovery.Visibility = Visibility.Collapsed;
                    if (BtnCancelFallbackReset != null) BtnCancelFallbackReset.Visibility = Visibility.Visible;

                    if (TxtFallbackActiveTitle != null)
                        TxtFallbackActiveTitle.Text = authType == (int)FallbackAuthType.Pin ? "Fallback PIN Protected" : "Fallback Password Protected";

                    if (TxtFallbackActiveDesc != null)
                        TxtFallbackActiveDesc.Text = authType == (int)FallbackAuthType.Pin
                            ? "Local PIN fallback unlock is enabled. You can unlock this PC with your PIN if your phone is away or offline."
                            : "Local Password fallback unlock is enabled. You can unlock this PC with your password if your phone is away or offline.";

                    if (TxtForgotFallbackCredLabel != null)
                        TxtForgotFallbackCredLabel.Text = "Forgot Password";

                    if (CmbFallbackAuthMethod != null) CmbFallbackAuthMethod.SelectedIndex = authType;
                    return;
                }

                // Disabled / Not configured
                if (TxtFallbackAuthBadge != null)
                {
                    TxtFallbackAuthBadge.Text = "DISABLED";
                    TxtFallbackAuthBadge.Foreground = (Brush)FindResource("TextSecondaryBrush");
                }
                if (PillFallbackAuthBadge != null)
                {
                    PillFallbackAuthBadge.BorderBrush = (Brush)FindResource("TextMutedBrush");
                }
                if (PnlFallbackActiveSummary != null) PnlFallbackActiveSummary.Visibility = Visibility.Collapsed;
                if (PnlFallbackConfig != null) PnlFallbackConfig.Visibility = Visibility.Visible;
                if (PnlFallbackCredentialInputs != null) PnlFallbackCredentialInputs.Visibility = Visibility.Collapsed;
                if (PnlForgotPasswordRecovery != null) PnlForgotPasswordRecovery.Visibility = Visibility.Collapsed;
                if (BtnCancelFallbackReset != null) BtnCancelFallbackReset.Visibility = Visibility.Collapsed;
                if (CmbFallbackAuthMethod != null) CmbFallbackAuthMethod.SelectedIndex = 0;
            }
            catch
            {
                if (CmbFallbackAuthMethod != null) CmbFallbackAuthMethod.SelectedIndex = 0;
            }
        }

        private void BtnCancelFallbackReset_Click(object sender, RoutedEventArgs e)
        {
            TxtFallbackPassword?.Clear();
            TxtFallbackPasswordConfirm?.Clear();
            LoadFallbackAuthConfig();
        }

        private void BtnForgotFallbackCred_Click(object sender, RoutedEventArgs e)
        {
            if (PnlFallbackActiveSummary != null) PnlFallbackActiveSummary.Visibility = Visibility.Collapsed;
            if (PnlFallbackConfig != null) PnlFallbackConfig.Visibility = Visibility.Collapsed;
            if (PnlForgotPasswordRecovery != null) PnlForgotPasswordRecovery.Visibility = Visibility.Visible;

            _phoneUnlockConfirmed = false;
            CheckPhoneUnlockSignal();

            TxtForgotWindowsPassword?.Clear();
            if (TxtForgotWindowsError != null) TxtForgotWindowsError.Visibility = Visibility.Collapsed;
            TxtForgotWindowsPassword?.Focus();

            StartPhoneUnlockPoll();
        }

        private void BtnCancelForgotRecovery_Click(object sender, RoutedEventArgs e)
        {
            StopPhoneUnlockPoll();
            TxtForgotWindowsPassword?.Clear();
            if (TxtForgotWindowsError != null) TxtForgotWindowsError.Visibility = Visibility.Collapsed;
            LoadFallbackAuthConfig();
        }

        private void StartPhoneUnlockPoll()
        {
            StopPhoneUnlockPoll();
            _phoneUnlockPollTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
            _phoneUnlockPollTimer.Tick += (s, e) =>
            {
                if (PnlForgotPasswordRecovery == null || PnlForgotPasswordRecovery.Visibility != Visibility.Visible)
                {
                    StopPhoneUnlockPoll();
                    return;
                }
                CheckPhoneUnlockSignal();
            };
            _phoneUnlockPollTimer.Start();
        }

        private void StopPhoneUnlockPoll()
        {
            if (_phoneUnlockPollTimer != null)
            {
                _phoneUnlockPollTimer.Stop();
                _phoneUnlockPollTimer = null;
            }
        }

        private bool CheckPhoneUnlockSignal()
        {
            if (_phoneUnlockConfirmed)
            {
                UpdateForgotPhoneUi(true);
                return true;
            }

            try
            {
                using var evt = EventWaitHandle.OpenExisting(@"Global\TetherPhoneAppUnlocked");
                if (evt.WaitOne(0))
                {
                    _phoneUnlockConfirmed = true;
                    UpdateForgotPhoneUi(true);
                    return true;
                }
            }
            catch { }

            UpdateForgotPhoneUi(false);
            return false;
        }

        private void UpdateForgotPhoneUi(bool confirmed)
        {
            if (TxtForgotPhoneStatus == null) return;
            if (confirmed)
            {
                TxtForgotPhoneStatus.Text = "✔ CONFIRMED";
                TxtForgotPhoneStatus.Foreground = (Brush)FindResource("StatusHealthyBrush");
                if (PillForgotPhoneStatus != null)
                    PillForgotPhoneStatus.BorderBrush = (Brush)FindResource("StatusHealthyBrush");
            }
            else
            {
                TxtForgotPhoneStatus.Text = "WAITING FOR UNLOCK...";
                TxtForgotPhoneStatus.Foreground = (Brush)FindResource("StatusDegradedBrush");
                if (PillForgotPhoneStatus != null)
                    PillForgotPhoneStatus.BorderBrush = (Brush)FindResource("StatusDegradedBrush");
            }
        }

        private void TxtForgotWindowsPassword_KeyDown(object sender, System.Windows.Input.KeyEventArgs e)
        {
            if (e.Key == System.Windows.Input.Key.Enter)
            {
                e.Handled = true;
                BtnVerifyForgotRecovery_Click(sender, e);
            }
        }

        private void BtnVerifyForgotRecovery_Click(object sender, RoutedEventArgs e)
        {
            if (TxtForgotWindowsError != null) TxtForgotWindowsError.Visibility = Visibility.Collapsed;

            // 1. Verification Requirement 1: Phone must send unlock command
            if (!CheckPhoneUnlockSignal())
            {
                if (TxtForgotWindowsError != null)
                {
                    TxtForgotWindowsError.Text = "Phone unlock confirmation required. Please open the Tether app on your phone and tap 'Unlock PC'.";
                    TxtForgotWindowsError.Visibility = Visibility.Visible;
                }
                ShowNotification("Phone Confirmation Required", "Please open the Tether app on your phone and tap 'Unlock PC' to verify device authorization.", NotificationType.Warning);
                return;
            }

            // 2. Verification Requirement 2: Registered Windows password
            if (TxtForgotWindowsPassword == null || TxtForgotWindowsPassword.SecurePassword.Length == 0)
            {
                if (TxtForgotWindowsError != null)
                {
                    TxtForgotWindowsError.Text = "Please enter your registered Windows password.";
                    TxtForgotWindowsError.Visibility = Visibility.Visible;
                }
                return;
            }

            IntPtr unmanagedPasswordPtr = IntPtr.Zero;
            bool winPwdOk = false;
            try
            {
                unmanagedPasswordPtr = Marshal.SecureStringToGlobalAllocUnicode(TxtForgotWindowsPassword.SecurePassword);
                string pwdStr = Marshal.PtrToStringUni(unmanagedPasswordPtr) ?? "";

                if (LogonUser(Environment.UserName, Environment.UserDomainName, pwdStr, 2, 0, out IntPtr token))
                {
                    winPwdOk = true;
                    CloseHandle(token);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"LogonUser failed during recovery: {ex.Message}");
            }
            finally
            {
                if (unmanagedPasswordPtr != IntPtr.Zero)
                {
                    Marshal.ZeroFreeGlobalAllocUnicode(unmanagedPasswordPtr);
                }
            }

            if (!winPwdOk)
            {
                if (TxtForgotWindowsError != null)
                {
                    TxtForgotWindowsError.Text = "Incorrect Windows password. Please enter the valid Windows password for this PC.";
                    TxtForgotWindowsError.Visibility = Visibility.Visible;
                }
                ShowNotification("Verification Failed", "Incorrect Windows password.", NotificationType.Error);
                return;
            }

            // Both requirements successfully met!
            StopPhoneUnlockPoll();
            TxtForgotWindowsPassword?.Clear();
            if (TxtForgotWindowsError != null) TxtForgotWindowsError.Visibility = Visibility.Collapsed;

            if (PnlForgotPasswordRecovery != null) PnlForgotPasswordRecovery.Visibility = Visibility.Collapsed;
            if (PnlFallbackConfig != null) PnlFallbackConfig.Visibility = Visibility.Visible;
            if (PnlFallbackCredentialInputs != null) PnlFallbackCredentialInputs.Visibility = Visibility.Visible;
            if (BtnCancelFallbackReset != null) BtnCancelFallbackReset.Visibility = Visibility.Visible;

            TxtFallbackPassword?.Clear();
            TxtFallbackPasswordConfirm?.Clear();
            TxtFallbackPassword?.Focus();

            ShowNotification("Identity Verified", "Phone command and Windows password confirmed. You may now enter a new Fallback Password.", NotificationType.Success);
            LogTerminal("Fallback password recovery unlocked via phone and Windows password verification.");
        }

        private void CmbFallbackAuthMethod_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (PnlFallbackCredentialInputs == null) return;

            int selected = CmbFallbackAuthMethod.SelectedIndex;
            if (selected == 1) // PIN
            {
                PnlFallbackCredentialInputs.Visibility = Visibility.Visible;
                if (LblFallbackCred != null) LblFallbackCred.Text = "New Fallback PIN (min 8 digits)";
                if (TxtSaveFallbackAuthLabel != null) TxtSaveFallbackAuthLabel.Text = "Save Fallback PIN";
                TxtFallbackPassword_PasswordChanged(this, new RoutedEventArgs());
            }
            else if (selected == 2) // Password
            {
                PnlFallbackCredentialInputs.Visibility = Visibility.Visible;
                if (LblFallbackCred != null) LblFallbackCred.Text = "New Fallback Password (min 8 chars)";
                if (TxtSaveFallbackAuthLabel != null) TxtSaveFallbackAuthLabel.Text = "Save Fallback Password";
                TxtFallbackPassword_PasswordChanged(this, new RoutedEventArgs());
            }
            else // Disabled
            {
                PnlFallbackCredentialInputs.Visibility = Visibility.Collapsed;
                if (TxtSaveFallbackAuthLabel != null) TxtSaveFallbackAuthLabel.Text = "Disable Fallback Auth";
            }
        }

        private void TxtFallbackPassword_PasswordChanged(object sender, RoutedEventArgs e)
        {
            if (TxtFallbackStrengthBadge == null || TxtFallbackStrengthFeedback == null || PillFallbackStrength == null || TxtFallbackPassword == null) return;

            string password = TxtFallbackPassword.Password;
            if (string.IsNullOrEmpty(password))
            {
                TxtFallbackStrengthBadge.Text = "EMPTY";
                TxtFallbackStrengthBadge.Foreground = (Brush)FindResource("TextMutedBrush");
                TxtFallbackStrengthFeedback.Text = "Requires minimum 8 characters with non-predictable patterns.";
                return;
            }

            int mode = CmbFallbackAuthMethod != null ? CmbFallbackAuthMethod.SelectedIndex : 0;
            ValidationResult res = mode == 1
                ? FallbackCredentialValidator.ValidatePin(password)
                : FallbackCredentialValidator.ValidatePassword(password);

            switch (res.Strength)
            {
                case CredentialStrength.Strong:
                    TxtFallbackStrengthBadge.Text = "STRONG";
                    TxtFallbackStrengthBadge.Foreground = (Brush)FindResource("StatusHealthyBrush");
                    break;
                case CredentialStrength.Fair:
                    TxtFallbackStrengthBadge.Text = "FAIR";
                    TxtFallbackStrengthBadge.Foreground = (Brush)FindResource("StatusDegradedBrush");
                    break;
                case CredentialStrength.Weak:
                    TxtFallbackStrengthBadge.Text = "WEAK";
                    TxtFallbackStrengthBadge.Foreground = (Brush)FindResource("StatusCriticalBrush");
                    break;
                default:
                    TxtFallbackStrengthBadge.Text = "VERY WEAK";
                    TxtFallbackStrengthBadge.Foreground = (Brush)FindResource("StatusCriticalBrush");
                    break;
            }

            TxtFallbackStrengthFeedback.Text = res.FeedbackMessage;
        }

        private void BtnSaveFallbackAuth_Click(object sender, RoutedEventArgs e)
        {
            int mode = CmbFallbackAuthMethod != null ? CmbFallbackAuthMethod.SelectedIndex : 0;
            if (mode == 0) // Disable
            {
                try
                {
                    using var hkcu = Registry.CurrentUser.CreateSubKey(@"Software\Tether", true);
                    hkcu?.SetValue("FallbackAuthType", 0, RegistryValueKind.DWord);
                    hkcu?.SetValue("MasterAuthType", 0, RegistryValueKind.DWord);
                }
                catch { }

                if (IsElevated)
                {
                    FallbackCredentialStore.DisableFallbackAuth();
                }
                else
                {
                    if (!RunElevatedSelf("--commit-fallback-auth 0 none"))
                    {
                        ShowNotification("Error", "Administrator approval was declined.", NotificationType.Error);
                        return;
                    }
                }
                LoadFallbackAuthConfig();
                ShowNotification("Security", "Fallback authentication disabled.", NotificationType.Info);
                return;
            }

            if (TxtFallbackPassword == null || TxtFallbackPasswordConfirm == null) return;

            string credential = TxtFallbackPassword.Password;
            string confirm = TxtFallbackPasswordConfirm.Password;

            if (string.IsNullOrEmpty(credential))
            {
                ShowNotification("Input Required", "Please enter a credential.", NotificationType.Warning);
                return;
            }

            FallbackAuthType type = mode == 1 ? FallbackAuthType.Pin : FallbackAuthType.Password;
            ValidationResult valResult = type == FallbackAuthType.Pin
                ? FallbackCredentialValidator.ValidatePin(credential)
                : FallbackCredentialValidator.ValidatePassword(credential);

            if (!valResult.IsValid)
            {
                ShowNotification("Security Validation", valResult.FeedbackMessage, NotificationType.Error);
                return;
            }

            if (!string.Equals(credential, confirm, StringComparison.Ordinal))
            {
                ShowNotification("Validation Error", "The credential confirmation does not match.", NotificationType.Error);
                return;
            }

            try
            {
                byte[] protectedPayload = FallbackCredentialStore.CreatePayload(credential, type);
                string hex = Convert.ToHexString(protectedPayload);

                try
                {
                    using var hkcu = Registry.CurrentUser.CreateSubKey(@"Software\Tether", true);
                    hkcu?.SetValue("FallbackAuthType", (int)type, RegistryValueKind.DWord);
                    hkcu?.SetValue("MasterAuthType", (int)type, RegistryValueKind.DWord);
                }
                catch { }

                if (IsElevated)
                {
                    FallbackCredentialStore.SaveFallbackAuth(protectedPayload, type);
                }
                else
                {
                    if (!RunElevatedSelf($"--commit-fallback-auth {(uint)type} {hex}"))
                    {
                        ShowNotification("Error", "Administrator approval was declined. Fallback authentication not saved.", NotificationType.Error);
                        return;
                    }
                }

                TxtFallbackPassword.Clear();
                TxtFallbackPasswordConfirm.Clear();
                LoadFallbackAuthConfig();
                ShowNotification("Success", $"Fallback {type} configured and saved securely.", NotificationType.Success);
            }
            catch (Exception ex)
            {
                ShowNotification("Error", $"Could not save fallback authentication: {ex.Message}", NotificationType.Error);
            }
        }

        // ==========================================
        // FILE TRANSFER LOGIC
        // ==========================================

        private static readonly System.Net.Http.HttpClient _httpClient = CreateSecureLocalHttpClient();

        public static bool ValidateWindowsServiceCertificate(System.Security.Cryptography.X509Certificates.X509Certificate2? cert)
        {
            if (cert == null) return false;

            var now = DateTime.UtcNow;
            if (cert.NotBefore.ToUniversalTime() > now || cert.NotAfter.ToUniversalTime() < now) return false;

            if (!string.Equals(cert.Subject, "CN=Tether Windows Identity", StringComparison.OrdinalIgnoreCase) &&
                !cert.Subject.Contains("CN=Tether Windows Identity"))
            {
                return false;
            }

            try
            {
                byte[] presentedSpki = ExportSpkiFromCert(cert);
                if (presentedSpki == null || presentedSpki.Length == 0) return false;

                byte[]? expectedSpki = GetExpectedWindowsIdentitySpki();
                if (expectedSpki != null && expectedSpki.Length > 0)
                {
                    return System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(expectedSpki, presentedSpki);
                }

                // If local store query is restricted by user account ACL, validate subject and valid SPKI
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static byte[]? GetExpectedWindowsIdentitySpki()
        {
            const string subjectDn = "CN=Tether Windows Identity";
            const string friendlyName = "Tether Windows Identity";

            foreach (var storeLocation in new[] { System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine, System.Security.Cryptography.X509Certificates.StoreLocation.CurrentUser })
            {
                try
                {
                    using var store = new System.Security.Cryptography.X509Certificates.X509Store("My", storeLocation);
                    store.Open(System.Security.Cryptography.X509Certificates.OpenFlags.ReadOnly);

                    var found = store.Certificates
                        .Find(System.Security.Cryptography.X509Certificates.X509FindType.FindBySubjectDistinguishedName, subjectDn, validOnly: false)
                        .OfType<System.Security.Cryptography.X509Certificates.X509Certificate2>()
                        .FirstOrDefault(c => string.Equals(c.FriendlyName, friendlyName, StringComparison.Ordinal) ||
                                             string.Equals(c.Subject, subjectDn, StringComparison.OrdinalIgnoreCase) ||
                                             c.Subject.Contains(subjectDn, StringComparison.OrdinalIgnoreCase));

                    if (found != null)
                    {
                        return ExportSpkiFromCert(found);
                    }
                }
                catch { }
            }
            return null;
        }

        private static byte[] ExportSpkiFromCert(System.Security.Cryptography.X509Certificates.X509Certificate2 cert)
        {
            using var ec = cert.GetECDsaPublicKey();
            if (ec != null) return ec.ExportSubjectPublicKeyInfo();

            using var rsa = cert.GetRSAPublicKey();
            if (rsa != null) return rsa.ExportSubjectPublicKeyInfo();

            return Array.Empty<byte>();
        }

        private static System.Net.Http.HttpClient CreateSecureLocalHttpClient()
        {
            var handler = new System.Net.Http.HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (message, cert, chain, errors) =>
                {
                    return ValidateWindowsServiceCertificate(cert);
                }
            };

            var client = new System.Net.Http.HttpClient(handler)
            {
                BaseAddress = new Uri($"https://127.0.0.1:{NetworkConstants.FileTransferPort}")
            };

            EnsureLocalAuthHeader(client);
            return client;
        }

        private static void EnsureLocalAuthHeader(System.Net.Http.HttpClient client)
        {
            try
            {
                string dataDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Tether");
                string localTokenFile = Path.Combine(dataDir, "local_ui_token.txt");
                if (File.Exists(localTokenFile))
                {
                    string token = File.ReadAllText(localTokenFile).Trim();
                    if (!string.IsNullOrEmpty(token))
                    {
                        client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
                    }
                }
            }
            catch { }
        }

        public class FileItem
        {
            [System.Text.Json.Serialization.JsonPropertyName("name")]
            public string Name { get; set; } = "";

            [System.Text.Json.Serialization.JsonPropertyName("isDirectory")]
            public bool IsDirectory { get; set; }

            [System.Text.Json.Serialization.JsonPropertyName("path")]
            public string Path { get; set; } = "";

            [System.Text.Json.Serialization.JsonIgnore]
            public string FullPath => Path;

            [System.Text.Json.Serialization.JsonPropertyName("size")]
            public long RawSize { get; set; }

            [System.Text.Json.Serialization.JsonIgnore]
            public string Size => IsDirectory ? "Directory" : FormatByteSize(RawSize);

            [System.Text.Json.Serialization.JsonIgnore]
            public string Type => IsDirectory ? "Folder" : "File";

            [System.Text.Json.Serialization.JsonIgnore]
            public string Icon => IsDirectory ? "\uE8B7" : "\uE8A5";
        }

        private static string FormatByteSize(long bytes)
        {
            if (bytes < 0) return "0 B";
            if (bytes < 1024) return $"{bytes} B";
            if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
            if (bytes < 1024L * 1024 * 1024) return $"{bytes / (1024.0 * 1024.0):F2} MB";
            if (bytes < 1024L * 1024 * 1024 * 1024) return $"{bytes / (1024.0 * 1024.0 * 1024.0):F2} GB";
            return $"{bytes / (1024.0 * 1024.0 * 1024.0 * 1024.0):F2} TB";
        }

        private void LoadLocalFiles(string path)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(path))
                {
                    path = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                }

                var dir = new DirectoryInfo(path);
                if (!dir.Exists) return;

                TxtLocalPath.Text = dir.FullName;
                TxtLocalPath.CaretIndex = TxtLocalPath.Text.Length;
                TxtLocalPath.ScrollToEnd();
                TxtLocalPath.ToolTip = dir.FullName;

                var items = new List<FileItem>();
                foreach (var d in dir.GetDirectories())
                {
                    items.Add(new FileItem { Name = d.Name, Path = d.FullName, IsDirectory = true });
                }
                foreach (var f in dir.GetFiles())
                {
                    items.Add(new FileItem { Name = f.Name, Path = f.FullName, RawSize = f.Length, IsDirectory = false });
                }

                ListLocalFiles.ItemsSource = items;
            }
            catch (Exception ex)
            {
                LogTerminal($"Local file error: {ex.Message}");
            }
        }

        private void BtnLocalUp_Click(object sender, RoutedEventArgs e)
        {
            var dir = new DirectoryInfo(TxtLocalPath.Text);
            if (dir.Parent != null)
            {
                LoadLocalFiles(dir.Parent.FullName);
            }
        }

        private void TxtLocalPath_KeyDown(object sender, System.Windows.Input.KeyEventArgs e)
        {
            if (e.Key == System.Windows.Input.Key.Enter) LoadLocalFiles(TxtLocalPath.Text);
        }

        private void ListLocalFiles_MouseDoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            if (ListLocalFiles.SelectedItem is FileItem item && item.IsDirectory)
            {
                LoadLocalFiles(item.FullPath);
            }
        }

        private async void LoadRemoteFiles(string path)
        {
            _loadRemoteFilesCts?.Cancel();
            _loadRemoteFilesCts?.Dispose();
            var cts = new CancellationTokenSource();
            _loadRemoteFilesCts = cts;
            var ct = cts.Token;

            try
            {
                EnsureLocalAuthHeader(_httpClient);
                if (path == null) path = "";

                TxtRemotePath.Text = path;
                TxtRemotePath.CaretIndex = TxtRemotePath.Text.Length;
                TxtRemotePath.ScrollToEnd();
                TxtRemotePath.ToolTip = string.IsNullOrEmpty(path) ? "Storage Roots" : path;

                var payload = new { path = path };
                var content = new System.Net.Http.StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

                var response = await _httpClient.PostAsync("/api/fs/remote/list", content, ct);
                ct.ThrowIfCancellationRequested();
                if (response.IsSuccessStatusCode)
                {
                    var json = await response.Content.ReadAsStringAsync(ct);
                    ct.ThrowIfCancellationRequested();
                    var list = JsonSerializer.Deserialize<List<FileItem>>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                    if (list != null)
                    {
                        list = list.OrderByDescending(f => f.IsDirectory).ThenBy(f => f.Name, StringComparer.OrdinalIgnoreCase).ToList();
                        int foldersCount = list.Count(f => f.IsDirectory);
                        int filesCount = list.Count(f => !f.IsDirectory);
                        LogTerminal($"Remote path '{path}': {foldersCount} folder(s), {filesCount} file(s).");
                    }
                    ListRemoteFiles.ItemsSource = list;
                }
                else
                {
                    LogTerminal($"Phone connection status: {response.StatusCode}");
                }
            }
            catch (OperationCanceledException)
            {
                // Silently drop superseded navigation requests
            }
            catch (Exception ex)
            {
                LogTerminal($"Phone storage error: {ex.Message}");
            }
        }

        private void BtnRemoteUp_Click(object sender, RoutedEventArgs e)
        {
            string p = TxtRemotePath.Text.TrimEnd('/');
            int lastSlash = p.LastIndexOf('/');
            if (lastSlash > 0)
            {
                LoadRemoteFiles(p.Substring(0, lastSlash));
            }
            else
            {
                LoadRemoteFiles("");
            }
        }

        private void TxtRemotePath_KeyDown(object sender, System.Windows.Input.KeyEventArgs e)
        {
            if (e.Key == System.Windows.Input.Key.Enter) LoadRemoteFiles(TxtRemotePath.Text);
        }

        private void BtnRemoteRefresh_Click(object sender, RoutedEventArgs e)
        {
            LoadRemoteFiles(TxtRemotePath.Text);
        }

        private void ListRemoteFiles_MouseDoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            if (ListRemoteFiles.SelectedItem is FileItem item && item.IsDirectory)
            {
                if (!string.IsNullOrWhiteSpace(item.FullPath))
                {
                    LoadRemoteFiles(item.FullPath);
                }
                else
                {
                    string current = TxtRemotePath.Text;
                    string sep = string.IsNullOrEmpty(current) || current.EndsWith("/") ? "" : "/";
                    string target = current + sep + item.Name;
                    LoadRemoteFiles(target);
                }
            }
        }

        private string? _lastSavedFilePath;

        private void UpdateTransferProgressUi(FileTransferProgressPayload progress)
        {
            if (CardFileTransferProgress == null) return;

            CardFileTransferProgress.Visibility = Visibility.Visible;
            if (IconTransferDirection != null) IconTransferDirection.Text = progress.IsUpload ? "\uE898" : "\uE896";
            if (TxtTransferFileName != null) TxtTransferFileName.Text = progress.IsUpload ? $"Sending {progress.FileName} to phone" : $"Receiving {progress.FileName} from phone";

            int percent = progress.TotalBytes > 0 ? (int)((progress.BytesTransferred * 100) / progress.TotalBytes) : 0;
            string speedStr = FormatSpeed(progress.SpeedBps);
            string etaStr = FormatEta(progress.EtaSec);
            string sizeStr = progress.TotalBytes > 0 ? $"{FormatBytes(progress.BytesTransferred)} / {FormatBytes(progress.TotalBytes)}" : FormatBytes(progress.BytesTransferred);

            if (TxtTransferMetrics != null) TxtTransferMetrics.Text = $"{percent}% ({sizeStr}) • {speedStr} • {etaStr}";
            if (ProgressFileTransfer != null)
            {
                ProgressFileTransfer.IsIndeterminate = progress.TotalBytes <= 0;
                ProgressFileTransfer.Value = Math.Clamp(percent, 0, 100);
            }
            if (BtnOpenSavedLocation != null) BtnOpenSavedLocation.Visibility = Visibility.Collapsed;
            if (BtnDismissTransferProgress != null) BtnDismissTransferProgress.Visibility = Visibility.Collapsed;
        }

        private void UpdateTransferCompletedUi(FileTransferProgressPayload progress)
        {
            if (CardFileTransferProgress == null) return;

            _lastSavedFilePath = progress.SavedPath;
            CardFileTransferProgress.Visibility = Visibility.Visible;
            if (IconTransferDirection != null) IconTransferDirection.Text = "\uE73E";
            if (ProgressFileTransfer != null)
            {
                ProgressFileTransfer.IsIndeterminate = false;
                ProgressFileTransfer.Value = 100;
            }

            if (progress.IsUpload)
            {
                if (TxtTransferFileName != null) TxtTransferFileName.Text = $"Sent {progress.FileName} to phone";
                if (TxtTransferMetrics != null) TxtTransferMetrics.Text = "Transfer completed successfully";
                if (BtnOpenSavedLocation != null) BtnOpenSavedLocation.Visibility = Visibility.Collapsed;
            }
            else
            {
                if (TxtTransferFileName != null) TxtTransferFileName.Text = $"Received {progress.FileName}";
                if (TxtTransferMetrics != null) TxtTransferMetrics.Text = $"Saved to: {progress.SavedPath}";
                if (BtnOpenSavedLocation != null) BtnOpenSavedLocation.Visibility = string.IsNullOrEmpty(progress.SavedPath) ? Visibility.Collapsed : Visibility.Visible;
                LogTerminal($"File received: {progress.FileName} saved to {progress.SavedPath}");
                LoadLocalFiles(TxtLocalPath?.Text ?? "");
            }
            if (BtnDismissTransferProgress != null) BtnDismissTransferProgress.Visibility = Visibility.Visible;
        }

        private void UpdateTransferFailedUi(FileTransferProgressPayload progress)
        {
            if (CardFileTransferProgress == null) return;

            CardFileTransferProgress.Visibility = Visibility.Visible;
            if (IconTransferDirection != null) IconTransferDirection.Text = "\uE783";
            if (ProgressFileTransfer != null)
            {
                ProgressFileTransfer.IsIndeterminate = false;
                ProgressFileTransfer.Value = 0;
            }
            if (TxtTransferFileName != null) TxtTransferFileName.Text = $"Transfer failed: {progress.FileName}";
            if (TxtTransferMetrics != null) TxtTransferMetrics.Text = progress.Error ?? "Transfer failed";
            if (BtnOpenSavedLocation != null) BtnOpenSavedLocation.Visibility = Visibility.Collapsed;
            if (BtnDismissTransferProgress != null) BtnDismissTransferProgress.Visibility = Visibility.Visible;
            LogTerminal($"Transfer error: {progress.Error ?? "Transfer failed"}");
        }

        private void BtnOpenSavedLocation_Click(object sender, RoutedEventArgs e)
        {
            if (!string.IsNullOrEmpty(_lastSavedFilePath))
            {
                try
                {
                    if (File.Exists(_lastSavedFilePath))
                    {
                        Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{_lastSavedFilePath}\"") { UseShellExecute = true });
                    }
                    else if (Directory.Exists(_lastSavedFilePath))
                    {
                        Process.Start(new ProcessStartInfo("explorer.exe", $"\"{_lastSavedFilePath}\"") { UseShellExecute = true });
                    }
                }
                catch (Exception ex)
                {
                    LogTerminal($"Failed to open folder: {ex.Message}");
                }
            }
        }

        private void BtnDismissTransferProgress_Click(object sender, RoutedEventArgs e)
        {
            if (CardFileTransferProgress != null)
            {
                CardFileTransferProgress.Visibility = Visibility.Collapsed;
            }
        }

        private static string FormatSpeed(long bps)
        {
            if (bps <= 0) return "0 KB/s";
            if (bps < 1024 * 1024) return $"{bps / 1024} KB/s";
            return $"{(bps / (1024.0 * 1024.0)):F1} MB/s";
        }

        private static string FormatEta(long sec)
        {
            if (sec <= 0) return "ETA: 0s";
            if (sec < 60) return $"ETA: {sec}s";
            if (sec < 3600) return $"ETA: {sec / 60}m {sec % 60}s";
            return $"ETA: {sec / 3600}h {(sec % 3600) / 60}m";
        }

        private static string FormatBytes(long bytes)
        {
            if (bytes < 0) return "0 B";
            if (bytes < 1024) return $"{bytes} B";
            if (bytes < 1024 * 1024) return $"{(bytes / 1024.0):F1} KB";
            if (bytes < 1024 * 1024 * 1024) return $"{(bytes / (1024.0 * 1024.0)):F1} MB";
            return $"{(bytes / (1024.0 * 1024.0 * 1024.0)):F2} GB";
        }

        private async void BtnUpload_Click(object sender, RoutedEventArgs e)
        {
            if (ListLocalFiles.SelectedItem is FileItem item && !item.IsDirectory)
            {
                try
                {
                    EnsureLocalAuthHeader(_httpClient);
                    LogTerminal($"Sending {item.Name} to phone...");
                    if (CardFileTransferProgress != null)
                    {
                        CardFileTransferProgress.Visibility = Visibility.Visible;
                        if (IconTransferDirection != null) IconTransferDirection.Text = "\uE898";
                        if (TxtTransferFileName != null) TxtTransferFileName.Text = $"Sending {item.Name} to phone";
                        if (TxtTransferMetrics != null) TxtTransferMetrics.Text = "Initiating transfer...";
                        if (ProgressFileTransfer != null) ProgressFileTransfer.IsIndeterminate = true;
                        if (BtnOpenSavedLocation != null) BtnOpenSavedLocation.Visibility = Visibility.Collapsed;
                        if (BtnDismissTransferProgress != null) BtnDismissTransferProgress.Visibility = Visibility.Collapsed;
                    }
                    var payload = new { localPath = item.FullPath, remoteDir = TxtRemotePath.Text };
                    var content = new System.Net.Http.StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
                    var res = await _httpClient.PostAsync("/api/fs/remote/upload", content);
                    if (res.IsSuccessStatusCode)
                    {
                        LogTerminal("File sent to phone.");
                        await Task.Delay(2000);
                        LoadRemoteFiles(TxtRemotePath.Text);
                    }
                    else
                    {
                        LogTerminal($"Upload error: {res.StatusCode}");
                    }
                }
                catch (Exception ex)
                {
                    LogTerminal($"Upload error: {ex.Message}");
                }
            }
        }

        private async void BtnDownload_Click(object sender, RoutedEventArgs e)
        {
            if (ListRemoteFiles.SelectedItem is FileItem item && !item.IsDirectory)
            {
                try
                {
                    EnsureLocalAuthHeader(_httpClient);
                    LogTerminal($"Downloading {item.Name} from phone...");
                    if (CardFileTransferProgress != null)
                    {
                        CardFileTransferProgress.Visibility = Visibility.Visible;
                        if (IconTransferDirection != null) IconTransferDirection.Text = "\uE896";
                        if (TxtTransferFileName != null) TxtTransferFileName.Text = $"Downloading {item.Name} from phone";
                        if (TxtTransferMetrics != null) TxtTransferMetrics.Text = "Initiating transfer...";
                        if (ProgressFileTransfer != null) ProgressFileTransfer.IsIndeterminate = true;
                        if (BtnOpenSavedLocation != null) BtnOpenSavedLocation.Visibility = Visibility.Collapsed;
                        if (BtnDismissTransferProgress != null) BtnDismissTransferProgress.Visibility = Visibility.Collapsed;
                    }
                    string sep = TxtRemotePath.Text.EndsWith("/") ? "" : "/";
                    string remotePath = TxtRemotePath.Text + sep + item.Name;
                    var payload = new { remotePath = remotePath, localDir = TxtLocalPath.Text };
                    var content = new System.Net.Http.StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
                    var res = await _httpClient.PostAsync("/api/fs/remote/download", content);
                    if (res.IsSuccessStatusCode)
                    {
                        LogTerminal("File downloaded to PC.");
                        await Task.Delay(2000);
                        LoadLocalFiles(TxtLocalPath.Text);
                    }
                    else
                    {
                        LogTerminal($"Download error: {res.StatusCode}");
                    }
                }
                catch (Exception ex)
                {
                    LogTerminal($"Download error: {ex.Message}");
                }
            }
        }

        private void ResolveUserContext() => TxtUserType.Text = $"{Environment.UserDomainName}\\{Environment.UserName}";
    }
}