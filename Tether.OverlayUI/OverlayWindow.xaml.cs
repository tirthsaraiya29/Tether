using System;
using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using System.Windows.Interop;

namespace Tether.OverlayUI
{
    public partial class OverlayWindow : Window
    {
        private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);
        private LowLevelKeyboardProc? _proc;
        private IntPtr _hookID = IntPtr.Zero;
        private CancellationTokenSource? _ipcTokenSource;

        private const int WH_KEYBOARD_LL = 13;
        private const int WM_KEYDOWN = 0x0100;
        private const int WM_SYSKEYDOWN = 0x0104;

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr SetWindowsHookEx(int idHook, LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UnhookWindowsHookEx(IntPtr hhk);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("dwmapi.dll")]
        private static extern int DwmSetWindowAttribute(IntPtr hwnd, uint dwAttribute, ref uint pvAttribute, uint cbAttribute);

        private const uint DWMWA_SYSTEMBACKDROP_TYPE = 38;
        private const uint DWMSBT_TRANSLUCENTBACKDROP = 3;

        public OverlayWindow()
        {
            InitializeComponent();
            this.Closing += OnWindowClosing;
            _proc = HookCallback;
            _hookID = SetHook(_proc);
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            this.Left = SystemParameters.VirtualScreenLeft;
            this.Top = SystemParameters.VirtualScreenTop;
            this.Width = SystemParameters.VirtualScreenWidth;
            this.Height = SystemParameters.VirtualScreenHeight;

            IntPtr windowHandle = new WindowInteropHelper(this).Handle;
            uint backdropType = DWMSBT_TRANSLUCENTBACKDROP;
            DwmSetWindowAttribute(windowHandle, DWMWA_SYSTEMBACKDROP_TYPE, ref backdropType, sizeof(uint));

            this.Activate();
            this.Focus();

            _ipcTokenSource = new CancellationTokenSource();
            Task.Run(() => StartIpcListenerLoopAsync(_ipcTokenSource.Token));
        }

        public void UpdateBlurFromRssi(double rssi)
        {
            if (!Dispatcher.CheckAccess())
            {
                Dispatcher.Invoke(() => UpdateBlurFromRssi(rssi));
                return;
            }

            try
            {
                double opacity = Math.Clamp((rssi + 50) / -30.0, 0.05, 0.75);
                if (BackgroundObfuscator != null)
                {
                    BackgroundObfuscator.Opacity = opacity;
                }
            }
            catch
            {
                // Fallback catch boundary
            }
        }

        private async Task StartIpcListenerLoopAsync(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                try
                {
                    using (var server = new NamedPipeServerStream("TetherUiPipe", PipeDirection.In, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous))
                    {
                        await server.WaitForConnectionAsync(token);

                        byte[] buffer = new byte[1024];
                        int bytesRead = await server.ReadAsync(buffer, 0, buffer.Length, token);
                        if (bytesRead > 0)
                        {
                            string json = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                            var tetherEvent = JsonSerializer.Deserialize<TetherEventMinimal>(json);

                            if (tetherEvent != null && (tetherEvent.EventType == "OVERLAY_DISABLED" || tetherEvent.EventType == "TRUST_RESTORED"))
                            {
                                await Dispatcher.InvokeAsync(() =>
                                {
                                    GracefulDismissal();
                                });
                                break;
                            }
                        }
                    }
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"UI Proximity IPC loop error: {ex.Message}");
                    await Task.Delay(1000, token);
                }
            }
        }

        private void Window_Deactivated(object sender, EventArgs e)
        {
            if (this.IsLoaded)
            {
                this.Topmost = false;
                this.Topmost = true;
                this.Activate();
                this.Focus();
            }
        }

        public void OnWindowClosing(object? sender, CancelEventArgs e)
        {
            e.Cancel = true;
        }

        private IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam)
        {
            if (nCode >= 0 && (wParam == (IntPtr)WM_KEYDOWN || wParam == (IntPtr)WM_SYSKEYDOWN))
            {
                int vkCode = Marshal.ReadInt32(lParam);
                Key key = KeyInterop.KeyFromVirtualKey(vkCode);

                bool isAlt = (Keyboard.Modifiers & ModifierKeys.Alt) != 0 || key == Key.System;
                bool isCtrl = (Keyboard.Modifiers & ModifierKeys.Control) != 0;

                if ((isAlt && key == Key.Tab) ||
                    (isCtrl && key == Key.Escape) ||
                    (key == Key.LWin) || (key == Key.RWin) ||
                    (isAlt && key == Key.F4))
                {
                    return (IntPtr)1;
                }
            }
            return CallNextHookEx(_hookID, nCode, wParam, lParam);
        }

        private IntPtr SetHook(LowLevelKeyboardProc proc)
        {
            using (var curProcess = System.Diagnostics.Process.GetCurrentProcess())
            using (var curModule = curProcess.MainModule)
            {
                if (curModule != null && !string.IsNullOrEmpty(curModule.ModuleName))
                {
                    return SetWindowsHookEx(WH_KEYBOARD_LL, proc, GetModuleHandle(curModule.ModuleName), 0);
                }
                return IntPtr.Zero;
            }
        }

        private async void Unlock_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // FIX: Use the strongly-typed TetherEvent class so the enum serializes perfectly for the service parser
                var releaseEvent = new Tether.Shared.Events.TetherEvent
                {
                    EventType = Tether.Shared.Events.TetherEventType.PHONE_UNLOCKED,
                    Source = "OverlayUI"
                };

                var json = JsonSerializer.Serialize(releaseEvent);
                var bytes = Encoding.UTF8.GetBytes(json);

                // FIX: Align the outbound target back to the shared PipeName definition
                using var client = new NamedPipeClientStream(".", Tether.Shared.IPC.IpcConstants.PipeName, PipeDirection.Out);
                await client.ConnectAsync(300);
                await client.WriteAsync(bytes, 0, bytes.Length);
                await client.FlushAsync();
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"IPC Release Failed: {ex.Message}");
            }
            finally
            {
                GracefulDismissal();
            }
        }

        private void GracefulDismissal()
        {
            _ipcTokenSource?.Cancel();
            if (_hookID != IntPtr.Zero)
            {
                UnhookWindowsHookEx(_hookID);
                _hookID = IntPtr.Zero;
            }
            this.Closing -= OnWindowClosing;
            this.Close();
            System.Windows.Application.Current.Shutdown();
        }

        private class TetherEventMinimal
        {
            public string EventType { get; set; } = string.Empty;
            public string Source { get; set; } = string.Empty;
        }
    }
}