using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Input;
using System.Windows.Interop;

namespace Tether.OverlayUI
{
    public partial class OverlayWindow : Window
    {
        // Low-Level Keyboard Interceptor Hooks
        private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);
        private LowLevelKeyboardProc? _proc;
        private IntPtr _hookID = IntPtr.Zero;

        private const int WH_KEYBOARD_LL = 13;
        private const int WM_KEYDOWN = 0x0100;
        private const int WM_SYSKEYDOWN = 0x0104;

        // Native Blur Attributes Constants
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
        private const uint DWMSBT_TRANSLUCENTBACKDROP = 3; // High-performance Acrylic/Mica Glass effect ceiling

        public OverlayWindow()
        {
            InitializeComponent();
            this.Closing += OnWindowClosing;
            _proc = HookCallback;
            _hookID = SetHook(_proc);
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            // Lock out full screen parameters safely
            this.Left = SystemParameters.VirtualScreenLeft;
            this.Top = SystemParameters.VirtualScreenTop;
            this.Width = SystemParameters.VirtualScreenWidth;
            this.Height = SystemParameters.VirtualScreenHeight;

            // Trigger Hardware Accelerated Windows 11 Translucent Acrylic Glass Backdrop
            IntPtr windowHandle = new WindowInteropHelper(this).Handle;
            uint backdropType = DWMSBT_TRANSLUCENTBACKDROP;
            DwmSetWindowAttribute(windowHandle, DWMWA_SYSTEMBACKDROP_TYPE, ref backdropType, sizeof(uint));

            this.Activate();
            this.Focus();
        }

        // Steal focus back aggressively if the user attempts to click away or activate Task Manager
        private void Window_Deactivated(object sender, EventArgs e)
        {
            if (this.IsLoaded)
            {
                this.Topmost = false;
                this.Topmost = true; // Refresh stacking priority
                this.Activate();
                this.Focus();
            }
        }

        public void OnWindowClosing(object? sender, CancelEventArgs e)
        {
            e.Cancel = true;
        }

        public void UpdateBlurFromRssi(double rssi)
        {
            // Unused since OS Acrylic backdrop handles visual isolation natively now
        }

        // Low-level system hook callback logic processing inputs safely
        private IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam)
        {
            if (nCode >= 0 && (wParam == (IntPtr)WM_KEYDOWN || wParam == (IntPtr)WM_SYSKEYDOWN))
            {
                int vkCode = Marshal.ReadInt32(lParam);
                Key key = KeyInterop.KeyFromVirtualKey(vkCode);

                // Intercept and absorb bypass keys: Alt+Tab, Windows Keys, Esc modifiers
                bool isAlt = (Keyboard.Modifiers & ModifierKeys.Alt) != 0 || key == Key.System;
                bool isCtrl = (Keyboard.Modifiers & ModifierKeys.Control) != 0;

                if ((isAlt && key == Key.Tab) ||
                    (isCtrl && key == Key.Escape) ||
                    (key == Key.LWin) || (key == Key.RWin) ||
                    (isAlt && key == Key.F4))
                {
                    return (IntPtr)1; // Consume input stream immediately
                }
            }
            return CallNextHookEx(_hookID, nCode, wParam, lParam);
        }

        private IntPtr SetHook(LowLevelKeyboardProc proc)
        {
            using (var curProcess = System.Diagnostics.Process.GetCurrentProcess())
            using (var curModule = curProcess.MainModule)
            {
                return SetWindowsHookEx(WH_KEYBOARD_LL, proc, GetModuleHandle(curModule!.ModuleName!), 0);
            }
        }

        private async void Unlock_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var releaseEvent = new Tether.Shared.Events.TetherEvent
                {
                    EventType = Tether.Shared.Events.TetherEventType.PHONE_UNLOCKED,
                    Source = "OverlayUI"
                };

                var json = System.Text.Json.JsonSerializer.Serialize(releaseEvent);
                var bytes = System.Text.Encoding.UTF8.GetBytes(json);

                using var client = new System.IO.Pipes.NamedPipeClientStream(".", Tether.Shared.IPC.IpcConstants.PipeName, System.IO.Pipes.PipeDirection.Out);
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
                if (_hookID != IntPtr.Zero)
                {
                    UnhookWindowsHookEx(_hookID);
                }
                this.Closing -= OnWindowClosing;
                this.Close();
                System.Windows.Application.Current.Shutdown();
            }
        }
    }
}