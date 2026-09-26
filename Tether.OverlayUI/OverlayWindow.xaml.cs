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

                        byte[] buffer = new byte[4096];
                        int bytesRead = await server.ReadAsync(buffer, 0, buffer.Length, token);
                        if (bytesRead > 0)
                        {
                            string json = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                            var tetherEvent = JsonSerializer.Deserialize<TetherEventMinimal>(json);

                            if (tetherEvent == null) continue;

                            // ── TOFU PAIRING ─────────────────────────────────
                            // First-time pairing request from an unprovisioned phone.
                            // The service has already broadcast PAIRING_REQUESTED over
                            // IEventBus and is now blocked awaiting our decision on
                            // IpcConstants.PipeName ("TetherPipe"). Do NOT break the
                            // listener loop here — the overlay may still need to react
                            // to OVERLAY_DISABLED later.
                            if (tetherEvent.EventType == "PAIRING_REQUESTED")
                            {
                                _ = HandlePairingRequestAsync(tetherEvent.PayloadJson);
                                continue;
                            }
                            // ─────────────────────────────────────────────────

                            if (tetherEvent.EventType == "OVERLAY_DISABLED" ||
                                tetherEvent.EventType == "TRUST_RESTORED")
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

        // ── TOFU PAIRING ─────────────────────────────────────────────────
        /// <summary>
        /// Displays the "New device wants to pair" dialog and, on user selection,
        /// sends a PAIRING_DECISION event over IpcConstants.PipeName ("TetherPipe")
        /// back to LanTransportServer. The service independently re-verifies the
        /// RequestId + phone key against its own pending-request state, so this
        /// process cannot self-authorize a pairing.
        /// </summary>
        private async Task HandlePairingRequestAsync(string payloadJson)
        {
            try
            {
                if (string.IsNullOrEmpty(payloadJson)) return;

                PairingRequestPayloadMinimal? payload;
                try
                {
                    payload = JsonSerializer.Deserialize<PairingRequestPayloadMinimal>(payloadJson);
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"PAIRING_REQUESTED payload parse failed: {ex.Message}");
                    return;
                }

                if (payload == null || string.IsNullOrEmpty(payload.RequestId))
                    return;

                // Marshal onto the UI thread and show the confirmation dialog.
                bool allowed = await Dispatcher.InvokeAsync(() =>
                {
                    var result = MessageBox.Show(
                        this,
                        $"A new phone wants to pair with this PC.\n\n" +
                        $"Device fingerprint:\n{payload.Fingerprint}\n\n" +
                        $"Only allow this if you just initiated pairing on your phone.",
                        "Tether — Pairing Request",
                        MessageBoxButton.YesNo,
                        MessageBoxImage.Question,
                        MessageBoxResult.No);

                    return result == MessageBoxResult.Yes;
                });

                await SendPairingDecisionAsync(
                    payload.RequestId,
                    payload.PhonePublicKeyBase64,
                    payload.Fingerprint,
                    allowed);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"HandlePairingRequestAsync failed: {ex.Message}");
            }
        }

        private async Task SendPairingDecisionAsync(
            string requestId,
            string phonePublicKeyBase64,
            string fingerprint,
            bool allowed)
        {
            try
            {
                // Build the outer TetherEvent envelope manually (the shared TetherEvent
                // type is serialized with an enum-as-string converter on the service side;
                // match it exactly by using the same strongly-typed class).
                var decisionPayload = new PairingDecisionPayloadMinimal
                {
                    RequestId = requestId,
                    PhonePublicKeyBase64 = phonePublicKeyBase64,
                    Fingerprint = fingerprint,
                    Allowed = allowed
                };

                var evt = new Tether.Shared.Events.TetherEvent
                {
                    EventType = Tether.Shared.Events.TetherEventType.PAIRING_DECISION,
                    Source = "OverlayUI",
                    PayloadJson = JsonSerializer.Serialize(decisionPayload)
                };

                var json = JsonSerializer.Serialize(evt);
                var bytes = Encoding.UTF8.GetBytes(json);

                using var client = new NamedPipeClientStream(
                    ".",
                    Tether.Shared.IPC.IpcConstants.PipeName,
                    PipeDirection.Out,
                    PipeOptions.Asynchronous);

                await client.ConnectAsync(500);
                await client.WriteAsync(bytes, 0, bytes.Length);
                await client.FlushAsync();

                System.Diagnostics.Debug.WriteLine(
                    $"PAIRING_DECISION sent (RequestId={requestId}, Allowed={allowed})");
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"PAIRING_DECISION send failed: {ex.Message}");
            }
        }

        // Local mirrors of the shared DTOs so this file has no compile-time dependency
        // on Tether.Shared.DTO. Field names MUST match PairingRequestPayload /
        // PairingDecisionPayload exactly for JsonSerializer round-tripping.
        private class PairingRequestPayloadMinimal
        {
            public string RequestId { get; set; } = string.Empty;
            public string PhonePublicKeyBase64 { get; set; } = string.Empty;
            public string Fingerprint { get; set; } = string.Empty;
            public long TimestampUtcTicks { get; set; }
        }

        private class PairingDecisionPayloadMinimal
        {
            public string RequestId { get; set; } = string.Empty;
            public string PhonePublicKeyBase64 { get; set; } = string.Empty;
            public string Fingerprint { get; set; } = string.Empty;
            public bool Allowed { get; set; }
        }
        // ─────────────────────────────────────────────────────────────────

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
            // ── TOFU PAIRING ──
            // Populated by LanTransportServer when it broadcasts PAIRING_REQUESTED.
            public string PayloadJson { get; set; } = string.Empty;
        }
    }
}