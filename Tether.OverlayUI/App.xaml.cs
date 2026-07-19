using System;
using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using Tether.Shared.Events;
using Tether.Shared.IPC;

namespace Tether.OverlayUI
{
    public partial class App : Application
    {
        private bool _isListening = true;
        private OverlayWindow? _activeOverlay = null;
        [DllImport("user32.dll")]
        private static extern bool LockWorkStation();

        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            // Fire up background server thread to track communication metrics asynchronously
            StartServiceListener();
        }

        private async void StartServiceListener()
        {
            while (_isListening)
            {
                NamedPipeServerStream? server = null;
                try
                {
                    // Explicitly allow Local SYSTEM account to communicate via this pipe
                    var pipeSecurity = new PipeSecurity();
                    pipeSecurity.AddAccessRule(new PipeAccessRule(
                        new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                        PipeAccessRights.ReadWrite,
                        AccessControlType.Allow));
                    pipeSecurity.AddAccessRule(new PipeAccessRule(
                        WindowsIdentity.GetCurrent().User!,
                        PipeAccessRights.FullControl,
                        AccessControlType.Allow));

                    server = NamedPipeServerStreamAcl.Create(
                        IpcConstants.UiPipeName,
                        PipeDirection.In,
                        NamedPipeServerStream.MaxAllowedServerInstances,
                        PipeTransmissionMode.Message,
                        PipeOptions.Asynchronous,
                        0,
                        0,
                        pipeSecurity
                    );

                    await server.WaitForConnectionAsync();

                    byte[] buffer = new byte[IpcConstants.PipeBufferSize];
                    int bytesRead = await server.ReadAsync(buffer, 0, buffer.Length);

                    if (bytesRead > 0)
                    {
                        string json = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                        var evt = JsonSerializer.Deserialize<TetherEvent>(json);

                        if (evt != null)
                        {
                            Current.Dispatcher.Invoke(() => HandleIncomingEvent(evt));
                        }
                    }
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"Named Pipe cross-session loop error: {ex.Message}");
                    await Task.Delay(250);
                }
                finally
                {
                    if (server != null)
                    {
                        if (server.IsConnected) server.Disconnect();
                        await server.DisposeAsync();
                    }
                }
            }
        }

        private void HandleIncomingEvent(TetherEvent evt)
        {
            // Automatically capture window instance on initialization path
            if (_activeOverlay == null)
            {
                _activeOverlay = MainWindow as OverlayWindow;
            }

            if (_activeOverlay == null) return;

            switch (evt.EventType)
            {
                case TetherEventType.TRUST_DEGRADED:
                    if (evt.PayloadJson != null)
                    {
                        try
                        {
                            var data = JsonSerializer.Deserialize<JsonElement>(evt.PayloadJson);
                            if (data.TryGetProperty("Rssi", out var rssiProp))
                            {
                                double currentRssi = rssiProp.GetDouble();
                                _activeOverlay.UpdateBlurFromRssi(currentRssi);
                            }
                        }
                        catch { }
                    }
                    break;

                case TetherEventType.LOCK_WORKSTATION:
                    LockWorkStation();
                    break;

                case TetherEventType.OVERLAY_ENABLED:
                    _activeOverlay.UpdateBlurFromRssi(-75);
                    break;

                case TetherEventType.OVERLAY_DISABLED:
                    _activeOverlay.UpdateBlurFromRssi(-60); // Clear blur 

                    _activeOverlay.Closing -= _activeOverlay.OnWindowClosing;
                    _activeOverlay.Close();

                    Application.Current.Shutdown();
                    break;
            }
        }

        protected override void OnExit(ExitEventArgs e)
        {
            _isListening = false;
            base.OnExit(e);
        }
    }
}