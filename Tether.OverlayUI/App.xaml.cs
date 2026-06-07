using System;
using System.ComponentModel;
using System.IO.Pipes;
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
                    // Configure server pipelines with multi-instance accessibility tokens allowed
                    server = new NamedPipeServerStream(
                        IpcConstants.UiPipeName,
                        PipeDirection.In,
                        NamedPipeServerStream.MaxAllowedServerInstances,
                        PipeTransmissionMode.Message,
                        PipeOptions.Asynchronous
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
                            // FIXED: Marshal compilation pipeline safely back to main thread context via UI Dispatcher
                            Current.Dispatcher.Invoke(() => HandleIncomingEvent(evt));
                        }
                    }
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"Named Pipe processing cycle exception caught: {ex.Message}");
                    await Task.Delay(500); // Prevent hard CPU spin on persistent pipeline faults
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