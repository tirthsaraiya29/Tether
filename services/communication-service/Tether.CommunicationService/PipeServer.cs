using System;
using System.IO;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Tether.EventBus;
using Tether.Shared.Events;
using Tether.Shared.IPC;
using Tether.Shared.Logging;
using System.Security.Principal;
using System.Runtime.InteropServices;

namespace Tether.CommunicationService;

public class PipeServer : IDisposable
{
    [DllImport("kernel32.dll", SetLastError = false)]
    private static extern uint WTSGetActiveConsoleSessionId();

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSQueryUserToken(uint SessionId, out IntPtr phToken);

    [DllImport("kernel32.dll", SetLastError = false)]
    private static extern bool CloseHandle(IntPtr hObject);

    private readonly IEventBus _eventBus;
    private readonly ITetherLogger _logger;
    private CancellationTokenSource? _cts;
    private Task? _listenTask;
    private bool _disposed = false;

    public PipeServer(IEventBus eventBus, ITetherLogger logger)
    {
        _eventBus = eventBus;
        _logger = logger;
    }

    public void Start()
    {
        _cts = new CancellationTokenSource();
        _listenTask = Task.Run(ListenForClients, _cts.Token);
        _logger.Info("Pipe server started");
    }

    private async Task ListenForClients()
    {
        while (_cts?.IsCancellationRequested == false)
        {
            try
            {
                var pipeSecurity = new PipeSecurity();
                pipeSecurity.AddAccessRule(new PipeAccessRule(
                    new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null),
                    PipeAccessRights.ReadWrite | PipeAccessRights.CreateNewInstance,
                    AccessControlType.Allow));

                using var pipeServer = NamedPipeServerStreamAcl.Create(
                    IpcConstants.PipeName,
                    PipeDirection.InOut,
                    1,
                    PipeTransmissionMode.Message,
                    PipeOptions.Asynchronous,
                    0,
                    0,
                    pipeSecurity);

                _logger.Info($"Named pipe server waiting for connection on {IpcConstants.PipeName}...");
                await pipeServer.WaitForConnectionAsync(_cts.Token);
                _logger.Info("Desktop UI connected to pipe.");

                await HandleClientMessages(pipeServer);

                _logger.Info("Desktop UI disconnected.");
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.Error($"Pipe server error: {ex.Message}", ex);
                await Task.Delay(1000);
            }
        }
    }

    private async Task HandleClientMessages(NamedPipeServerStream pipeStream)
    {
        var buffer = new byte[IpcConstants.PipeBufferSize];
        bool clientAuthorized = false;

        // 1. Impersonate the client connection to verify its user SID matches the active console user
        try
        {
            pipeStream.RunAsClient(() =>
            {
                using (var identity = WindowsIdentity.GetCurrent())
                {
                    var principal = new WindowsPrincipal(identity);

                    // Fetch the token identifier of the active console session user
                    uint sessionId = WTSGetActiveConsoleSessionId();
                    IntPtr userToken;
                    if (WTSQueryUserToken(sessionId, out userToken))
                    {
                        using (var tokenIdentity = new WindowsIdentity(userToken))
                        {
                            // Check if the connecting user matches the logged-in interactive user context
                            if (identity.User == tokenIdentity.User)
                            {
                                clientAuthorized = true;
                            }
                        }
                        CloseHandle(userToken);
                    }
                }
            });
        }
        catch (Exception ex)
        {
            _logger.Error($"Client authorization failed: {ex.Message}");
            return;
        }

        if (!clientAuthorized)
        {
            _logger.Warning("Rejected connection from unauthorized user.");
            return;
        }

        // Process secure stream loop
        while (pipeStream.IsConnected)
        {
            try
            {
                var read = await pipeStream.ReadAsync(buffer, 0, buffer.Length);
                if (read == 0) break;

                var json = Encoding.UTF8.GetString(buffer, 0, read);
                var evt = JsonSerializer.Deserialize<TetherEvent>(json);

                if (evt != null)
                {
                    // 2. Strict Event Whitelist Filtering
                    // Reject all administrative or state alteration commands except for initial phone provisioning
                    if (evt.EventType != TetherEventType.PROVISION_PHONE)
                    {
                        _logger.Warning($"Rejected disallowed event type: {evt.EventType}");
                        continue;
                    }

                    _logger.Debug($"IPC received event: {evt.EventType} from Desktop UI");
                    _eventBus.Publish(evt);
                }
            }
            catch (IOException ex) when (ex.Message.Contains("pipe") || ex.Message.Contains("broken"))
            {
                _logger.Warning("Pipe client disconnected abruptly.");
                break;
            }
            catch (Exception ex)
            {
                _logger.Error($"Failed to handle pipe message: {ex.Message}");
                break;
            }
        }
    }

    public void Dispose()
    {
        lock (this)
        {
            if (_disposed) return;
            _disposed = true;
        }

        try
        {
            _cts?.Cancel();
            _listenTask?.Wait(5000);
        }
        catch { }
        finally
        {
            _cts?.Dispose();
        }
    }
}