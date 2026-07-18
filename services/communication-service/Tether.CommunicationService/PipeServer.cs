using System;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
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

namespace Tether.CommunicationService;

public class PipeServer : IDisposable
{
    [DllImport("kernel32.dll", SetLastError = false)]
    private static extern uint WTSGetActiveConsoleSessionId();

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSQueryUserToken(uint SessionId, out IntPtr phToken);

    [DllImport("kernel32.dll", SetLastError = false)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeClientProcessId(IntPtr Pipe, out uint ClientProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ProcessIdToSessionId(uint dwProcessId, out uint pSessionId);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(
        IntPtr TokenHandle,
        int TokenInformationClass,
        out uint TokenInformation,
        uint TokenInformationLength,
        out uint ReturnLength);

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

    private static uint GetClientSessionId(NamedPipeServerStream pipeStream)
    {
        try
        {
            if (GetNamedPipeClientProcessId(pipeStream.SafePipeHandle.DangerousGetHandle(), out uint pid))
            {
                if (ProcessIdToSessionId(pid, out uint sessionId))
                {
                    return sessionId;
                }
            }
        }
        catch
        {
            // Fallback if process handle query fails
        }
        return 0xFFFFFFFF; // Invalid/Unknown Session ID
    }

    private async Task HandleClientMessages(NamedPipeServerStream pipeStream)
    {
        var buffer = new byte[IpcConstants.PipeBufferSize];

        while (pipeStream.IsConnected)
        {
            try
            {
                // 1. Read payload first before impersonating client token
                var read = await pipeStream.ReadAsync(buffer, 0, buffer.Length);
                if (read == 0) break;

                // Capture service host identity
                SecurityIdentifier? serviceOwnerSid = WindowsIdentity.GetCurrent().User;

                // Retrieve pipe client session ID via Win32 process API
                uint clientSessionId = GetClientSessionId(pipeStream);

                // Intermediate context variables to extract from the client token
                bool clientAuthorized = false;
                string? clientSid = null;
                bool isClientSystem = false;
                uint tokenSessionId = 0xFFFFFFFF;

                // 2. Perform light identification capture INSIDE the client context
                try
                {
                    pipeStream.RunAsClient(() =>
                    {
                        using var clientIdentity = WindowsIdentity.GetCurrent();
                        if (clientIdentity.User != null)
                        {
                            clientSid = clientIdentity.User.Value;
                            isClientSystem = clientIdentity.User.IsWellKnown(WellKnownSidType.LocalSystemSid);

                            // Reading session info from the active thread token is permitted without SE_TCB_NAME
                            if (GetTokenInformation(clientIdentity.Token, 12, out uint sessionInfo, sizeof(uint), out _))
                            {
                                tokenSessionId = sessionInfo;
                            }
                        }
                    });
                }
                catch (Exception ex)
                {
                    _logger.Error($"Failed to safely collect client identification tokens: {ex.Message}");
                    break;
                }

                // If identity resolution failed, abort connection early
                if (string.IsNullOrEmpty(clientSid))
                {
                    _logger.Warning("Rejected connection: Client identity bounds could not be resolved.");
                    break;
                }

                // 3. Perform privilege-heavy token validation OUTSIDE of the impersonation context (Running as SYSTEM)
                // Check 1: Client matches service host owner (Dev/Debug execution or same user process)
                if (serviceOwnerSid != null && clientSid.Equals(serviceOwnerSid.Value, StringComparison.OrdinalIgnoreCase))
                {
                    clientAuthorized = true;
                }
                // Check 2: Client is NT AUTHORITY\SYSTEM
                else if (isClientSystem)
                {
                    clientAuthorized = true;
                }
                // Check 3: Check against session mappings now that TCB privilege availability is restored
                else
                {
                    uint consoleSessionId = WTSGetActiveConsoleSessionId();
                    uint[] sessionIdsToCheck = new[] { tokenSessionId, clientSessionId, consoleSessionId };

                    foreach (var sid in sessionIdsToCheck)
                    {
                        if (sid != 0xFFFFFFFF && WTSQueryUserToken(sid, out IntPtr userToken))
                        {
                            try
                            {
                                using var tokenIdentity = new WindowsIdentity(userToken);
                                if (tokenIdentity.User != null && clientSid.Equals(tokenIdentity.User.Value, StringComparison.OrdinalIgnoreCase))
                                {
                                    clientAuthorized = true;
                                    break;
                                }
                            }
                            finally
                            {
                                CloseHandle(userToken);
                            }
                        }
                    }
                }

                if (!clientAuthorized)
                {
                    _logger.Warning("Rejected connection from unauthorized local user session.");
                    break;
                }

                // 4. Process authorized JSON event payload
                var json = Encoding.UTF8.GetString(buffer, 0, read);
                var evt = JsonSerializer.Deserialize<TetherEvent>(json);

                if (evt != null)
                {
                    // Strict Event Filtering
                    if (evt.EventType != TetherEventType.PROVISION_PHONE &&
                        evt.EventType != TetherEventType.PHONE_UNLOCKED &&
                        evt.EventType != TetherEventType.PANIC_TRIGGERED &&
                        evt.EventType != TetherEventType.AUTH_SUCCESS)
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