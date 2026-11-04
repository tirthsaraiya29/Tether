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
    private const int MaxServerInstances = 10;
    private static readonly TimeSpan IdleTimeout = TimeSpan.FromMinutes(5);

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

    public static bool IsAllowedIpcEvent(TetherEventType type) =>
        type == TetherEventType.PANIC_TRIGGERED ||
        type == TetherEventType.HARDWARE_SYNC_REQUESTED;

    public void Start()
    {
        _cts = new CancellationTokenSource();
        _listenTask = Task.Run(ListenForClients, _cts.Token);
        _logger.Info("Pipe server started with concurrent client dispatch and idle timeouts.");
    }

    private static PipeSecurity CreatePipeSecurity()
    {
        var pipeSecurity = new PipeSecurity();

        // 1. Explicitly DENY Network SID to reject any remote/network-based named pipe connection (SMB/RPC)
        pipeSecurity.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.NetworkSid, null),
            PipeAccessRights.ReadWrite,
            AccessControlType.Deny));

        // 2. Allow SYSTEM Full Control
        pipeSecurity.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            PipeAccessRights.FullControl,
            AccessControlType.Allow));

        // 3. Allow Administrators Full Control
        pipeSecurity.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            PipeAccessRights.FullControl,
            AccessControlType.Allow));

        // 4. Allow Authenticated Users ReadWrite to connect from the local interactive session
        pipeSecurity.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null),
            PipeAccessRights.ReadWrite | PipeAccessRights.CreateNewInstance,
            AccessControlType.Allow));

        return pipeSecurity;
    }

    private async Task ListenForClients()
    {
        while (_cts?.IsCancellationRequested == false)
        {
            NamedPipeServerStream? pipeServer = null;
            try
            {
                var pipeSecurity = CreatePipeSecurity();

                pipeServer = NamedPipeServerStreamAcl.Create(
                    IpcConstants.PipeName,
                    PipeDirection.InOut,
                    MaxServerInstances,
                    PipeTransmissionMode.Message,
                    PipeOptions.Asynchronous,
                    0,
                    0,
                    pipeSecurity);

                await pipeServer.WaitForConnectionAsync(_cts.Token);

                // Transfer ownership of the connected stream to an asynchronous worker task
                var activeStream = pipeServer;
                pipeServer = null;

                _ = Task.Run(() => ProcessClientAsync(activeStream, _cts.Token));
            }
            catch (OperationCanceledException)
            {
                pipeServer?.Dispose();
                break;
            }
            catch (Exception ex)
            {
                pipeServer?.Dispose();
                _logger.Error($"Pipe server accept error: {ex.Message}", ex);
                try
                {
                    await Task.Delay(500, _cts.Token);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
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
        }
        return 0xFFFFFFFF;
    }

    private bool AuthenticateClient(NamedPipeServerStream pipeStream, out string clientSid, out uint clientSessionId)
    {
        clientSid = string.Empty;
        clientSessionId = GetClientSessionId(pipeStream);

        bool clientAuthorized = false;
        string? extractedSid = null;
        bool isClientSystem = false;
        uint tokenSessionId = 0xFFFFFFFF;

        try
        {
            pipeStream.RunAsClient(() =>
            {
                using var clientIdentity = WindowsIdentity.GetCurrent();
                if (clientIdentity.User != null)
                {
                    extractedSid = clientIdentity.User.Value;
                    isClientSystem = clientIdentity.User.IsWellKnown(WellKnownSidType.LocalSystemSid);

                    if (GetTokenInformation(clientIdentity.Token, 12, out uint sessionInfo, sizeof(uint), out _))
                    {
                        tokenSessionId = sessionInfo;
                    }
                }
            });
        }
        catch (Exception ex)
        {
            _logger.Error($"Failed to collect client identification tokens: {ex.Message}");
            return false;
        }

        if (string.IsNullOrEmpty(extractedSid))
        {
            _logger.Warning("Rejected connection: Client identity could not be resolved.");
            return false;
        }

        clientSid = extractedSid;
        SecurityIdentifier? serviceOwnerSid = WindowsIdentity.GetCurrent().User;

        if (serviceOwnerSid != null && clientSid.Equals(serviceOwnerSid.Value, StringComparison.OrdinalIgnoreCase))
        {
            clientAuthorized = true;
        }
        else if (isClientSystem)
        {
            clientAuthorized = true;
        }
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

        return clientAuthorized;
    }

    private async Task ProcessClientAsync(NamedPipeServerStream pipeStream, CancellationToken serviceCt)
    {
        using (pipeStream)
        using (var clientCts = CancellationTokenSource.CreateLinkedTokenSource(serviceCt))
        {
            // Immediate client authentication prior to accepting any data
            if (!AuthenticateClient(pipeStream, out string clientSid, out uint clientSessionId))
            {
                _logger.Warning($"Rejected unauthorized named pipe client (SID: {clientSid}, Session: {clientSessionId}). Closing connection.");
                return;
            }

            _logger.Info($"Authorized client connected to pipe (SID: {clientSid}, Session: {clientSessionId}).");

            var buffer = new byte[IpcConstants.PipeBufferSize];

            while (pipeStream.IsConnected && !clientCts.IsCancellationRequested)
            {
                try
                {
                    using var readTimeoutCts = CancellationTokenSource.CreateLinkedTokenSource(clientCts.Token);
                    readTimeoutCts.CancelAfter(IdleTimeout);

                    int read = await pipeStream.ReadAsync(buffer, 0, buffer.Length, readTimeoutCts.Token);
                    if (read == 0)
                    {
                        break;
                    }

                    var json = Encoding.UTF8.GetString(buffer, 0, read);
                    var evt = JsonSerializer.Deserialize<TetherEvent>(json);

                    if (evt != null)
                    {
                        if (evt.EventType == TetherEventType.PHONE_UNLOCKED ||
                            evt.EventType == TetherEventType.AUTH_SUCCESS)
                        {
                            _logger.Warning($"Security Block: Disallowed state injection event attempt rejected over IPC: {evt.EventType}");
                            continue;
                        }

                        if (!IsAllowedIpcEvent(evt.EventType))
                        {
                            _logger.Warning($"Rejected disallowed event type: {evt.EventType}");
                            continue;
                        }

                        _logger.Debug($"IPC received event: {evt.EventType} from Desktop UI");
                        _eventBus.Publish(evt);
                    }
                }
                catch (OperationCanceledException) when (!serviceCt.IsCancellationRequested)
                {
                    _logger.Info($"Pipe client timed out after {IdleTimeout.TotalMinutes:0} min of inactivity. Disconnecting idle client.");
                    break;
                }
                catch (IOException ex) when (ex.Message.Contains("pipe") || ex.Message.Contains("broken"))
                {
                    _logger.Info("Pipe client disconnected cleanly.");
                    break;
                }
                catch (Exception ex)
                {
                    _logger.Error($"Failed to handle pipe message: {ex.Message}");
                    break;
                }
            }

            _logger.Info($"Pipe client disconnected (Session: {clientSessionId}).");
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