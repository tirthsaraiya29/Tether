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
using Microsoft.Win32;
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

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct DATA_BLOB
    {
        public int cbData;
        public IntPtr pbData;
    }

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern bool CryptUnprotectData(
        ref DATA_BLOB pDataIn,
        StringBuilder? ppszDataDescr,
        ref DATA_BLOB pOptionalEntropy,
        IntPtr pvReserved,
        IntPtr pPromptStruct,
        uint dwFlags,
        ref DATA_BLOB pDataOut);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LogonUser(
        string lpszUsername,
        string? lpszDomain,
        string lpszPassword,
        int dwLogonType,
        int dwLogonProvider,
        out IntPtr phToken);

    [DllImport("kernel32.dll", SetLastError = false)]
    private static extern void RtlZeroMemory(IntPtr dest, IntPtr size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LocalFree(IntPtr hMem);

    private const uint CRYPTPROTECT_UI_FORBIDDEN = 0x1;
    private const uint CRYPTPROTECT_LOCAL_MACHINE = 0x4;
    private const int LOGON32_LOGON_INTERACTIVE = 2;
    private const int LOGON32_PROVIDER_DEFAULT = 0;

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
        type == TetherEventType.HARDWARE_SYNC_REQUESTED ||
        type == TetherEventType.FORGET_PHONE ||
        type == TetherEventType.VAULT_UPDATE ||
        type == TetherEventType.TELEMETRY_SYNC_REQUESTED ||
        type == TetherEventType.SHUTDOWN_INITIATED ||
        type == TetherEventType.RESTART_INITIATED ||
        type == TetherEventType.POWER_EVENT_DETECTED;

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

    private bool AuthenticateClient(NamedPipeServerStream pipeStream, out string clientSid, out uint clientSessionId) =>
        AuthenticateClient(pipeStream, out clientSid, out clientSessionId, out _);

    private bool AuthenticateClient(NamedPipeServerStream pipeStream, out string clientSid, out uint clientSessionId, out bool isClientSystem)
    {
        clientSid = string.Empty;
        clientSessionId = GetClientSessionId(pipeStream);
        isClientSystem = false;

        bool clientAuthorized = false;
        string? extractedSid = null;
        bool localIsClientSystem = false;
        uint tokenSessionId = 0xFFFFFFFF;

        try
        {
            pipeStream.RunAsClient(() =>
            {
                using var clientIdentity = WindowsIdentity.GetCurrent();
                if (clientIdentity.User != null)
                {
                    extractedSid = clientIdentity.User.Value;
                    localIsClientSystem = clientIdentity.User.IsWellKnown(WellKnownSidType.LocalSystemSid);

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

        isClientSystem = localIsClientSystem;

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
            if (consoleSessionId == 0xFFFFFFFF)
            {
                _logger.Warning("PipeServer: No active console session found. Rejecting non-SYSTEM client.");
                return false;
            }

            if (clientSessionId != consoleSessionId || tokenSessionId != consoleSessionId)
            {
                _logger.Warning($"PipeServer: Access denied. Client session {clientSessionId} or token session {tokenSessionId} does not match active console session {consoleSessionId}.");
                return false;
            }

            if (WTSQueryUserToken(consoleSessionId, out IntPtr userToken))
            {
                try
                {
                    using var tokenIdentity = new WindowsIdentity(userToken);
                    if (tokenIdentity.User != null && clientSid.Equals(tokenIdentity.User.Value, StringComparison.OrdinalIgnoreCase))
                    {
                        clientAuthorized = true;
                    }
                }
                finally
                {
                    CloseHandle(userToken);
                }
            }
        }

        return clientAuthorized;
    }

    internal static bool IsActiveConsoleUser(string clientSid)
    {
        try
        {
            uint consoleSessionId = WTSGetActiveConsoleSessionId();
            if (consoleSessionId == 0xFFFFFFFF) return false;
            if (WTSQueryUserToken(consoleSessionId, out IntPtr userToken))
            {
                try
                {
                    using var tokenIdentity = new WindowsIdentity(userToken);
                    return tokenIdentity.User != null && clientSid.Equals(tokenIdentity.User.Value, StringComparison.OrdinalIgnoreCase);
                }
                finally
                {
                    CloseHandle(userToken);
                }
            }
        }
        catch { }
        return false;
    }

    private static bool ValidateVaultSecretPayload(byte[] protectedPayload, string clientSid, string? username)
    {
        if (protectedPayload == null || protectedPayload.Length == 0) return false;

        byte[] entropyBytes = Encoding.UTF8.GetBytes("Tether_System_Bound_Vault_v1");
        IntPtr unmanagedIn = Marshal.AllocHGlobal(protectedPayload.Length);
        IntPtr unmanagedEntropy = Marshal.AllocHGlobal(entropyBytes.Length);
        DATA_BLOB dataOut = new DATA_BLOB();

        try
        {
            Marshal.Copy(protectedPayload, 0, unmanagedIn, protectedPayload.Length);
            Marshal.Copy(entropyBytes, 0, unmanagedEntropy, entropyBytes.Length);

            var dataIn = new DATA_BLOB { cbData = protectedPayload.Length, pbData = unmanagedIn };
            var entropy = new DATA_BLOB { cbData = entropyBytes.Length, pbData = unmanagedEntropy };

            if (!CryptUnprotectData(ref dataIn, null, ref entropy, IntPtr.Zero, IntPtr.Zero, CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE, ref dataOut) &&
                !CryptUnprotectData(ref dataIn, null, ref entropy, IntPtr.Zero, IntPtr.Zero, CRYPTPROTECT_UI_FORBIDDEN, ref dataOut))
            {
                return false;
            }

            if (dataOut.pbData == IntPtr.Zero || dataOut.cbData <= 0)
            {
                return false;
            }

            if (!string.IsNullOrEmpty(username))
            {
                try
                {
                    var account = new NTAccount(username);
                    var sid = (SecurityIdentifier)account.Translate(typeof(SecurityIdentifier));
                    if (!sid.Value.Equals(clientSid, StringComparison.OrdinalIgnoreCase))
                    {
                        return false;
                    }
                }
                catch (IdentityNotMappedException)
                {
                    // Translation can fail for local/MS account format; LogonUser token SID check below validates
                }
                catch
                {
                    return false;
                }
            }

            string targetUser = username ?? string.Empty;
            string? targetDomain = null;

            if (string.IsNullOrEmpty(targetUser))
            {
                try
                {
                    var sidObj = new SecurityIdentifier(clientSid);
                    var account = (NTAccount)sidObj.Translate(typeof(NTAccount));
                    targetUser = account.Value;
                }
                catch { }
            }

            if (targetUser.Contains('\\'))
            {
                var parts = targetUser.Split('\\', 2);
                targetDomain = parts[0];
                targetUser = parts[1];
            }
            else if (targetUser.Contains('@'))
            {
                var parts = targetUser.Split('@', 2);
                targetUser = parts[0];
                targetDomain = parts[1];
            }

            int charCount = dataOut.cbData / sizeof(char);
            while (charCount > 0 && Marshal.ReadInt16(dataOut.pbData, (charCount - 1) * sizeof(char)) == 0)
            {
                charCount--;
            }

            string password = Marshal.PtrToStringUni(dataOut.pbData, charCount);

            bool logonOk = false;
            IntPtr tokenHandle = IntPtr.Zero;
            try
            {
                if (LogonUser(targetUser, targetDomain, password, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, out tokenHandle) ||
                    (string.IsNullOrEmpty(targetDomain) && LogonUser(targetUser, ".", password, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, out tokenHandle)) ||
                    (!string.IsNullOrEmpty(targetDomain) && LogonUser(targetUser, null, password, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, out tokenHandle)))
                {
                    using var tokenIdentity = new WindowsIdentity(tokenHandle);
                    string? tokenUserSid = tokenIdentity.User?.Value;
                    if (string.Equals(tokenUserSid, clientSid, StringComparison.OrdinalIgnoreCase))
                    {
                        logonOk = true;
                    }
                }
            }
            finally
            {
                if (tokenHandle != IntPtr.Zero)
                {
                    CloseHandle(tokenHandle);
                }
            }

            return logonOk;
        }
        catch
        {
            return false;
        }
        finally
        {
            if (dataOut.pbData != IntPtr.Zero && dataOut.cbData > 0)
            {
                RtlZeroMemory(dataOut.pbData, (IntPtr)dataOut.cbData);
                LocalFree(dataOut.pbData);
            }
            if (unmanagedIn != IntPtr.Zero)
            {
                RtlZeroMemory(unmanagedIn, (IntPtr)protectedPayload.Length);
                Marshal.FreeHGlobal(unmanagedIn);
            }
            if (unmanagedEntropy != IntPtr.Zero)
            {
                RtlZeroMemory(unmanagedEntropy, (IntPtr)entropyBytes.Length);
                Marshal.FreeHGlobal(unmanagedEntropy);
            }
        }
    }

    private static void SaveVaultSecret(byte[] encryptedPassword, string clientSid, string? username)
    {
        using var rootKey = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Tether\CredentialProvider", true);
        rootKey?.SetValue("VaultDaclVersion", 2, Microsoft.Win32.RegistryValueKind.DWord);

        var rs = new RegistrySecurity();
        var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var adminsSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);

        rs.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        rs.AddAccessRule(new RegistryAccessRule(systemSid, RegistryRights.FullControl, AccessControlType.Allow));
        rs.AddAccessRule(new RegistryAccessRule(adminsSid, RegistryRights.FullControl, AccessControlType.Allow));

        using var secretsKey = rootKey?.CreateSubKey("Secrets", RegistryKeyPermissionCheck.ReadWriteSubTree, rs);
        if (secretsKey != null)
        {
            secretsKey.SetAccessControl(rs);
            secretsKey.SetValue("EncryptedPassword", encryptedPassword, Microsoft.Win32.RegistryValueKind.Binary);
            if (!string.IsNullOrEmpty(clientSid))
            {
                secretsKey.SetValue("TargetUserSid", clientSid, Microsoft.Win32.RegistryValueKind.String);
            }
            if (!string.IsNullOrEmpty(username))
            {
                secretsKey.SetValue("TargetUsername", username, Microsoft.Win32.RegistryValueKind.String);
            }
        }
    }

    private async Task ProcessClientAsync(NamedPipeServerStream pipeStream, CancellationToken serviceCt)
    {
        using (pipeStream)
        using (var clientCts = CancellationTokenSource.CreateLinkedTokenSource(serviceCt))
        {
            var buffer = new byte[IpcConstants.PipeBufferSize];
            bool isAuthenticated = false;
            string clientSid = string.Empty;
            uint clientSessionId = 0xFFFFFFFF;
            bool isClientSystem = false;

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

                    if (!isAuthenticated)
                    {
                        if (!AuthenticateClient(pipeStream, out clientSid, out clientSessionId, out isClientSystem))
                        {
                            _logger.Warning($"Rejected unauthorized named pipe client (SID: {clientSid}, Session: {clientSessionId}). Closing connection.");
                            return;
                        }

                        isAuthenticated = true;
                        _logger.Info($"Authorized client connected to pipe (SID: {clientSid}, Session: {clientSessionId}).");
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

                        if (evt.EventType == TetherEventType.VAULT_UPDATE)
                        {
                            if (!isClientSystem && !IsActiveConsoleUser(clientSid))
                            {
                                _logger.Warning($"Security Block: Rejected VAULT_UPDATE from non-active console user SID {clientSid}.");
                                continue;
                            }

                            try
                            {
                                using var doc = JsonDocument.Parse(evt.PayloadJson ?? "{}");
                                var root = doc.RootElement;
                                string? hexPayload = root.TryGetProperty("hexPayload", out var hexProp) ? hexProp.GetString() : null;
                                string? username = root.TryGetProperty("username", out var userProp) ? userProp.GetString() : null;
                                string? domain = root.TryGetProperty("domain", out var domProp) ? domProp.GetString() : null;
                                if (!string.IsNullOrEmpty(domain) && !string.IsNullOrEmpty(username) && !username.Contains('\\') && !username.Contains('@'))
                                {
                                    username = $"{domain}\\{username}";
                                }

                                if (!string.IsNullOrEmpty(hexPayload))
                                {
                                    byte[] protectedPayload = Convert.FromHexString(hexPayload);
                                    if (ValidateVaultSecretPayload(protectedPayload, clientSid, username))
                                    {
                                        SaveVaultSecret(protectedPayload, clientSid, username);
                                        _logger.Info($"Vault secret verified and updated securely over IPC for client SID: {clientSid}");
                                    }
                                    else
                                    {
                                        _logger.Warning($"Security Block: Rejected VAULT_UPDATE from client SID {clientSid} because password validation failed.");
                                    }
                                }
                                else
                                {
                                    _logger.Warning("VAULT_UPDATE payload missing hexPayload.");
                                }
                            }
                            catch (Exception ex)
                            {
                                _logger.Error($"Failed to process VAULT_UPDATE: {ex.Message}", ex);
                            }
                            continue;
                        }

                        if (evt.EventType == TetherEventType.FORGET_PHONE)
                        {
                            if (!isClientSystem && !IsActiveConsoleUser(clientSid))
                            {
                                _logger.Warning($"Security Block: Rejected FORGET_PHONE from non-active console user SID {clientSid}.");
                                continue;
                            }
                        }

                        if (evt.EventType == TetherEventType.SHUTDOWN_INITIATED)
                        {
                            Power.PowerEventHub.Watcher?.RecordInitiated(Power.TetherPowerEventType.Shutdown, evt.Source ?? "IPC.DesktopUI");
                        }
                        else if (evt.EventType == TetherEventType.RESTART_INITIATED)
                        {
                            Power.PowerEventHub.Watcher?.RecordInitiated(Power.TetherPowerEventType.Restart, evt.Source ?? "IPC.DesktopUI");
                        }
                        else if (evt.EventType == TetherEventType.POWER_EVENT_DETECTED)
                        {
                            var powerType = Power.TetherPowerEventType.Shutdown;
                            if (!string.IsNullOrEmpty(evt.PayloadJson) && evt.PayloadJson.Contains("restart", StringComparison.OrdinalIgnoreCase))
                                powerType = Power.TetherPowerEventType.Restart;
                            Power.PowerEventHub.Watcher?.RecordInitiated(powerType, evt.Source ?? "IPC.DesktopUI");
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
