using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Tether.LinuxDaemon.Common;
using Tether.LinuxDaemon.Config;
using Tether.Shared.Logging;

namespace Tether.LinuxDaemon.Security;

public sealed class UnlockGrant
{
    public string TargetUser { get; init; } = "";
    public string DeviceFingerprint { get; init; } = "";
    public DateTime GrantedAtUtc { get; init; } = DateTime.UtcNow;
    public DateTime ExpiresAtUtc { get; init; } = DateTime.UtcNow.AddSeconds(15);
    public bool IsConsumed { get; set; } = false;
}

public sealed class LinuxPamAuthServer : IDisposable
{
    // Whitelist of permitted local workstation display managers and screen lockers.
    // Unrelated services (sshd, sudo, su, polkit-1, etc.) must NEVER consume mobile unlock authority.
    public static readonly HashSet<string> PermittedPamServices = new(StringComparer.OrdinalIgnoreCase)
    {
        "gdm-password",
        "gdm",
        "gdm-fingerprint",
        "sddm",
        "sddm-greeter",
        "lightdm",
        "lightdm-greeter",
        "login",
        "gnome-screensaver",
        "swaylock",
        "hyprlock",
        "waylock",
        "gtklock",
        "cinnamon-screensaver",
        "mate-screensaver",
        "xfce4-screensaver",
        "lockscreen",
        "tether-test"
    };

    private readonly ITetherLogger _logger;
    private readonly LinuxDaemonConfig _config;
    private readonly ConcurrentDictionary<string, UnlockGrant> _grantsByUser = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, DateTime> _pendingPromptsByUser = new(StringComparer.Ordinal);
    private Socket? _serverSocket;
    private CancellationTokenSource? _cts;
    private Task? _listenTask;

    // Status providers injected from DaemonWorker/SessionManager
    public Func<bool>? PhoneConnectedProvider { get; set; }
    public Func<string>? ConnectedDeviceNameProvider { get; set; }
    public Func<string>? ConnectedDeviceFingerprintProvider { get; set; }
    public Action<string>? RequestPhoneAuthHandler { get; set; }

    // Testability flags
    public bool BypassUidCheckForTesting { get; set; } = false;
    public bool AllowIpcArmGrantForTesting { get; set; } = false;

    public LinuxPamAuthServer(ITetherLogger logger, LinuxDaemonConfig config)
    {
        _logger = logger;
        _config = config;
    }

    public void ArmUnlockGrant(string targetUser, string deviceFingerprint, int validitySeconds = 20)
    {
        if (string.IsNullOrWhiteSpace(targetUser)) return;

        var grant = new UnlockGrant
        {
            TargetUser = targetUser,
            DeviceFingerprint = deviceFingerprint ?? "unknown-phone",
            GrantedAtUtc = DateTime.UtcNow,
            ExpiresAtUtc = validitySeconds > 0
                ? DateTime.UtcNow.AddSeconds(Math.Min(validitySeconds, 120))
                : DateTime.UtcNow.AddSeconds(validitySeconds),
            IsConsumed = false
        };

        _grantsByUser[targetUser] = grant;
        _pendingPromptsByUser.TryRemove(targetUser, out _);
        _logger.Info($"LinuxPamAuthServer: Armed unlock grant for user '{targetUser}' from phone '{deviceFingerprint}' (valid for {validitySeconds}s).");
    }

    public bool HasActiveGrant(string targetUser)
    {
        if (string.IsNullOrEmpty(targetUser)) return false;

        if (_grantsByUser.TryGetValue(targetUser, out var grant))
        {
            if (!grant.IsConsumed && DateTime.UtcNow <= grant.ExpiresAtUtc)
            {
                return true;
            }
        }
        return false;
    }

    public bool ConsumeGrant(string targetUser)
    {
        if (string.IsNullOrEmpty(targetUser)) return false;

        if (_grantsByUser.TryGetValue(targetUser, out var grant))
        {
            lock (grant)
            {
                if (!grant.IsConsumed && DateTime.UtcNow <= grant.ExpiresAtUtc)
                {
                    grant.IsConsumed = true;
                    _grantsByUser.TryRemove(targetUser, out _);
                    _logger.Info($"LinuxPamAuthServer: Successfully consumed one-time unlock grant for user '{targetUser}'.");
                    return true;
                }
            }
        }

        _logger.Warning($"LinuxPamAuthServer: Unlock grant missing, consumed, or expired for user '{targetUser}'.");
        return false;
    }

    public void ClearAllGrants()
    {
        _grantsByUser.Clear();
        _pendingPromptsByUser.Clear();
    }

    public void InvalidateDeviceGrants(string deviceFingerprint)
    {
        if (string.IsNullOrEmpty(deviceFingerprint)) return;

        var toRemove = _grantsByUser
            .Where(kv => string.Equals(kv.Value.DeviceFingerprint, deviceFingerprint, StringComparison.OrdinalIgnoreCase))
            .Select(kv => kv.Key)
            .ToList();

        foreach (var user in toRemove)
        {
            _grantsByUser.TryRemove(user, out _);
            _logger.Info($"LinuxPamAuthServer: Invalided unlock grant for user '{user}' due to device '{deviceFingerprint}' disconnect or revocation.");
        }
    }

    public bool HasPendingPrompt(string targetUser)
    {
        if (string.IsNullOrEmpty(targetUser)) return false;
        if (_pendingPromptsByUser.TryGetValue(targetUser, out var exp))
        {
            if (DateTime.UtcNow <= exp) return true;
            _pendingPromptsByUser.TryRemove(targetUser, out _);
        }
        return false;
    }

    public void SetPendingPrompt(string targetUser, int validitySeconds = 30)
    {
        if (!string.IsNullOrEmpty(targetUser))
        {
            _pendingPromptsByUser[targetUser] = DateTime.UtcNow.AddSeconds(validitySeconds);
        }
    }

    public void ClearPendingPrompt(string targetUser)
    {
        if (!string.IsNullOrEmpty(targetUser))
        {
            _pendingPromptsByUser.TryRemove(targetUser, out _);
        }
    }

    public string? GetFirstPendingPromptUser()
    {
        var now = DateTime.UtcNow;
        var valid = _pendingPromptsByUser.FirstOrDefault(kv => kv.Value > now);
        return valid.Key;
    }

    public void Start()
    {
        Stop();

        string sockPath = _config.PamSocketPath;
        try
        {
            string? dir = Path.GetDirectoryName(sockPath);
            if (!string.IsNullOrEmpty(dir))
            {
                Directory.CreateDirectory(dir);
                if (OperatingSystem.IsLinux())
                {
                    try
                    {
                        // 0755: Greeter users (gdm, sddm, lightdm) and locked session users must be able to reach socket
                        File.SetUnixFileMode(dir, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute |
                                                  UnixFileMode.GroupRead | UnixFileMode.GroupExecute |
                                                  UnixFileMode.OtherRead | UnixFileMode.OtherExecute);
                    }
                    catch { }
                }
            }

            if (File.Exists(sockPath))
            {
                var fi = new FileInfo(sockPath);
                // Symlink race defense (TETH-SEC-LNX-006)
                if (fi.LinkTarget == null)
                {
                    File.Delete(sockPath);
                }
                else
                {
                    _logger.Warning($"LinuxPamAuthServer: Refusing to delete symlink at {sockPath}");
                    return;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Warning($"LinuxPamAuthServer socket cleanup warning: {ex.Message}");
        }

        _cts = new CancellationTokenSource();
        _serverSocket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        var endpoint = new UnixDomainSocketEndPoint(sockPath);

        try
        {
            _serverSocket.Bind(endpoint);
            _serverSocket.Listen(16);

            if (OperatingSystem.IsLinux())
            {
                try
                {
                    // 0666: Access is gated strictly by SO_PEERCRED authentication
                    File.SetUnixFileMode(sockPath, UnixFileMode.UserRead | UnixFileMode.UserWrite |
                                                  UnixFileMode.GroupRead | UnixFileMode.GroupWrite |
                                                  UnixFileMode.OtherRead | UnixFileMode.OtherWrite);
                }
                catch { }
            }

            _listenTask = Task.Run(() => AcceptLoopAsync(_cts.Token));
            _logger.Info($"Linux PAM Auth Server listening on UNIX socket {sockPath}.");
        }
        catch (Exception ex)
        {
            _logger.Error($"Failed to bind Linux PAM Auth socket {sockPath}: {ex.Message}");
        }
    }

    public void Stop()
    {
        try { _cts?.Cancel(); } catch { }
        try { _serverSocket?.Close(); } catch { }
        try { _listenTask?.Wait(TimeSpan.FromSeconds(2)); } catch { }
        try { _cts?.Dispose(); } catch { }
        _cts = null;
        _serverSocket = null;

        try
        {
            if (File.Exists(_config.PamSocketPath))
            {
                var fi = new FileInfo(_config.PamSocketPath);
                if (fi.LinkTarget == null)
                {
                    File.Delete(_config.PamSocketPath);
                }
            }
        }
        catch { }
    }

    public void Dispose() => Stop();

    private async Task AcceptLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested && _serverSocket != null)
        {
            Socket? client = null;
            try
            {
                client = await _serverSocket.AcceptAsync(ct);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                if (ct.IsCancellationRequested) break;
                _logger.Warning($"Linux PAM socket accept error: {ex.Message}");
                try { await Task.Delay(200, ct); } catch { break; }
                continue;
            }

            _ = Task.Run(async () =>
            {
                using (client)
                {
                    await HandlePamClientAsync(client, ct);
                }
            }, ct);
        }
    }

    private async Task HandlePamClientAsync(Socket client, CancellationToken ct)
    {
        try
        {
            uint peerPid = 0;
            uint peerUid = uint.MaxValue;
            uint peerGid = uint.MaxValue;

            if (OperatingSystem.IsLinux())
            {
                if (!GetPeerCredentials(client, out peerPid, out peerUid, out peerGid))
                {
                    _logger.Warning("LinuxPamAuthServer: Rejected IPC connection (failed to read peer credentials via SO_PEERCRED).");
                    return;
                }
            }

            client.ReceiveTimeout = 5000;
            client.SendTimeout = 5000;

            using var ns = new NetworkStream(client, ownsSocket: false);
            byte[] lenBytes = new byte[4];
            int read = await ns.ReadAsync(lenBytes.AsMemory(0, 4), ct);
            if (read < 4) return;

            int len = System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian(lenBytes);
            if (len <= 0 || len > 4096)
            {
                _logger.Warning($"LinuxPamAuthServer: Invalid request size: {len} bytes.");
                return;
            }

            byte[] body = new byte[len];
            int totalRead = 0;
            while (totalRead < len)
            {
                int r = await ns.ReadAsync(body.AsMemory(totalRead, len - totalRead), ct);
                if (r <= 0) break;
                totalRead += r;
            }

            if (totalRead < len) return;

            string json = Encoding.UTF8.GetString(body);
            using var doc = JsonDocument.Parse(json);
            string action = doc.RootElement.TryGetProperty("action", out var aProp) ? (aProp.GetString() ?? "")
                : (doc.RootElement.TryGetProperty("type", out var tProp) ? (tProp.GetString() ?? "") : "");
            string targetUser = doc.RootElement.TryGetProperty("user", out var uProp) ? (uProp.GetString() ?? "")
                : (doc.RootElement.TryGetProperty("username", out var unProp) ? (unProp.GetString() ?? "") : "");
            string service = doc.RootElement.TryGetProperty("service", out var sProp) ? (sProp.GetString() ?? "") : "";

            if (action == "AUTH_REQUEST")
            {
                // TETH-SEC-LNX-001: Strict PAM service authorization check
                if (string.IsNullOrEmpty(service) || !PermittedPamServices.Contains(service))
                {
                    _logger.Warning($"LinuxPamAuthServer: Rejected unlock request for unauthorized PAM service '{service}' (user='{targetUser}').");
                    var serviceDeniedResp = new
                    {
                        status = "SERVICE_DENIED",
                        user = targetUser,
                        service = service,
                        reason = $"Service '{service}' is not authorized for workstation mobile unlock.",
                        timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
                    };
                    await SendJsonResponseAsync(ns, serviceDeniedResp, ct);
                    return;
                }

                // Peer UID authorization: UID 0 (root display managers) or matching target user UID
                if (OperatingSystem.IsLinux() && !BypassUidCheckForTesting && peerUid != 0)
                {
                    uint? targetUid = GetUidForUser(targetUser);
                    if (targetUid == null || targetUid.Value != peerUid)
                    {
                        _logger.Warning($"LinuxPamAuthServer: Rejected AUTH_REQUEST: Caller UID {peerUid} unauthorized for target user '{targetUser}' (target UID {targetUid}).");
                        var deniedResp = new
                        {
                            status = "DENIED",
                            user = targetUser,
                            service = service,
                            reason = "Caller UID does not match target user UID.",
                            timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
                        };
                        await SendJsonResponseAsync(ns, deniedResp, ct);
                        return;
                    }
                }

                string authStatus = "DENIED";
                if (!string.IsNullOrEmpty(targetUser))
                {
                    if (_grantsByUser.TryGetValue(targetUser, out var grant))
                    {
                        lock (grant)
                        {
                            if (grant.IsConsumed)
                            {
                                authStatus = "CONSUMED";
                            }
                            else if (DateTime.UtcNow > grant.ExpiresAtUtc)
                            {
                                authStatus = "EXPIRED";
                                _grantsByUser.TryRemove(targetUser, out _);
                            }
                            else
                            {
                                grant.IsConsumed = true;
                                _grantsByUser.TryRemove(targetUser, out _);
                                authStatus = "SUCCESS";
                                _logger.Info($"LinuxPamAuthServer: Successfully consumed one-time unlock grant for user '{targetUser}' via service '{service}'.");
                            }
                        }
                    }
                    else
                    {
                        authStatus = "NO_GRANT";
                        _logger.Info($"LinuxPamAuthServer: No active grant for user '{targetUser}'. Forwarding to native fallback.");
                    }
                }

                var resp = new
                {
                    status = authStatus,
                    user = targetUser,
                    service = service,
                    timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
                };
                await SendJsonResponseAsync(ns, resp, ct);
            }
            else if (action is "STATUS_REQUEST" or "STATUS_QUERY")
            {
                if (string.IsNullOrEmpty(targetUser) && OperatingSystem.IsLinux() && peerUid != 0 && peerUid != uint.MaxValue)
                {
                    targetUser = GetUserForUid(peerUid) ?? "";
                }

                bool phoneConnected = PhoneConnectedProvider?.Invoke() ?? false;
                string deviceName = ConnectedDeviceNameProvider?.Invoke() ?? "";
                string deviceFp = ConnectedDeviceFingerprintProvider?.Invoke() ?? "";
                bool hasGrant = !string.IsNullOrEmpty(targetUser) && HasActiveGrant(targetUser);
                int remainingSeconds = 0;
                if (hasGrant && _grantsByUser.TryGetValue(targetUser, out var g))
                {
                    remainingSeconds = (int)Math.Max(0, (g.ExpiresAtUtc - DateTime.UtcNow).TotalSeconds);
                }
                bool promptPending = !string.IsNullOrEmpty(targetUser) && HasPendingPrompt(targetUser);
                var session = PlatformDetection.GetActiveSessionInfo();

                var statusResp = new
                {
                    status = "ONLINE",
                    version = "2.0-production",
                    daemonRunning = true,
                    phoneConnected = phoneConnected,
                    connectedDeviceName = deviceName,
                    connectedDeviceFingerprint = deviceFp,
                    grantActive = hasGrant,
                    grantRemainingSeconds = remainingSeconds,
                    authPromptPending = promptPending,
                    activeUser = session.UserName,
                    displayServer = session.DisplayServer.ToString(),
                    timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
                };
                await SendJsonResponseAsync(ns, statusResp, ct);
            }
            else if (action == "REQUEST_PHONE_AUTH")
            {
                if (string.IsNullOrEmpty(targetUser) && OperatingSystem.IsLinux() && peerUid != 0 && peerUid != uint.MaxValue)
                {
                    targetUser = GetUserForUid(peerUid) ?? "";
                }

                if (string.IsNullOrEmpty(targetUser))
                {
                    var badReq = new
                    {
                        status = "DENIED",
                        reason = "Missing target user for phone auth prompt",
                        timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
                    };
                    await SendJsonResponseAsync(ns, badReq, ct);
                    return;
                }

                if (OperatingSystem.IsLinux() && !BypassUidCheckForTesting && peerUid != 0)
                {
                    uint? targetUid = GetUidForUser(targetUser);
                    if (targetUid == null || targetUid.Value != peerUid)
                    {
                        _logger.Warning($"LinuxPamAuthServer: Rejected REQUEST_PHONE_AUTH: Caller UID {peerUid} unauthorized for target user '{targetUser}'.");
                        var deniedResp = new
                        {
                            status = "DENIED",
                            user = targetUser,
                            reason = "Unauthorized: Caller UID does not match target user UID.",
                            timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
                        };
                        await SendJsonResponseAsync(ns, deniedResp, ct);
                        return;
                    }
                }

                bool phoneConnected = PhoneConnectedProvider?.Invoke() ?? false;
                if (!phoneConnected)
                {
                    var disconnectedResp = new
                    {
                        status = "PHONE_DISCONNECTED",
                        user = targetUser,
                        message = "No paired phone is currently connected to authenticate unlock request.",
                        timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
                    };
                    await SendJsonResponseAsync(ns, disconnectedResp, ct);
                    return;
                }

                SetPendingPrompt(targetUser, 30);
                try
                {
                    RequestPhoneAuthHandler?.Invoke(targetUser);
                }
                catch (Exception ex)
                {
                    _logger.Warning($"LinuxPamAuthServer: Failed dispatching phone auth prompt: {ex.Message}");
                }

                var promptResp = new
                {
                    status = "PROMPTED",
                    user = targetUser,
                    message = "Unlock authorization request dispatched to connected phone.",
                    timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
                };
                await SendJsonResponseAsync(ns, promptResp, ct);
            }
            else if (action == "ARM_GRANT")
            {
                // TETH-SEC-LNX-002: Local IPC callers must NEVER manufacture unlock grants.
                // Grants are armed strictly via cryptographic mobile authentication over TLS.
                if (!AllowIpcArmGrantForTesting)
                {
                    _logger.Warning($"LinuxPamAuthServer: Blocked unauthorized ARM_GRANT attempt over IPC from UID {peerUid}.");
                    var resp = new
                    {
                        status = "DENIED",
                        reason = "ARM_GRANT cannot be invoked via local IPC. Workstation unlock grants are created exclusively through authenticated phone confirmation.",
                        timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
                    };
                    await SendJsonResponseAsync(ns, resp, ct);
                    return;
                }

                string deviceId = doc.RootElement.TryGetProperty("deviceId", out var dProp) ? (dProp.GetString() ?? "test-local") : "test-local";
                int validity = doc.RootElement.TryGetProperty("validitySeconds", out var vProp) ? vProp.GetInt32() : 20;

                if (!string.IsNullOrEmpty(targetUser))
                {
                    ArmUnlockGrant(targetUser, deviceId, validity);
                }

                var testResp = new
                {
                    status = "ARMED",
                    user = targetUser,
                    success = !string.IsNullOrEmpty(targetUser),
                    timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
                };
                await SendJsonResponseAsync(ns, testResp, ct);
            }
            else if (action == "CANCEL_GRANT")
            {
                if (OperatingSystem.IsLinux() && !BypassUidCheckForTesting && peerUid != 0)
                {
                    if (string.IsNullOrEmpty(targetUser))
                    {
                        targetUser = GetUserForUid(peerUid) ?? "";
                    }
                    else
                    {
                        uint? targetUid = GetUidForUser(targetUser);
                        if (targetUid == null || targetUid.Value != peerUid)
                        {
                            _logger.Warning($"LinuxPamAuthServer: Rejected CANCEL_GRANT from peer UID {peerUid} for target user '{targetUser}'.");
                            var deniedResp = new
                            {
                                status = "DENIED",
                                reason = "Unauthorized: Caller UID does not match target user UID.",
                                timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
                            };
                            await SendJsonResponseAsync(ns, deniedResp, ct);
                            return;
                        }
                    }
                }

                if (!string.IsNullOrEmpty(targetUser))
                {
                    _grantsByUser.TryRemove(targetUser, out _);
                    _pendingPromptsByUser.TryRemove(targetUser, out _);
                }
                else if (peerUid == 0 || BypassUidCheckForTesting)
                {
                    ClearAllGrants();
                }

                var resp = new
                {
                    status = "CANCELLED",
                    user = targetUser,
                    timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
                };
                await SendJsonResponseAsync(ns, resp, ct);
            }
            else if (action == "RESTART_REQUEST")
            {
                uint? tetherGid = GetGidForGroup("tether");
                var session = PlatformDetection.GetActiveSessionInfo();
                bool isAuthorized = BypassUidCheckForTesting ||
                                    (peerUid == 0) ||
                                    (tetherGid.HasValue && peerGid == tetherGid.Value) ||
                                    (session.Uid == peerUid && peerUid != uint.MaxValue);

                if (!isAuthorized)
                {
                    _logger.Warning($"LinuxPamAuthServer: Rejected unauthorized RESTART_REQUEST from peer UID {peerUid}, GID {peerGid}.");
                    var unauthResp = new
                    {
                        status = "UNAUTHORIZED",
                        message = "Caller not authorized to restart service.",
                        timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
                    };
                    await SendJsonResponseAsync(ns, unauthResp, ct);
                    return;
                }

                _logger.Info($"LinuxPamAuthServer: Received authorized service restart request from peer UID {peerUid}.");
                var restartResp = new
                {
                    status = "RESTARTING",
                    message = "Tether background daemon restarting...",
                    timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
                };
                await SendJsonResponseAsync(ns, restartResp, ct);

                _ = Task.Run(async () =>
                {
                    await Task.Delay(500);
                    try
                    {
                        var psi = new ProcessStartInfo
                        {
                            FileName = "systemctl",
                            UseShellExecute = false,
                            CreateNoWindow = true
                        };
                        psi.ArgumentList.Add("restart");
                        psi.ArgumentList.Add("tether.service");
                        using var p = Process.Start(psi);
                        p?.WaitForExit(5000);
                    }
                    catch (Exception ex)
                    {
                        _logger.Error($"LinuxPamAuthServer restart failed: {ex.Message}");
                    }
                });
            }
            else
            {
                var unknownResp = new
                {
                    status = "UNKNOWN_ACTION",
                    action = action,
                    timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
                };
                await SendJsonResponseAsync(ns, unknownResp, ct);
            }
        }
        catch (Exception ex)
        {
            _logger.Warning($"LinuxPamAuthServer: Client handler error: {ex.Message}");
        }
    }

    private static async Task SendJsonResponseAsync(NetworkStream ns, object responseObj, CancellationToken ct)
    {
        byte[] respBytes = JsonSerializer.SerializeToUtf8Bytes(responseObj);
        byte[] respLen = new byte[4];
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(respLen, respBytes.Length);

        await ns.WriteAsync(respLen.AsMemory(0, 4), ct);
        await ns.WriteAsync(respBytes, ct);
        await ns.FlushAsync(ct);
    }

    private static bool GetPeerCredentials(Socket socket, out uint pid, out uint uid, out uint gid)
    {
        pid = 0;
        uid = uint.MaxValue;
        gid = uint.MaxValue;

        if (!OperatingSystem.IsLinux()) return false;

        try
        {
            byte[] credBytes = new byte[12];
            int optlen = 12;
            int res = getsockopt(socket.Handle, 1 /* SOL_SOCKET */, 17 /* SO_PEERCRED */, credBytes, ref optlen);
            if (res == 0 && optlen == 12)
            {
                pid = BitConverter.ToUInt32(credBytes, 0);
                uid = BitConverter.ToUInt32(credBytes, 4);
                gid = BitConverter.ToUInt32(credBytes, 8);
                return true;
            }
        }
        catch { }

        return false;
    }

    public static uint? GetUidForUser(string userName)
    {
        if (string.IsNullOrEmpty(userName) || !OperatingSystem.IsLinux()) return null;
        try
        {
            IntPtr ptr = getpwnam(userName);
            if (ptr == IntPtr.Zero) return null;
            return (uint)Marshal.ReadInt32(ptr, 16);
        }
        catch
        {
            return null;
        }
    }

    public static string? GetUserForUid(uint uid)
    {
        if (!OperatingSystem.IsLinux()) return null;
        try
        {
            IntPtr ptr = getpwuid(uid);
            if (ptr == IntPtr.Zero) return null;
            IntPtr namePtr = Marshal.ReadIntPtr(ptr, 0);
            return Marshal.PtrToStringUTF8(namePtr);
        }
        catch
        {
            return null;
        }
    }

    public static uint? GetGidForGroup(string groupName)
    {
        if (string.IsNullOrEmpty(groupName) || !OperatingSystem.IsLinux()) return null;
        try
        {
            IntPtr ptr = getgrnam(groupName);
            if (ptr == IntPtr.Zero) return null;
            return (uint)Marshal.ReadInt32(ptr, 16);
        }
        catch
        {
            return null;
        }
    }

    [DllImport("libc", SetLastError = true)]
    private static extern int getsockopt(IntPtr sockfd, int level, int optname, byte[] optval, ref int optlen);

    [DllImport("libc", EntryPoint = "getpwnam")]
    private static extern IntPtr getpwnam(string name);

    [DllImport("libc", EntryPoint = "getpwuid")]
    private static extern IntPtr getpwuid(uint uid);

    [DllImport("libc", EntryPoint = "getgrnam")]
    private static extern IntPtr getgrnam(string name);
}
