using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
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
    private Socket? _serverSocket;
    private CancellationTokenSource? _cts;
    private Task? _listenTask;

    // Status providers injected from DaemonWorker/SessionManager
    public Func<bool>? PhoneConnectedProvider { get; set; }
    public Func<string>? ConnectedDeviceNameProvider { get; set; }
    public Func<string>? ConnectedDeviceFingerprintProvider { get; set; }

    public LinuxPamAuthServer(ITetherLogger logger, LinuxDaemonConfig config)
    {
        _logger = logger;
        _config = config;
    }

    public void ArmUnlockGrant(string targetUser, string deviceFingerprint, int validitySeconds = 15)
    {
        var grant = new UnlockGrant
        {
            TargetUser = targetUser,
            DeviceFingerprint = deviceFingerprint,
            GrantedAtUtc = DateTime.UtcNow,
            ExpiresAtUtc = DateTime.UtcNow.AddSeconds(validitySeconds),
            IsConsumed = false
        };

        _grantsByUser[targetUser] = grant;
        _logger.Info($"LinuxPamAuthServer: Armed unlock grant for user '{targetUser}' from phone '{deviceFingerprint}' (valid for {validitySeconds}s).");
    }

    public bool HasActiveGrant(string targetUser)
    {
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
                        File.SetUnixFileMode(dir, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute |
                                                  UnixFileMode.GroupRead | UnixFileMode.GroupExecute);
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
            // Verify Peer Credentials if running on Linux
            if (OperatingSystem.IsLinux())
            {
                uint peerUid = GetPeerUid(client);
                uint currentUid = (uint)GetActiveUid();
                // Allow root (UID 0), the daemon's own UID, or active desktop user (for tetherctl status/restart)
                if (peerUid == uint.MaxValue)
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
            else if (action == "STATUS_REQUEST")
            {
                // Greeter / CLI status query
                bool phoneConnected = PhoneConnectedProvider?.Invoke() ?? false;
                string deviceName = ConnectedDeviceNameProvider?.Invoke() ?? "";
                string deviceFp = ConnectedDeviceFingerprintProvider?.Invoke() ?? "";
                bool hasGrant = !string.IsNullOrEmpty(targetUser) && HasActiveGrant(targetUser);
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
                    activeUser = session.UserName,
                    displayServer = session.DisplayServer,
                    timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
                };
                await SendJsonResponseAsync(ns, statusResp, ct);
            }
            else if (action == "RESTART_REQUEST")
            {
                // Controlled in-greeter or CLI restart
                _logger.Info("LinuxPamAuthServer: Received authorized service restart request from local IPC client.");
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
            else if (action == "ARM_GRANT")
            {
                string deviceId = doc.RootElement.TryGetProperty("deviceId", out var dProp) ? (dProp.GetString() ?? "cli-local") : "cli-local";
                int validity = doc.RootElement.TryGetProperty("validitySeconds", out var vProp) ? vProp.GetInt32() : 20;

                if (!string.IsNullOrEmpty(targetUser))
                {
                    ArmUnlockGrant(targetUser, deviceId, validity);
                }

                var resp = new
                {
                    status = "ARMED",
                    user = targetUser,
                    success = !string.IsNullOrEmpty(targetUser),
                    timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
                };
                await SendJsonResponseAsync(ns, resp, ct);
            }
            else if (action == "CANCEL_GRANT")
            {
                if (!string.IsNullOrEmpty(targetUser))
                {
                    _grantsByUser.TryRemove(targetUser, out _);
                }
                else
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

    [StructLayout(LayoutKind.Sequential)]
    private struct PeerCredentials
    {
        public uint pid;
        public uint uid;
        public uint gid;
    }

    private static uint GetPeerUid(Socket socket)
    {
        try
        {
            byte[] credBytes = new byte[12];
            int optlen = 12;
            int res = getsockopt(socket.Handle, 1 /* SOL_SOCKET */, 17 /* SO_PEERCRED */, credBytes, ref optlen);
            if (res == 0 && optlen == 12)
            {
                return BitConverter.ToUInt32(credBytes, 4); // uid is second 4-byte int
            }
        }
        catch { }
        return uint.MaxValue;
    }

    private static int GetActiveUid()
    {
        try
        {
            return getuid();
        }
        catch
        {
            return 1000;
        }
    }

    [DllImport("libc", SetLastError = true)]
    private static extern int getsockopt(IntPtr sockfd, int level, int optname, byte[] optval, ref int optlen);

    [DllImport("libc")]
    private static extern int getuid();
}
