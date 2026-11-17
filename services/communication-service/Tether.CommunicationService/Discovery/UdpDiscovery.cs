using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Tether.CommunicationService.Security;
using Tether.Shared.Logging;
using Tether.Shared.Network;

namespace Tether.CommunicationService.Discovery;

/// <summary>
/// Fast UDP Broadcast Discovery Listener & Responder (KDE Connect Style).
/// Listens on UDP port for discovery probes from Tether Android devices
/// and broadcasts discovery pongs over local subnets, directed broadcasts,
/// and default gateways (supporting Android mobile hotspot networks).
/// Enforces local-subnet isolation, rate limiting, and strict packet validation.
/// </summary>
public sealed class UdpDiscovery : IDisposable
{
    public const int UdpPort = NetworkConstants.DiscoveryPort;
    public const int TcpPort = NetworkConstants.ControlPort;
    public const int MaxPayloadBytes = 1024;
    public const int MinPayloadBytes = 10;
    public const int MaxProbesPerSecondPerIp = 5;
    public const int MaxProbesPerSecondGlobal = 30;

    private static readonly Regex DeviceIdRegex = new(@"^[a-zA-Z0-9_\-\.:]{1,128}$", RegexOptions.Compiled);

    private readonly ITetherLogger _logger;
    private readonly WindowsIdentity _identity;
    private UdpClient? _udpClient;
    private CancellationTokenSource? _cts;
    private Task? _workerTask;
    private readonly NetworkAddressChangedEventHandler _addressChangedHandler;
    private readonly NetworkAvailabilityChangedEventHandler _availabilityChangedHandler;
    private Action? _triggerBurst;

    private readonly ConcurrentDictionary<IPAddress, (int count, long windowStartTicks)> _rateLimits = new();
    private int _globalProbeCount = 0;
    private long _globalWindowStartTicks = 0;

    public string? LastDiscoveryIp { get; private set; }

    public UdpDiscovery(ITetherLogger logger, WindowsIdentity identity)
    {
        _logger = logger;
        _identity = identity;
        _addressChangedHandler = (_, _) => _triggerBurst?.Invoke();
        _availabilityChangedHandler = (_, _) => _triggerBurst?.Invoke();
    }

    public static bool IsValidDeviceId(string? id)
    {
        return !string.IsNullOrWhiteSpace(id) && id.Length <= 128 && DeviceIdRegex.IsMatch(id);
    }

    public static bool IsPrivateIpv4(IPAddress addr)
    {
        if (addr.AddressFamily != AddressFamily.InterNetwork) return false;
        byte[] b = addr.GetAddressBytes();

        // 10.0.0.0/8
        if (b[0] == 10) return true;
        // 172.16.0.0/12
        if (b[0] == 172 && (b[1] >= 16 && b[1] <= 31)) return true;
        // 192.168.0.0/16
        if (b[0] == 192 && b[1] == 168) return true;
        // Link-local 169.254.0.0/16
        if (b[0] == 169 && b[1] == 254) return true;

        // Reject 100.64.0.0/10 (CGNAT), 127.0.0.0/8 (loopback), 224+/multicast, 0.0.0.0, 255.255.255.255
        return false;
    }

    public static bool IsAllowedInterface(NetworkInterface ni)
    {
        if (ni.OperationalStatus != OperationalStatus.Up) return false;
        if (ni.NetworkInterfaceType is NetworkInterfaceType.Loopback or
            NetworkInterfaceType.Tunnel or
            NetworkInterfaceType.Ppp or
            NetworkInterfaceType.Slip)
        {
            return false;
        }

        // Exclude WWAN / Cellular interface type IDs if present
        int typeVal = (int)ni.NetworkInterfaceType;
        if (typeVal is 243 or 244) return false;

        string desc = (ni.Description + " " + ni.Name).ToLowerInvariant();
        if (desc.Contains("virtual") || desc.Contains("hyper-v") || desc.Contains("vmware") ||
            desc.Contains("wsl") || desc.Contains("tap-") || desc.Contains("wireguard") ||
            desc.Contains("tailscale") || desc.Contains("zerotier") || desc.Contains("cisco") ||
            desc.Contains("cellular") || desc.Contains("mobile broadband") || desc.Contains("wwan"))
        {
            return false;
        }

        return true;
    }

    public void Start()
    {
        Stop();
        _cts = new CancellationTokenSource();
        try
        {
            NetworkChange.NetworkAddressChanged += _addressChangedHandler;
            NetworkChange.NetworkAvailabilityChanged += _availabilityChangedHandler;
        }
        catch { }
        _workerTask = Task.Run(() => RunDiscoveryLoopAsync(_cts.Token));
        _logger.Info($"UDP Discovery (KDE Connect style) active on port {UdpPort}.");
    }

    public void Stop()
    {
        try
        {
            NetworkChange.NetworkAddressChanged -= _addressChangedHandler;
            NetworkChange.NetworkAvailabilityChanged -= _availabilityChangedHandler;
        }
        catch { }
        _triggerBurst = null;
        try { _cts?.Cancel(); } catch { }
        try { _udpClient?.Close(); } catch { }
        try { _workerTask?.Wait(TimeSpan.FromSeconds(2)); } catch { }
        try { _cts?.Dispose(); } catch { }
        _cts = null;
        _udpClient = null;
        _rateLimits.Clear();
    }

    public void Dispose() => Stop();

    public static List<IPEndPoint> GetDiscoveryTargetEndPoints(int port)
    {
        var targets = new List<IPEndPoint>
        {
            new IPEndPoint(IPAddress.Broadcast, port)
        };

        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (!IsAllowedInterface(ni)) continue;

                var ipProps = ni.GetIPProperties();

                // 1. Unicast addresses and directed subnet broadcasts
                foreach (var unicast in ipProps.UnicastAddresses)
                {
                    if (!IsPrivateIpv4(unicast.Address)) continue;

                    if (unicast.IPv4Mask != null)
                    {
                        var ipBytes = unicast.Address.GetAddressBytes();
                        var maskBytes = unicast.IPv4Mask.GetAddressBytes();
                        var bcastBytes = new byte[4];
                        for (int i = 0; i < 4; i++)
                        {
                            bcastBytes[i] = (byte)(ipBytes[i] | ~maskBytes[i]);
                        }
                        var subnetBcast = new IPAddress(bcastBytes);
                        if (!targets.Any(t => t.Address.Equals(subnetBcast)))
                        {
                            targets.Add(new IPEndPoint(subnetBcast, port));
                        }
                    }
                }

                // 2. Default Gateways (on an Android mobile hotspot, the gateway is the phone itself)
                foreach (var gw in ipProps.GatewayAddresses)
                {
                    if (IsPrivateIpv4(gw.Address))
                    {
                        if (!targets.Any(t => t.Address.Equals(gw.Address)))
                        {
                            targets.Add(new IPEndPoint(gw.Address, port));
                        }
                    }
                }
            }
        }
        catch
        {
            // Fall back to general broadcast if interface enumeration fails
        }

        return targets;
    }

    internal bool CheckRateLimit(IPAddress remoteIp)
    {
        long now = DateTime.UtcNow.Ticks;
        long oneSecondTicks = TimeSpan.FromSeconds(1).Ticks;

        // Global rate limit
        long globalWindow = Volatile.Read(ref _globalWindowStartTicks);
        if (now - globalWindow > oneSecondTicks)
        {
            Interlocked.Exchange(ref _globalWindowStartTicks, now);
            Interlocked.Exchange(ref _globalProbeCount, 1);
        }
        else
        {
            if (Interlocked.Increment(ref _globalProbeCount) > MaxProbesPerSecondGlobal)
            {
                return false;
            }
        }

        // Per-IP rate limit
        var record = _rateLimits.AddOrUpdate(
            remoteIp,
            _ => (1, now),
            (_, existing) =>
            {
                if (now - existing.windowStartTicks > oneSecondTicks)
                {
                    return (1, now);
                }
                return (existing.count + 1, existing.windowStartTicks);
            });

        return record.count <= MaxProbesPerSecondPerIp;
    }

    internal bool ValidateInboundProbe(byte[] buffer, IPEndPoint remoteEndPoint, out string? probeDeviceId)
    {
        probeDeviceId = null;
        if (buffer.Length < MinPayloadBytes || buffer.Length > MaxPayloadBytes)
        {
            return false;
        }

        var remoteIp = remoteEndPoint.Address;
        if (!IsPrivateIpv4(remoteIp))
        {
            return false;
        }

        if (!CheckRateLimit(remoteIp))
        {
            return false;
        }

        try
        {
            string jsonStr = Encoding.UTF8.GetString(buffer);
            using var doc = JsonDocument.Parse(jsonStr);
            if (!doc.RootElement.TryGetProperty("type", out var typeProp))
            {
                return false;
            }

            string type = typeProp.GetString() ?? "";
            if (type != "TETHER_DISCOVERY_PROBE")
            {
                return false;
            }

            if (doc.RootElement.TryGetProperty("deviceId", out var devIdProp))
            {
                string devId = devIdProp.GetString() ?? "";
                if (!string.IsNullOrEmpty(devId))
                {
                    if (!IsValidDeviceId(devId)) return false;
                    probeDeviceId = devId;
                }
            }

            if (doc.RootElement.TryGetProperty("tcpPort", out var portProp))
            {
                if (portProp.TryGetInt32(out int port))
                {
                    if (port < 1024 || port > 65535) return false;
                }
            }

            return true;
        }
        catch (JsonException)
        {
            return false;
        }
        catch
        {
            return false;
        }
    }

    private async Task RunDiscoveryLoopAsync(CancellationToken ct)
    {
        try
        {
            _udpClient = new UdpClient();
            _udpClient.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            _udpClient.Client.Bind(new IPEndPoint(IPAddress.Any, UdpPort));
            _udpClient.EnableBroadcast = true;
        }
        catch (Exception ex)
        {
            _logger.Warning($"Could not bind UDP discovery socket on port {UdpPort}: {ex.Message}");
            return;
        }

        var responsePayload = JsonSerializer.SerializeToUtf8Bytes(new
        {
            type = "TETHER_DISCOVERY_RESPONSE",
            deviceId = _identity.DeviceId,
            deviceName = _identity.DeviceName,
            tcpPort = TcpPort
        });

        async Task SendDiscoveryToTargetsAsync()
        {
            if (_udpClient == null) return;
            var targets = GetDiscoveryTargetEndPoints(UdpPort);
            foreach (var target in targets)
            {
                try
                {
                    await _udpClient.SendAsync(responsePayload, responsePayload.Length, target);
                }
                catch { }
            }
        }

        _triggerBurst = () =>
        {
            _ = Task.Run(async () =>
            {
                for (int i = 0; i < 3 && !ct.IsCancellationRequested; i++)
                {
                    await SendDiscoveryToTargetsAsync();
                    try { await Task.Delay(500, ct); } catch { break; }
                }
            }, ct);
        };

        // Start background periodic broadcast loop across subnet broadcasts and default gateways
        _ = Task.Run(async () =>
        {
            while (!ct.IsCancellationRequested)
            {
                await SendDiscoveryToTargetsAsync();
                try { await Task.Delay(2500, ct); } catch { break; }
            }
        }, ct);

        // Inbound UDP packet listener loop
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var result = await _udpClient.ReceiveAsync(ct);

                if (!ValidateInboundProbe(result.Buffer, result.RemoteEndPoint, out _))
                {
                    continue;
                }

                LastDiscoveryIp = result.RemoteEndPoint.Address.ToString();
                _logger.Debug($"UDP Discovery: Received valid probe from {LastDiscoveryIp}. Responding...");
                await _udpClient.SendAsync(responsePayload, responsePayload.Length, result.RemoteEndPoint);
            }
            catch (OperationCanceledException) { break; }
            catch (JsonException)
            {
                // Discard malformed JSON probe frames safely
            }
            catch (Exception ex)
            {
                if (ct.IsCancellationRequested) break;
                _logger.Debug($"UDP Discovery receive error: {ex.Message}");
                try { await Task.Delay(1000, ct); } catch { break; }
            }
        }
    }
}
