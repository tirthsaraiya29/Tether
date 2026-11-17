using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
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
/// </summary>
public sealed class UdpDiscovery : IDisposable
{
    public const int UdpPort = NetworkConstants.DiscoveryPort;
    public const int TcpPort = NetworkConstants.ControlPort;

    private readonly ITetherLogger _logger;
    private readonly WindowsIdentity _identity;
    private UdpClient? _udpClient;
    private CancellationTokenSource? _cts;
    private Task? _workerTask;
    private readonly NetworkAddressChangedEventHandler _addressChangedHandler;
    private readonly NetworkAvailabilityChangedEventHandler _availabilityChangedHandler;
    private Action? _triggerBurst;

    public string? LastDiscoveryIp { get; private set; }

    public UdpDiscovery(ITetherLogger logger, WindowsIdentity identity)
    {
        _logger = logger;
        _identity = identity;
        _addressChangedHandler = (_, _) => _triggerBurst?.Invoke();
        _availabilityChangedHandler = (_, _) => _triggerBurst?.Invoke();
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
                if (ni.OperationalStatus != OperationalStatus.Up ||
                    ni.NetworkInterfaceType == NetworkInterfaceType.Loopback ||
                    ni.NetworkInterfaceType == NetworkInterfaceType.Tunnel)
                {
                    continue;
                }

                var ipProps = ni.GetIPProperties();

                // 1. Unicast addresses and directed subnet broadcasts
                foreach (var unicast in ipProps.UnicastAddresses)
                {
                    if (unicast.Address.AddressFamily != AddressFamily.InterNetwork ||
                        IPAddress.IsLoopback(unicast.Address))
                    {
                        continue;
                    }

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
                    if (gw.Address.AddressFamily == AddressFamily.InterNetwork &&
                        !gw.Address.Equals(IPAddress.Any) &&
                        !gw.Address.Equals(IPAddress.None) &&
                        !IPAddress.IsLoopback(gw.Address))
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
                string jsonStr = Encoding.UTF8.GetString(result.Buffer);

                using var doc = JsonDocument.Parse(jsonStr);
                string type = doc.RootElement.GetProperty("type").GetString() ?? "";

                if (type == "TETHER_DISCOVERY_PROBE")
                {
                    LastDiscoveryIp = result.RemoteEndPoint.Address.ToString();
                    _logger.Debug($"UDP Discovery: Received probe from {LastDiscoveryIp}. Responding...");
                    await _udpClient.SendAsync(responsePayload, responsePayload.Length, result.RemoteEndPoint);
                }
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                if (ct.IsCancellationRequested) break;
                _logger.Debug($"UDP Discovery receive error: {ex.Message}");
                try { await Task.Delay(1000, ct); } catch { break; }
            }
        }
    }
}
