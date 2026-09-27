using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Tether.CommunicationService.Security;
using Tether.Shared.Logging;

namespace Tether.CommunicationService.Discovery;

/// <summary>
/// Fast UDP Broadcast Discovery Listener & Responder (KDE Connect Style).
/// Listens on UDP port 37124 for discovery probes from Tether Android devices
/// and broadcasts discovery pongs every 4 seconds over local subnet.
/// </summary>
public sealed class UdpDiscovery : IDisposable
{
    public const int UdpPort = 37124;
    public const int TcpPort = 37123;

    private readonly ITetherLogger _logger;
    private readonly WindowsIdentity _identity;
    private UdpClient? _udpClient;
    private CancellationTokenSource? _cts;
    private Task? _workerTask;

    public UdpDiscovery(ITetherLogger logger, WindowsIdentity identity)
    {
        _logger = logger;
        _identity = identity;
    }

    public void Start()
    {
        Stop();
        _cts = new CancellationTokenSource();
        _workerTask = Task.Run(() => RunDiscoveryLoopAsync(_cts.Token));
        _logger.Info($"UDP Discovery (KDE Connect style) active on port {UdpPort}.");
    }

    public void Stop()
    {
        try { _cts?.Cancel(); } catch { }
        try { _udpClient?.Close(); } catch { }
        try { _workerTask?.Wait(TimeSpan.FromSeconds(2)); } catch { }
        try { _cts?.Dispose(); } catch { }
        _cts = null;
        _udpClient = null;
    }

    public void Dispose() => Stop();

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

        var broadcastEndpoint = new IPEndPoint(IPAddress.Broadcast, UdpPort);

        // Start background periodic broadcast loop
        _ = Task.Run(async () =>
        {
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await _udpClient.SendAsync(responsePayload, responsePayload.Length, broadcastEndpoint);
                }
                catch { }
                try { await Task.Delay(4000, ct); } catch { break; }
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
                    _logger.Debug($"UDP Discovery: Received probe from {result.RemoteEndPoint.Address}. Responding...");
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
