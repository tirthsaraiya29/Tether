using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Tether.CommunicationService.Capabilities;
using Tether.CommunicationService.Devices;
using Tether.CommunicationService.Pairing;
using Tether.CommunicationService.Protocol;
using Tether.CommunicationService.Security;
using Tether.CommunicationService.Sessions;
using Tether.EventBus;
using Tether.Shared.Logging;

namespace Tether.CommunicationService.Transport;

public sealed class TetherTcpServer : IDisposable
{
    public const int ListenPort = 37123;

    private readonly IEventBus _eventBus;
    private readonly ITetherLogger _logger;
    private readonly WindowsIdentity _identity;
    private readonly DeviceManager _deviceManager;
    private readonly SessionManager _sessionManager;
    private readonly PairingManager _pairingManager;
    private readonly PacketRouter _packetRouter;

    private TcpListener? _listener;
    private CancellationTokenSource? _cts;
    private Task? _acceptLoop;

    public TetherTcpServer(
        IEventBus eventBus,
        ITetherLogger logger,
        WindowsIdentity identity,
        DeviceManager deviceManager,
        SessionManager sessionManager,
        PairingManager pairingManager,
        PacketRouter packetRouter)
    {
        _eventBus = eventBus;
        _logger = logger;
        _identity = identity;
        _deviceManager = deviceManager;
        _sessionManager = sessionManager;
        _pairingManager = pairingManager;
        _packetRouter = packetRouter;
    }

    public void Start()
    {
        _cts = new CancellationTokenSource();
        _acceptLoop = Task.Run(() => AcceptLoopAsync(_cts.Token));
        _logger.Info($"TCP listener starting on DualMode [::]:{ListenPort} (TLS 1.3).");
    }

    public void Stop()
    {
        try { _cts?.Cancel(); } catch { }
        try { _listener?.Stop(); } catch { }
        try { _acceptLoop?.Wait(TimeSpan.FromSeconds(3)); } catch { }
        try { _cts?.Dispose(); } catch { }
        _cts = null;
        _logger.Info("TCP listener stopped.");
    }

    public void Dispose() => Stop();

    private async Task AcceptLoopAsync(CancellationToken ct)
    {
        try
        {
            _listener = new TcpListener(IPAddress.IPv6Any, ListenPort);
            _listener.Server.DualMode = true;
            _listener.Start(backlog: 8);
        }
        catch (Exception ex)
        {
            _logger.Error($"Failed to bind TCP {ListenPort}: {ex.Message}");
            return;
        }

        while (!ct.IsCancellationRequested)
        {
            TcpClient? client = null;
            try { client = await _listener.AcceptTcpClientAsync(ct); }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                if (ct.IsCancellationRequested) break;
                _logger.Warning($"Accept failed: {ex.Message}");
                try { await Task.Delay(250, ct); } catch { break; }
                continue;
            }

            ConfigureSocketOptions(client.Client);

            _ = RunSessionAsync(client, ct);
        }
    }

    private async Task RunSessionAsync(TcpClient client, CancellationToken ct)
    {
        try
        {
            using var session = new TetherSession(
                _eventBus,
                _logger,
                _identity,
                _deviceManager,
                _sessionManager,
                _pairingManager,
                _packetRouter);

            await session.RunAsync(client, ct);
        }
        catch (Exception ex)
        {
            _logger.Warning($"Session ended: {ex.Message}");
        }
        finally
        {
            try { client.Close(); } catch { }
        }
    }

    private void ConfigureSocketOptions(Socket socket)
    {
        try
        {
            socket.NoDelay = true;
            socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);

            socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveTime, 15);
            socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveInterval, 5);
            socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveRetryCount, 3);
        }
        catch (Exception ex)
        {
            _logger.Debug($"Could not set custom TCP KeepAlive socket options: {ex.Message}");
        }
    }
}
