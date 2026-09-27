// services/communication-service/Tether.CommunicationService/Transport/TetherTcpServer.cs
using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Tether.CommunicationService.Protocol;
using Tether.CommunicationService.Security;
using Tether.CommunicationService.Trust;
using Tether.EventBus;
using Tether.Shared.Logging;

namespace Tether.CommunicationService.Transport;

/// <summary>
/// TCP 37123 listener. Accepts one connection at a time; TLS 1.3 + Tether handshake
/// run inside TetherSession. LAN is treated as hostile: no subnet filtering is
/// performed (that is impossible to enforce across arbitrary topologies), so
/// authentication happens entirely at the TLS+handshake layer.
/// </summary>
public sealed class TetherTcpServer : IDisposable
{
    public const int ListenPort = 37123;
    private const int MaxConcurrentSessions = 1;
    private const int HandshakeTimeoutSeconds = 20;

    private readonly IEventBus _eventBus;
    private readonly ITetherLogger _logger;
    private readonly WindowsIdentity _identity;
    private readonly TrustStore _trust;
    private readonly PairingCoordinator _pairing;

    private TcpListener? _listener;
    private CancellationTokenSource? _cts;
    private Task? _acceptLoop;
    private readonly SemaphoreSlim _slots = new(MaxConcurrentSessions, MaxConcurrentSessions);
    private bool _isStopping;

    public TetherTcpServer(IEventBus eventBus, ITetherLogger logger,
                           WindowsIdentity identity, TrustStore trust, PairingCoordinator pairing)
    {
        _eventBus = eventBus;
        _logger = logger;
        _identity = identity;
        _trust = trust;
        _pairing = pairing;
    }

    public void Start()
    {
        _isStopping = false;
        _cts = new CancellationTokenSource();
        _acceptLoop = Task.Run(() => AcceptLoopAsync(_cts.Token));
        _logger.Info($"TCP listener starting on 0.0.0.0:{ListenPort} (TLS 1.3).");
    }

    public void Stop()
    {
        _isStopping = true;
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
            _listener = new TcpListener(IPAddress.Any, ListenPort);
            _listener.Start(backlog: 4);
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

            if (!await _slots.WaitAsync(0, ct))
            {
                _logger.Warning("Rejecting additional peer: a session is already active.");
                try { client.Close(); } catch { }
                continue;
            }

            _ = RunSessionAsync(client, ct);
        }
    }

    private async Task RunSessionAsync(TcpClient client, CancellationToken ct)
    {
        try
        {
            client.NoDelay = true;
            using var session = new TetherSession(
                _eventBus, _logger, _identity, _trust, _pairing,
                HandshakeTimeoutSeconds);

            await session.RunAsync(client, ct);
        }
        catch (Exception ex)
        {
            _logger.Warning($"Session ended: {ex.Message}");
        }
        finally
        {
            try { client.Close(); } catch { }
            _slots.Release();
        }
    }
}