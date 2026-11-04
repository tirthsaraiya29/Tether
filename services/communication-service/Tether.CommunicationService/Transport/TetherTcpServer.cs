using System.Collections.Generic;
﻿using System;
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
    private const int MaxConcurrentSessions = 16;
    private const int MaxSessionsPerIp = 5;
    private const int MaxConnectionsPerMinutePerIp = 60;
    private const int MaxTrackedIps = 1024;

    private readonly System.Collections.Concurrent.ConcurrentDictionary<IPAddress, int> _activePerIp = new();
    private readonly System.Collections.Concurrent.ConcurrentDictionary<IPAddress, Queue<DateTime>> _ratePerIp = new();
    private readonly object _rateLock = new();

    private readonly IEventBus _eventBus;
    private readonly ITetherLogger _logger;
    private readonly WindowsIdentity _identity;
    private readonly DeviceManager _deviceManager;
    private readonly SessionManager _sessionManager;
    private readonly PairingManager _pairingManager;
    private readonly PacketRouter _packetRouter;
    private readonly InputForwarder _inputForwarder;

    private TcpListener? _listener;
    private CancellationTokenSource? _cts;
    private Task? _acceptLoop;
    private int _activeSessionCount = 0;

    public TetherTcpServer(
        IEventBus eventBus,
        ITetherLogger logger,
        WindowsIdentity identity,
        DeviceManager deviceManager,
        SessionManager sessionManager,
        PairingManager pairingManager,
        PacketRouter packetRouter,
        InputForwarder inputForwarder)
    {
        _eventBus = eventBus;
        _logger = logger;
        _identity = identity;
        _deviceManager = deviceManager;
        _sessionManager = sessionManager;
        _pairingManager = pairingManager;
        _packetRouter = packetRouter;
        _inputForwarder = inputForwarder;
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

            var remoteEp = client.Client.RemoteEndPoint as IPEndPoint;
            var remoteIp = remoteEp?.Address;

            if (remoteIp != null)
            {
                // Rate limiting check (sliding 1-minute window with bounded memory)
                lock (_rateLock)
                {
                    var now = DateTime.UtcNow;

                    // Bound rate-limiting tracking dictionary
                    if (_ratePerIp.Count >= MaxTrackedIps)
                    {
                        var staleKeys = new List<IPAddress>();
                        foreach (var kvp in _ratePerIp)
                        {
                            while (kvp.Value.Count > 0 && (now - kvp.Value.Peek()).TotalSeconds > 60)
                            {
                                kvp.Value.Dequeue();
                            }
                            if (kvp.Value.Count == 0)
                            {
                                staleKeys.Add(kvp.Key);
                            }
                        }
                        foreach (var staleKey in staleKeys)
                        {
                            _ratePerIp.TryRemove(staleKey, out _);
                        }

                        if (_ratePerIp.Count >= MaxTrackedIps)
                        {
                            int toRemove = _ratePerIp.Count - (MaxTrackedIps / 2);
                            foreach (var key in _ratePerIp.Keys)
                            {
                                if (toRemove-- <= 0) break;
                                _ratePerIp.TryRemove(key, out _);
                            }
                        }
                    }

                    if (!_ratePerIp.TryGetValue(remoteIp, out var timestamps))
                    {
                        timestamps = new Queue<DateTime>();
                        _ratePerIp[remoteIp] = timestamps;
                    }

                    while (timestamps.Count > 0 && (now - timestamps.Peek()).TotalSeconds > 60)
                    {
                        timestamps.Dequeue();
                    }

                    if (timestamps.Count >= MaxConnectionsPerMinutePerIp)
                    {
                        _logger.Warning($"TetherTcpServer: Rate limit exceeded for {remoteIp} ({timestamps.Count} connections/min). Dropping.");
                        try { client.Close(); } catch { }
                        continue;
                    }

                    timestamps.Enqueue(now);
                }

                // Concurrency limit per IP
                int ipActive = _activePerIp.AddOrUpdate(remoteIp, 1, (_, current) => current + 1);
                if (ipActive > MaxSessionsPerIp)
                {
                    DecrementActivePerIp(remoteIp);
                    _logger.Warning($"TetherTcpServer: Concurrency limit ({MaxSessionsPerIp}) reached for IP {remoteIp}. Dropping connection.");
                    try { client.Close(); } catch { }
                    continue;
                }
            }

            if (Interlocked.Increment(ref _activeSessionCount) > MaxConcurrentSessions)
            {
                Interlocked.Decrement(ref _activeSessionCount);
                if (remoteIp != null)
                {
                    DecrementActivePerIp(remoteIp);
                }
                _logger.Warning($"TetherTcpServer: Max concurrent session limit ({MaxConcurrentSessions}) reached. Connection rejected.");
                try { client.Close(); } catch { }
                continue;
            }

            _ = RunSessionAsync(client, remoteIp, ct);
        }
    }

    private async Task RunSessionAsync(TcpClient client, IPAddress? remoteIp, CancellationToken ct)
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
                _packetRouter,
                _inputForwarder);

            await session.RunAsync(client, ct);
        }
        catch (Exception ex)
        {
            _logger.Warning($"Session ended: {ex.Message}");
        }
        finally
        {
            if (remoteIp != null)
            {
                DecrementActivePerIp(remoteIp);
            }
            Interlocked.Decrement(ref _activeSessionCount);
            try { client.Close(); } catch { }
        }
    }

    private void DecrementActivePerIp(IPAddress ip)
    {
        _activePerIp.AddOrUpdate(ip, 0, (_, current) => Math.Max(0, current - 1));
        if (_activePerIp.TryGetValue(ip, out int val) && val <= 0)
        {
            _activePerIp.TryRemove(new KeyValuePair<IPAddress, int>(ip, 0));
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