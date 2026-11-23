using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Tether.EventBus;
using Tether.LinuxDaemon.Config;
using Tether.LinuxDaemon.Devices;
using Tether.LinuxDaemon.Pairing;
using Tether.LinuxDaemon.Sessions;
using Tether.LinuxDaemon.Trust;
using Tether.Shared.Logging;
using Tether.Shared.Network;
using Tether.Shared.Security;

namespace Tether.LinuxDaemon.Transport;

public sealed class LinuxTcpServer : IDisposable
{
    public const int DefaultListenPort = NetworkConstants.ControlPort;
    private const int MaxConcurrentSessions = 16;
    private const int MaxSessionsPerIp = 5;
    private const int MaxConnectionsPerMinutePerIp = 60;
    private const int MaxTrackedIps = 1024;

    private readonly ConcurrentDictionary<IPAddress, int> _activePerIp = new();
    private readonly ConcurrentDictionary<IPAddress, Queue<DateTime>> _ratePerIp = new();
    private readonly object _rateLock = new();

    private readonly IEventBus _eventBus;
    private readonly ITetherLogger _logger;
    private readonly IHostIdentity _identity;
    private readonly LinuxDaemonConfig _config;
    private readonly LinuxDeviceManager _deviceManager;
    private readonly LinuxSessionManager _sessionManager;
    private readonly LinuxPairingManager _pairingManager;
    private readonly LinuxTrustStore _trustStore;
    private readonly Func<ReadOnlyMemory<byte>, LinuxSession, CancellationToken, Task> _rawFrameRouter;

    private TcpListener? _listener;
    private CancellationTokenSource? _cts;
    private Task? _acceptLoop;
    private int _activeSessionCount = 0;
    private readonly TaskCompletionSource<bool> _startedTcs = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public int BoundPort => (_listener?.LocalEndpoint as IPEndPoint)?.Port ?? _config.ControlPort;

    public Task WaitForStartAsync(CancellationToken ct = default) => _startedTcs.Task.WaitAsync(ct);

    public LinuxTcpServer(
        IEventBus eventBus,
        ITetherLogger logger,
        IHostIdentity identity,
        LinuxDaemonConfig config,
        LinuxDeviceManager deviceManager,
        LinuxSessionManager sessionManager,
        LinuxPairingManager pairingManager,
        LinuxTrustStore trustStore,
        Func<ReadOnlyMemory<byte>, LinuxSession, CancellationToken, Task> rawFrameRouter)
    {
        _eventBus = eventBus;
        _logger = logger;
        _identity = identity;
        _config = config;
        _deviceManager = deviceManager;
        _sessionManager = sessionManager;
        _pairingManager = pairingManager;
        _trustStore = trustStore;
        _rawFrameRouter = rawFrameRouter;
    }

    public LinuxTcpServer(
        IEventBus eventBus,
        ITetherLogger logger,
        IHostIdentity identity,
        LinuxDaemonConfig config,
        LinuxDeviceManager deviceManager,
        LinuxSessionManager sessionManager,
        LinuxPairingManager pairingManager,
        LinuxTrustStore trustStore,
        Func<JsonDocument, LinuxSession, LinuxDevice, Stream, CancellationToken, Task> legacyRouter)
        : this(eventBus, logger, identity, config, deviceManager, sessionManager, pairingManager, trustStore,
            async (memory, sess, ct) =>
            {
                if (memory.Length > 0 && memory.Span[0] == (byte)'{' && sess.Device != null)
                {
                    using var doc = JsonDocument.Parse(memory);
                    var st = (Stream?)sess.GetType().GetField("_tls", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)?.GetValue(sess)
                             ?? (Stream?)sess.GetType().GetField("_testStream", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)?.GetValue(sess);
                    if (st != null)
                    {
                        await legacyRouter(doc, sess, sess.Device, st, ct);
                    }
                }
            })
    {
    }

    public void Start()
    {
        _cts = new CancellationTokenSource();
        _acceptLoop = Task.Run(() => AcceptLoopAsync(_cts.Token));
        _logger.Info($"Linux TCP server starting on DualMode [::]:{_config.ControlPort} (TLS 1.3).");
    }

    public void Stop()
    {
        try { _cts?.Cancel(); } catch { }
        try { _listener?.Stop(); } catch { }
        try { _startedTcs.TrySetCanceled(); } catch { }
        try { _acceptLoop?.Wait(TimeSpan.FromSeconds(3)); } catch { }
        try { _cts?.Dispose(); } catch { }
        _cts = null;
        _logger.Info("Linux TCP server stopped.");
    }

    public void Dispose() => Stop();

    private async Task AcceptLoopAsync(CancellationToken ct)
    {
        try
        {
            _listener = new TcpListener(IPAddress.IPv6Any, _config.ControlPort);
            _listener.Server.DualMode = true;
            _listener.Start(backlog: 8);
            _startedTcs.TrySetResult(true);
        }
        catch (Exception ex)
        {
            _startedTcs.TrySetException(ex);
            _logger.Error($"Failed to bind Linux TCP {_config.ControlPort}: {ex.Message}");
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
                lock (_rateLock)
                {
                    var now = DateTime.UtcNow;
                    if (_ratePerIp.Count >= MaxTrackedIps)
                    {
                        var stale = new List<IPAddress>();
                        foreach (var kvp in _ratePerIp)
                        {
                            while (kvp.Value.Count > 0 && (now - kvp.Value.Peek()).TotalSeconds > 60)
                                kvp.Value.Dequeue();
                            if (kvp.Value.Count == 0) stale.Add(kvp.Key);
                        }
                        foreach (var k in stale) _ratePerIp.TryRemove(k, out _);
                    }

                    var timestamps = _ratePerIp.GetOrAdd(remoteIp, _ => new Queue<DateTime>());
                    while (timestamps.Count > 0 && (now - timestamps.Peek()).TotalSeconds > 60)
                        timestamps.Dequeue();

                    if (!IPAddress.IsLoopback(remoteIp) && timestamps.Count >= MaxConnectionsPerMinutePerIp)
                    {
                        _logger.Warning($"LinuxTcpServer: Rate limit exceeded for {remoteIp}. Dropping.");
                        try { client.Close(); } catch { }
                        continue;
                    }
                    timestamps.Enqueue(now);
                }

                int ipActive = _activePerIp.AddOrUpdate(remoteIp, 1, (_, curr) => curr + 1);
                if (ipActive > MaxSessionsPerIp)
                {
                    DecrementActivePerIp(remoteIp);
                    _logger.Warning($"LinuxTcpServer: Concurrency limit per IP reached for {remoteIp}. Dropping.");
                    try { client.Close(); } catch { }
                    continue;
                }
            }

            if (Interlocked.Increment(ref _activeSessionCount) > MaxConcurrentSessions)
            {
                Interlocked.Decrement(ref _activeSessionCount);
                if (remoteIp != null) DecrementActivePerIp(remoteIp);
                _logger.Warning($"LinuxTcpServer: Global session concurrency limit reached. Connection rejected.");
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
            using var session = new LinuxSession(
                _eventBus,
                _logger,
                _identity,
                _deviceManager,
                _sessionManager,
                _pairingManager,
                _trustStore,
                _rawFrameRouter);

            await session.RunAsync(client, ct);
        }
        catch (Exception ex)
        {
            _logger.Warning($"Session ended: {ex.Message}");
        }
        finally
        {
            if (remoteIp != null) DecrementActivePerIp(remoteIp);
            Interlocked.Decrement(ref _activeSessionCount);
            try { client.Close(); } catch { }
        }
    }

    private void DecrementActivePerIp(IPAddress ip)
    {
        _activePerIp.AddOrUpdate(ip, 0, (_, curr) => Math.Max(0, curr - 1));
        if (_activePerIp.TryGetValue(ip, out int val) && val <= 0)
        {
            _activePerIp.TryRemove(new KeyValuePair<IPAddress, int>(ip, 0));
        }
    }

    private static void ConfigureSocketOptions(Socket socket)
    {
        try
        {
            socket.NoDelay = true;
            socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
            socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveTime, 15);
            socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveInterval, 5);
            socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveRetryCount, 3);
        }
        catch { }
    }
}
