using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Tether.CommunicationService.Capabilities;
using Tether.Shared.Logging;

namespace Tether.CommunicationService.Transport;

public sealed class SessionHelperDaemon : IHostedService, IDisposable
{
    private static readonly TimeSpan TickInterval = TimeSpan.FromSeconds(10);
    private const string HelperProcessName = "Tether.SessionHelper";

    private readonly ITetherLogger _logger;
    private readonly CancellationTokenSource _cts = new();
    private Task? _loop;

    public SessionHelperDaemon(ITetherLogger logger)
    {
        _logger = logger;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _loop = Task.Run(() => LoopAsync(_cts.Token));
        _logger.Info("SessionHelperDaemon: started.");
        return Task.CompletedTask;
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        try { _cts.Cancel(); } catch { }
        if (_loop is not null)
        {
            try { await Task.WhenAny(_loop, Task.Delay(2000, cancellationToken)); } catch { }
        }
        _logger.Info("SessionHelperDaemon: stopped.");
    }

    private async Task LoopAsync(CancellationToken ct)
    {
        try { await Task.Delay(TimeSpan.FromSeconds(2), ct); } catch { return; }

        while (!ct.IsCancellationRequested)
        {
            try
            {
                EnsureRunning();
            }
            catch (Exception ex)
            {
                _logger.Warning($"SessionHelperDaemon: tick failed: {ex.Message}");
            }

            try { await Task.Delay(TickInterval, ct); }
            catch (OperationCanceledException) { break; }
        }
    }

    private void EnsureRunning()
    {
        if (IsHelperRunning())
        {
            return;
        }

        bool launched = HardwareExecutor.LaunchHelperDaemonInUserSession(_logger);
        if (launched)
        {
            _logger.Info("SessionHelperDaemon: launched Tether.SessionHelper in active user session.");
        }
        else
        {
            _logger.Debug("SessionHelperDaemon: no active user session available for helper launch.");
        }
    }

    private static bool IsHelperRunning()
    {
        Process[] procs;
        try { procs = Process.GetProcessesByName(HelperProcessName); }
        catch { return false; }

        try
        {
            if (procs.Length == 0) return false;
            foreach (var p in procs)
            {
                try { if (!p.HasExited) return true; } catch { }
            }
            return false;
        }
        finally
        {
            foreach (var p in procs)
            {
                try { p.Dispose(); } catch { }
            }
        }
    }

    public void Dispose()
    {
        try { _cts.Cancel(); } catch { }
        try { _cts.Dispose(); } catch { }
    }
}