using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
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

    [DllImport("kernel32.dll", SetLastError = false)]
    private static extern uint WTSGetActiveConsoleSessionId();

    private readonly ITetherLogger _logger;
    private readonly InputForwarder _inputForwarder;
    private readonly CancellationTokenSource _cts = new();
    private Task? _loop;
    private int _disconnectedTicks;

    public SessionHelperDaemon(ITetherLogger logger, InputForwarder inputForwarder)
    {
        _logger = logger;
        _inputForwarder = inputForwarder;
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
        TerminateHelperProcesses();
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
        uint activeSession = WTSGetActiveConsoleSessionId();
        if (activeSession == 0xFFFFFFFF)
        {
            return;
        }

        if (_inputForwarder.IsHelperConnected)
        {
            _disconnectedTicks = 0;
            return;
        }

        _disconnectedTicks++;

        // Audit running helper instances in active and background sessions
        Process[] procs;
        try { procs = Process.GetProcessesByName(HelperProcessName); }
        catch { procs = Array.Empty<Process>(); }

        try
        {
            bool hasRunningInActiveSession = false;
            foreach (var p in procs)
            {
                try
                {
                    if (p.HasExited) continue;

                    if ((uint)p.SessionId == activeSession)
                    {
                        if (hasRunningInActiveSession || _disconnectedTicks > 2)
                        {
                            // Duplicate or hung instance that failed to connect within 20s: kill it
                            _logger.Warning($"SessionHelperDaemon: terminating hung/duplicate helper PID {p.Id} in session {activeSession}.");
                            try { p.Kill(); } catch { }
                        }
                        else
                        {
                            hasRunningInActiveSession = true;
                        }
                    }
                }
                catch { }
            }

            // If a healthy instance is already in active session and we haven't timed out, give it time
            if (hasRunningInActiveSession && _disconnectedTicks <= 2)
            {
                return;
            }

            bool launched = HardwareExecutor.LaunchHelperDaemonInUserSession(_logger);
            if (launched)
            {
                _disconnectedTicks = 0;
                _logger.Info($"SessionHelperDaemon: launched Tether.SessionHelper in active user session {activeSession}.");
            }
            else
            {
                _logger.Debug($"SessionHelperDaemon: could not launch helper in user session {activeSession}.");
            }
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
        TerminateHelperProcesses();
    }

    private void TerminateHelperProcesses()
    {
        try
        {
            var procs = Process.GetProcessesByName(HelperProcessName);
            foreach (var p in procs)
            {
                try
                {
                    if (!p.HasExited)
                    {
                        _logger.Info($"SessionHelperDaemon: terminating helper PID {p.Id} on service stop.");
                        p.Kill();
                    }
                }
                catch { }
                finally
                {
                    try { p.Dispose(); } catch { }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Warning($"SessionHelperDaemon: error stopping helper processes: {ex.Message}");
        }
    }
}
