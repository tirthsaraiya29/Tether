using System;
using System.Reflection;
using System.ServiceProcess;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Tether.CommunicationService.Power;
using Tether.CommunicationService.Sessions;

namespace Tether.CommunicationService;

/// <summary>
/// Thin ServiceBase wrapper around the generic Host.
///
/// .NET 8's ServiceBase has no public CanPreshutdown property and no virtual
/// OnPreshutdown method, so SERVICE_CONTROL_PRESHUTDOWN (0xF) can only be
/// received by:
///   1. injecting SERVICE_ACCEPT_PRESHUTDOWN into the private accepted-commands
///      field before the service reports SERVICE_RUNNING (done here via reflection), and
///   2. handling control code 15 in OnCustomCommand.
///
/// Power and session control codes arrive on the proper virtual methods:
///   SERVICE_CONTROL_POWEREVENT    -> OnPowerEvent
///   SERVICE_CONTROL_SESSIONCHANGE -> OnSessionChange
///   SERVICE_CONTROL_SHUTDOWN      -> OnShutdown (late fallback)
/// </summary>
public sealed class TetherWindowsService : ServiceBase
{
    private const int SERVICE_ACCEPT_PRESHUTDOWN = 0x0100;
    private const int SERVICE_CONTROL_PRESHUTDOWN = 0x000F;

    private readonly IHost _host;

    public TetherWindowsService(IHost host)
    {
        _host = host;

        ServiceName = "TetherCommService";
        CanHandlePowerEvent = true;  // SERVICE_ACCEPT_POWEREVENT
        CanHandleSessionChangeEvent = true;  // SERVICE_ACCEPT_SESSIONCHANGE
        CanShutdown = true;  // SERVICE_ACCEPT_SHUTDOWN (late fallback)

        EnablePreshutdown();
    }

    /// <summary>
    /// There is no public API for this. The private field is named
    /// '_acceptedCommands' on modern .NET (5+), and 'acceptedCommands' on
    /// legacy .NET Framework. Probe both so this works across runtimes.
    /// </summary>
    private void EnablePreshutdown()
    {
        try
        {
            var field = typeof(ServiceBase).GetField(
                            "_acceptedCommands",
                            BindingFlags.Instance | BindingFlags.NonPublic)
                     ?? typeof(ServiceBase).GetField(
                            "acceptedCommands",
                            BindingFlags.Instance | BindingFlags.NonPublic);

            if (field is null)
            {
                System.Diagnostics.Debug.WriteLine(
                    "EnablePreshutdown: accepted-commands field not found. " +
                    "Preshutdown will not be delivered; OnShutdown remains the fallback.");
                return;
            }

            int current = (int)field.GetValue(this)!;
            if ((current & SERVICE_ACCEPT_PRESHUTDOWN) != 0)
            {
                return; // already set
            }

            field.SetValue(this, current | SERVICE_ACCEPT_PRESHUTDOWN);
        }
        catch (Exception ex)
        {
            // Never let this crash OnStart. The service will still start, just
            // without the preshutdown control code.
            System.Diagnostics.Debug.WriteLine(
                $"EnablePreshutdown failed: {ex.Message}");
        }
    }

    protected override void OnStart(string[] args)
    {
        _host.Start();
    }

    protected override void OnStop()
    {
        // Normal service stop (`sc stop` / Services.msc).
        StopHost(TimeSpan.FromSeconds(20));
    }

    /// <summary>
    /// Late fallback. On modern Windows with fast startup / hybrid shutdown,
    /// preshutdown (OnCustomCommand 0xF) fires first; OnShutdown then becomes
    /// a near-instant no-op because the queue was already drained.
    /// </summary>
    protected override void OnShutdown()
    {
        FlushPowerEventToPhone(TimeSpan.FromSeconds(1));
    }

    // SERVICE_CONTROL_POWEREVENT. Must return bool (true = allow, false = veto).
    protected override bool OnPowerEvent(PowerBroadcastStatus powerStatus)
    {
        var watcher = _host.Services.GetService<PowerEventWatcher>();
        if (watcher is null) return true;

        var type = powerStatus switch
        {
            PowerBroadcastStatus.Suspend => TetherPowerEventType.Sleep,
            PowerBroadcastStatus.ResumeSuspend => TetherPowerEventType.Resume,
            PowerBroadcastStatus.ResumeAutomatic => TetherPowerEventType.Resume,
            PowerBroadcastStatus.ResumeCritical => TetherPowerEventType.Resume,
            // QuerySuspend / QuerySuspendFailed are veto windows; we never veto.
            _ => TetherPowerEventType.None,
        };

        if (type != TetherPowerEventType.None)
            watcher.RecordInitiated(type, "ServiceBase.OnPowerEvent");

        // Always allow the transition. Vetoing QuerySuspend can hang shutdown
        // on some systems, so return true unconditionally.
        return true;
    }

    // SERVICE_CONTROL_SESSIONCHANGE
    protected override void OnSessionChange(SessionChangeDescription change)
    {
        var watcher = _host.Services.GetService<PowerEventWatcher>();
        if (watcher is null) return;

        var type = change.Reason switch
        {
            SessionChangeReason.SessionLock => TetherPowerEventType.Lock,
            SessionChangeReason.SessionUnlock => TetherPowerEventType.Unlock,
            SessionChangeReason.SessionLogoff => TetherPowerEventType.Logoff,
            _ => TetherPowerEventType.None,
        };

        if (type != TetherPowerEventType.None)
            watcher.RecordInitiated(type, "ServiceBase.OnSessionChange", change.SessionId);
    }

    // SERVICE_CONTROL_PRESHUTDOWN arrives here (0xF = 15).
    protected override void OnCustomCommand(int command)
    {
        base.OnCustomCommand(command);

        if (command == SERVICE_CONTROL_PRESHUTDOWN)
        {
            // Vista+ preshutdown path. Hybrid shutdown and fast startup land
            // here, not in OnShutdown. ~5 s default budget; raise it with:
            //   reg add "HKLM\SYSTEM\CurrentControlSet\Services\TetherCommService" ^
            //           /v PreshutdownTimeout /t REG_DWORD /d 10000 /f
            FlushPowerEventToPhone(TimeSpan.FromSeconds(2));
            StopHost(TimeSpan.FromSeconds(2));
        }
    }

    private void FlushPowerEventToPhone(TimeSpan budget)
    {
        try
        {
            var notifier = _host.Services.GetService<PowerEventNotifier>();
            var sessions = _host.Services.GetService<SessionManager>();
            if (notifier is null || sessions is null) return;

            // FlushToSession is a no-op when the watcher has nothing queued.
            notifier.FlushToSession(json => sessions.TryBroadcastRawFrameBlocking(json, budget));
        }
        catch
        {
            // Shutdown path is best-effort.
        }
    }

    private void StopHost(TimeSpan timeout)
    {
        try { _host.StopAsync(timeout).GetAwaiter().GetResult(); }
        catch { /* best effort */ }
    }
}