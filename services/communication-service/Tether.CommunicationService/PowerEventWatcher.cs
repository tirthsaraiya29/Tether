using System;
using System.Collections.Generic;
using System.Management;
using Microsoft.Win32;
using Tether.Shared.Logging;

namespace Tether.CommunicationService.Power;

public enum TetherPowerEventType
{
    None,
    Shutdown,
    Restart,
    Sleep,
    Hibernate,
    Lock,
    Unlock,
    Resume,
}

public sealed record TetherPowerEvent(
    TetherPowerEventType Type,
    DateTimeOffset TimestampUtc,
    string Source);

public sealed class PowerEventWatcher : IDisposable
{
    private const int MaxPending = 32;
    private const double DedupeWindowSeconds = 2.0;

    private readonly ITetherLogger _logger;
    private readonly object _lock = new();
    private readonly Queue<TetherPowerEvent> _pending = new();

    private ManagementEventWatcher? _wmiShutdownWatcher;
    private ManagementEventWatcher? _wmiPowerWatcher;
    private bool _disposed;

    private TetherPowerEventType _lastRecordedType = TetherPowerEventType.None;
    private DateTimeOffset _lastRecordedAt = DateTimeOffset.MinValue;

    public event Action<TetherPowerEvent>? PowerEventOccurred;

    public PowerEventWatcher(ITetherLogger logger)
    {
        _logger = logger;
    }

    public void Start()
    {
        try
        {
            SystemEvents.PowerModeChanged += OnPowerModeChanged;
            SystemEvents.SessionSwitch += OnSessionSwitch;
            SystemEvents.SessionEnding += OnSessionEnding;
            _logger.Info("PowerEventWatcher: subscribed to SystemEvents.");
        }
        catch (Exception ex)
        {
            _logger.Error($"PowerEventWatcher: SystemEvents subscribe failed: {ex.Message}", ex);
        }

        try
        {
            var shutdownQuery = new WqlEventQuery("SELECT * FROM Win32_ComputerShutdownEvent");
            _wmiShutdownWatcher = new ManagementEventWatcher(shutdownQuery);
            _wmiShutdownWatcher.EventArrived += OnWmiShutdown;
            _wmiShutdownWatcher.Start();

            var powerQuery = new WqlEventQuery("SELECT * FROM Win32_PowerManagementEvent");
            _wmiPowerWatcher = new ManagementEventWatcher(powerQuery);
            _wmiPowerWatcher.EventArrived += OnWmiPower;
            _wmiPowerWatcher.Start();

            _logger.Info("PowerEventWatcher: WMI watchers started.");
        }
        catch (Exception ex)
        {
            _logger.Error($"PowerEventWatcher: WMI watcher failed: {ex.Message}", ex);
        }
    }

    public void RecordInitiated(TetherPowerEventType type, string source)
    {
        if (type == TetherPowerEventType.None) return;
        Record(type, source);
    }

    public IReadOnlyList<TetherPowerEvent> SnapshotAndClear()
    {
        lock (_lock)
        {
            if (_pending.Count == 0) return Array.Empty<TetherPowerEvent>();
            var list = _pending.ToArray();
            _pending.Clear();
            return list;
        }
    }

    public bool HasPending
    {
        get { lock (_lock) return _pending.Count > 0; }
    }

    private void OnPowerModeChanged(object sender, PowerModeChangedEventArgs e)
    {
        var type = e.Mode switch
        {
            PowerModes.Suspend => TetherPowerEventType.Sleep,
            PowerModes.Resume => TetherPowerEventType.Resume,
            PowerModes.StatusChange => TetherPowerEventType.None,
            _ => TetherPowerEventType.None,
        };
        if (type != TetherPowerEventType.None)
            Record(type, "SystemEvents.PowerModeChanged");
    }

    private void OnSessionSwitch(object sender, SessionSwitchEventArgs e)
    {
        var type = e.Reason switch
        {
            SessionSwitchReason.SessionLock => TetherPowerEventType.Lock,
            SessionSwitchReason.SessionUnlock => TetherPowerEventType.Unlock,
            _ => TetherPowerEventType.None,
        };
        if (type != TetherPowerEventType.None)
            Record(type, "SystemEvents.SessionSwitch");
    }

    private void OnSessionEnding(object sender, SessionEndingEventArgs e)
    {
        var type = e.Reason switch
        {
            SessionEndReasons.SystemShutdown => TetherPowerEventType.Shutdown,
            SessionEndReasons.Logoff => TetherPowerEventType.Shutdown,
            _ => TetherPowerEventType.None,
        };
        if (type != TetherPowerEventType.None)
            Record(type, "SystemEvents.SessionEnding");
    }

    private void OnWmiShutdown(object sender, EventArrivedEventArgs e)
    {
        try
        {
            var kind = e.NewEvent.Properties["EventType"]?.Value;
            var type = kind switch
            {
                (ushort)1 or (uint)1 or 1 => TetherPowerEventType.Shutdown,
                (ushort)2 or (uint)2 or 2 => TetherPowerEventType.Restart,
                _ => TetherPowerEventType.Shutdown,
            };
            Record(type, "WMI.Win32_ComputerShutdownEvent");
        }
        catch (Exception ex)
        {
            _logger.Warning($"PowerEventWatcher: WMI shutdown parse failed: {ex.Message}");
        }
    }

    private void OnWmiPower(object sender, EventArrivedEventArgs e)
    {
        try
        {
            var evType = e.NewEvent.Properties["EventType"]?.Value;
            var type = evType switch
            {
                (ushort)4 or (uint)4 or 4 => TetherPowerEventType.Sleep,
                (ushort)7 or (uint)7 or 7 => TetherPowerEventType.Resume,
                (ushort)10 or (uint)10 or 10 => TetherPowerEventType.Resume,
                (ushort)18 or (uint)18 or 18 => TetherPowerEventType.Resume,
                _ => TetherPowerEventType.None,
            };
            if (type != TetherPowerEventType.None)
                Record(type, "WMI.Win32_PowerManagementEvent");
        }
        catch (Exception ex)
        {
            _logger.Warning($"PowerEventWatcher: WMI power parse failed: {ex.Message}");
        }
    }

    private void Record(TetherPowerEventType type, string source)
    {
        TetherPowerEvent? evt = null;

        lock (_lock)
        {
            var now = DateTimeOffset.UtcNow;

            if (type == _lastRecordedType &&
                (now - _lastRecordedAt).TotalSeconds < DedupeWindowSeconds)
            {
                _logger.Info($"PowerEventWatcher: suppressed duplicate {type} (source={source}).");
                return;
            }

            _lastRecordedType = type;
            _lastRecordedAt = now;

            evt = new TetherPowerEvent(type, now, source);
            _pending.Enqueue(evt);
            while (_pending.Count > MaxPending) _pending.Dequeue();
        }

        _logger.Info($"PowerEventWatcher: recorded {type} (source={source}).");
        try { PowerEventOccurred?.Invoke(evt!); } catch { }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        try { SystemEvents.PowerModeChanged -= OnPowerModeChanged; } catch { }
        try { SystemEvents.SessionSwitch -= OnSessionSwitch; } catch { }
        try { SystemEvents.SessionEnding -= OnSessionEnding; } catch { }

        try { _wmiShutdownWatcher?.Stop(); _wmiShutdownWatcher?.Dispose(); } catch { }
        try { _wmiPowerWatcher?.Stop(); _wmiPowerWatcher?.Dispose(); } catch { }
    }
}