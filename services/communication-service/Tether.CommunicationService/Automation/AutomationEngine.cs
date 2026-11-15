using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Tether.CommunicationService.Capabilities;
using Tether.CommunicationService.Trust;
using Tether.Shared.Logging;

namespace Tether.CommunicationService.Automation;

public sealed class AutomationEngine : IHostedService, IDisposable
{
    private static readonly string DefaultWorkflowsDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Tether");
    private readonly string _workflowsDir;
    private readonly string _workflowsFile;

    private readonly ITetherLogger _logger;
    private readonly WindowsAdminManager _adminManager;
    private readonly TrustStore? _trustStore;
    internal readonly ConcurrentDictionary<string, TetherWorkflow> _workflows = new();
    internal readonly ConcurrentDictionary<string, byte> _runningWorkflows = new();
    private readonly object _persistLock = new();
    private readonly CancellationTokenSource _cts = new();
    private Task? _schedulerTask;

    public AutomationEngine(ITetherLogger logger, WindowsAdminManager adminManager, TrustStore? trustStore = null, string? customWorkflowsDir = null)
    {
        _logger = logger;
        _adminManager = adminManager;
        _trustStore = trustStore;
        _workflowsDir = customWorkflowsDir ?? DefaultWorkflowsDir;
        _workflowsFile = Path.Combine(_workflowsDir, "Workflows.json");
        LoadWorkflows();
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _schedulerTask = Task.Run(() => SchedulerLoopAsync(_cts.Token));
        _logger.Info("AutomationEngine started.");
        return Task.CompletedTask;
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        try { _cts.Cancel(); } catch { }
        if (_schedulerTask != null)
        {
            try { await Task.WhenAny(_schedulerTask, Task.Delay(2000, cancellationToken)); } catch { }
        }
        _logger.Info("AutomationEngine stopped.");
    }

    public List<TetherWorkflow> GetWorkflows()
    {
        return _workflows.Values.OrderBy(w => w.Name).ToList();
    }

    public void SaveWorkflow(TetherWorkflow wf)
    {
        if (string.IsNullOrEmpty(wf.Id)) wf.Id = Guid.NewGuid().ToString("N")[..8];
        _workflows[wf.Id] = wf;
        PersistWorkflows();
    }

    public bool DeleteWorkflow(string id)
    {
        if (_workflows.TryRemove(id, out _))
        {
            PersistWorkflows();
            return true;
        }
        return false;
    }

    public async Task<WorkflowExecutionResult> RunWorkflowAsync(string id, CancellationToken ct)
    {
        if (!_workflows.TryGetValue(id, out var wf))
        {
            return new WorkflowExecutionResult { WorkflowId = id, Success = false, Message = "Workflow not found" };
        }

        if (!_runningWorkflows.TryAdd(id, 0))
        {
            return new WorkflowExecutionResult { WorkflowId = id, Success = false, Message = "Workflow is already running" };
        }

        try
        {
            // Evaluate Originating Device Authorization if bound
            TrustedPhone? originatingPhone = null;
            if (!string.IsNullOrEmpty(wf.OriginatingFingerprint) && _trustStore != null)
            {
                originatingPhone = _trustStore.All().FirstOrDefault(p =>
                    string.Equals(p.Fingerprint, wf.OriginatingFingerprint, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(p.DeviceId, wf.OriginatingDeviceId, StringComparison.OrdinalIgnoreCase));

                if (originatingPhone == null)
                {
                    _logger.Warning($"AutomationEngine: Workflow '{id}' originating device '{wf.OriginatingFingerprint}' is revoked or not found in trust store.");
                    wf.LastExecutedMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                    wf.LastStatus = "FAILED_REVOKED";
                    PersistWorkflows();
                    return new WorkflowExecutionResult { WorkflowId = id, Success = false, Message = "Originating device revoked or unauthorized" };
                }
            }

            // Evaluate Condition if specified
            if (!string.IsNullOrEmpty(wf.ConditionType) && wf.ConditionType != "none")
            {
                bool condPass = EvaluateCondition(wf.ConditionType, wf.ConditionValue);
                if (!condPass)
                {
                    wf.LastExecutedMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                    wf.LastStatus = "SKIPPED_CONDITION";
                    PersistWorkflows();
                    return new WorkflowExecutionResult
                    {
                        WorkflowId = id,
                        Success = true,
                        Message = "Condition not met; step skipped."
                    };
                }
            }

            // Execute Actions
            bool allOk = true;
            var executedActions = new List<string>();

            foreach (var action in wf.Actions)
            {
                ct.ThrowIfCancellationRequested();

                if (originatingPhone != null)
                {
                    var reqCap = CapabilityManager.MapCommandToCapability(action);
                    if (!string.IsNullOrEmpty(reqCap) && !CapabilityManager.HasCapability(originatingPhone.Capabilities, reqCap))
                    {
                        _logger.Warning($"AutomationEngine: Workflow '{id}' action '{action}' requires capability '{reqCap}' which originating device lacks.");
                        executedActions.Add($"{action}: REJECTED (Missing {reqCap})");
                        allOk = false;
                        continue;
                    }
                }

                try
                {
                    bool ok = HardwareExecutor.ExecuteCommand(action, _logger, out _);
                    executedActions.Add($"{action}: {(ok ? "OK" : "FAILED")}");
                    if (!ok) allOk = false;
                }
                catch (Exception ex)
                {
                    executedActions.Add($"{action}: ERROR ({ex.Message})");
                    allOk = false;
                }
                await Task.Delay(100, ct);
            }

            wf.LastExecutedMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            wf.LastStatus = allOk ? "SUCCESS" : "FAILED";
            PersistWorkflows();

            return new WorkflowExecutionResult
            {
                WorkflowId = id,
                Success = allOk,
                Message = string.Join(", ", executedActions)
            };
        }
        finally
        {
            _runningWorkflows.TryRemove(id, out _);
        }
    }

    private bool EvaluateCondition(string type, string? val)
    {
        try
        {
            switch (type.ToLowerInvariant())
            {
                case "battery_below":
                    if (int.TryParse(val, out int threshold))
                    {
                        var snap = LaptopStateCollector.GetLaptopSnapshot(_logger);
                        return snap.BatteryLevel < threshold;
                    }
                    return false;

                case "battery_not_charging":
                    var snapChg = LaptopStateCollector.GetLaptopSnapshot(_logger);
                    return !snapChg.IsCharging;

                case "process_running":
                    if (!string.IsNullOrEmpty(val))
                    {
                        string pName = val.Replace(".exe", "", StringComparison.OrdinalIgnoreCase);
                        var procs = Process.GetProcessesByName(pName);
                        return procs.Length > 0;
                    }
                    return false;

                default:
                    _logger.Warning($"AutomationEngine: Unknown condition type '{type}'. Failing closed.");
                    return false;
            }
        }
        catch (Exception ex)
        {
            _logger.Warning($"AutomationEngine: Condition evaluation threw exception: {ex.Message}. Failing closed.");
            return false;
        }
    }

    private async Task SchedulerLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(30), ct);
            }
            catch (OperationCanceledException) { break; }

            var now = DateTime.UtcNow;
            long nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            foreach (var wf in _workflows.Values)
            {
                if (!wf.IsEnabled) continue;

                if (wf.ScheduleType == "interval" && int.TryParse(wf.ScheduleValue, out int min) && min > 0)
                {
                    long intervalMs = min * 60 * 1000L;
                    if (nowMs - wf.LastExecutedMs >= intervalMs)
                    {
                        _ = RunWorkflowAsync(wf.Id, ct);
                    }
                }
                else if (wf.ScheduleType == "time" && TimeSpan.TryParse(wf.ScheduleValue, out var targetTime))
                {
                    var localNow = DateTime.Now.TimeOfDay;
                    if (Math.Abs((localNow - targetTime).TotalMinutes) < 1.0)
                    {
                        if (nowMs - wf.LastExecutedMs > 120_000L) // Prevent multiple runs in same minute
                        {
                            _ = RunWorkflowAsync(wf.Id, ct);
                        }
                    }
                }
            }
        }
    }

    private void LoadWorkflows()
    {
        try
        {
            if (File.Exists(_workflowsFile))
            {
                string json = File.ReadAllText(_workflowsFile);
                var list = JsonSerializer.Deserialize<List<TetherWorkflow>>(json);
                if (list != null)
                {
                    foreach (var w in list)
                    {
                        _workflows[w.Id] = w;
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Warning($"AutomationEngine: Failed to load workflows: {ex.Message}");
        }

        // Add helpful default workflows if empty
        if (_workflows.IsEmpty)
        {
            var def1 = new TetherWorkflow
            {
                Id = "wf_sleep_lock",
                Name = "Desk Departure",
                IsEnabled = true,
                ScheduleType = "manual",
                ConditionType = "none",
                Actions = new List<string> { "volume_mute", "brightness_down", "lock_now" }
            };
            var def2 = new TetherWorkflow
            {
                Id = "wf_battery_saver",
                Name = "Low Battery Protocol",
                IsEnabled = true,
                ScheduleType = "interval",
                ScheduleValue = "15",
                ConditionType = "battery_below",
                ConditionValue = "20",
                Actions = new List<string> { "brightness_down", "volume_down" }
            };
            SaveWorkflow(def1);
            SaveWorkflow(def2);
        }
    }

    private void PersistWorkflows()
    {
        lock (_persistLock)
        {
            try
            {
                if (!Directory.Exists(_workflowsDir))
                {
                    Directory.CreateDirectory(_workflowsDir);
                }
                string json = JsonSerializer.Serialize(_workflows.Values.ToList(), new JsonSerializerOptions { WriteIndented = true });
                string tempFile = _workflowsFile + $".tmp_{Guid.NewGuid():N}";
                File.WriteAllText(tempFile, json);
                File.Move(tempFile, _workflowsFile, overwrite: true);
            }
            catch (Exception ex)
            {
                _logger.Warning($"AutomationEngine: Failed to persist workflows: {ex.Message}");
            }
        }
    }

    public void Dispose()
    {
        try { _cts.Cancel(); } catch { }
        try { _cts.Dispose(); } catch { }
    }
}

public sealed class TetherWorkflow
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public bool IsEnabled { get; set; } = true;
    public string ScheduleType { get; set; } = "manual"; // manual, interval, time
    public string ScheduleValue { get; set; } = "";
    public string ConditionType { get; set; } = "none";  // none, battery_below, battery_not_charging, process_running
    public string ConditionValue { get; set; } = "";
    public List<string> Actions { get; set; } = new();
    public long LastExecutedMs { get; set; }
    public string LastStatus { get; set; } = "NEVER";
    public string OriginatingDeviceId { get; set; } = string.Empty;
    public string OriginatingFingerprint { get; set; } = string.Empty;
}

public sealed class WorkflowExecutionResult
{
    public string WorkflowId { get; set; } = string.Empty;
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
}
