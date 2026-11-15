using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Tether.CommunicationService.Automation;
using Tether.Shared.Logging;
using Xunit;

namespace Tether.Tests;

public class TETH_BUG_001_AutomationLifecycleTests
{
    private readonly string _testDir;

    public TETH_BUG_001_AutomationLifecycleTests()
    {
        _testDir = Path.Combine(Path.GetTempPath(), "Tether_Bug001_Test_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_testDir);
    }

    [Fact]
    public async Task RunWorkflowAsync_ConditionNotMet_EvictsFromRunningWorkflows_CanRunAgain()
    {
        var logger = new TestLogger();
        var engine = new AutomationEngine(logger, null!, null, _testDir);

        // A workflow with a condition that fails: e.g., battery_below 0
        var wf = new TetherWorkflow
        {
            Id = "wf-cond-fail",
            Name = "Battery Low Check",
            ConditionType = "battery_below",
            ConditionValue = "0", // 0% battery is never met in practice
            Actions = new List<string> { "volume_mute" }
        };
        engine.SaveWorkflow(wf);

        // First run: condition will not be met
        var res1 = await engine.RunWorkflowAsync(wf.Id, CancellationToken.None);
        Assert.True(res1.Success);
        Assert.Contains("Condition not met", res1.Message);

        var stored = engine.GetWorkflows().Find(w => w.Id == wf.Id);
        Assert.NotNull(stored);
        Assert.Equal("SKIPPED_CONDITION", stored.LastStatus);

        // Crucial test: in TETH-BUG-001, previous buggy code left wf.Id in _runningWorkflows!
        // Run again to verify it is NOT stuck in "Workflow is already running"
        var res2 = await engine.RunWorkflowAsync(wf.Id, CancellationToken.None);
        Assert.NotEqual("Workflow is already running", res2.Message);
    }

    [Fact]
    public async Task RunWorkflowAsync_CancelledExecution_EvictsFromRunningWorkflows()
    {
        var logger = new TestLogger();
        var engine = new AutomationEngine(logger, null!, null, _testDir);

        var wf = new TetherWorkflow
        {
            Id = "wf-cancel-test",
            Name = "Cancel Workflow",
            ConditionType = "none",
            Actions = new List<string> { "volume_mute", "volume_up" }
        };
        engine.SaveWorkflow(wf);

        using var cts = new CancellationTokenSource();
        cts.Cancel(); // Pre-cancelled token

        try
        {
            await engine.RunWorkflowAsync(wf.Id, cts.Token);
        }
        catch (OperationCanceledException)
        {
            // Expected
        }

        // Verify that after cancellation, workflow is not stuck in _runningWorkflows
        var resAfterCancel = await engine.RunWorkflowAsync(wf.Id, CancellationToken.None);
        Assert.NotEqual("Workflow is already running", resAfterCancel.Message);
    }
}
