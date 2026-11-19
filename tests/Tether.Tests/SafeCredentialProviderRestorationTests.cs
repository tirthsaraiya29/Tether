using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Tether.PanicEngine;
using Tether.Shared.Logging;
using Xunit;

namespace Tether.Tests;

public class SafeCredentialProviderRestorationTests
{
    private readonly TestLogger _logger = new();

    private readonly Guid _provA = Guid.NewGuid();
    private readonly Guid _provB = Guid.NewGuid();
    private readonly Guid _provC = Guid.NewGuid();
    private readonly Guid _tetherProv = SafeCredentialFilterManager.TetherProviderGuid;

    [Fact]
    public void Filter_ProvidersInitiallyVisibleBeforePanicLock_HidesAlternatives_AndRestoresOnlyTetherHidden()
    {
        var store = new InMemoryPanicRestorationStore();
        var manager = new SafeCredentialFilterManager(_logger, store);

        var providers = new[] { _provA, _provB, _tetherProv };
        var allowStates = new[] { true, true, true }; // All initially visible

        // 1. Activate Panic Lock
        manager.ActivatePanicLock("session-init-vis");
        Assert.True(manager.IsPanicActive);

        // 2. Apply filtering
        manager.ApplyFilter(providers, allowStates);

        // Verify alternatives are hidden while Tether remains visible
        Assert.False(allowStates[0], "Provider A should be hidden during Panic Lock");
        Assert.False(allowStates[1], "Provider B should be hidden during Panic Lock");
        Assert.True(allowStates[2], "Tether Credential Provider must remain visible");

        // Verify tracking captured ownership and original visibility
        var tracked = manager.GetTrackedProviders();
        var trackA = tracked.FirstOrDefault(p => p.ProviderId == _provA);
        var trackB = tracked.FirstOrDefault(p => p.ProviderId == _provB);

        Assert.NotNull(trackA);
        Assert.True(trackA.OriginalVisibility);
        Assert.True(trackA.HiddenByTether);

        Assert.NotNull(trackB);
        Assert.True(trackB.OriginalVisibility);
        Assert.True(trackB.HiddenByTether);

        // 3. Deactivate Panic Lock & Restore
        manager.DeactivatePanicLock();
        Assert.False(manager.IsPanicActive);

        bool restored = manager.Restore(providers, allowStates);
        Assert.True(restored);

        // 4. Verify only Tether-hidden providers are restored
        Assert.True(allowStates[0], "Provider A should be restored to visible");
        Assert.True(allowStates[1], "Provider B should be restored to visible");
        Assert.True(allowStates[2], "Tether Provider remains visible");
    }

    [Fact]
    public void Filter_ProvidersAlreadyHiddenBeforePanicLock_NeverUnhidesOnUnlock()
    {
        var store = new InMemoryPanicRestorationStore();
        var manager = new SafeCredentialFilterManager(_logger, store);

        var providers = new[] { _provA, _provB, _tetherProv };
        var allowStates = new[] { false, false, true }; // A and B already hidden by Windows or domain policy

        // 1. Activate Panic Lock
        manager.ActivatePanicLock("session-pre-hidden");

        // 2. Apply filtering
        manager.ApplyFilter(providers, allowStates);

        Assert.False(allowStates[0]);
        Assert.False(allowStates[1]);
        Assert.True(allowStates[2]);

        // Verify Tether does NOT claim ownership of pre-hidden tiles
        var tracked = manager.GetTrackedProviders();
        var trackA = tracked.FirstOrDefault(p => p.ProviderId == _provA);
        var trackB = tracked.FirstOrDefault(p => p.ProviderId == _provB);

        Assert.NotNull(trackA);
        Assert.False(trackA.OriginalVisibility);
        Assert.False(trackA.HiddenByTether, "Tether must not claim ownership of pre-hidden provider A");

        Assert.NotNull(trackB);
        Assert.False(trackB.OriginalVisibility);
        Assert.False(trackB.HiddenByTether, "Tether must not claim ownership of pre-hidden provider B");

        // 3. Deactivate Panic Lock & Restore
        manager.DeactivatePanicLock();
        bool restored = manager.Restore(providers, allowStates);
        Assert.True(restored);

        // 4. Verify pre-hidden providers are NEVER unhidden
        Assert.False(allowStates[0], "Pre-hidden provider A must remain hidden after unlock");
        Assert.False(allowStates[1], "Pre-hidden provider B must remain hidden after unlock");
        Assert.True(allowStates[2]);
    }

    [Fact]
    public void Filter_MixedVisibilityStates_RestoresOnlyTetherHiddenProviders()
    {
        var store = new InMemoryPanicRestorationStore();
        var manager = new SafeCredentialFilterManager(_logger, store);

        var providers = new[] { _provA, _provB, _provC, _tetherProv };
        var allowStates = new[] { true, false, true, true }; // A is visible, B is already hidden, C is visible

        manager.ActivatePanicLock("session-mixed");
        manager.ApplyFilter(providers, allowStates);

        Assert.False(allowStates[0]);
        Assert.False(allowStates[1]);
        Assert.False(allowStates[2]);
        Assert.True(allowStates[3]);

        manager.DeactivatePanicLock();
        bool restored = manager.Restore(providers, allowStates);
        Assert.True(restored);

        // A and C were visible before Panic Lock -> Restored
        // B was hidden before Panic Lock -> Remains hidden
        Assert.True(allowStates[0], "Initially visible provider A must be restored");
        Assert.False(allowStates[1], "Pre-hidden provider B must remain hidden");
        Assert.True(allowStates[2], "Initially visible provider C must be restored");
        Assert.True(allowStates[3], "Tether must remain visible");
    }

    [Fact]
    public void Filter_RepeatedPanicLockActivationAndDeactivation_IsConsistentAndIdempotent()
    {
        var store = new InMemoryPanicRestorationStore();
        var manager = new SafeCredentialFilterManager(_logger, store);

        var providers = new[] { _provA, _provB, _tetherProv };

        for (int cycle = 1; cycle <= 3; cycle++)
        {
            var allowStates = new[] { true, false, true }; // A is visible, B is pre-hidden

            manager.ActivatePanicLock($"session-cycle-{cycle}");
            Assert.True(manager.IsPanicActive);

            manager.ApplyFilter(providers, allowStates);
            Assert.False(allowStates[0]);
            Assert.False(allowStates[1]);
            Assert.True(allowStates[2]);

            manager.DeactivatePanicLock();
            Assert.False(manager.IsPanicActive);

            // First restoration
            bool r1 = manager.Restore(providers, allowStates);
            Assert.True(r1);
            Assert.True(allowStates[0]);
            Assert.False(allowStates[1]);
            Assert.True(allowStates[2]);

            // Repeated restoration call must be strictly idempotent
            bool r2 = manager.Restore(providers, allowStates);
            Assert.True(r2);
            Assert.True(allowStates[0]);
            Assert.False(allowStates[1]);
            Assert.True(allowStates[2]);
        }
    }

    [Fact]
    public void Filter_LogonUiReEnumeration_PreservesOriginalStateAndOwnershipAcrossMultipleCalls()
    {
        var store = new InMemoryPanicRestorationStore();
        var manager = new SafeCredentialFilterManager(_logger, store);

        var providers = new[] { _provA, _provB, _tetherProv };
        var allowStates = new[] { true, false, true }; // A is visible, B is pre-hidden

        manager.ActivatePanicLock("session-reenum");

        // Call 1: Initial enumeration
        manager.ApplyFilter(providers, allowStates);
        Assert.False(allowStates[0]);
        Assert.False(allowStates[1]);
        Assert.True(allowStates[2]);

        // Call 2: LogonUI re-enumerates. In the second call, incoming allowStates are [false, false, true]
        // because of the previous filtering pass.
        manager.ApplyFilter(providers, allowStates);
        Assert.False(allowStates[0]);
        Assert.False(allowStates[1]);
        Assert.True(allowStates[2]);

        // Call 3: Another re-enumeration (e.g. smart card or token event)
        manager.ApplyFilter(providers, allowStates);

        // Verify tracking didn't forget that Tether hid A in this session
        var tracked = manager.GetTrackedProviders();
        var trackA = tracked.First(p => p.ProviderId == _provA);
        Assert.True(trackA.OriginalVisibility, "A's original visibility must still be true");
        Assert.True(trackA.HiddenByTether, "A must still be owned by Tether");

        var trackB = tracked.First(p => p.ProviderId == _provB);
        Assert.False(trackB.OriginalVisibility);
        Assert.False(trackB.HiddenByTether);

        // Unlock
        manager.DeactivatePanicLock();
        manager.Restore(providers, allowStates);

        Assert.True(allowStates[0], "A was hid by Tether, must be restored");
        Assert.False(allowStates[1], "B was already hidden before Panic Lock, must stay hidden");
        Assert.True(allowStates[2]);
    }

    [Fact]
    public void Filter_TetherServiceRestartDuringPanicLock_PreservesOwnershipAndRestoresCorrectly()
    {
        var store = new InMemoryPanicRestorationStore();

        // 1. Service instance 1 activates Panic Lock and captures state
        var manager1 = new SafeCredentialFilterManager(_logger, store);
        var providers = new[] { _provA, _provB, _tetherProv };
        var allowStates = new[] { true, false, true };

        manager1.ActivatePanicLock("session-survive-restart");
        manager1.ApplyFilter(providers, allowStates);

        Assert.False(allowStates[0]);
        Assert.False(allowStates[1]);

        // 2. Simulate service restart: create manager2 connecting to the same store
        var manager2 = new SafeCredentialFilterManager(_logger, store);

        Assert.True(manager2.IsPanicActive, "Panic Lock must remain active after restart");
        Assert.Equal("session-survive-restart", manager2.ActiveSessionId);

        // Re-enumeration after restart
        manager2.ApplyFilter(providers, allowStates);
        Assert.False(allowStates[0]);
        Assert.False(allowStates[1]);

        // 3. Unlock after restart
        manager2.DeactivatePanicLock();
        bool restored = manager2.Restore(providers, allowStates);
        Assert.True(restored);

        Assert.True(allowStates[0], "Provider A must be restored after service restart");
        Assert.False(allowStates[1], "Pre-hidden Provider B must remain hidden after service restart");
        Assert.True(allowStates[2]);
    }

    [Fact]
    public void Filter_InterruptedOrIncompleteRestoration_HandlesGracefullyAndFailsSafely()
    {
        var store = new InMemoryPanicRestorationStore();
        var manager = new SafeCredentialFilterManager(_logger, store);

        var providers = new[] { _provA, _provB, _tetherProv };
        var allowStates = new[] { true, true, true };

        manager.ActivatePanicLock("session-interrupted");
        manager.ApplyFilter(providers, allowStates);
        manager.DeactivatePanicLock();

        // Simulate partial / segmented restoration: only provider A is passed
        var partialProviders = new[] { _provA };
        var partialAllow = new[] { false };

        bool p1 = manager.Restore(partialProviders, partialAllow);
        Assert.True(p1);
        Assert.True(partialAllow[0], "Provider A should be restored in first pass");

        // Second pass: provider B and Tether are passed
        var remainingProviders = new[] { _provB, _tetherProv };
        var remainingAllow = new[] { false, true };

        bool p2 = manager.Restore(remainingProviders, remainingAllow);
        Assert.True(p2);
        Assert.True(remainingAllow[0], "Provider B should be restored in second pass");
        Assert.True(remainingAllow[1]);

        // Third pass with empty/invalid inputs fails safely without throwing
        Assert.False(manager.Restore(Array.Empty<Guid>(), new[] { true }));
        Assert.False(manager.Restore(null!, null!));
    }

    [Fact]
    public async Task Filter_ConcurrentFilteringAndUnlockOperations_IsThreadSafeAndRaceFree()
    {
        var store = new InMemoryPanicRestorationStore();
        var manager = new SafeCredentialFilterManager(_logger, store);

        var providers = new[] { _provA, _provB, _provC, _tetherProv };
        var exceptions = new System.Collections.Concurrent.ConcurrentBag<Exception>();

        var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3));

        var filterTask = Task.Run(() =>
        {
            while (!cts.IsCancellationRequested)
            {
                try
                {
                    var allow = new[] { true, false, true, true };
                    manager.ApplyFilter(providers, allow);
                    Thread.Sleep(1);
                }
                catch (Exception ex)
                {
                    exceptions.Add(ex);
                }
            }
        });

        var stateToggleTask = Task.Run(() =>
        {
            int counter = 0;
            while (!cts.IsCancellationRequested)
            {
                try
                {
                    if (counter++ % 2 == 0)
                        manager.ActivatePanicLock($"concurrent-sess-{counter}");
                    else
                        manager.DeactivatePanicLock();

                    Thread.Sleep(2);
                }
                catch (Exception ex)
                {
                    exceptions.Add(ex);
                }
            }
        });

        var restoreTask = Task.Run(() =>
        {
            while (!cts.IsCancellationRequested)
            {
                try
                {
                    var allow = new[] { false, false, false, true };
                    manager.Restore(providers, allow);
                    Thread.Sleep(1);
                }
                catch (Exception ex)
                {
                    exceptions.Add(ex);
                }
            }
        });

        await Task.WhenAll(filterTask, stateToggleTask, restoreTask);

        Assert.Empty(exceptions);
    }

    [Fact]
    public void Filter_AttemptsByUnprivilegedProcessesToTamperWithRestorationState_RejectedOrFailSafe()
    {
        var store = new InMemoryPanicRestorationStore();
        var manager = new SafeCredentialFilterManager(_logger, store);

        var providers = new[] { _provA, _tetherProv };
        var allowStates = new[] { true, true };

        manager.ActivatePanicLock("session-tamper-test");
        manager.ApplyFilter(providers, allowStates);

        // 1. Simulate unprivileged access denial during Save / Load
        store.SimulateUnauthorizedAccess = true;
        Assert.False(store.VerifyAccessAcl());

        // Attempt to save state under simulated unauthorized access throws UnauthorizedAccessException
        Assert.Throws<UnauthorizedAccessException>(() => store.Save(new PanicLockSessionState()));

        // Restore unauthorized access
        store.SimulateUnauthorizedAccess = false;

        // 2. Simulate cryptographic digest tampering (e.g. attacker modifying SessionData directly)
        store.SimulateTampering = true;

        // Load must detect tampering and return null (fails safe)
        var loaded = store.Load();
        Assert.Null(loaded);

        // In a new manager instance with tampered store, initialization fails safe
        var tamperSafeManager = new SafeCredentialFilterManager(_logger, store);
        Assert.False(tamperSafeManager.IsPanicActive, "Tampered state must not be trusted");

        var attemptAllow = new[] { false, false };
        bool restoreResult = tamperSafeManager.Restore(providers, attemptAllow);
        Assert.False(restoreResult, "Restoration must fail safely when state cannot be established reliably");
        Assert.False(attemptAllow[0], "Tampered state must not blindly unhide providers");
    }

    [Fact]
    public void Filter_OutsidePanicLock_PreservesIncomingFilteringBehavior()
    {
        var store = new InMemoryPanicRestorationStore();
        var manager = new SafeCredentialFilterManager(_logger, store);

        var providers = new[] { _provA, _provB, _tetherProv };
        var allowStates = new[] { true, false, true }; // Pre-existing states from earlier filters

        // Outside Panic Lock
        Assert.False(manager.IsPanicActive);
        manager.ApplyFilter(providers, allowStates);

        // Exact preservation of incoming decisions
        Assert.True(allowStates[0]);
        Assert.False(allowStates[1]);
        Assert.True(allowStates[2]);
    }

    [Fact]
    public void Filter_IncomingDenialOnTetherProvider_IsNeverReversed_ByFilterOrRestore()
    {
        var store = new InMemoryPanicRestorationStore();
        var manager = new SafeCredentialFilterManager(_logger, store);

        var providers = new[] { _provA, _tetherProv };
        var allowStates = new[] { true, false }; // Tether provider already denied by another filter or policy

        manager.ActivatePanicLock("session-tether-denied");
        manager.ApplyFilter(providers, allowStates);

        // Tether provider denial must be preserved!
        Assert.False(allowStates[0], "Alternative provider hidden during panic");
        Assert.False(allowStates[1], "Existing denial of Tether provider must NEVER be reversed");

        manager.DeactivatePanicLock("session-tether-denied");
        bool restored = manager.Restore(providers, allowStates);
        Assert.True(restored);

        Assert.True(allowStates[0], "Alternative provider restored");
        Assert.False(allowStates[1], "Tether provider denial remains strictly preserved after restore");
    }

    [Fact]
    public void Filter_MultipleCooperatingFilters_PreservesAllPriorDenials()
    {
        var store = new InMemoryPanicRestorationStore();
        var manager = new SafeCredentialFilterManager(_logger, store);

        var providers = new[] { _provA, _provB, _provC, _tetherProv };
        // Suppose Filter 1 already denied ProvB and TetherProv
        var allowStates = new[] { true, false, true, false };

        manager.ActivatePanicLock("session-cooperating-filters");
        manager.ApplyFilter(providers, allowStates);

        // ProvA and ProvC should be hidden by Tether; ProvB and TetherProv remain denied
        Assert.False(allowStates[0]);
        Assert.False(allowStates[1]);
        Assert.False(allowStates[2]);
        Assert.False(allowStates[3]);

        manager.DeactivatePanicLock("session-cooperating-filters");
        bool restored = manager.Restore(providers, allowStates);
        Assert.True(restored);

        // ProvA and ProvC restored (since Tether hid them and they were originally allowed)
        Assert.True(allowStates[0]);
        Assert.False(allowStates[1], "ProvB was denied by prior filter and must remain denied");
        Assert.True(allowStates[2]);
        Assert.False(allowStates[3], "TetherProv was denied by prior filter and must remain denied");
    }

    [Fact]
    public void PanicManager_Lifecycle_SessionAwareTransitions_RejectMismatchedOrStaleEvents()
    {
        var eventBus = new Tether.EventBus.InMemoryEventBus(_logger);
        var store = new InMemoryPanicRestorationStore();
        var filterManager = new SafeCredentialFilterManager(_logger, store);
        var panicManager = new PanicManager(eventBus, _logger, filterManager);

        // 1. Trigger panic with specific session
        string activeSession = panicManager.TriggerPanic("session-abc", sequenceNumber: 10);
        Assert.Equal("session-abc", activeSession);
        Assert.True(filterManager.IsPanicActive);
        Assert.Equal("session-abc", panicManager.ActivePanicSessionId);

        // 2. Attempt unlock with wrong session ID -> must be rejected
        bool wrongUnlock = panicManager.ClearPanic("session-wrong", sequenceNumber: 11);
        Assert.False(wrongUnlock);
        Assert.True(filterManager.IsPanicActive, "Panic must remain active after mismatched session unlock attempt");

        // 3. Attempt unlock with stale sequence number -> must be rejected
        bool staleUnlock = panicManager.ClearPanic("session-abc", sequenceNumber: 5);
        Assert.False(staleUnlock);
        Assert.True(filterManager.IsPanicActive, "Panic must remain active after stale sequence unlock attempt");

        // 4. Correct unlock with matching session and valid sequence number -> success
        bool validUnlock = panicManager.ClearPanic("session-abc", sequenceNumber: 12);
        Assert.True(validUnlock);
        Assert.False(filterManager.IsPanicActive);
        Assert.Null(panicManager.ActivePanicSessionId);
    }

    [Fact]
    public void PanicManager_PersistenceFailure_AbortsActivationAndPropagatesException()
    {
        var eventBus = new Tether.EventBus.InMemoryEventBus(_logger);
        var store = new InMemoryPanicRestorationStore();
        store.SimulateSaveFailure = true; // Simulate write failure

        var filterManager = new SafeCredentialFilterManager(_logger, store);
        var panicManager = new PanicManager(eventBus, _logger, filterManager);

        Assert.Throws<System.IO.IOException>(() => panicManager.TriggerPanic("fail-session"));
        Assert.Null(panicManager.ActivePanicSessionId);
        Assert.False(filterManager.IsPanicActive);
    }
}
