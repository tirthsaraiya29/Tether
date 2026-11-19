using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Tether.PanicEngine;
using Tether.Shared.Logging;
using Microsoft.Win32;
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

    [Fact]
    public void ManagedNativeStateSynchronization_NativeHiddenProvidersMergedOnLoad()
    {
        var store = new InMemoryPanicRestorationStore();

        // 1. Initial activation from managed side
        var manager1 = new SafeCredentialFilterManager(_logger, store);
        manager1.ActivatePanicLock("sess-sync-1");

        // 2. Simulate native filter running in LogonUI and recording ProvA
        store.SimulatedHiddenProviders.Add(_provA);

        // 3. New manager instance loads from store (service restart or re-read)
        var manager2 = new SafeCredentialFilterManager(_logger, store);
        var tracked = manager2.GetTrackedProviders();

        Assert.True(manager2.IsPanicActive);
        var trackA = tracked.FirstOrDefault(p => p.ProviderId == _provA);
        Assert.NotNull(trackA);
        Assert.True(trackA.HiddenByTether);
        Assert.True(trackA.OriginalVisibility);

        // 4. Managed manager adds ProvB and saves
        var providers = new[] { _provA, _provB, _tetherProv };
        var allowStates = new[] { false, true, true }; // ProvA already hidden natively, ProvB newly encountered
        manager2.ApplyFilter(providers, allowStates);

        // Both ProvA (native) and ProvB (managed) must be retained
        Assert.Contains(_provA, store.SimulatedHiddenProviders);
        Assert.Contains(_provB, store.SimulatedHiddenProviders);
    }

    [Fact]
    public void UnlockAfterNativeOnlyProviderTracking_RestoresExclusivelyTetherHidden()
    {
        var store = new InMemoryPanicRestorationStore();

        // Save session where only native filter recorded hidden providers
        var nativeSession = new PanicLockSessionState
        {
            SessionId = "sess-native-only",
            IsPanicActive = true,
            ActivatedAt = DateTimeOffset.UtcNow
        };
        store.Save(nativeSession);
        store.SimulatedHiddenProviders.Add(_provA);

        // Service starts up with native-only tracking
        var manager = new SafeCredentialFilterManager(_logger, store);
        Assert.True(manager.IsPanicActive);

        var providers = new[] { _provA, _provB, _tetherProv };
        var allowStates = new[] { false, false, true }; // ProvA hidden by native filter, ProvB pre-hidden

        // Unlock
        manager.DeactivatePanicLock("sess-native-only");
        Assert.False(manager.IsPanicActive);

        bool restored = manager.Restore(providers, allowStates);
        Assert.True(restored);

        Assert.True(allowStates[0], "Native-tracked ProvA must be restored upon unlock");
        Assert.False(allowStates[1], "Pre-hidden ProvB must remain hidden");
        Assert.True(allowStates[2]);
    }

    [Fact]
    public void RepeatedActivationDuringExistingPanicSession_IsIdempotentAndPreservesOwnership()
    {
        var eventBus = new Tether.EventBus.InMemoryEventBus(_logger);
        var store = new InMemoryPanicRestorationStore();
        var filterManager = new SafeCredentialFilterManager(_logger, store);
        var panicManager = new PanicManager(eventBus, _logger, filterManager);

        var providers = new[] { _provA, _tetherProv };
        var allowStates = new[] { true, true };

        // 1. Initial activation
        string session1 = panicManager.TriggerPanic("session-initial", sequenceNumber: 1);
        Assert.Equal("session-initial", session1);
        filterManager.ApplyFilter(providers, allowStates);
        Assert.False(allowStates[0]);

        var tracked1 = filterManager.GetTrackedProviders();
        Assert.Single(tracked1);
        Assert.True(tracked1[0].HiddenByTether);

        // 2. Repeated activation attempt during active panic
        string session2 = panicManager.TriggerPanic("session-duplicate", sequenceNumber: 2);
        Assert.Equal("session-initial", session2); // Must return existing session, not replace
        Assert.Equal("session-initial", panicManager.ActivePanicSessionId);

        // Calling FilterManager directly with another session must also be strictly idempotent
        filterManager.ActivatePanicLock("session-another");
        Assert.Equal("session-initial", filterManager.ActiveSessionId);

        // Verify tracked providers were not wiped or reset
        var tracked2 = filterManager.GetTrackedProviders();
        Assert.Single(tracked2);
        Assert.Equal(_provA, tracked2[0].ProviderId);
        Assert.True(tracked2[0].HiddenByTether);

        // 3. Stale sequence activation rejected
        string staleSession = panicManager.TriggerPanic("session-stale", sequenceNumber: 1);
        Assert.Equal("session-initial", staleSession);
    }

    [Fact]
    public void FailedRegistryWritesAndDeletions_PreservesActivePanicStateAndRecoveryInfo()
    {
        var store = new InMemoryPanicRestorationStore();
        var manager = new SafeCredentialFilterManager(_logger, store);

        manager.ActivatePanicLock("sess-fail-deact");
        Assert.True(manager.IsPanicActive);

        // Simulate registry write failure during deactivation
        store.SimulateSaveFailure = true;

        Assert.Throws<System.IO.IOException>(() => manager.DeactivatePanicLock());

        // CRITICAL INVARIANT: Active panic state must be preserved if persistence fails!
        Assert.True(manager.IsPanicActive, "Panic state must remain active if deactivation cannot be persisted!");

        // In PanicManager:
        var eventBus = new Tether.EventBus.InMemoryEventBus(_logger);
        var panicManager = new PanicManager(eventBus, _logger, manager);
        bool unlockResult = panicManager.ClearPanic("sess-fail-deact", sequenceNumber: 5);
        Assert.False(unlockResult);
        Assert.Equal("sess-fail-deact", panicManager.ActivePanicSessionId);

        // Remove simulated failure and complete deactivation
        store.SimulateSaveFailure = false;
        bool validUnlock = panicManager.ClearPanic("sess-fail-deact", sequenceNumber: 6);
        Assert.True(validUnlock);
        Assert.False(manager.IsPanicActive);
        Assert.Null(panicManager.ActivePanicSessionId);
    }

    [Fact]
    public void ProvidersAbsentDuringFirstRestorationEnumeration_RetainedUntilSubsequentRestoration()
    {
        var store = new InMemoryPanicRestorationStore();
        var manager = new SafeCredentialFilterManager(_logger, store);

        var allProviders = new[] { _provA, _provB, _tetherProv };
        var allAllow = new[] { true, true, true };

        manager.ActivatePanicLock("sess-partial-enum");
        manager.ApplyFilter(allProviders, allAllow);

        manager.DeactivatePanicLock("sess-partial-enum");

        // Pass 1: Only ProvA is enumerated by LogonUI (ProvB is absent)
        var pass1Providers = new[] { _provA, _tetherProv };
        var pass1Allow = new[] { false, true };

        bool r1 = manager.Restore(pass1Providers, pass1Allow);
        Assert.True(r1);
        Assert.True(pass1Allow[0], "ProvA must be restored in first pass");

        // ProvB was absent: its ownership record must be RETAINED!
        var trackedAfterPass1 = manager.GetTrackedProviders();
        Assert.Single(trackedAfterPass1);
        Assert.Equal(_provB, trackedAfterPass1[0].ProviderId);
        Assert.True(trackedAfterPass1[0].HiddenByTether);

        // Pass 2: ProvB is enumerated
        var pass2Providers = new[] { _provB, _tetherProv };
        var pass2Allow = new[] { false, true };

        bool r2 = manager.Restore(pass2Providers, pass2Allow);
        Assert.True(r2);
        Assert.True(pass2Allow[0], "ProvB must be restored in second pass");

        // Now all providers have been successfully restored
        var trackedFinal = manager.GetTrackedProviders();
        Assert.Empty(trackedFinal);
    }

    [Fact]
    public void ThirdPartyDenialIntroducedAfterTetherHidesProvider_PreservesDenial()
    {
        var store = new InMemoryPanicRestorationStore();
        var manager = new SafeCredentialFilterManager(_logger, store);

        var providers = new[] { _provA, _provB, _tetherProv };
        var allowStates = new[] { true, true, true };

        // 1. Tether hides both ProvA and ProvB
        manager.ActivatePanicLock("sess-3rdparty");
        manager.ApplyFilter(providers, allowStates);
        Assert.False(allowStates[0]);
        Assert.False(allowStates[1]);

        // 2. An independent filter / policy introduces a denial for ProvB AFTER Tether hid it
        bool revoked = manager.RecordIndependentDenial(_provB);
        Assert.True(revoked);

        // 3. Unlock and restore
        manager.DeactivatePanicLock("sess-3rdparty");

        bool restored = manager.Restore(providers, allowStates);
        Assert.True(restored);

        // ProvA was restored:
        Assert.True(allowStates[0], "ProvA must be restored");
        // ProvB was independently denied: NEVER reverse an independently imposed filtering denial!
        Assert.False(allowStates[1], "ProvB must remain denied after third-party denial was introduced");
        Assert.True(allowStates[2]);
    }

    [Fact]
    public void ServiceRestartDuringActivationAndDeactivation_PreservesSessionState()
    {
        var store = new InMemoryPanicRestorationStore();

        // 1. Restart during active panic
        var m1 = new SafeCredentialFilterManager(_logger, store);
        m1.ActivatePanicLock("sess-restart-active");
        var provs = new[] { _provA, _tetherProv };
        var allow = new[] { true, true };
        m1.ApplyFilter(provs, allow);

        var m2 = new SafeCredentialFilterManager(_logger, store);
        Assert.True(m2.IsPanicActive, "Must preserve active panic state across restart");
        Assert.Equal("sess-restart-active", m2.ActiveSessionId);
        Assert.Single(m2.GetTrackedProviders());

        // 2. Restart after deactivation before restoration completed
        m2.DeactivatePanicLock("sess-restart-active");
        Assert.False(m2.IsPanicActive);

        // Service restarts right after deactivation before LogonUI called Restore
        var m3 = new SafeCredentialFilterManager(_logger, store);
        Assert.False(m3.IsPanicActive);
        Assert.Equal("sess-restart-active", m3.ActiveSessionId);
        // Ownership records must NOT be lost on restart!
        Assert.Single(m3.GetTrackedProviders());
        Assert.Equal(_provA, m3.GetTrackedProviders()[0].ProviderId);

        // Restoration executes in restarted instance
        bool restored = m3.Restore(provs, allow);
        Assert.True(restored);
        Assert.True(allow[0]);
    }

    [Fact]
    public void WindowsRegistryPanicStore_FailureSafeDeactivation_WritesIsPanicActiveLast()
    {
        const string testKey = @"Software\Tether\TestAtomicDeactivation";
        Registry.CurrentUser.DeleteSubKeyTree(testKey, false);

        try
        {
            var store = new WindowsRegistryPanicStore(_logger, Registry.CurrentUser, testKey);
            var manager = new SafeCredentialFilterManager(_logger, store);

            var providers = new[] { _provA, _tetherProv };
            var allowStates = new[] { true, true };

            manager.ActivatePanicLock("sess-atomic-deact");
            manager.ApplyFilter(providers, allowStates);

            using (var key = Registry.CurrentUser.OpenSubKey(testKey, false))
            {
                Assert.NotNull(key);
                Assert.Equal(1, key.GetValue("IsPanicActive"));
            }

            // Normal deactivation writes SessionData and IntegrityDigest first, then IsPanicActive = 0
            manager.DeactivatePanicLock("sess-atomic-deact");

            using (var key = Registry.CurrentUser.OpenSubKey(testKey, false))
            {
                Assert.NotNull(key);
                Assert.Equal(0, key.GetValue("IsPanicActive"));
                Assert.NotNull(key.GetValue("SessionData"));
                Assert.NotNull(key.GetValue("IntegrityDigest"));
            }
        }
        finally
        {
            Registry.CurrentUser.DeleteSubKeyTree(testKey, false);
        }
    }

    [Fact]
    public void WindowsRegistryPanicStore_MissingOrMalformedIsPanicActive_RefusesRestoration()
    {
        const string testKey = @"Software\Tether\TestMalformedActive";
        Registry.CurrentUser.DeleteSubKeyTree(testKey, false);

        try
        {
            var store = new WindowsRegistryPanicStore(_logger, Registry.CurrentUser, testKey);
            var manager = new SafeCredentialFilterManager(_logger, store);

            manager.ActivatePanicLock("sess-malformed-active");
            var providers = new[] { _provA, _tetherProv };
            var allowStates = new[] { true, true };
            manager.ApplyFilter(providers, allowStates);

            // Corrupt IsPanicActive in registry: change from DWORD to string
            using (var key = Registry.CurrentUser.OpenSubKey(testKey, true))
            {
                Assert.NotNull(key);
                key.SetValue("IsPanicActive", "malformed_string_val", RegistryValueKind.String);
            }

            // Load must fail closed on malformed state: return null!
            var loaded = store.Load();
            Assert.Null(loaded);

            // Starting a new manager with this store fails closed to an inactive empty state, never restoring
            var newManager = new SafeCredentialFilterManager(_logger, store);
            Assert.False(newManager.IsPanicActive);
            Assert.Empty(newManager.GetTrackedProviders());
        }
        finally
        {
            Registry.CurrentUser.DeleteSubKeyTree(testKey, false);
        }
    }

    [Fact]
    public void WindowsRegistryPanicStore_PartialWritesToSessionDataAndIntegrityDigest_RefusesRestoration()
    {
        const string testKey = @"Software\Tether\TestPartialWrites";
        Registry.CurrentUser.DeleteSubKeyTree(testKey, false);

        try
        {
            var store = new WindowsRegistryPanicStore(_logger, Registry.CurrentUser, testKey);
            var manager = new SafeCredentialFilterManager(_logger, store);

            manager.ActivatePanicLock("sess-partial-write");
            var providers = new[] { _provA, _tetherProv };
            var allowStates = new[] { true, true };
            manager.ApplyFilter(providers, allowStates);

            // Corrupt IntegrityDigest (simulating partial write or tampering)
            using (var key = Registry.CurrentUser.OpenSubKey(testKey, true))
            {
                Assert.NotNull(key);
                var digest = key.GetValue("IntegrityDigest") as byte[];
                Assert.NotNull(digest);
                digest[0] ^= 0xFF; // Flip byte
                key.SetValue("IntegrityDigest", digest, RegistryValueKind.Binary);
            }

            // Load must detect mismatch and return null
            var loaded = store.Load();
            Assert.Null(loaded);
        }
        finally
        {
            Registry.CurrentUser.DeleteSubKeyTree(testKey, false);
        }
    }

    [Fact]
    public void WindowsRegistryPanicStore_ManagedRestorationOfNativeOnlyOwnershipRecords_RemovesFromRegistry()
    {
        const string testKey = @"Software\Tether\TestNativeOnlyRestore";
        Registry.CurrentUser.DeleteSubKeyTree(testKey, false);

        try
        {
            var store = new WindowsRegistryPanicStore(_logger, Registry.CurrentUser, testKey);
            var manager = new SafeCredentialFilterManager(_logger, store);

            manager.ActivatePanicLock("sess-native-restore");

            // Native filter independently captured ProvB and wrote it to HiddenProviders in registry
            using (var key = Registry.CurrentUser.OpenSubKey(testKey, true))
            {
                Assert.NotNull(key);
                key.SetValue("HiddenProviders", new[] { _provB.ToString("B") }, RegistryValueKind.MultiString);
            }

            // Service restarts and loads registry state
            var restartedManager = new SafeCredentialFilterManager(_logger, store);
            Assert.True(restartedManager.IsPanicActive);

            var tracked = restartedManager.GetTrackedProviders();
            Assert.Contains(tracked, p => p.ProviderId == _provB);

            // Deactivate and restore ProvB
            restartedManager.DeactivatePanicLock("sess-native-restore");
            var restoreProvs = new[] { _provB, _tetherProv };
            var restoreAllow = new[] { false, true };

            bool restored = restartedManager.Restore(restoreProvs, restoreAllow);
            Assert.True(restored);
            Assert.True(restoreAllow[0]);

            // Verified: ProvB was removed from HiddenProviders in the registry!
            using (var key = Registry.CurrentUser.OpenSubKey(testKey, false))
            {
                Assert.NotNull(key);
                var hiddenAfter = key.GetValue("HiddenProviders") as string[];
                Assert.True(hiddenAfter == null || !hiddenAfter.Any(s => s.Contains(_provB.ToString())));
            }
        }
        finally
        {
            Registry.CurrentUser.DeleteSubKeyTree(testKey, false);
        }
    }

    [Fact]
    public void WindowsRegistryPanicStore_StaleOwnershipRecordsAfterSuccessfulRestoration_NotResurrectedBySave()
    {
        const string testKey = @"Software\Tether\TestNoResurrection";
        Registry.CurrentUser.DeleteSubKeyTree(testKey, false);

        try
        {
            var store = new WindowsRegistryPanicStore(_logger, Registry.CurrentUser, testKey);
            var manager = new SafeCredentialFilterManager(_logger, store);

            manager.ActivatePanicLock("sess-resurrect");
            var providers = new[] { _provA, _tetherProv };
            var allowStates = new[] { true, true };
            manager.ApplyFilter(providers, allowStates);

            // Deactivate and restore ProvA
            manager.DeactivatePanicLock("sess-resurrect");
            bool restored = manager.Restore(providers, allowStates);
            Assert.True(restored);
            Assert.True(allowStates[0]);

            // Now perform another save or filtering operation
            var session = store.Load();
            Assert.NotNull(session);
            Assert.Contains(_provA.ToString("D"), session.RestoredProviders);

            // Calling Save on the store must NOT resurrect ProvA into HiddenProviders
            store.Save(session);

            using (var key = Registry.CurrentUser.OpenSubKey(testKey, false))
            {
                Assert.NotNull(key);
                var hiddenAfter = key.GetValue("HiddenProviders") as string[];
                Assert.True(hiddenAfter == null || !hiddenAfter.Any(s => s.Contains(_provA.ToString())));
            }
        }
        finally
        {
            Registry.CurrentUser.DeleteSubKeyTree(testKey, false);
        }
    }

    [Fact]
    public void InMemoryStore_Simulation_UnexpectedAceAndUnauthorizedAllow_Rejected()
    {
        var store = new InMemoryPanicRestorationStore();

        Assert.True(store.VerifyAccessAcl());

        store.SimulateUnexpectedAce = true;
        Assert.False(store.VerifyAccessAcl(), "Must reject unexpected ACE type");
        store.SimulateUnexpectedAce = false;

        store.SimulateUnauthorizedAllow = true;
        Assert.False(store.VerifyAccessAcl(), "Must reject unauthorized allow ACE");
        store.SimulateUnauthorizedAllow = false;

        store.SimulatePartialWriteSessionData = true;
        var state = new PanicLockSessionState { SessionId = "test", IsPanicActive = true };
        Assert.Throws<System.IO.IOException>(() => store.Save(state));
    }
}
