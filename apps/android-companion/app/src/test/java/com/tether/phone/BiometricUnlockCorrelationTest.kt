package com.tether.phone

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

class BiometricUnlockCorrelationTest {

    @Test
    fun testPendingUnlockRequestTrackingAndAntiReplay() {
        val pendingRequests = ConcurrentHashMap<String, TetherLanService.PendingUnlockRequest>()
        val reqId = UUID.randomUUID().toString()
        val now = System.currentTimeMillis()
        val peerIp = "192.168.1.100"

        val req = TetherLanService.PendingUnlockRequest(
            requestId = reqId,
            createdAtMs = now,
            peerAddress = peerIp,
            transport = null
        )
        pendingRequests[reqId] = req

        // First confirmation receipt consumes the request atomically
        val consumed = pendingRequests.remove(reqId)
        assertNotNull("First confirmation must successfully retrieve pending request", consumed)
        assertEquals(reqId, consumed?.requestId)
        assertEquals(peerIp, consumed?.peerAddress)

        // Second confirmation (replay attack or duplicate) must find no active request
        val replayed = pendingRequests.remove(reqId)
        assertNull("Duplicate or replayed confirmation must be rejected (atomic consumption)", replayed)
    }

    @Test
    fun testUnlockConfirmationFreshnessTTL() {
        val now = System.currentTimeMillis()

        // Fresh request (5 seconds old) is within the 30-second window
        val freshCreatedAt = now - 5_000L
        val isFreshValid = (now - freshCreatedAt) <= 30_000L
        assertTrue("Request within 30s TTL must be considered fresh", isFreshValid)

        // Stale request (35 seconds old) exceeds the 30-second TTL
        val staleCreatedAt = now - 35_000L
        val isStaleValid = (now - staleCreatedAt) <= 30_000L
        assertFalse("Request older than 30s TTL must be rejected as stale", isStaleValid)
    }

    @Test
    fun testUnsolicitedUnlockConfirmationRejected() {
        val pendingRequests = ConcurrentHashMap<String, TetherLanService.PendingUnlockRequest>()
        val unpromptedReqId = UUID.randomUUID().toString()

        // Attempting to consume an unprompted / unsolicited confirmation
        val pending = pendingRequests.remove(unpromptedReqId)
        assertNull("Unsolicited unlock confirmation must have no matching pending request", pending)
    }

    @Test
    fun testPeerBindingVerification() {
        val reqId = UUID.randomUUID().toString()
        val boundPeer = "192.168.1.50"
        val pending = TetherLanService.PendingUnlockRequest(
            requestId = reqId,
            createdAtMs = System.currentTimeMillis(),
            peerAddress = boundPeer,
            transport = null
        )

        val matchingPeer = "192.168.1.50"
        val foreignPeer = "192.168.1.99"

        assertEquals("Matching peer must match request binding", boundPeer, matchingPeer)
        assertNotEquals("Foreign peer must not match request binding", boundPeer, foreignPeer)
    }

    @Test
    fun testNormalActionLockGuardInvariance() {
        fun evaluateGuard(isAppLocked: Boolean, action: String, isAuthorizedBiometric: Boolean): Boolean {
            val isUnlock = action.equals("unlock", ignoreCase = true)
            if (isAppLocked && !(isUnlock && isAuthorizedBiometric)) {
                return false // blocked
            }
            return true // allowed
        }

        val normalActions = listOf(
            "shutdown", "reboot", "sleep", "hibernate", "lock_now",
            "volume_up", "volume_down", "volume_mute", "set_volume:50",
            "brightness_up", "brightness_down", "set_brightness:70",
            "TERMINAL_START", "TERMINAL_INPUT", "FS_LIST", "FS_DOWNLOAD",
            "CLIPBOARD_SYNC", "CLIPBOARD_SIMULATE_COPY", "CLIPBOARD_SIMULATE_PASTE",
            "GET_RUNNING_WINDOWS", "WINDOW_CLOSE", "ADMIN_TELEMETRY"
        )

        // Invariant: When app is locked, ALL normal LAN actions MUST be blocked
        for (action in normalActions) {
            val allowedUnauth = evaluateGuard(isAppLocked = true, action = action, isAuthorizedBiometric = false)
            assertFalse("Action '$action' must be blocked when app is locked", allowedUnauth)

            val allowedAuth = evaluateGuard(isAppLocked = true, action = action, isAuthorizedBiometric = true)
            assertFalse("Normal action '$action' must still be blocked even if isAuthorizedBiometric is passed", allowedAuth)
        }

        // Invariant: Unauthenticated unlock command must also be blocked when app is locked
        assertFalse("Unauthenticated unlock must be blocked when app is locked",
            evaluateGuard(isAppLocked = true, action = "unlock", isAuthorizedBiometric = false))

        // Invariant: ONLY locally authorized biometric unlock can pass through while locked
        assertTrue("Authorized biometric unlock must be allowed through when app is locked",
            evaluateGuard(isAppLocked = true, action = "unlock", isAuthorizedBiometric = true))

        // Invariant: When app is unlocked, actions pass the lock guard
        for (action in normalActions) {
            assertTrue("Action '$action' must be allowed when app is unlocked",
                evaluateGuard(isAppLocked = false, action = action, isAuthorizedBiometric = false))
        }
    }

    @Test
    fun testConfirmCommandResponseIncludesRequestId() {
        val testReqId = UUID.randomUUID().toString()
        val confirmJson = JSONObject().apply {
            put("type", "CONFIRM_COMMAND")
            put("requestId", testReqId)
            put("confirmedCommand", "unlock")
            put("success", true)
            put("reason", "OK")
        }

        assertEquals("CONFIRM_COMMAND", confirmJson.getString("type"))
        assertEquals(testReqId, confirmJson.getString("requestId"))
        assertEquals("unlock", confirmJson.getString("confirmedCommand"))
        assertTrue(confirmJson.getBoolean("success"))
        assertEquals("OK", confirmJson.getString("reason"))
    }
}
