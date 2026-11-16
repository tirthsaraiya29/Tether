package com.tether.phone

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class CompanionCapabilityTests {

    @Test
    fun testFromScopeName() {
        assertEquals(TetherCapability.POWER_ELEVATED, TetherCapability.fromScopeName("power_elevated"))
        assertNull(TetherCapability.fromScopeName("Automation"))
        assertNull(TetherCapability.fromScopeName("NON_EXISTENT_CAP"))
    }

    @Test
    fun testNegotiateCapabilities_EmptyString_DefaultsToStandard() {
        val manager = TetherCapabilityManager()
        val negotiated = manager.negotiateCapabilities("")
        assertEquals(TetherCapabilityManager.DEFAULT_ANDROID_CAPABILITIES, negotiated)
        assertTrue(manager.isCapabilityGranted(TetherCapability.MEDIA))
        assertTrue(manager.isCapabilityGranted(TetherCapability.POWER_ELEVATED))
    }

    @Test
    fun testNegotiateCapabilities_RestrictedPeer_IntersectsCorrectly() {
        val manager = TetherCapabilityManager()
        val negotiated = manager.negotiateCapabilities("MEDIA")
        assertTrue(negotiated.contains(TetherCapability.MEDIA))
        assertFalse(negotiated.contains(TetherCapability.POWER_ELEVATED))
        assertFalse(manager.isCapabilityGranted(TetherCapability.POWER_ELEVATED))
    }

    @Test
    fun testCanExecuteCommand_RequiresPowerElevated() {
        val manager = TetherCapabilityManager()
        // Default has POWER_ELEVATED
        assertTrue(manager.canExecuteCommand("unlock"))
        assertTrue(manager.canExecuteCommand("shutdown"))
        assertTrue(manager.canExecuteCommand("lock_now"))

        // When restricted to MEDIA only:
        manager.negotiateCapabilities("MEDIA")
        assertFalse(manager.canExecuteCommand("unlock"))
        assertFalse(manager.canExecuteCommand("shutdown"))
        assertFalse(manager.canExecuteCommand("lock_now"))
        assertTrue(manager.canExecuteCommand("volume_up"))
        assertTrue(manager.canExecuteCommand("brightness_down"))
    }
}
