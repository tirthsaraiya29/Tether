package com.tether.phone

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class AdversarialEcosystemTests {

    @Test
    fun testCapabilityNegotiation_WithEcosystemCaps() {
        val manager = TetherCapabilityManager()

        // When server advertises newly supported ecosystem capabilities
        val peerCaps = "CLIPBOARD,FILES,NOTIFICATIONS,MEDIA,TERMINAL,POWER_ELEVATED,INPUT,WINDOWS_ADMIN,APP_MANAGEMENT,AUTOMATION"
        val negotiated = manager.negotiateCapabilities(peerCaps)

        assertTrue(negotiated.contains(TetherCapability.WINDOWS_ADMIN))
        assertTrue(negotiated.contains(TetherCapability.APP_MANAGEMENT))
        assertTrue(negotiated.contains(TetherCapability.AUTOMATION))
        assertTrue(negotiated.contains(TetherCapability.MEDIA))
        assertTrue(negotiated.contains(TetherCapability.TERMINAL))

        assertTrue(manager.isCapabilityGranted(TetherCapability.WINDOWS_ADMIN))
        assertTrue(manager.isCapabilityGranted(TetherCapability.APP_MANAGEMENT))
        assertTrue(manager.isCapabilityGranted(TetherCapability.AUTOMATION))
    }

    @Test
    fun testCapabilityNegotiation_RestrictedServerBlocksAdmin() {
        val manager = TetherCapabilityManager()

        // When connected to restricted guest server without admin
        val guestCaps = "CLIPBOARD,MEDIA"
        val negotiated = manager.negotiateCapabilities(guestCaps)

        assertTrue(negotiated.contains(TetherCapability.MEDIA))
        assertTrue(negotiated.contains(TetherCapability.CLIPBOARD))
        assertFalse(negotiated.contains(TetherCapability.WINDOWS_ADMIN))
        assertFalse(negotiated.contains(TetherCapability.APP_MANAGEMENT))
        assertFalse(negotiated.contains(TetherCapability.AUTOMATION))

        assertFalse(manager.isCapabilityGranted(TetherCapability.WINDOWS_ADMIN))
    }

    @Test
    fun testAdminTelemetryDecoding_NestedVsFlat() {
        // Nested telemetry object (as sent by Windows PacketRouter)
        val windowsJson = JSONObject().apply {
            put("type", "ADMIN_TELEMETRY_RESPONSE")
            put("requestId", "req-123")
            put("telemetry", JSONObject().apply {
                put("cpuUsage", 37)
                put("totalRamMb", 32768L)
                put("availRamMb", 16384L)
                put("ramUsagePct", 50)
            })
        }

        val tObj = windowsJson.optJSONObject("telemetry") ?: windowsJson
        assertEquals(37, tObj.optInt("cpuUsage", 0))
        assertEquals(32768L, tObj.optLong("totalRamMb", 0L))
        assertEquals(16384L, tObj.optLong("availRamMb", 0L))
        assertEquals(50, tObj.optInt("ramUsagePct", 0))
    }

    @Test
    fun testPowerPlansAndUsbDevices_Aliasing() {
        val powerPlanJson = JSONObject().apply {
            put("type", "POWER_PLANS_RESPONSE")
            put("powerPlans", JSONArray().apply {
                put(JSONObject().apply {
                    put("guid", "381b4222-f694-41f0-9685-ff5bb260df2e")
                    put("name", "Balanced")
                    put("isActive", true)
                })
            })
        }

        val plansArr = powerPlanJson.optJSONArray("powerPlans") ?: powerPlanJson.optJSONArray("plans")
        assertNotNull(plansArr)
        assertEquals(1, plansArr!!.length())
        assertEquals("Balanced", plansArr.getJSONObject(0).getString("name"))

        val usbJson = JSONObject().apply {
            put("type", "USB_DEVICES_RESPONSE")
            put("usbDevices", JSONArray().apply {
                put(JSONObject().apply {
                    put("name", "USB Keyboard")
                    put("deviceId", "USB\\VID_046D")
                })
            })
        }

        val usbArr = usbJson.optJSONArray("usbDevices") ?: usbJson.optJSONArray("devices")
        assertNotNull(usbArr)
        assertEquals(1, usbArr!!.length())
        assertEquals("USB Keyboard", usbArr.getJSONObject(0).getString("name"))
    }

    @Test
    fun testClipboardHashCaseInsensitiveMatching() {
        val windowsHash = "4F53A1B2C3D4E5F6"
        val androidHash = "4f53a1b2c3d4e5f6"

        assertFalse(windowsHash == androidHash)
        assertTrue(windowsHash.equals(androidHash, ignoreCase = true))
    }
}
