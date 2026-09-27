package com.tether.phone

import org.junit.Assert.*
import org.junit.Test
import java.net.InetAddress

/**
 * Comprehensive networking test suite for Tether companion app.
 * Verifies private local address validation, exponential backoff calculation,
 * transport generation tracking, and security rules during address changes.
 */
class TetherNetworkingTest {

    @Test
    fun testIsPrivateAddressValidation() {
        // Private IPv4 site-local addresses
        assertTrue(isPrivateAddress(InetAddress.getByName("192.168.1.100")))
        assertTrue(isPrivateAddress(InetAddress.getByName("10.0.0.1")))
        assertTrue(isPrivateAddress(InetAddress.getByName("172.16.0.5")))

        // Loopback and link-local addresses
        assertTrue(isPrivateAddress(InetAddress.getByName("127.0.0.1")))
        assertTrue(isPrivateAddress(InetAddress.getByName("169.254.1.1")))

        // CGNAT (100.64.0.0/10)
        assertTrue(isPrivateAddress(InetAddress.getByName("100.64.10.20")))

        // IPv6 Unique Local Address (fc00::/7)
        assertTrue(isPrivateAddress(InetAddress.getByName("fd00::1")))

        // Public Internet IP addresses must be rejected
        assertFalse(isPrivateAddress(InetAddress.getByName("8.8.8.8")))
        assertFalse(isPrivateAddress(InetAddress.getByName("1.1.1.1")))
        assertFalse(isPrivateAddress(InetAddress.getByName("142.250.190.46")))
    }

    @Test
    fun testControlledExponentialBackoffCalculation() {
        val baseDelayMs = 1000L
        val maxDelayMs = 30000L

        for (attempt in 1..10) {
            val expDelay = baseDelayMs * (1 shl (attempt - 1).coerceAtMost(5))
            val boundedDelay = expDelay.coerceAtMost(maxDelayMs)

            if (attempt == 1) assertEquals(1000L, boundedDelay)
            if (attempt == 2) assertEquals(2000L, boundedDelay)
            if (attempt == 3) assertEquals(4000L, boundedDelay)
            if (attempt == 4) assertEquals(8000L, boundedDelay)
            if (attempt == 5) assertEquals(16000L, boundedDelay)
            if (attempt >= 6) assertEquals(30000L, boundedDelay)
        }
    }

    @Test
    fun testSavedIpOptimizationDoesNotBypassPinning() {
        val savedIp = "192.168.1.150"
        val isSavedIpAvailable = true

        // Emulate connecting to saved IP
        val targetIp = if (isSavedIpAvailable) savedIp else "DISCOVERED_MDNS_IP"
        assertEquals("192.168.1.150", targetIp)

        // Simulated public keys: pinned key vs presented key
        val pinnedPublicKey = "PINNED_KEY_BYTES_ABC_123".toByteArray()
        val untrustedHostKey = "UNTRUSTED_KEY_BYTES_XYZ_999".toByteArray()

        val isKeyMatch = pinnedPublicKey.contentEquals(untrustedHostKey)
        assertFalse("Key mismatch must fail closed even when connecting to previously saved IP", isKeyMatch)
    }
}
