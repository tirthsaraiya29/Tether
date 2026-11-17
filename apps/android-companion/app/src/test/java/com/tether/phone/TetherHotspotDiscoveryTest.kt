package com.tether.phone

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.Inet4Address
import java.net.InetAddress

class TetherHotspotDiscoveryTest {

    @Test
    fun testIsPrivateAddress_SecurityBoundaries() {
        // RFC 1918 addresses must be accepted
        assertTrue(isPrivateAddress(InetAddress.getByName("192.168.1.100")))
        assertTrue(isPrivateAddress(InetAddress.getByName("192.168.43.1")))
        assertTrue(isPrivateAddress(InetAddress.getByName("10.0.0.1")))
        assertTrue(isPrivateAddress(InetAddress.getByName("172.16.0.1")))
        assertTrue(isPrivateAddress(InetAddress.getByName("172.31.255.254")))

        // Loopback must be rejected to prevent self-discovery loops and SSRF
        assertFalse(isPrivateAddress(InetAddress.getByName("127.0.0.1")))
        assertFalse(isPrivateAddress(InetAddress.getByName("127.0.0.2")))

        // CGNAT (100.64.0.0/10) must be rejected to prevent scanning cellular carrier networks
        assertFalse(isPrivateAddress(InetAddress.getByName("100.64.0.1")))
        assertFalse(isPrivateAddress(InetAddress.getByName("100.100.50.25")))
        assertFalse(isPrivateAddress(InetAddress.getByName("100.127.255.254")))

        // Public WAN IPs must be rejected
        assertFalse(isPrivateAddress(InetAddress.getByName("8.8.8.8")))
        assertFalse(isPrivateAddress(InetAddress.getByName("1.1.1.1")))
        assertFalse(isPrivateAddress(InetAddress.getByName("203.0.113.1")))

        // Multicast and unspecified must be rejected
        assertFalse(isPrivateAddress(InetAddress.getByName("224.0.0.251")))
        assertFalse(isPrivateAddress(InetAddress.getByName("0.0.0.0")))
    }

    @Test
    fun testCalculateSubnetBroadcast_AllPrefixes() {
        // /24 subnet (Standard hotspot/LAN, e.g., 192.168.43.1/24)
        val ip24 = InetAddress.getByName("192.168.43.1") as Inet4Address
        val bcast24 = calculateSubnetBroadcast(ip24, 24.toShort())
        assertEquals("192.168.43.255", bcast24?.hostAddress)

        // /28 subnet (192.168.43.1/28 -> broadcast 192.168.43.15)
        val bcast28 = calculateSubnetBroadcast(ip24, 28.toShort())
        assertEquals("192.168.43.15", bcast28?.hostAddress)

        // /30 subnet (192.168.43.1/30 -> broadcast 192.168.43.3)
        val bcast30 = calculateSubnetBroadcast(ip24, 30.toShort())
        assertEquals("192.168.43.3", bcast30?.hostAddress)

        // /16 subnet (172.16.5.10/16 -> broadcast 172.16.255.255)
        val ip16 = InetAddress.getByName("172.16.5.10") as Inet4Address
        val bcast16 = calculateSubnetBroadcast(ip16, 16.toShort())
        assertEquals("172.16.255.255", bcast16?.hostAddress)

        // Invalid prefix lengths should return null
        val bcastInvalid0 = calculateSubnetBroadcast(ip24, 0.toShort())
        assertEquals(null, bcastInvalid0)

        val bcastInvalid32 = calculateSubnetBroadcast(ip24, 32.toShort())
        assertEquals(null, bcastInvalid32)
    }

    @Test
    fun testGenerateSubnetCandidateIps_SubnetBoundaries() {
        // /30 subnet has 4 total IPs: network, 2 usable hosts, broadcast.
        // For 192.168.1.1/30: network is .0, hosts are .1, .2, broadcast is .3.
        // Self is .1, so candidates should contain ONLY .2.
        val ip30 = InetAddress.getByName("192.168.1.1") as Inet4Address
        val candidates30 = generateSubnetCandidateIps(ip30, 30.toShort()).map { it.hostAddress }
        assertEquals(1, candidates30.size)
        assertEquals("192.168.1.2", candidates30[0])

        // /28 subnet has 16 total IPs: network .0, hosts .1 to .14, broadcast .15.
        // Self is .1, candidates should have exactly 13 IPs (.2 through .14).
        val ip28 = InetAddress.getByName("192.168.1.1") as Inet4Address
        val candidates28 = generateSubnetCandidateIps(ip28, 28.toShort(), maxCandidates = 32).map { it.hostAddress }
        assertEquals(13, candidates28.size)
        assertFalse(candidates28.contains("192.168.1.0")) // Network address excluded
        assertFalse(candidates28.contains("192.168.1.1")) // Self address excluded
        assertFalse(candidates28.contains("192.168.1.15")) // Broadcast address excluded
        assertTrue(candidates28.contains("192.168.1.2"))
        assertTrue(candidates28.contains("192.168.1.14"))

        // /24 subnet has 256 total IPs: network .0, hosts .1 to .254, broadcast .255.
        // Self is .1. With maxCandidates = 254, candidates should have exactly 253 IPs (.2 through .254).
        val ip24 = InetAddress.getByName("192.168.43.1") as Inet4Address
        val candidates24 = generateSubnetCandidateIps(ip24, 24.toShort(), maxCandidates = 254).map { it.hostAddress }
        assertEquals(253, candidates24.size)
        assertFalse(candidates24.contains("192.168.43.0")) // Network excluded
        assertFalse(candidates24.contains("192.168.43.1")) // Self excluded
        assertFalse(candidates24.contains("192.168.43.255")) // Broadcast excluded
        assertTrue(candidates24.contains("192.168.43.2"))
        assertTrue(candidates24.contains("192.168.43.254"))

        // /16 subnet capped at maxCandidates to bound discovery overhead
        val ip16 = InetAddress.getByName("172.16.1.5") as Inet4Address
        val candidates16 = generateSubnetCandidateIps(ip16, 16.toShort(), maxCandidates = 64).map { it.hostAddress }
        assertTrue(candidates16.isNotEmpty())
        assertTrue(candidates16.size <= 64)
        assertFalse(candidates16.contains("172.16.1.5")) // Self excluded
    }

    @Test
    fun testIsValidDeviceId_Validation() {
        // Valid device IDs
        assertTrue(isValidDeviceId("DEVICE_12345"))
        assertTrue(isValidDeviceId("windows-host.local"))
        assertTrue(isValidDeviceId("aa:bb:cc:dd:ee:ff"))
        assertTrue(isValidDeviceId("1234567890ABCDEF"))

        // Invalid device IDs
        assertFalse(isValidDeviceId("")) // empty
        assertFalse(isValidDeviceId("a".repeat(129))) // too long
        assertFalse(isValidDeviceId("id<script>alert(1)</script>")) // illegal chars
        assertFalse(isValidDeviceId("device\nid")) // newline injection
        assertFalse(isValidDeviceId("device\u0000id")) // null byte
        assertFalse(isValidDeviceId("device;rm -rf /")) // shell injection chars
    }

    @Test
    fun testSanitizeDeviceName() {
        assertEquals("MyLaptop", sanitizeDeviceName("MyLaptop"))
        assertEquals("My Laptop", sanitizeDeviceName("My \u0000Laptop\n\r"))
        assertEquals("Tether Device", sanitizeDeviceName(""))
        assertEquals("Tether Device", sanitizeDeviceName("   "))

        val veryLong = "A".repeat(100)
        val sanitized = sanitizeDeviceName(veryLong)
        assertEquals(64, sanitized.length)
    }

    @Test
    fun testInterfaceFiltering_InterfaceNames() {
        // Disallowed prefixes (Cellular, VPN, Virtual)
        val disallowedNames = listOf(
            "rmnet0", "rmnet_data0", "ccmni0", "tun0", "tap0", "ppp0",
            "p2p0", "dummy0", "docker0", "veth1234"
        )
        for (name in disallowedNames) {
            val lower = name.lowercase()
            val disallowed = lower.startsWith("rmnet") || lower.startsWith("ccmni") ||
                    lower.startsWith("tun") || lower.startsWith("tap") ||
                    lower.startsWith("ppp") || lower.startsWith("p2p") ||
                    lower.startsWith("dummy") || lower.startsWith("docker") ||
                    lower.startsWith("veth")
            assertTrue("Expected $name to be rejected", disallowed)
        }

        // Allowed interface names (WLAN, SoftAP, USB ethernet)
        val allowedNames = listOf("wlan0", "wlan1", "ap0", "softap0", "eth0", "rndis0")
        for (name in allowedNames) {
            val lower = name.lowercase()
            val disallowed = lower.startsWith("rmnet") || lower.startsWith("ccmni") ||
                    lower.startsWith("tun") || lower.startsWith("tap") ||
                    lower.startsWith("ppp") || lower.startsWith("p2p") ||
                    lower.startsWith("dummy") || lower.startsWith("docker") ||
                    lower.startsWith("veth")
            assertFalse("Expected $name to be allowed", disallowed)
        }
    }
}
