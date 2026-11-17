package com.tether.phone

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.Inet4Address
import java.net.InetAddress

class TetherHotspotDiscoveryTest {

    @Test
    fun testCalculateSubnetBroadcast_HotspotSubnets() {
        val addr1 = InetAddress.getByName("192.168.43.1") as Inet4Address
        val bcast1 = calculateSubnetBroadcast(addr1, 24)
        assertNotNull(bcast1)
        assertEquals("192.168.43.255", bcast1?.hostAddress)

        val addr2 = InetAddress.getByName("192.168.49.1") as Inet4Address
        val bcast2 = calculateSubnetBroadcast(addr2, 24)
        assertNotNull(bcast2)
        assertEquals("192.168.49.255", bcast2?.hostAddress)

        val addr3 = InetAddress.getByName("172.20.10.1") as Inet4Address
        val bcast3 = calculateSubnetBroadcast(addr3, 28)
        assertNotNull(bcast3)
        assertEquals("172.20.10.15", bcast3?.hostAddress)

        val addr4 = InetAddress.getByName("10.42.0.1") as Inet4Address
        val bcast4 = calculateSubnetBroadcast(addr4, 24)
        assertNotNull(bcast4)
        assertEquals("10.42.0.255", bcast4?.hostAddress)
    }

    @Test
    fun testCalculateSubnetBroadcast_InvalidPrefix() {
        val addr = InetAddress.getByName("192.168.43.1") as Inet4Address
        assertNull(calculateSubnetBroadcast(addr, 0))
        assertNull(calculateSubnetBroadcast(addr, 32))
        assertNull(calculateSubnetBroadcast(addr, -1))
    }

    @Test
    fun testGenerateSubnetCandidateIps_ExcludesSelfAndMatchesSubnet() {
        val addr = InetAddress.getByName("192.168.43.1") as Inet4Address
        val candidates = generateSubnetCandidateIps(addr, 24, maxCandidates = 20)

        assertTrue(candidates.isNotEmpty())
        assertTrue(candidates.size <= 20)

        for (candidate in candidates) {
            assertTrue(candidate is Inet4Address)
            val ipStr = candidate.hostAddress
            assertTrue(ipStr != null && ipStr.startsWith("192.168.43."))
            assertTrue(ipStr != "192.168.43.1") // Must exclude the phone's own IP
        }

        // Must include the primary DHCP client allocation IP (192.168.43.2)
        assertTrue(candidates.any { it.hostAddress == "192.168.43.2" })
    }

    @Test
    fun testIsPrivateAddress_SecurityValidation() {
        // Private / Hotspot addresses must be accepted
        assertTrue(isPrivateAddress(InetAddress.getByName("127.0.0.1")))
        assertTrue(isPrivateAddress(InetAddress.getByName("192.168.43.1")))
        assertTrue(isPrivateAddress(InetAddress.getByName("192.168.43.15")))
        assertTrue(isPrivateAddress(InetAddress.getByName("10.0.0.1")))
        assertTrue(isPrivateAddress(InetAddress.getByName("172.20.10.1")))
        assertTrue(isPrivateAddress(InetAddress.getByName("169.254.1.1"))) // Link-local

        // Public Internet addresses must be strictly rejected
        assertFalse(isPrivateAddress(InetAddress.getByName("8.8.8.8")))
        assertFalse(isPrivateAddress(InetAddress.getByName("1.1.1.1")))
        assertFalse(isPrivateAddress(InetAddress.getByName("93.184.216.34")))
        assertFalse(isPrivateAddress(InetAddress.getByName("142.250.190.46")))
    }
}
