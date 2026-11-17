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
    fun testIsPrivateAddress_SecurityBoundaries() {
        // RFC 1918 addresses must be accepted
        assertTrue(isPrivateAddress(InetAddress.getByName("192.168.1.100")))
        assertTrue(isPrivateAddress(InetAddress.getByName("192.168.43.1")))
        assertTrue(isPrivateAddress(InetAddress.getByName("10.0.0.1")))
        assertTrue(isPrivateAddress(InetAddress.getByName("172.16.0.1")))
        assertTrue(isPrivateAddress(InetAddress.getByName("172.31.255.254")))
        assertTrue(isPrivateAddress(InetAddress.getByName("169.254.10.5")))

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

        // Multicast, unspecified, and global broadcast must be rejected
        assertFalse(isPrivateAddress(InetAddress.getByName("224.0.0.251")))
        assertFalse(isPrivateAddress(InetAddress.getByName("0.0.0.0")))
        assertFalse(isPrivateAddress(InetAddress.getByName("255.255.255.255")))
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

        // Invalid prefix lengths (0, 31, 32) should return null
        assertEquals(null, calculateSubnetBroadcast(ip24, 0.toShort()))
        assertEquals(null, calculateSubnetBroadcast(ip24, 31.toShort()))
        assertEquals(null, calculateSubnetBroadcast(ip24, 32.toShort()))
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
    fun testIsIpInSubnet_AllPrefixes() {
        val base24 = InetAddress.getByName("192.168.43.1") as Inet4Address
        assertTrue(isIpInSubnet(InetAddress.getByName("192.168.43.50") as Inet4Address, base24, 24.toShort()))
        assertFalse(isIpInSubnet(InetAddress.getByName("192.168.44.1") as Inet4Address, base24, 24.toShort()))

        val base28 = InetAddress.getByName("192.168.1.1") as Inet4Address
        assertTrue(isIpInSubnet(InetAddress.getByName("192.168.1.14") as Inet4Address, base28, 28.toShort()))
        assertFalse(isIpInSubnet(InetAddress.getByName("192.168.1.16") as Inet4Address, base28, 28.toShort()))

        val base16 = InetAddress.getByName("172.16.10.5") as Inet4Address
        assertTrue(isIpInSubnet(InetAddress.getByName("172.16.200.50") as Inet4Address, base16, 16.toShort()))
        assertFalse(isIpInSubnet(InetAddress.getByName("172.17.1.1") as Inet4Address, base16, 16.toShort()))
    }

    @Test
    fun testInterfaceFiltering_ExercisesProductionFunction() {
        // Production function: isAllowedDiscoveryInterface(name, isUp, isLoopback, isPointToPoint)

        // Eligible interfaces: Wi-Fi, SoftAP, Ethernet, USB tethering
        assertTrue(isAllowedDiscoveryInterface("wlan0", isUp = true, isLoopback = false, isPointToPoint = false))
        assertTrue(isAllowedDiscoveryInterface("wlan1", isUp = true, isLoopback = false, isPointToPoint = false))
        assertTrue(isAllowedDiscoveryInterface("ap0", isUp = true, isLoopback = false, isPointToPoint = false))
        assertTrue(isAllowedDiscoveryInterface("softap0", isUp = true, isLoopback = false, isPointToPoint = false))
        assertTrue(isAllowedDiscoveryInterface("swlan0", isUp = true, isLoopback = false, isPointToPoint = false))
        assertTrue(isAllowedDiscoveryInterface("eth0", isUp = true, isLoopback = false, isPointToPoint = false))
        assertTrue(isAllowedDiscoveryInterface("rndis0", isUp = true, isLoopback = false, isPointToPoint = false))

        // Ineligible: Down interfaces
        assertFalse(isAllowedDiscoveryInterface("wlan0", isUp = false, isLoopback = false, isPointToPoint = false))
        assertFalse(isAllowedDiscoveryInterface("ap0", isUp = false, isLoopback = false, isPointToPoint = false))

        // Ineligible: Loopback & PointToPoint
        assertFalse(isAllowedDiscoveryInterface("lo", isUp = true, isLoopback = true, isPointToPoint = false))
        assertFalse(isAllowedDiscoveryInterface("ppp0", isUp = true, isLoopback = false, isPointToPoint = true))

        // Ineligible: Cellular / Carrier WWAN interfaces
        assertFalse(isAllowedDiscoveryInterface("rmnet0"))
        assertFalse(isAllowedDiscoveryInterface("rmnet_data0"))
        assertFalse(isAllowedDiscoveryInterface("ccmni0"))
        assertFalse(isAllowedDiscoveryInterface("radio0"))
        assertFalse(isAllowedDiscoveryInterface("pdp0"))
        assertFalse(isAllowedDiscoveryInterface("wwan0"))
        assertFalse(isAllowedDiscoveryInterface("qcom0"))

        // Ineligible: VPN & Tunnel interfaces
        assertFalse(isAllowedDiscoveryInterface("tun0"))
        assertFalse(isAllowedDiscoveryInterface("tap0"))
        assertFalse(isAllowedDiscoveryInterface("wg0"))
        assertFalse(isAllowedDiscoveryInterface("tailscale0"))
        assertFalse(isAllowedDiscoveryInterface("ipsec0"))

        // Ineligible: Virtual / Container interfaces
        assertFalse(isAllowedDiscoveryInterface("dummy0"))
        assertFalse(isAllowedDiscoveryInterface("docker0"))
        assertFalse(isAllowedDiscoveryInterface("virbr0"))
        assertFalse(isAllowedDiscoveryInterface("vboxnet0"))
    }

    @Test
    fun testParseArpTableForInterface_InterfaceAndSubnetEnforcement() {
        val arpContent = listOf(
            "IP address       HW type     Flags       HW address            Mask     Device",
            "192.168.43.50    0x1         0x2         aa:bb:cc:dd:ee:ff     *        ap0",     // Valid ap0 entry in subnet
            "192.168.43.1     0x1         0x2         11:22:33:44:55:66     *        ap0",     // Own IP (must be excluded)
            "192.168.43.60    0x1         0x0         00:00:00:00:00:00     *        ap0",     // Incomplete flag 0x0 (must be excluded)
            "192.168.1.100    0x1         0x2         aa:bb:cc:dd:ee:11     *        wlan0",   // Different interface (must not associate with ap0)
            "10.0.0.5         0x1         0x2         aa:bb:cc:dd:ee:22     *        ap0",     // Wrong subnet for 192.168.43.0/24 (must be excluded)
            "8.8.8.8          0x1         0x2         aa:bb:cc:dd:ee:33     *        ap0"      // Public WAN (must be excluded)
        )

        val ap0Ip = InetAddress.getByName("192.168.43.1") as Inet4Address
        val ap0Candidates = parseArpTableForInterface("ap0", ap0Ip, 24.toShort(), arpContent)

        // Only 192.168.43.50 meets all criteria: matching interface ap0, private IP, in subnet, valid flag, not self
        assertEquals(1, ap0Candidates.size)
        assertEquals("192.168.43.50", ap0Candidates[0].hostAddress)

        // Querying wlan0 interface
        val wlan0Ip = InetAddress.getByName("192.168.1.1") as Inet4Address
        val wlan0Candidates = parseArpTableForInterface("wlan0", wlan0Ip, 24.toShort(), arpContent)
        assertEquals(1, wlan0Candidates.size)
        assertEquals("192.168.1.100", wlan0Candidates[0].hostAddress)
    }

    @Test
    fun testResolveInterfaceDiscoveryTargets_ExcludesGlobalBroadcast() {
        val targets = resolveInterfaceDiscoveryTargets()
        for (target in targets) {
            assertFalse("Global broadcast 255.255.255.255 must never be used", target.subnetBroadcast?.hostAddress == "255.255.255.255")
            for (cand in target.candidateIps) {
                assertFalse("Global broadcast must not be a candidate", cand.hostAddress == "255.255.255.255")
                assertFalse("Loopback must not be a candidate", cand.isLoopbackAddress)
                assertTrue("Candidate must be private IPv4", isPrivateAddress(cand))
            }
        }
    }

    @Test
    fun testValidateDiscoveryResponse_StrictPortAndIdValidation() {
        val sender = InetAddress.getByName("192.168.43.50")
        val phoneId = "phone-own-device-id"

        // 1. Valid discovery response with Tether control port 37123
        val validJson = """
            {"type":"TETHER_DISCOVERY_RESPONSE","deviceId":"win-pc-123","deviceName":"My Laptop","tcpPort":37123}
        """.trimIndent()
        val validDev = validateDiscoveryResponse(validJson, sender, phoneId)
        assertNotNull(validDev)
        assertEquals("win-pc-123", validDev?.deviceId)
        assertEquals(37123, validDev?.port)
        assertEquals("192.168.43.50", validDev?.hostAddress)

        // 2. Reject invalid TCP ports (arbitrary port selection prevention)
        for (badPort in listOf(80, 443, 8080, 22, 37124, 70000, 0, -1)) {
            val badPortJson = """
                {"type":"TETHER_DISCOVERY_RESPONSE","deviceId":"win-pc-123","deviceName":"My Laptop","tcpPort":$badPort}
            """.trimIndent()
            assertNull("Port $badPort must be rejected", validateDiscoveryResponse(badPortJson, sender, phoneId))
        }

        // 3. Reject invalid device IDs
        val badIdJson = """
            {"type":"TETHER_DISCOVERY_RESPONSE","deviceId":"evil<script>","deviceName":"My Laptop","tcpPort":37123}
        """.trimIndent()
        assertNull(validateDiscoveryResponse(badIdJson, sender, phoneId))

        // 4. Reject own reflection advertisement
        val selfJson = """
            {"type":"TETHER_DISCOVERY_RESPONSE","deviceId":"$phoneId","deviceName":"My Laptop","tcpPort":37123}
        """.trimIndent()
        assertNull(validateDiscoveryResponse(selfJson, sender, phoneId))

        // 5. Reject loopback and public WAN sender IPs
        val loopbackSender = InetAddress.getByName("127.0.0.1")
        assertNull(validateDiscoveryResponse(validJson, loopbackSender, phoneId))

        val wanSender = InetAddress.getByName("8.8.8.8")
        assertNull(validateDiscoveryResponse(validJson, wanSender, phoneId))

        // 6. Reject malformed / non-JSON responses
        assertNull(validateDiscoveryResponse("NOT_JSON", sender, phoneId))
        assertNull(validateDiscoveryResponse("""{"type":"UNKNOWN"}""", sender, phoneId))
    }

    @Test
    fun testDiscoveryRateLimiter_PerSourceGlobalAndCapacityBounds() {
        val limiter = DiscoveryRateLimiter(maxPerIp = 5, maxGlobal = 30, maxTrackedSources = 50)
        val now = System.currentTimeMillis()

        // 1. Per-IP rate limiting: max 5 per second
        for (i in 1..5) {
            assertTrue("Probe $i from same IP should be allowed", limiter.checkAllowed("192.168.1.10", now))
        }
        assertFalse("6th probe from same IP within 1s window must be rejected", limiter.checkAllowed("192.168.1.10", now))

        // 2. Global rate limiting across changing IPs (prevents source rotation attack)
        limiter.reset()
        for (i in 1..30) {
            assertTrue("Global probe $i should be allowed", limiter.checkAllowed("10.0.0.$i", now))
        }
        assertFalse("31st probe from new IP must be rejected by global limit", limiter.checkAllowed("10.0.0.99", now))

        // 3. Window expiration allows new probes
        val nextWindow = now + 1100L
        assertTrue("Probes in new window should be allowed", limiter.checkAllowed("10.0.0.99", nextWindow))

        // 4. Tracked capacity bound and inactive entry eviction
        limiter.reset()
        for (i in 1..50) {
            limiter.checkAllowed("192.168.1.$i", now)
        }
        assertTrue("Tracked sources must not exceed capacity", limiter.trackedSourceCount <= 50)

        // After expiry (3.5s later), new entries should safely prune expired entries
        val later = now + 3500L
        for (i in 51..70) {
            limiter.checkAllowed("192.168.1.$i", later)
        }
        assertTrue("Expired entries must be evicted without exceeding capacity", limiter.trackedSourceCount <= 50)
    }

    @Test
    fun testHotspotStateTracker_CompleteLifecycle() {
        val tracker = HotspotStateTracker()
        assertFalse(tracker.isHotspotActive())

        // 1. Wi-Fi AP activation (WIFI_AP_STATE_ENABLED = 13)
        assertTrue(tracker.onWifiApStateChanged(13))
        assertTrue(tracker.isHotspotActive())
        assertTrue(tracker.isWifiApEnabled)

        // 2. Tether state changed with active interface list
        assertTrue(tracker.onTetherStateChanged(listOf("ap0"), null))
        assertTrue(tracker.isHotspotActive())
        assertTrue(tracker.isTetheringActive)

        // 3. Wi-Fi AP deactivation (WIFI_AP_STATE_DISABLED = 11) while tether list is still reported
        // Out of order broadcast tolerance: still active via tether
        assertTrue(tracker.onWifiApStateChanged(11))
        assertFalse(tracker.isWifiApEnabled)
        assertTrue(tracker.isHotspotActive()) // Still active because tethering had not yet reported deactivation

        // 4. Tether state reports empty interface list -> Complete deactivation
        assertFalse(tracker.onTetherStateChanged(emptyList(), emptyList()))
        assertFalse(tracker.isHotspotActive())
        assertFalse(tracker.isTetheringActive)

        // 5. Duplicate deactivation broadcasts must remain inactive
        assertFalse(tracker.onWifiApStateChanged(11))
        assertFalse(tracker.onTetherStateChanged(null, null))
        assertFalse(tracker.isHotspotActive())

        // 6. Tether activation first, then AP enabled
        assertTrue(tracker.onTetherStateChanged(listOf("swlan0"), null))
        assertTrue(tracker.isHotspotActive())
        assertTrue(tracker.onWifiApStateChanged(13))
        assertTrue(tracker.isHotspotActive())

        // 7. Reset clears all state
        tracker.reset()
        assertFalse(tracker.isHotspotActive())
        assertFalse(tracker.isWifiApEnabled)
        assertFalse(tracker.isTetheringActive)
    }

    @Test
    fun testIsValidDeviceId_Validation() {
        assertTrue(isValidDeviceId("DEVICE_12345"))
        assertTrue(isValidDeviceId("windows-host.local"))
        assertTrue(isValidDeviceId("aa:bb:cc:dd:ee:ff"))
        assertTrue(isValidDeviceId("1234567890ABCDEF"))

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
}
