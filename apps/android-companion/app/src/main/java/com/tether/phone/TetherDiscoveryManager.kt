package com.tether.phone

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.util.Log
import org.json.JSONObject
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.SocketTimeoutException
import java.nio.charset.StandardCharsets
import java.util.ArrayDeque
import java.util.concurrent.ConcurrentHashMap

data class DiscoveredDevice(
    val deviceId: String,
    val name: String,
    val hostAddress: String,
    val port: Int,
    val protocolVersion: String = "2.0",
    val capabilities: String = "",
    val pqcSupported: Boolean = false,
    val lastSeenTimestamp: Long = System.currentTimeMillis(),
)

interface TetherDiscoveryListener {
    fun onDeviceDiscovered(device: DiscoveredDevice)
    fun onDeviceLost(deviceId: String)
    fun onDiscoveryError(errorCode: Int, message: String)
}

fun isPrivateAddress(address: InetAddress): Boolean {
    if (address.isLoopbackAddress || address.isAnyLocalAddress || address.isMulticastAddress) {
        return false
    }
    if (address is Inet4Address) {
        val bytes = address.address
        val firstOctet = bytes[0].toInt() and 0xFF
        val secondOctet = bytes[1].toInt() and 0xFF

        // 10.0.0.0/8
        if (firstOctet == 10) return true
        // 172.16.0.0/12
        if (firstOctet == 172 && (secondOctet in 16..31)) return true
        // 192.168.0.0/16
        if (firstOctet == 192 && secondOctet == 168) return true
        // Link-local 169.254.0.0/16
        if (firstOctet == 169 && secondOctet == 254) return true

        // Explicitly rejects 100.64.0.0/10 (CGNAT), 127.0.0.0/8 (loopback), 0.0.0.0, 255.255.255.255, public WAN
        return false
    } else if (address is Inet6Address) {
        val bytes = address.address
        val firstOctet = bytes[0].toInt() and 0xFF
        if ((firstOctet and 0xFE) == 0xFC) return true // ULA fc00::/7
    }
    return false
}

fun isAllowedDiscoveryInterface(
    name: String,
    isUp: Boolean = true,
    isLoopback: Boolean = false,
    isPointToPoint: Boolean = false,
): Boolean {
    if (!isUp || isLoopback || isPointToPoint) return false
    val lowerName = name.lowercase(java.util.Locale.US)
    if (lowerName.startsWith("rmnet") || lowerName.startsWith("ccmni") || lowerName.startsWith("radio") ||
        lowerName.startsWith("pdp") || lowerName.startsWith("wwan") || lowerName.startsWith("qcom") ||
        lowerName.startsWith("tun") || lowerName.startsWith("tap") || lowerName.startsWith("ppp") ||
        lowerName.startsWith("p2p") || lowerName.startsWith("dummy") || lowerName.startsWith("docker") ||
        lowerName.startsWith("virbr") || lowerName.startsWith("vboxnet") || lowerName.startsWith("ipsec") ||
        lowerName.startsWith("wg") || lowerName.startsWith("tailscale")) {
        return false
    }
    return true
}

fun isAllowedDiscoveryInterface(iface: java.net.NetworkInterface): Boolean {
    return isAllowedDiscoveryInterface(
        name = iface.name,
        isUp = iface.isUp,
        isLoopback = iface.isLoopback,
        isPointToPoint = iface.isPointToPoint,
    )
}

fun isIpInSubnet(target: Inet4Address, subnetIp: Inet4Address, prefixLength: Short): Boolean {
    val prefix = prefixLength.toInt()
    if (prefix !in 1..32) return false
    val maskInt = if (prefix == 32) -1 else (-1 shl (32 - prefix))
    val targetBytes = target.address
    val netBytes = subnetIp.address
    val targetInt = ((targetBytes[0].toInt() and 0xFF) shl 24) or
                    ((targetBytes[1].toInt() and 0xFF) shl 16) or
                    ((targetBytes[2].toInt() and 0xFF) shl 8) or
                    (targetBytes[3].toInt() and 0xFF)
    val netInt = ((netBytes[0].toInt() and 0xFF) shl 24) or
                 ((netBytes[1].toInt() and 0xFF) shl 16) or
                 ((netBytes[2].toInt() and 0xFF) shl 8) or
                 (netBytes[3].toInt() and 0xFF)
    return (targetInt and maskInt) == (netInt and maskInt)
}

fun isValidDeviceId(id: String?): Boolean {
    if (id.isNullOrBlank() || id.length > 128) return false
    return id.all { c -> c.isLetterOrDigit() || c == '-' || c == '_' || c == '.' || c == ':' }
}

fun sanitizeDeviceName(name: String?): String {
    if (name.isNullOrBlank()) return "Tether Device"
    val filtered = name.filter { c -> c.code in 32..126 }.take(64).trim()
    return if (filtered.isEmpty()) "Tether Device" else filtered
}

fun calculateSubnetBroadcast(addr: Inet4Address, prefixLength: Short): InetAddress? {
    val prefix = prefixLength.toInt()
    if (prefix !in 1..30) return null
    val ipBytes = addr.address
    val maskInt = -1 shl (32 - prefix)
    val ipInt = ((ipBytes[0].toInt() and 0xFF) shl 24) or
                ((ipBytes[1].toInt() and 0xFF) shl 16) or
                ((ipBytes[2].toInt() and 0xFF) shl 8) or
                (ipBytes[3].toInt() and 0xFF)
    val bcastInt = ipInt or maskInt.inv()
    val bcastBytes = byteArrayOf(
        ((bcastInt ushr 24) and 0xFF).toByte(),
        ((bcastInt ushr 16) and 0xFF).toByte(),
        ((bcastInt ushr 8) and 0xFF).toByte(),
        (bcastInt and 0xFF).toByte()
    )
    return try { InetAddress.getByAddress(bcastBytes) } catch (_: Exception) { null }
}

fun generateSubnetCandidateIps(addr: Inet4Address, prefixLength: Short, maxCandidates: Int = 32): List<InetAddress> {
    val prefix = prefixLength.toInt()
    if (prefix !in 16..30) return emptyList()

    val ipBytes = addr.address
    val ipInt = ((ipBytes[0].toInt() and 0xFF) shl 24) or
                ((ipBytes[1].toInt() and 0xFF) shl 16) or
                ((ipBytes[2].toInt() and 0xFF) shl 8) or
                (ipBytes[3].toInt() and 0xFF)

    val mask = -1 shl (32 - prefix)
    val networkInt = ipInt and mask
    val bcastInt = networkInt or mask.inv()

    val firstHost = networkInt + 1
    val lastHost = bcastInt - 1
    val totalHosts = (lastHost - firstHost + 1).coerceAtLeast(0)
    if (totalHosts <= 0) return emptyList()

    val candidateInts = linkedSetOf<Int>()

    if (totalHosts <= maxCandidates) {
        for (h in firstHost..lastHost) {
            if (h != ipInt) {
                candidateInts.add(h)
            }
        }
    } else {
        // Enumerate sequential DHCP range starting at firstHost
        for (h in firstHost..(firstHost + 24)) {
            if (h in firstHost..lastHost && h != ipInt) {
                candidateInts.add(h)
            }
        }
        // Alternate vendor DHCP pool
        val midBase = firstHost + 99
        for (h in midBase..(midBase + 15)) {
            if (h in firstHost..lastHost && h != ipInt) {
                candidateInts.add(h)
            }
        }
        // Last host before broadcast
        if (lastHost != ipInt && lastHost >= firstHost) {
            candidateInts.add(lastHost)
        }
    }

    val result = mutableListOf<InetAddress>()
    for (cInt in candidateInts.take(maxCandidates)) {
        if (cInt in firstHost..lastHost && cInt != ipInt && ((cInt and mask) == networkInt)) {
            val cBytes = byteArrayOf(
                ((cInt ushr 24) and 0xFF).toByte(),
                ((cInt ushr 16) and 0xFF).toByte(),
                ((cInt ushr 8) and 0xFF).toByte(),
                (cInt and 0xFF).toByte()
            )
            try {
                result.add(InetAddress.getByAddress(cBytes))
            } catch (_: Exception) {}
        }
    }
    return result
}

fun parseArpTableForInterface(
    ifaceName: String,
    subnetIp: Inet4Address,
    prefixLength: Short,
    arpLines: List<String>? = null,
): List<InetAddress> {
    val addresses = mutableListOf<InetAddress>()
    try {
        val lines = arpLines ?: run {
            val file = java.io.File("/proc/net/arp")
            if (file.exists() && file.canRead()) file.readLines() else emptyList()
        }
        for (line in lines) {
            val tokens = line.trim().split("\\s+".toRegex())
            // Standard /proc/net/arp: IP HW_type Flags HW_address Mask Device
            if (tokens.size >= 6 && tokens[0] != "IP") {
                val ipStr = tokens[0]
                val flags = tokens[2]
                val device = tokens[5]
                if (flags != "0x0" && device.equals(ifaceName, ignoreCase = true)) {
                    val addr = try { InetAddress.getByName(ipStr) } catch (_: Exception) { null }
                    if (addr is Inet4Address && isPrivateAddress(addr) && addr != subnetIp) {
                        if (isIpInSubnet(addr, subnetIp, prefixLength)) {
                            addresses.add(addr)
                        }
                    }
                }
            }
        }
    } catch (_: Exception) {}
    return addresses
}

data class InterfaceDiscoveryTargets(
    val interfaceName: String,
    val localAddress: Inet4Address,
    val subnetBroadcast: InetAddress?,
    val candidateIps: List<InetAddress>,
)

fun resolveInterfaceDiscoveryTargets(arpLines: List<String>? = null): List<InterfaceDiscoveryTargets> {
    val results = mutableListOf<InterfaceDiscoveryTargets>()
    try {
        val interfaces = java.net.NetworkInterface.getNetworkInterfaces()
        while (interfaces != null && interfaces.hasMoreElements()) {
            val networkInterface = interfaces.nextElement()
            if (!isAllowedDiscoveryInterface(networkInterface)) continue
            for (interfaceAddress in networkInterface.interfaceAddresses) {
                val addr = interfaceAddress.address
                if (addr is Inet4Address && isPrivateAddress(addr)) {
                    val prefix = interfaceAddress.networkPrefixLength
                    val broadcast = interfaceAddress.broadcast?.takeIf { isPrivateAddress(it) }
                        ?: calculateSubnetBroadcast(addr, prefix)?.takeIf { isPrivateAddress(it) }

                    val candidates = mutableListOf<InetAddress>()
                    candidates.addAll(parseArpTableForInterface(networkInterface.name, addr, prefix, arpLines))
                    for (cand in generateSubnetCandidateIps(addr, prefix)) {
                        if (!candidates.contains(cand)) {
                            candidates.add(cand)
                        }
                    }

                    results.add(
                        InterfaceDiscoveryTargets(
                            interfaceName = networkInterface.name,
                            localAddress = addr,
                            subnetBroadcast = broadcast,
                            candidateIps = candidates,
                        )
                    )
                }
            }
        }
    } catch (e: Exception) {
        Log.w("TetherDiscoveryManager", "Failed resolving interface discovery targets: ${e.message}")
    }
    return results
}

class DiscoveryRateLimiter(
    val maxPerIp: Int = 5,
    val maxGlobal: Int = 30,
    val maxTrackedSources: Int = 256,
    val windowMs: Long = 1000L,
    val expiryMs: Long = 3000L,
) {
    private val lock = Any()
    private val sources = mutableMapOf<String, Pair<Int, Long>>()
    private var globalCount = 0
    private var globalWindowStartMs = 0L

    val trackedSourceCount: Int
        get() = synchronized(lock) { sources.size }

    fun checkAllowed(sourceIp: String, nowMs: Long = System.currentTimeMillis()): Boolean {
        if (sourceIp.isBlank()) return false
        synchronized(lock) {
            // 1. Global limit checked first (prevents source rotation DoS bypass)
            if (nowMs - globalWindowStartMs > windowMs) {
                globalWindowStartMs = nowMs
                globalCount = 1
            } else {
                if (globalCount >= maxGlobal) {
                    return false
                }
                globalCount++
            }

            // 2. Per-source limit
            val existing = sources[sourceIp]
            if (existing != null) {
                if (nowMs - existing.second > windowMs) {
                    sources[sourceIp] = Pair(1, nowMs)
                    return true
                } else {
                    if (existing.first >= maxPerIp) {
                        return false
                    }
                    sources[sourceIp] = Pair(existing.first + 1, existing.second)
                    return true
                }
            }

            // 3. New source tracking with bounded capacity and safe eviction
            if (sources.size >= maxTrackedSources) {
                val iterator = sources.entries.iterator()
                while (iterator.hasNext()) {
                    val entry = iterator.next()
                    if (nowMs - entry.value.second > expiryMs) {
                        iterator.remove()
                    }
                }

                if (sources.size >= maxTrackedSources) {
                    var oldestKey: String? = null
                    var oldestMs = Long.MAX_VALUE
                    for ((k, v) in sources) {
                        if (v.second < oldestMs) {
                            oldestMs = v.second
                            oldestKey = k
                        }
                    }
                    if (oldestKey != null) {
                        sources.remove(oldestKey)
                    }
                }
            }

            sources[sourceIp] = Pair(1, nowMs)
            return true
        }
    }

    fun reset() {
        synchronized(lock) {
            sources.clear()
            globalCount = 0
            globalWindowStartMs = 0L
        }
    }
}

class HotspotStateTracker {
    var isWifiApEnabled: Boolean = false
        private set
    var isTetheringActive: Boolean = false
        private set
    var activeTetherInterfaces: Set<String> = emptySet()
        private set

    fun onWifiApStateChanged(state: Int): Boolean {
        // WIFI_AP_STATE_DISABLING = 10, WIFI_AP_STATE_DISABLED = 11,
        // WIFI_AP_STATE_ENABLING = 12, WIFI_AP_STATE_ENABLED = 13, WIFI_AP_STATE_FAILED = 14
        if (state == 13) {
            isWifiApEnabled = true
        } else if (state == 10 || state == 11 || state == 14) {
            isWifiApEnabled = false
        }
        return isHotspotActive()
    }

    fun onTetherStateChanged(activeList: List<String>?, localOnlyList: List<String>?): Boolean {
        val active = mutableSetOf<String>()
        if (activeList != null) active.addAll(activeList)
        if (localOnlyList != null) active.addAll(localOnlyList)
        activeTetherInterfaces = active
        isTetheringActive = active.isNotEmpty()
        return isHotspotActive()
    }

    fun isHotspotActive(): Boolean {
        return isWifiApEnabled || isTetheringActive
    }

    fun reset() {
        isWifiApEnabled = false
        isTetheringActive = false
        activeTetherInterfaces = emptySet()
    }
}

fun validateDiscoveryResponse(
    responseStr: String,
    senderAddr: InetAddress,
    ownPhoneId: String,
): DiscoveredDevice? {
    if (senderAddr !is Inet4Address || !isPrivateAddress(senderAddr) || senderAddr.isLoopbackAddress) {
        return null
    }
    val hostAddr = senderAddr.hostAddress ?: return null
    val json = try { JSONObject(responseStr) } catch (_: Exception) { return null }
    val type = json.optString("type", "")
    if (type != "TETHER_DISCOVERY_RESPONSE") return null

    val devId = json.optString("deviceId", "")
    if (!isValidDeviceId(devId) || devId.equals(ownPhoneId, ignoreCase = true)) return null

    val tcpPort = json.optInt("tcpPort", -1)
    if (tcpPort != TetherNetworkConstants.CONTROL_PORT) return null

    val devName = sanitizeDeviceName(json.optString("deviceName", "Tether Windows PC"))
    return DiscoveredDevice(
        deviceId = devId,
        name = devName,
        hostAddress = hostAddr,
        port = tcpPort,
    )
}

class NsdResolveQueue(
    private val context: Context,
    private val nsdManager: NsdManager,
) {
    private val lock = Any()

    private data class PendingResolve(
        val serviceInfo: NsdServiceInfo,
        val onResolved: (NsdServiceInfo) -> Unit,
        val onError: (NsdServiceInfo?, Int) -> Unit,
    )

    private val queue = ArrayDeque<PendingResolve>()
    private var isResolving = false

    fun resolveOrEnqueue(
        serviceInfo: NsdServiceInfo,
        onResolved: (NsdServiceInfo) -> Unit,
        onError: (NsdServiceInfo?, Int) -> Unit,
    ) {
        synchronized(lock) {
            val name = serviceInfo.serviceName
            if (queue.any { (serviceInfo) -> serviceInfo.serviceName == name }) {
                Log.d("NsdResolveQueue", "Suppressing duplicate resolve enqueue for: $name")
                return
            }
            queue.addLast(PendingResolve(serviceInfo, onResolved, onError))
            if (!isResolving) {
                processNextLocked()
            }
        }
    }

    fun clear() {
        synchronized(lock) {
            queue.clear()
            isResolving = false
        }
    }

    private fun processNextLocked() {
        if (queue.isEmpty()) {
            isResolving = false
            return
        }
        isResolving = true
        val item = queue.first()

        val resolveListener = object : NsdManager.ResolveListener {
            override fun onResolveFailed(serviceInfo: NsdServiceInfo?, errorCode: Int) {
                try {
                    item.onError(serviceInfo, errorCode)
                } finally {
                    onComplete()
                }
            }

            override fun onServiceResolved(resolvedInfo: NsdServiceInfo?) {
                try {
                    resolvedInfo?.let { item.onResolved(it) }
                } finally {
                    onComplete()
                }
            }

            private fun onComplete() {
                synchronized(lock) {
                    if (queue.isNotEmpty()) {
                        queue.removeFirst()
                    }
                    processNextLocked()
                }
            }
        }

        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                val executor = androidx.core.content.ContextCompat.getMainExecutor(context)
                val callback = object : NsdManager.ServiceInfoCallback {
                    override fun onServiceInfoCallbackRegistrationFailed(errorCode: Int) {
                        resolveListener.onResolveFailed(item.serviceInfo, errorCode)
                    }

                    override fun onServiceUpdated(serviceInfo: NsdServiceInfo) {
                        resolveListener.onServiceResolved(serviceInfo)
                        try {
                            nsdManager.unregisterServiceInfoCallback(this)
                        } catch (_: Exception) {}
                    }

                    override fun onServiceLost() {}

                    override fun onServiceInfoCallbackUnregistered() {}
                }
                nsdManager.registerServiceInfoCallback(item.serviceInfo, executor, callback)
            } else {
                try {
                    nsdManager.resolveService(item.serviceInfo, resolveListener)
                } catch (e: Exception) {
                    Log.e("NsdResolveQueue", "Legacy resolveService failed: ${e.message}")
                }
            }
        } catch (e: Exception) {
            Log.e("NsdResolveQueue", "Exception invoking resolveService: ${e.message}")
            synchronized(lock) {
                if (queue.isNotEmpty()) {
                    queue.removeFirst()
                }
                processNextLocked()
            }
        }
    }
}

class TetherDiscoveryManager(
    context: Context,
    private val securityEngine: ProductionSecurityEngine,
) {

    companion object {
        private const val TAG = "TetherDiscoveryManager"
        const val SERVICE_TYPE = "_tether._tcp"
        const val DEFAULT_PORT = TetherNetworkConstants.CONTROL_PORT
        const val UDP_DISCOVERY_PORT = TetherNetworkConstants.DISCOVERY_PORT
        private const val MULTICAST_LOCK_TAG = "TetherMdnsMulticastLock"
    }

    private val nsdManager = context.getSystemService(Context.NSD_SERVICE) as NsdManager
    private val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
    private val multicastLock: WifiManager.MulticastLock = wifiManager.createMulticastLock(MULTICAST_LOCK_TAG).apply {
        setReferenceCounted(false)
    }

    private val nsdResolveQueue = NsdResolveQueue(context, nsdManager)
    private val mainHandler = Handler(Looper.getMainLooper())

    private var discoveryListener: NsdManager.DiscoveryListener? = null
    private var registrationListener: NsdManager.RegistrationListener? = null

    private var udpSocket: DatagramSocket? = null
    private var udpWorkerThread: Thread? = null

    private val discoveredDevices = ConcurrentHashMap<String, DiscoveredDevice>()
    private var externalListener: TetherDiscoveryListener? = null

    @Volatile
    var isSearching = false
        private set

    @Volatile
    var isAdvertising = false
        private set

    fun setDiscoveryListener(listener: TetherDiscoveryListener?) {
        this.externalListener = listener
    }

    @Synchronized
    fun startDiscovery() {
        stopDiscovery()
        discoveredDevices.clear()
        Log.i(TAG, "Starting mDNS & UDP Broadcast discovery for service type $SERVICE_TYPE / UDP $UDP_DISCOVERY_PORT")

        acquireMulticastLock()
        startUdpBroadcastDiscovery()

        val listener = object : NsdManager.DiscoveryListener {
            override fun onStartDiscoveryFailed(serviceType: String?, errorCode: Int) {
                Log.e(TAG, "mDNS Discovery start failed: errorCode=$errorCode")
                isSearching = false
                releaseMulticastLock()
                discoveryListener = null
            }

            override fun onStopDiscoveryFailed(serviceType: String?, errorCode: Int) {
                Log.e(TAG, "mDNS Discovery stop failed: errorCode=$errorCode")
                isSearching = false
                releaseMulticastLock()
                discoveryListener = null
            }

            override fun onDiscoveryStarted(serviceType: String?) {
                Log.i(TAG, "mDNS discovery started successfully for $serviceType")
                isSearching = true
            }

            override fun onDiscoveryStopped(serviceType: String?) {
                Log.i(TAG, "mDNS discovery stopped")
                isSearching = false
                releaseMulticastLock()
                discoveryListener = null
            }

            override fun onServiceFound(serviceInfo: NsdServiceInfo?) {
                if (serviceInfo == null) return
                Log.d(TAG, "Service found: ${serviceInfo.serviceName}, type=${serviceInfo.serviceType}")

                if (serviceInfo.serviceType.contains("_tether")) {
                    resolveService(serviceInfo)
                }
            }

            override fun onServiceLost(serviceInfo: NsdServiceInfo?) {
                if (serviceInfo == null) return
                Log.i(TAG, "Service lost: ${serviceInfo.serviceName}")
                val lostName = serviceInfo.serviceName
                val lostDevice = discoveredDevices.values.firstOrNull { (_, name) -> name == lostName }
                val deviceId = lostDevice?.deviceId ?: lostName
                discoveredDevices.remove(deviceId)
                mainHandler.post { externalListener?.onDeviceLost(deviceId) }
            }
        }

        this.discoveryListener = listener
        try {
            nsdManager.discoverServices(SERVICE_TYPE, NsdManager.PROTOCOL_DNS_SD, listener)
        } catch (e: Exception) {
            Log.e(TAG, "Error initiating discoverServices: ${e.message}", e)
            isSearching = false
            releaseMulticastLock()
            discoveryListener = null
        }
    }

    private fun startUdpBroadcastDiscovery() {
        isSearching = true
        val phonePublicKey = securityEngine.getPublicKeyBytes()
        val phoneId = securityEngine.computePublicKeyFingerprint(phonePublicKey)
        val deviceName = "Tether-Android-${Build.MODEL}"

        val probeJson = JSONObject().apply {
            put("type", "TETHER_DISCOVERY_PROBE")
            put("deviceId", phoneId)
            put("deviceName", deviceName)
            put("tcpPort", DEFAULT_PORT)
        }
        val probeBytes = probeJson.toString().toByteArray(StandardCharsets.UTF_8)

        udpWorkerThread = Thread {
            val socket = try {
                DatagramSocket(null).apply {
                    reuseAddress = true
                    bind(java.net.InetSocketAddress(UDP_DISCOVERY_PORT))
                    broadcast = true
                    soTimeout = 1000
                }
            } catch (e: Exception) {
                Log.w(TAG, "Binding fixed port $UDP_DISCOVERY_PORT failed (${e.message}); using ephemeral socket for UDP discovery.")
                try {
                    DatagramSocket().apply {
                        broadcast = true
                        soTimeout = 1000
                    }
                } catch (e2: Exception) {
                    Log.e(TAG, "Failed creating UDP discovery socket: ${e2.message}")
                    return@Thread
                }
            }
            udpSocket = socket

            val probeThread = Thread {
                while (isSearching && !Thread.currentThread().isInterrupted) {
                    try {
                        val interfaceTargets = resolveInterfaceDiscoveryTargets()
                        for (itf in interfaceTargets) {
                            var ifaceSocket: DatagramSocket? = null
                            try {
                                ifaceSocket = DatagramSocket(java.net.InetSocketAddress(itf.localAddress, 0)).apply {
                                    broadcast = true
                                    soTimeout = 500
                                }
                            } catch (_: Exception) {
                                // Binding per-interface socket failed; fall back to general socket for this interface
                            }

                            val activeSocket = ifaceSocket ?: socket
                            try {
                                itf.subnetBroadcast?.let { bcast ->
                                    try {
                                        val sendPacket = DatagramPacket(probeBytes, probeBytes.size, bcast, UDP_DISCOVERY_PORT)
                                        activeSocket.send(sendPacket)
                                    } catch (_: Exception) {}
                                }
                                for (cand in itf.candidateIps) {
                                    try {
                                        val sendPacket = DatagramPacket(probeBytes, probeBytes.size, cand, UDP_DISCOVERY_PORT)
                                        activeSocket.send(sendPacket)
                                    } catch (_: Exception) {}
                                }
                            } finally {
                                if (ifaceSocket != null) {
                                    try { ifaceSocket.close() } catch (_: Exception) {}
                                }
                            }
                        }
                    } catch (_: Exception) {}
                    try { Thread.sleep(2000) } catch (_: InterruptedException) { break }
                }
            }.apply { start() }

            val buffer = ByteArray(2048)
            val rateLimiter = DiscoveryRateLimiter()

            while (isSearching && !Thread.currentThread().isInterrupted) {
                try {
                    val recvPacket = DatagramPacket(buffer, buffer.size)
                    socket.receive(recvPacket)

                    // Enforce payload bounds
                    if (recvPacket.length < 10 || recvPacket.length > 1024) continue

                    val senderAddr = recvPacket.address
                    if (senderAddr !is Inet4Address || !isPrivateAddress(senderAddr) || senderAddr.isLoopbackAddress) {
                        continue
                    }

                    val hostAddr = senderAddr.hostAddress ?: continue

                    // Bounded per-source & global rate limiting
                    if (!rateLimiter.checkAllowed(hostAddr)) continue

                    val responseStr = String(recvPacket.data, 0, recvPacket.length, StandardCharsets.UTF_8)
                    val device = validateDiscoveryResponse(responseStr, senderAddr, phoneId)

                    if (device != null) {
                        Log.i(TAG, "UDP Discovered Tether device: $device")
                        discoveredDevices[device.deviceId] = device
                        mainHandler.post { externalListener?.onDeviceDiscovered(device) }
                    } else {
                        val json = try { JSONObject(responseStr) } catch (_: Exception) { null }
                        val type = json?.optString("type", "") ?: ""
                        if (type == "TETHER_DISCOVERY_PROBE") {
                            val devId = json?.optString("deviceId", "") ?: ""
                            val probePort = json?.optInt("tcpPort", -1) ?: -1
                            if (probePort == DEFAULT_PORT && devId.isNotEmpty() && !devId.equals(phoneId, ignoreCase = true) && isValidDeviceId(devId)) {
                                // Respond to valid incoming probe without treating the probe as a connection target
                                val respJson = JSONObject().apply {
                                    put("type", "TETHER_DISCOVERY_RESPONSE")
                                    put("deviceId", phoneId)
                                    put("deviceName", deviceName)
                                    put("tcpPort", DEFAULT_PORT)
                                }
                                val respBytes = respJson.toString().toByteArray(StandardCharsets.UTF_8)
                                val respPacket = DatagramPacket(respBytes, respBytes.size, recvPacket.socketAddress)
                                try { socket.send(respPacket) } catch (_: Exception) {}
                            }
                        }
                    }
                } catch (_: SocketTimeoutException) {
                    // Normal timeout
                } catch (e: Exception) {
                    if (!isSearching) break
                    Log.d(TAG, "UDP receive exception: ${e.message}")
                }
            }

            try { probeThread.interrupt() } catch (_: Exception) {}
        }.apply { start() }
    }

    private fun resolveService(serviceInfo: NsdServiceInfo) {
        nsdResolveQueue.resolveOrEnqueue(
            serviceInfo,
            onResolved = { resolvedInfo ->
                val host: InetAddress? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                    resolvedInfo.hostAddresses.firstOrNull { it is Inet4Address }
                        ?: resolvedInfo.hostAddresses.firstOrNull { !it.isLinkLocalAddress }
                        ?: resolvedInfo.hostAddresses.firstOrNull()
                        ?: resolvedInfo.host
                } else {
                    try {
                        resolvedInfo.host ?: (NsdServiceInfo::class.java.getMethod("getHost").invoke(resolvedInfo) as? InetAddress)
                    } catch (_: Exception) {
                        resolvedInfo.host
                    }
                }
                val port: Int = resolvedInfo.port
                val hostAddr = host?.hostAddress ?: return@resolveOrEnqueue

                if (!isPrivateAddress(host)) {
                    Log.w(TAG, "Discarding resolved mDNS address $hostAddr: Not a private LAN IP")
                    return@resolveOrEnqueue
                }

                val txtAttributes = parseAttributes(resolvedInfo)
                val deviceId = txtAttributes["id"] ?: resolvedInfo.serviceName
                val name = txtAttributes["name"] ?: resolvedInfo.serviceName

                val phonePublicKey = securityEngine.getPublicKeyBytes()
                val phoneId = securityEngine.computePublicKeyFingerprint(phonePublicKey)
                if (deviceId.equals(phoneId, ignoreCase = true) || deviceId.replace(":", "").equals(phoneId.replace(":", ""), ignoreCase = true)) {
                    Log.d(TAG, "[XFER-TRACE] ignoring own mDNS advertisement ($phoneId)")
                    return@resolveOrEnqueue
                }

                val version = txtAttributes["v"] ?: "1.0"
                val caps = txtAttributes["caps"] ?: ""
                val pqc = txtAttributes["pqc"] == "true"

                val device = DiscoveredDevice(
                    deviceId = deviceId,
                    name = name,
                    hostAddress = hostAddr,
                    port = port,
                    protocolVersion = version,
                    capabilities = caps,
                    pqcSupported = pqc,
                )

                Log.i(TAG, "Resolved Tether device: $device")
                discoveredDevices[deviceId] = device
                mainHandler.post { externalListener?.onDeviceDiscovered(device) }
            },
        ) { info, errorCode ->
            Log.w(TAG, "Service resolve failed for ${info?.serviceName}, error=$errorCode")
        }
    }

    private fun parseAttributes(info: NsdServiceInfo): Map<String, String> {
        val map = mutableMapOf<String, String>()
        try {
            info.attributes?.forEach { (key, bytes) ->
                if (bytes != null) {
                    map[key] = String(bytes, StandardCharsets.UTF_8)
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "Error reading service attributes: ${e.message}")
        }
        return map
    }

    fun advertiseService(port: Int = DEFAULT_PORT) {
        if (isAdvertising) return

        val phonePublicKey = securityEngine.getPublicKeyBytes()
        val phoneId = securityEngine.computePublicKeyFingerprint(phonePublicKey)
        val deviceName = "Tether-Android-${Build.MODEL}"

        val serviceInfo = NsdServiceInfo().apply {
            serviceName = deviceName
            serviceType = SERVICE_TYPE
            setPort(port)
            setAttribute("v", "2.0")
            setAttribute("id", phoneId)
            setAttribute("name", deviceName)
            setAttribute("caps", "FILES,NOTIFICATIONS,MEDIA,TERMINAL,POWER_ELEVATED")
            setAttribute("pqc", "false")
        }

        val listener = object : NsdManager.RegistrationListener {
            override fun onRegistrationFailed(serviceInfo: NsdServiceInfo?, errorCode: Int) {
                Log.e(TAG, "mDNS Service registration failed: errorCode=$errorCode")
                isAdvertising = false
                registrationListener = null
            }

            override fun onUnregistrationFailed(serviceInfo: NsdServiceInfo?, errorCode: Int) {
                Log.e(TAG, "mDNS Service unregistration failed: errorCode=$errorCode")
                isAdvertising = false
            }

            override fun onServiceRegistered(registeredInfo: NsdServiceInfo?) {
                Log.i(TAG, "mDNS Service registered successfully as ${registeredInfo?.serviceName}")
                isAdvertising = true
            }

            override fun onServiceUnregistered(serviceInfo: NsdServiceInfo?) {
                Log.i(TAG, "mDNS Service unregistered")
                isAdvertising = false
                registrationListener = null
            }
        }

        this.registrationListener = listener
        try {
            nsdManager.registerService(serviceInfo, NsdManager.PROTOCOL_DNS_SD, listener)
        } catch (e: Exception) {
            Log.e(TAG, "Error registering service: ${e.message}", e)
            isAdvertising = false
            registrationListener = null
        }
    }

    @Synchronized
    fun stopDiscovery() {
        isSearching = false
        nsdResolveQueue.clear()
        discoveredDevices.clear()

        try {
            udpSocket?.close()
        } catch (_: Exception) {}
        udpSocket = null

        udpWorkerThread?.interrupt()
        udpWorkerThread = null

        discoveryListener?.let { listener ->
            try { nsdManager.stopServiceDiscovery(listener) } catch (_: Exception) {}
        }
        discoveryListener = null
        releaseMulticastLock()
    }

    fun stopAdvertising() {
        registrationListener?.let { listener ->
            try { nsdManager.unregisterService(listener) } catch (_: Exception) {}
        }
        registrationListener = null
        isAdvertising = false
    }

    private fun acquireMulticastLock() {
        try {
            if (!multicastLock.isHeld) {
                multicastLock.acquire()
                Log.d(TAG, "Acquired WifiManager.MulticastLock for mDNS discovery")
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed acquiring MulticastLock: ${e.message}")
        }
    }

    private fun releaseMulticastLock() {
        try {
            if (multicastLock.isHeld) {
                multicastLock.release()
                Log.d(TAG, "Released WifiManager.MulticastLock")
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed releasing MulticastLock: ${e.message}")
        }
    }

    fun getDiscoveredDevices(): List<DiscoveredDevice> {
        return discoveredDevices.values.toList()
    }
}