@file:Suppress("DEPRECATION", "unused")

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
    val protocolVersion: String = "1.0",
    val capabilities: String = "",
    val pqcSupported: Boolean = false,
    val lastSeenTimestamp: Long = System.currentTimeMillis(),
)

interface TetherDiscoveryListener {
    fun onDeviceDiscovered(device: DiscoveredDevice)
    fun onDeviceLost(deviceId: String)
    fun onDiscoveryError(errorCode: Int, message: String)
}

/**
 * Validates whether the given address belongs to a private local area network scope.
 */
fun isPrivateAddress(address: InetAddress): Boolean {
    if (address.isLoopbackAddress || address.isSiteLocalAddress || address.isLinkLocalAddress) {
        return true
    }
    if (address is Inet4Address) {
        val bytes = address.address
        val firstOctet = bytes[0].toInt() and 0xFF
        val secondOctet = bytes[1].toInt() and 0xFF
        // CGNAT 100.64.0.0/10
        if ((firstOctet == 100) && ((secondOctet and 0xC0) == 0x40)) return true
    } else if (address is Inet6Address) {
        val bytes = address.address
        val firstOctet = bytes[0].toInt() and 0xFF
        // IPv6 Unique Local fc00::/7
        if ((firstOctet and 0xFE) == 0xFC) return true
    }
    return false
}

/**
 * Thread-safe queue for resolving NsdServiceInfo entries sequentially.
 * Prevents NsdManager error 3 (FAILURE_ALREADY_ACTIVE) caused by concurrent resolutions.
 */
class NsdResolveQueue(private val nsdManager: NsdManager) {
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
            if (queue.any { it.serviceInfo.serviceName == name }) {
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
            nsdManager.resolveService(item.serviceInfo, resolveListener)
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
        const val DEFAULT_PORT = 37123
        const val UDP_DISCOVERY_PORT = 37124
        private const val MULTICAST_LOCK_TAG = "TetherMdnsMulticastLock"
    }

    private val nsdManager = context.getSystemService(Context.NSD_SERVICE) as NsdManager
    private val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
    private val multicastLock: WifiManager.MulticastLock = wifiManager.createMulticastLock(MULTICAST_LOCK_TAG).apply {
        setReferenceCounted(false)
    }

    private val nsdResolveQueue = NsdResolveQueue(nsdManager)
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
        if (isSearching) {
            Log.d(TAG, "Discovery already active. Skipping duplicate start.")
            return
        }

        stopDiscovery()
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
                val lostDevice = discoveredDevices.values.firstOrNull { it.name == lostName }
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
        udpWorkerThread = Thread {
            try {
                val socket = DatagramSocket(UDP_DISCOVERY_PORT).apply {
                    broadcast = true
                    soTimeout = 2000
                }
                udpSocket = socket

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
                val broadcastAddr = InetAddress.getByName("255.255.255.255")

                val buffer = ByteArray(2048)

                while (isSearching && !Thread.currentThread().isInterrupted) {
                    try {
                        // 1. Broadcast discovery probe packet
                        val sendPacket = DatagramPacket(probeBytes, probeBytes.size, broadcastAddr, UDP_DISCOVERY_PORT)
                        socket.send(sendPacket)

                        // 2. Receive responses
                        val recvPacket = DatagramPacket(buffer, buffer.size)
                        socket.receive(recvPacket)

                        val responseStr = String(recvPacket.data, 0, recvPacket.length, StandardCharsets.UTF_8)
                        val json = JSONObject(responseStr)
                        val type = json.optString("type", "")

                        if ((type == "TETHER_DISCOVERY_RESPONSE") || (type == "TETHER_DISCOVERY_PROBE")) {
                            val hostAddr = recvPacket.address.hostAddress ?: continue
                            val devId = json.optString("deviceId", hostAddr)
                            val devName = json.optString("deviceName", "Tether Windows PC")
                            val tcpPort = json.optInt("tcpPort", DEFAULT_PORT)

                            val device = DiscoveredDevice(
                                deviceId = devId,
                                name = devName,
                                hostAddress = hostAddr,
                                port = tcpPort,
                            )

                            if (!discoveredDevices.containsKey(devId)) {
                                Log.i(TAG, "KDE-Connect Style UDP Broadcast Discovered Tether device: $device")
                                discoveredDevices[devId] = device
                                mainHandler.post { externalListener?.onDeviceDiscovered(device) }
                            }
                        }
                    } catch (_: SocketTimeoutException) {
                        // Expected socket receive timeout
                    } catch (e: Exception) {
                        if (!isSearching) break
                        Log.d(TAG, "UDP receive exception: ${e.message}")
                    }

                    try { Thread.sleep(3000) } catch (_: InterruptedException) { break }
                }
            } catch (e: Exception) {
                Log.w(TAG, "Could not bind UDP discovery socket on $UDP_DISCOVERY_PORT: ${e.message}")
            }
        }.apply { start() }
    }

    private fun resolveService(serviceInfo: NsdServiceInfo) {
        nsdResolveQueue.resolveOrEnqueue(
            serviceInfo,
            onResolved = { resolvedInfo ->
                val host: InetAddress? = resolvedInfo.host
                val port: Int = resolvedInfo.port
                val hostAddr = host?.hostAddress ?: return@resolveOrEnqueue

                if (!isPrivateAddress(host)) {
                    Log.w(TAG, "Discarding resolved mDNS address $hostAddr: Not a private LAN IP")
                    return@resolveOrEnqueue
                }

                val txtAttributes = parseAttributes(resolvedInfo)
                val deviceId = txtAttributes["id"] ?: resolvedInfo.serviceName
                val name = txtAttributes["name"] ?: resolvedInfo.serviceName
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
            setAttribute("caps", "CLIPBOARD,FILES,NOTIFICATIONS,MEDIA,TERMINAL,POWER_ELEVATED")
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
