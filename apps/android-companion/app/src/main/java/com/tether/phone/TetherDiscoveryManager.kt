@file:Suppress("DEPRECATION", "unused")

package com.tether.phone

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.util.Log
import java.net.InetAddress
import java.nio.charset.StandardCharsets
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

class TetherDiscoveryManager(
    context: Context,
    private val securityEngine: ProductionSecurityEngine,
) {

    companion object {
        private const val TAG = "TetherDiscoveryManager"
        const val SERVICE_TYPE = "_tether._tcp."
        const val DEFAULT_PORT = 37123
    }

    private val nsdManager = context.getSystemService(Context.NSD_SERVICE) as NsdManager
    private val mainHandler = Handler(Looper.getMainLooper())

    private var discoveryListener: NsdManager.DiscoveryListener? = null
    private var registrationListener: NsdManager.RegistrationListener? = null

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

    fun startDiscovery() {
        if (isSearching) return
        Log.i(TAG, "Starting mDNS discovery for service type $SERVICE_TYPE")

        val listener = object : NsdManager.DiscoveryListener {
            override fun onStartDiscoveryFailed(serviceType: String?, errorCode: Int) {
                Log.e(TAG, "Discovery start failed: errorCode=$errorCode")
                isSearching = false
                externalListener?.onDiscoveryError(errorCode, "Failed to start discovery")
                try { nsdManager.stopServiceDiscovery(this) } catch (_: Exception) {}
            }

            override fun onStopDiscoveryFailed(serviceType: String?, errorCode: Int) {
                Log.e(TAG, "Discovery stop failed: errorCode=$errorCode")
                isSearching = false
            }

            override fun onDiscoveryStarted(serviceType: String?) {
                Log.i(TAG, "mDNS discovery started successfully for $serviceType")
                isSearching = true
            }

            override fun onDiscoveryStopped(serviceType: String?) {
                Log.i(TAG, "mDNS discovery stopped")
                isSearching = false
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
        }
    }

    private fun resolveService(serviceInfo: NsdServiceInfo) {
        val resolveListener = object : NsdManager.ResolveListener {
            override fun onResolveFailed(serviceInfo: NsdServiceInfo?, errorCode: Int) {
                Log.w(TAG, "Service resolve failed for ${serviceInfo?.serviceName}, error=$errorCode")
            }

            override fun onServiceResolved(resolvedInfo: NsdServiceInfo?) {
                if (resolvedInfo == null) return
                val host: InetAddress? = resolvedInfo.host
                val port: Int = resolvedInfo.port
                val hostAddr = host?.hostAddress ?: return

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
            }
        }

        try {
            nsdManager.resolveService(serviceInfo, resolveListener)
        } catch (e: Exception) {
            Log.e(TAG, "Error resolving service ${serviceInfo.serviceName}: ${e.message}", e)
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
            setAttribute("pqc", "true")
        }

        val listener = object : NsdManager.RegistrationListener {
            override fun onRegistrationFailed(serviceInfo: NsdServiceInfo?, errorCode: Int) {
                Log.e(TAG, "mDNS Service registration failed: errorCode=$errorCode")
                isAdvertising = false
            }

            override fun onUnregistrationFailed(serviceInfo: NsdServiceInfo?, errorCode: Int) {
                Log.e(TAG, "mDNS Service unregistration failed: errorCode=$errorCode")
            }

            override fun onServiceRegistered(registeredInfo: NsdServiceInfo?) {
                Log.i(TAG, "mDNS Service registered successfully as ${registeredInfo?.serviceName}")
                isAdvertising = true
            }

            override fun onServiceUnregistered(serviceInfo: NsdServiceInfo?) {
                Log.i(TAG, "mDNS Service unregistered")
                isAdvertising = false
            }
        }

        this.registrationListener = listener
        try {
            nsdManager.registerService(serviceInfo, NsdManager.PROTOCOL_DNS_SD, listener)
        } catch (e: Exception) {
            Log.e(TAG, "Error registering service: ${e.message}", e)
            isAdvertising = false
        }
    }

    fun stopDiscovery() {
        discoveryListener?.let {
            try { nsdManager.stopServiceDiscovery(it) } catch (_: Exception) {}
        }
        discoveryListener = null
        isSearching = false
    }

    fun stopAdvertising() {
        registrationListener?.let {
            try { nsdManager.unregisterService(it) } catch (_: Exception) {}
        }
        registrationListener = null
        isAdvertising = false
    }

    fun getDiscoveredDevices(): List<DiscoveredDevice> {
        return discoveredDevices.values.toList()
    }
}
