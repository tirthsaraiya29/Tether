package com.tether.phone

import android.annotation.SuppressLint
import android.app.AlarmManager
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.PowerManager
import android.os.SystemClock
import android.util.Base64
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.content.edit
import org.json.JSONObject
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

enum class TransportState {
    DISCONNECTED,
    DISCOVERING,
    HOST_FOUND,
    CONNECTING,
    AUTHENTICATING,
    AUTHENTICATED,
    READY,
    FAILED,
    HOTSPOT_UNSUPPORTED
}

class TetherLanService : Service() {

    companion object {
        const val TAG = "TetherLanService"
        const val SERVICE_TYPE = "_tether._tcp"
        const val DEFAULT_PORT = 37123

        const val ACTION_LAN_STATE_CHANGED = "com.tether.phone.ACTION_GATT_STATE_CHANGED"
        const val ACTION_COMMAND_CONFIRMED = "com.tether.phone.ACTION_COMMAND_CONFIRMED"
        const val ACTION_CONNECT_DIRECT = "com.tether.phone.ACTION_CONNECT_DIRECT"
        const val EXTRA_CONNECTION_COUNT = "extra_connection_count"
        const val EXTRA_TRANSPORT_STATE = "extra_transport_state"

        const val ALARM_ACTION = "com.tether.phone.ALARM_HEALTH_CHECK"
        const val ACTION_RESTART_SERVER = "com.tether.phone.ACTION_RESTART_SERVER"

        private const val CHANNEL_ID = "tether_lan_channel"
        private const val NOTIFICATION_ID = 1
        private const val HEALTH_CHECK_INTERVAL_MS = 60000L
        private const val WAKE_LOCK_TAG = "tether:LanWakeLock"
    }

    private val mainHandler = Handler(Looper.getMainLooper())
    private val networkExecutor = Executors.newCachedThreadPool()

    private lateinit var securityEngine: ProductionSecurityEngine
    private lateinit var powerManager: PowerManager
    private var wakeLock: PowerManager.WakeLock? = null

    private var alarmManager: AlarmManager? = null
    private var alarmPendingIntent: PendingIntent? = null

    @Volatile
    var currentState: TransportState = TransportState.DISCONNECTED
        private set(value) {
            field = value
            Log.i(TAG, "Transport state changed to: $value")
            notifyStateToInterface()
        }

    @Volatile
    private var connectedHostAddress: String? = null

    @Volatile
    private var connectedHostPort: Int = DEFAULT_PORT

    private var nsdManager: NsdManager? = null
    private var discoveryListener: NsdManager.DiscoveryListener? = null
    private var multicastLock: WifiManager.MulticastLock? = null

    private var activeSocket: Socket? = null
    private var dataInputStream: DataInputStream? = null
    private var dataOutputStream: DataOutputStream? = null

    @Volatile
    private var sessionKey: ByteArray? = null

    private val processedRequestIds = ConcurrentHashMap<String, Long>()

    private var connectivityManager: ConnectivityManager? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    @Volatile
    private var isUdpDiscovering = false

    private val broadcastReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            when (intent?.action) {
                PowerManager.ACTION_POWER_SAVE_MODE_CHANGED -> {
                    if (currentState == TransportState.DISCONNECTED) {
                        startLanDiscovery()
                    }
                }
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()

        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                startForeground(NOTIFICATION_ID, createNotification(), ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE)
            } else {
                startForeground(NOTIFICATION_ID, createNotification())
            }
        } catch (_: Exception) {
            stopSelf()
            return
        }

        securityEngine = try {
            ProductionSecurityEngine()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to initialize security engine: ${e.message}")
            stopSelf()
            return
        }

        powerManager = getSystemService(POWER_SERVICE) as PowerManager
        wakeLock = powerManager.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, WAKE_LOCK_TAG)
        try {
            wakeLock?.acquire(10 * 60 * 1000L)
        } catch (_: Exception) {}

        registerReceiver(broadcastReceiver, IntentFilter(PowerManager.ACTION_POWER_SAVE_MODE_CHANGED))

        setupNetworkCallback()
        scheduleAlarmForHealthCheck()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                startForeground(NOTIFICATION_ID, createNotification(), ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE)
            } else {
                startForeground(NOTIFICATION_ID, createNotification())
            }
        } catch (_: Exception) {}

        if (wakeLock?.isHeld == false) {
            try { wakeLock?.acquire(10 * 60 * 1000L) } catch (_: Exception) {}
        }

        val action = intent?.action
        Log.d(TAG, "onStartCommand action: $action")

        when (action) {
            ALARM_ACTION -> {
                performHealthCheck()
                scheduleAlarmForHealthCheck()
                return START_STICKY
            }
            "ACTION_GET_STATUS" -> {
                notifyStateToInterface()
                if ((currentState == TransportState.DISCONNECTED) || (currentState == TransportState.FAILED)) {
                    startLanDiscovery()
                }
                return START_STICKY
            }
            ACTION_RESTART_SERVER -> {
                Log.w(TAG, "Manual server/transport restart requested")
                restartLanTransport()
                return START_STICKY
            }
            ACTION_CONNECT_DIRECT -> {
                val targetIp = intent.getStringExtra("target_ip")
                if (!targetIp.isNullOrBlank()) {
                    Log.i(TAG, "Direct target connection requested: $targetIp")
                    getSharedPreferences("tether_secure_prefs", MODE_PRIVATE).edit {
                        putString("saved_host_ip", targetIp)
                    }
                    onHostDiscovered(targetIp, DEFAULT_PORT)
                } else {
                    restartLanTransport()
                }
                return START_STICKY
            }
            null -> {
                if (currentState == TransportState.DISCONNECTED) {
                    startLanDiscovery()
                }
                return START_STICKY
            }
            else -> {
                // Command requested via action
                if (action.isNotEmpty()) {
                    dispatchCommand(action)
                }
            }
        }

        return START_STICKY
    }

    // Strict Same Wi-Fi and Hotspot Checks
    private fun isHotspotActive(): Boolean {
        return try {
            val wifiManager = applicationContext.getSystemService(WIFI_SERVICE) as WifiManager
            val method = wifiManager.javaClass.getDeclaredMethod("isWifiApEnabled")
            method.isAccessible = true
            (method.invoke(wifiManager) as? Boolean) == true
        } catch (_: Exception) {
            false
        }
    }

    @SuppressLint("MissingPermission")
    private fun isConnectedToInfrastructureWifi(): Boolean {
        val cm = getSystemService(CONNECTIVITY_SERVICE) as ConnectivityManager
        val activeNetwork = cm.activeNetwork ?: return false
        val caps = cm.getNetworkCapabilities(activeNetwork) ?: return false

        // Must be on Wi-Fi (TRANSPORT_WIFI)
        val isWifi = caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
        if (!isWifi) return false

        // Check hotspot status: phone must be a Wi-Fi CLIENT, not an AP/hotspot
        if (isHotspotActive()) {
            Log.w(TAG, "Phone is operating as Mobile Hotspot. Hotspot mode is UNSUPPORTED for Tether LAN transport.")
            return false
        }

        return true
    }

    @SuppressLint("MissingPermission")
    private fun setupNetworkCallback() {
        connectivityManager = getSystemService(CONNECTIVITY_SERVICE) as ConnectivityManager
        val request = NetworkRequest.Builder()
            .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
            .build()

        networkCallback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                Log.i(TAG, "Wi-Fi network available: $network")
                mainHandler.post {
                    if (isHotspotActive()) {
                        currentState = TransportState.HOTSPOT_UNSUPPORTED
                    } else {
                        restartLanTransport()
                    }
                }
            }

            override fun onLost(network: Network) {
                Log.w(TAG, "Wi-Fi network lost: $network")
                mainHandler.post {
                    disconnectActiveSession("Wi-Fi network disconnected")
                    currentState = TransportState.DISCONNECTED
                }
            }

            override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {
                if (isHotspotActive()) {
                    mainHandler.post {
                        disconnectActiveSession("Mobile Hotspot detected")
                        currentState = TransportState.HOTSPOT_UNSUPPORTED
                    }
                }
            }
        }

        try {
            connectivityManager?.registerNetworkCallback(request, networkCallback!!)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to register network callback: ${e.message}")
        }
    }

    private fun acquireMulticastLock() {
        if (multicastLock == null) {
            val wifiManager = applicationContext.getSystemService(WIFI_SERVICE) as WifiManager
            multicastLock = wifiManager.createMulticastLock("TetherLanMulticastLock").apply {
                setReferenceCounted(false)
            }
        }
        if (multicastLock?.isHeld == false) {
            try {
                multicastLock?.acquire()
                Log.i(TAG, "MulticastLock acquired for Wi-Fi LAN mDNS/UDP discovery.")
            } catch (e: Exception) {
                Log.e(TAG, "Failed acquiring MulticastLock: ${e.message}")
            }
        }
    }

    private fun releaseMulticastLock() {
        if (multicastLock?.isHeld == true) {
            try {
                multicastLock?.release()
                Log.i(TAG, "MulticastLock released.")
            } catch (_: Exception) {}
        }
    }

    // LAN Discovery (NSD + UDP Broadcast)
    @Synchronized
    private fun startLanDiscovery() {
        if (!isConnectedToInfrastructureWifi()) {
            if (isHotspotActive()) {
                currentState = TransportState.HOTSPOT_UNSUPPORTED
            } else {
                currentState = TransportState.DISCONNECTED
            }
            return
        }

        if ((currentState == TransportState.AUTHENTICATED) || (currentState == TransportState.READY) || (currentState == TransportState.CONNECTING)) {
            return
        }

        acquireMulticastLock()

        currentState = TransportState.DISCOVERING
        stopLanDiscovery()

        val savedHostIp = getSharedPreferences("tether_secure_prefs", MODE_PRIVATE).getString("saved_host_ip", null)
        if (!savedHostIp.isNullOrBlank()) {
            Log.i(TAG, "Attempting connection to saved target host IP: $savedHostIp")
            onHostDiscovered(savedHostIp, DEFAULT_PORT)
        }

        nsdManager = getSystemService(NSD_SERVICE) as NsdManager

        discoveryListener = object : NsdManager.DiscoveryListener {
            override fun onStartDiscoveryFailed(serviceType: String?, errorCode: Int) {
                Log.e(TAG, "NSD Discovery start failed with error $errorCode")
                nsdManager?.stopServiceDiscovery(this)
            }

            override fun onStopDiscoveryFailed(serviceType: String?, errorCode: Int) {
                Log.e(TAG, "NSD Discovery stop failed with error $errorCode")
            }

            override fun onDiscoveryStarted(serviceType: String?) {
                Log.i(TAG, "NSD Discovery started for $serviceType")
            }

            override fun onDiscoveryStopped(serviceType: String?) {
                Log.i(TAG, "NSD Discovery stopped")
            }

            @Suppress("DEPRECATION")
            override fun onServiceFound(serviceInfo: NsdServiceInfo?) {
                Log.i(TAG, "NSD Service found: ${serviceInfo?.serviceName}")
                if (serviceInfo?.serviceType?.contains("_tether") == true || serviceInfo?.serviceName?.contains("Tether") == true) {
                    try {
                        nsdManager?.resolveService(
                            serviceInfo,
                            object : NsdManager.ResolveListener {
                                override fun onResolveFailed(serviceInfo: NsdServiceInfo?, errorCode: Int) {
                                    Log.e(TAG, "NSD Resolve failed with code $errorCode")
                                }

                                override fun onServiceResolved(serviceInfo: NsdServiceInfo?) {
                                    val host = serviceInfo?.host?.hostAddress
                                    val port = serviceInfo?.port ?: DEFAULT_PORT
                                    if (host != null) {
                                        Log.i(TAG, "NSD Resolved host: $host:$port")
                                        onHostDiscovered(host, port)
                                    }
                                }
                            },
                        )
                    } catch (e: Exception) {
                        Log.e(TAG, "Error resolving NSD service: ${e.message}")
                    }
                }
            }

            override fun onServiceLost(serviceInfo: NsdServiceInfo?) {
                Log.w(TAG, "NSD Service lost: ${serviceInfo?.serviceName}")
            }
        }

        try {
            nsdManager?.discoverServices(SERVICE_TYPE, NsdManager.PROTOCOL_DNS_SD, discoveryListener)
        } catch (e: Exception) {
            Log.e(TAG, "Failed starting NSD service discovery: ${e.message}")
        }

        // UDP Broadcast scan fallback
        startUdpDiscoveryScan()
    }

    private fun stopLanDiscovery() {
        discoveryListener?.let {
            try {
                nsdManager?.stopServiceDiscovery(it)
            } catch (_: Exception) {}
            discoveryListener = null
        }
        isUdpDiscovering = false
    }

    private fun startUdpDiscoveryScan() {
        if (isUdpDiscovering) return
        isUdpDiscovering = true

        networkExecutor.execute {
            var socket: DatagramSocket? = null
            try {
                socket = DatagramSocket()
                socket.broadcast = true
                socket.soTimeout = 3000

                val reqJson = JSONObject().apply {
                    put("type", "TETHER_DISCOVER_REQ")
                    put("client", "AndroidCompanion")
                    put("timestamp", System.currentTimeMillis())
                }.toString().toByteArray(StandardCharsets.UTF_8)

                val broadcastAddr = InetAddress.getByName("255.255.255.255")
                val packet = DatagramPacket(reqJson, reqJson.size, broadcastAddr, DEFAULT_PORT)

                var attempts = 0
                while (isUdpDiscovering && attempts < 5 && currentState == TransportState.DISCOVERING) {
                    attempts++
                    Log.d(TAG, "Sending UDP discovery broadcast request (Attempt $attempts)...")
                    try {
                        socket.send(packet)
                    } catch (e: Exception) {
                        Log.w(TAG, "UDP broadcast send error: ${e.message}")
                    }

                    val recvBuf = ByteArray(2048)
                    val recvPacket = DatagramPacket(recvBuf, recvBuf.size)
                    try {
                        socket.receive(recvPacket)
                        val respStr = String(recvPacket.data, 0, recvPacket.length, StandardCharsets.UTF_8)
                        val json = JSONObject(respStr)
                        if (json.optString("type") == "TETHER_DISCOVER_RESP") {
                            val hostIp = recvPacket.address?.hostAddress ?: return@execute
                            val hostPort = json.optInt("port", DEFAULT_PORT)
                            Log.i(TAG, "Discovered Tether Windows host via UDP broadcast: $hostIp:$hostPort")
                            isUdpDiscovering = false
                            onHostDiscovered(hostIp, hostPort)
                            break
                        }
                    } catch (_: SocketTimeoutException) {
                        // Retry loop
                    }
                    Thread.sleep(1000)
                }
            } catch (e: Exception) {
                Log.e(TAG, "UDP discovery scan error: ${e.message}")
            } finally {
                socket?.close()
                isUdpDiscovering = false
            }
        }
    }

    private fun onHostDiscovered(hostAddress: String, port: Int) {
        if (currentState == TransportState.AUTHENTICATED || currentState == TransportState.READY || currentState == TransportState.CONNECTING) return

        connectedHostAddress = hostAddress
        connectedHostPort = port
        currentState = TransportState.HOST_FOUND

        stopLanDiscovery()
        connectToHost(hostAddress, port)
    }

    // TCP Secure Session & Handshake
    private fun connectToHost(hostAddress: String, port: Int) {
        if (currentState == TransportState.CONNECTING || currentState == TransportState.AUTHENTICATING) return
        currentState = TransportState.CONNECTING

        networkExecutor.execute {
            try {
                Log.i(TAG, "Connecting TCP socket to $hostAddress:$port...")
                val socket = Socket()
                socket.connect(InetSocketAddress(hostAddress, port), 5000)
                socket.soTimeout = 15000

                activeSocket = socket
                dataInputStream = DataInputStream(socket.getInputStream())
                dataOutputStream = DataOutputStream(socket.getOutputStream())

                Log.i(TAG, "TCP socket connected. Initiating cryptographic handshake...")
                performCryptographicHandshake()
            } catch (e: Exception) {
                Log.e(TAG, "TCP Connection failed to $hostAddress:$port: ${e.message}")
                disconnectActiveSession("Connection failed")
                mainHandler.postDelayed({
                    if (isConnectedToInfrastructureWifi()) {
                        startLanDiscovery()
                    }
                }, 3000)
            }
        }
    }

    private fun performCryptographicHandshake() {
        currentState = TransportState.AUTHENTICATING
        try {
            val phoneNonceBytes = ByteArray(32)
            SecureRandom().nextBytes(phoneNonceBytes)
            val phoneNonceBase64 = Base64.encodeToString(phoneNonceBytes, Base64.NO_WRAP)

            val phonePublicKeyBase64 = Base64.encodeToString(securityEngine.getPublicKeyBytes(), Base64.NO_WRAP)

            val handshakeReq = JSONObject().apply {
                put("type", "INIT_HANDSHAKE")
                put("phonePublicKey", phonePublicKeyBase64)
                put("phoneNonce", phoneNonceBase64)
            }

            sendRawFrame(handshakeReq.toString())

            // Read Response
            val responseStr = readRawFrame() ?: throw IllegalStateException("No handshake response from host")
            val respJson = JSONObject(responseStr)

            if (respJson.optString("type") != "HANDSHAKE_RESPONSE") {
                throw IllegalStateException("Invalid handshake response type: ${respJson.optString("type")}")
            }

            val encSessionKeyBase64 = respJson.getString("encryptedSessionKey")
            val winPubKeyBase64 = respJson.getString("windowsPublicKey")
            val winNonceBase64 = respJson.getString("windowsNonce")
            val winSigBase64 = respJson.getString("signature")

            val winPubKeyBytes = Base64.decode(winPubKeyBase64, Base64.NO_WRAP)
            val winSigBytes = Base64.decode(winSigBase64, Base64.NO_WRAP)
            val winNonceBytes = Base64.decode(winNonceBase64, Base64.NO_WRAP)

            // Verify Windows Host Public Key against pinned key
            val pinnedKeyBytes = securityEngine.getPinnedKeyDecrypted(this)
            val prefs = getSharedPreferences("tether_secure_prefs", MODE_PRIVATE)
            val pairingTimestamp = prefs.getLong("pairing_window_start_time", 0L)
            val isPairingWindowOpen = (System.currentTimeMillis() - pairingTimestamp) < 120000

            val isKeyTrusted = if (pinnedKeyBytes != null) {
                winPubKeyBytes.contentEquals(pinnedKeyBytes)
            } else {
                isPairingWindowOpen
            }

            if (!isKeyTrusted) {
                throw SecurityException("Windows Host Public Key untrusted and pairing window closed.")
            }

            // Verify Windows Signature over (phoneNonce + winNonce)
            val dataToVerify = phoneNonceBytes + winNonceBytes
            val sigValid = securityEngine.verifySignature(dataToVerify, winSigBytes, winPubKeyBytes)
            if (!sigValid) {
                throw SecurityException("Windows Host signature verification failed.")
            }

            // Decrypt Session Key using RSA Private Key
            val encSessionKeyBytes = Base64.decode(encSessionKeyBase64, Base64.NO_WRAP)
            val decryptedSessionKey = securityEngine.decryptSessionKey(encSessionKeyBytes)
            this.sessionKey = decryptedSessionKey

            // Pin Windows Public Key if new pairing
            if (pinnedKeyBytes == null) {
                Log.i(TAG, "Pairing successful. Storing pinned Windows public key securely in Keystore.")
                securityEngine.storePinnedKeySecurely(this, winPubKeyBytes)
            }

            // Send AUTH_CONFIRM frame
            val authConfirmData = winNonceBytes + decryptedSessionKey
            val confirmSig = securityEngine.computeHmac(authConfirmData, decryptedSessionKey)
            val authConfirmReq = JSONObject().apply {
                put("type", "AUTH_CONFIRM")
                put("signature", Base64.encodeToString(confirmSig, Base64.NO_WRAP))
            }
            sendRawFrame(authConfirmReq.toString())

            Log.i(TAG, "Cryptographic handshake completed successfully! Session authenticated.")
            currentState = TransportState.AUTHENTICATED

            mainHandler.postDelayed({
                currentState = TransportState.READY
            }, 200)

            // Start socket listener loop
            networkExecutor.execute { listenSocketLoop() }

        } catch (e: Exception) {
            Log.e(TAG, "Handshake failed: ${e.message}", e)
            disconnectActiveSession("Handshake failed: ${e.message}")
            currentState = TransportState.FAILED
            mainHandler.postDelayed({
                if (isConnectedToInfrastructureWifi()) startLanDiscovery()
            }, 5000)
        }
    }

    // Encrypted Frame I/O
    private fun sendRawFrame(dataStr: String) {
        val bytes = dataStr.toByteArray(StandardCharsets.UTF_8)
        val dos = dataOutputStream ?: throw IllegalStateException("OutputStream null")
        synchronized(dos) {
            dos.writeInt(bytes.size)
            dos.write(bytes)
            dos.flush()
        }
    }

    private fun readRawFrame(): String? {
        val dis = dataInputStream ?: return null
        val length = dis.readInt()
        if (length <= 0 || length > 1024 * 1024) return null
        val bytes = ByteArray(length)
        dis.readFully(bytes)
        return String(bytes, StandardCharsets.UTF_8)
    }

    private fun sendEncryptedFrame(jsonObj: JSONObject) {
        val sk = sessionKey ?: throw IllegalStateException("Session key not established")
        val plaintext = jsonObj.toString().toByteArray(StandardCharsets.UTF_8)

        val iv = ByteArray(12)
        SecureRandom().nextBytes(iv)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val keySpec = SecretKeySpec(sk, "AES")
        val gcmSpec = GCMParameterSpec(128, iv)
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec)

        val ciphertext = cipher.doFinal(plaintext)
        val combined = iv + ciphertext

        val dos = dataOutputStream ?: throw IllegalStateException("OutputStream null")
        synchronized(dos) {
            dos.writeInt(combined.size)
            dos.write(combined)
            dos.flush()
        }
    }

    private fun listenSocketLoop() {
        try {
            while (currentState == TransportState.AUTHENTICATED || currentState == TransportState.READY) {
                val dis = dataInputStream ?: break
                val length = try { dis.readInt() } catch (_: Exception) { break }
                if (length <= 0 || length > 1024 * 1024) break

                val encryptedBytes = ByteArray(length)
                dis.readFully(encryptedBytes)

                if (encryptedBytes.size <= 12) continue

                val sk = sessionKey ?: break
                val iv = encryptedBytes.copyOfRange(0, 12)
                val ciphertext = encryptedBytes.copyOfRange(12, encryptedBytes.size)

                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                val keySpec = SecretKeySpec(sk, "AES")
                val gcmSpec = GCMParameterSpec(128, iv)
                cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec)

                val decryptedBytes = cipher.doFinal(ciphertext)
                val jsonStr = String(decryptedBytes, StandardCharsets.UTF_8)

                processIncomingFrame(JSONObject(jsonStr))
            }
        } catch (e: Exception) {
            Log.w(TAG, "Socket loop error/disconnect: ${e.message}")
        } finally {
            disconnectActiveSession("Socket closed")
        }
    }

    private fun processIncomingFrame(json: JSONObject) {
        val requestId = json.optString("requestId", "")
        if (requestId.isNotEmpty() && processedRequestIds.containsKey(requestId)) {
            Log.w(TAG, "Duplicate frame ignored: $requestId")
            return
        }
        if (requestId.isNotEmpty()) {
            processedRequestIds[requestId] = System.currentTimeMillis()
        }

        val type = json.optString("type", "")
        val command = json.optString("command", "")

        Log.d(TAG, "Incoming frame type=$type command=$command")

        when (type) {
            "CONFIRM_COMMAND" -> {
                val confirmedCmd = json.optString("confirmedCommand", command)
                Log.i(TAG, "Command confirmed by Windows host: $confirmedCmd")
                mainHandler.post {
                    val intent = Intent(ACTION_COMMAND_CONFIRMED).apply {
                        putExtra("confirmed_command", confirmedCmd)
                        setPackage(packageName)
                    }
                    sendBroadcast(intent)
                }
            }
            "HARDWARE_METRICS" -> {
                val vol = json.optInt("volumeLevel", -1)
                val bright = json.optInt("brightnessLevel", -1)
                if (vol >= 0 || bright >= 0) {
                    val intent = Intent("com.tether.phone.ACTION_SYNC_HARDWARE_METRICS").apply {
                        putExtra("VOLUME_LEVEL", vol)
                        putExtra("BRIGHTNESS_LEVEL", bright)
                        setPackage(packageName)
                    }
                    sendBroadcast(intent)
                }
            }
        }
    }

    // Public Command Dispatcher
    fun dispatchCommand(actionCommand: String) {
        if (!isConnectedToInfrastructureWifi()) {
            Log.e(TAG, "Cannot dispatch command: Wi-Fi infrastructure connection unavailable.")
            return
        }

        networkExecutor.execute {
            try {
                if (currentState != TransportState.READY && currentState != TransportState.AUTHENTICATED) {
                    Log.w(TAG, "Transport not ready ($currentState). Queuing command and starting discovery...")
                    startLanDiscovery()
                    Thread.sleep(1000)
                }

                val reqId = UUID.randomUUID().toString()
                val cmdJson = JSONObject().apply {
                    put("type", "COMMAND_EXECUTE")
                    put("requestId", reqId)
                    put("command", actionCommand)
                    put("timestamp", System.currentTimeMillis())
                }

                sendEncryptedFrame(cmdJson)
                Log.i(TAG, "Dispatched command frame over secure LAN: $actionCommand (reqId=$reqId)")

            } catch (e: Exception) {
                Log.e(TAG, "Failed to dispatch command ($actionCommand): ${e.message}")
            }
        }
    }

    private fun disconnectActiveSession(reason: String) {
        Log.w(TAG, "Disconnecting active session: $reason")
        sessionKey = null
        try { activeSocket?.close() } catch (_: Exception) {}
        activeSocket = null
        dataInputStream = null
        dataOutputStream = null
        currentState = TransportState.DISCONNECTED
    }

    private fun restartLanTransport() {
        disconnectActiveSession("Transport restart requested")
        startLanDiscovery()
    }

    private fun performHealthCheck() {
        if (!isConnectedToInfrastructureWifi()) {
            if (isHotspotActive()) {
                currentState = TransportState.HOTSPOT_UNSUPPORTED
            } else {
                currentState = TransportState.DISCONNECTED
            }
            return
        }

        if (currentState == TransportState.DISCONNECTED || currentState == TransportState.FAILED) {
            startLanDiscovery()
        } else if (currentState == TransportState.READY || currentState == TransportState.AUTHENTICATED) {
            // Ping host
            dispatchCommand("PING")
        }
    }

    private fun notifyStateToInterface() {
        val isConn = (currentState == TransportState.READY || currentState == TransportState.AUTHENTICATED)
        val count = if (isConn) 1 else 0

        val intent = Intent(ACTION_LAN_STATE_CHANGED).apply {
            putExtra(EXTRA_CONNECTION_COUNT, count)
            putExtra(EXTRA_TRANSPORT_STATE, currentState.name)
            putExtra("extra_host_address", connectedHostAddress ?: "")
            setPackage(packageName)
        }
        sendBroadcast(intent)
    }

    private fun scheduleAlarmForHealthCheck() {
        alarmManager = getSystemService(ALARM_SERVICE) as AlarmManager
        val intent = Intent(this, TetherServiceReceiver::class.java).apply {
            action = ALARM_ACTION
        }
        val pendingIntent = PendingIntent.getBroadcast(
            this, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        alarmPendingIntent = pendingIntent

        alarmManager?.setAndAllowWhileIdle(
            AlarmManager.ELAPSED_REALTIME_WAKEUP,
            SystemClock.elapsedRealtime() + HEALTH_CHECK_INTERVAL_MS,
            pendingIntent
        )
    }

    private fun cancelAlarm() {
        alarmPendingIntent?.let { alarmManager?.cancel(it) }
        alarmPendingIntent = null
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.notification_channel_name),
            NotificationManager.IMPORTANCE_LOW
        )
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    private fun createNotification(): Notification = NotificationCompat.Builder(this, CHANNEL_ID)
        .setContentTitle(getString(R.string.notification_title))
        .setContentText(getString(R.string.notification_text))
        .setSmallIcon(android.R.drawable.ic_lock_lock)
        .setPriority(NotificationCompat.PRIORITY_LOW)
        .build()

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        try { unregisterReceiver(broadcastReceiver) } catch (_: Exception) {}
        networkCallback?.let {
            try { connectivityManager?.unregisterNetworkCallback(it) } catch (_: Exception) {}
        }

        cancelAlarm()
        stopLanDiscovery()
        releaseMulticastLock()
        disconnectActiveSession("Service destroyed")

        wakeLock?.let { if (it.isHeld) it.release() }
        wakeLock = null

        mainHandler.removeCallbacksAndMessages(null)
        networkExecutor.shutdown()
        super.onDestroy()
    }
}
