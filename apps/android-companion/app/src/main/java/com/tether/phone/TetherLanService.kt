@file:Suppress("DEPRECATION")

package com.tether.phone

import android.Manifest
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
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.NetworkInfo
import android.net.wifi.p2p.WifiP2pConfig
import android.net.wifi.p2p.WifiP2pDevice
import android.net.wifi.p2p.WifiP2pInfo
import android.net.wifi.p2p.WifiP2pManager
import android.net.wifi.WpsInfo
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.PowerManager
import android.os.SystemClock
import android.util.Base64
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import androidx.core.content.edit
import org.json.JSONObject
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
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

        @Suppress("Unused")
        const val SERVICE_TYPE = "_tether._tcp."
        const val DEFAULT_PORT = 37123

        const val ACTION_LAN_STATE_CHANGED = "com.tether.phone.ACTION_GATT_STATE_CHANGED"
        const val ACTION_COMMAND_CONFIRMED = "com.tether.phone.ACTION_COMMAND_CONFIRMED"
        const val ACTION_CONNECT_DIRECT = "com.tether.phone.ACTION_CONNECT_DIRECT"
        const val ACTION_INITIATE_PAIRING = "com.tether.phone.ACTION_INITIATE_PAIRING"
        const val ACTION_CANCEL_PAIRING = "com.tether.phone.ACTION_CANCEL_PAIRING"
        const val ACTION_FORGET_TRUST = "com.tether.phone.ACTION_FORGET_TRUST"

        const val EXTRA_CONNECTION_COUNT = "extra_connection_count"
        const val EXTRA_TRANSPORT_STATE = "extra_transport_state"
        const val EXTRA_TRUST_STATE = "extra_trust_state"
        const val EXTRA_PHONE_FINGERPRINT = "extra_phone_fingerprint"
        const val EXTRA_WINDOWS_FINGERPRINT = "extra_windows_fingerprint"

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
    var trustState: TrustState = TrustState.UNPAIRED
        private set(value) {
            field = value
            Log.i(TAG, "Trust state changed to: $value")
            notifyStateToInterface()
        }

    @Volatile
    private var connectedHostAddress: String? = null

    @Volatile
    private var connectedHostPort: Int = DEFAULT_PORT

    // Wi-Fi Direct (Wi-Fi P2P) components
    private var wifiP2pManager: WifiP2pManager? = null
    private var p2pChannel: WifiP2pManager.Channel? = null
    private var p2pReceiver: BroadcastReceiver? = null
    private var serverSocket: ServerSocket? = null

    @Volatile
    private var isP2pEnabled = false

    @Volatile
    private var isP2pConnecting = false

    private var activeSocket: Socket? = null
    private var dataInputStream: DataInputStream? = null
    private var dataOutputStream: DataOutputStream? = null

    @Volatile
    private var sessionKey: ByteArray? = null

    private val processedRequestIds = ConcurrentHashMap<String, Long>()

    private val powerSaveReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            when (intent?.action) {
                PowerManager.ACTION_POWER_SAVE_MODE_CHANGED -> {
                    if (currentState == TransportState.DISCONNECTED) {
                        startP2pDiscovery()
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

        val pinnedKey = securityEngine.getPinnedKeyDecrypted(this)
        trustState = if (pinnedKey != null) TrustState.PAIRED else TrustState.UNPAIRED

        powerManager = getSystemService(POWER_SERVICE) as PowerManager
        wakeLock = powerManager.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, WAKE_LOCK_TAG)
        try {
            wakeLock?.acquire(10 * 60 * 1000L)
        } catch (_: Exception) {}

        registerReceiver(powerSaveReceiver, IntentFilter(PowerManager.ACTION_POWER_SAVE_MODE_CHANGED))

        setupWifiP2p()
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
                    startP2pDiscovery()
                }
                return START_STICKY
            }
            ACTION_RESTART_SERVER -> {
                Log.w(TAG, "Manual server/transport restart requested")
                restartP2pTransport()
                return START_STICKY
            }
            ACTION_CONNECT_DIRECT -> {
                val targetIp = intent.getStringExtra("target_ip")
                if (!targetIp.isNullOrBlank()) {
                    Log.i(TAG, "Direct target connection requested: $targetIp")
                    getSharedPreferences("tether_secure_prefs", MODE_PRIVATE).edit {
                        putString("saved_host_ip", targetIp)
                    }
                    connectToTcpHost(targetIp)
                } else {
                    restartP2pTransport()
                }
                return START_STICKY
            }
            ACTION_INITIATE_PAIRING -> {
                Log.i(TAG, "Explicit pairing requested by user.")
                trustState = TrustState.PAIRING_REQUESTED
                restartP2pTransport()
                return START_STICKY
            }
            ACTION_CANCEL_PAIRING -> {
                Log.i(TAG, "Pairing request cancelled by user.")
                if (trustState == TrustState.PAIRING_REQUESTED) {
                    trustState = TrustState.UNPAIRED
                }
                disconnectActiveSession("Pairing cancelled by user")
                return START_STICKY
            }
            ACTION_FORGET_TRUST -> {
                Log.i(TAG, "Forget Windows trust requested by user.")
                securityEngine.clearPinnedKey(this)
                trustState = TrustState.REPAIRING
                disconnectActiveSession("Trust cleared by user")
                return START_STICKY
            }
            null -> {
                if (currentState == TransportState.DISCONNECTED) {
                    startP2pDiscovery()
                }
                return START_STICKY
            }
            else -> {
                if (action.isNotEmpty()) {
                    dispatchCommand(action)
                }
            }
        }

        return START_STICKY
    }

    // Wi-Fi Direct (P2P) Initialization & Receiver Registration
    private fun setupWifiP2p() {
        wifiP2pManager = getSystemService(WIFI_P2P_SERVICE) as? WifiP2pManager
        p2pChannel = wifiP2pManager?.initialize(this, mainLooper) {
            Log.w(TAG, "Wi-Fi P2P channel disconnected. Re-initializing...")
            setupWifiP2p()
        }

        val filter = IntentFilter().apply {
            addAction(WifiP2pManager.WIFI_P2P_STATE_CHANGED_ACTION)
            addAction(WifiP2pManager.WIFI_P2P_PEERS_CHANGED_ACTION)
            addAction(WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION)
            addAction(WifiP2pManager.WIFI_P2P_THIS_DEVICE_CHANGED_ACTION)
        }

        p2pReceiver = object : BroadcastReceiver() {
            @SuppressLint("MissingPermission")
            override fun onReceive(context: Context?, intent: Intent?) {
                when (intent?.action) {
                    WifiP2pManager.WIFI_P2P_STATE_CHANGED_ACTION -> {
                        val state = intent.getIntExtra(WifiP2pManager.EXTRA_WIFI_STATE, -1)
                        isP2pEnabled = (state == WifiP2pManager.WIFI_P2P_STATE_ENABLED)
                        Log.i(TAG, "Wi-Fi P2P state changed: enabled=$isP2pEnabled")
                        if (!isP2pEnabled) {
                            currentState = TransportState.HOTSPOT_UNSUPPORTED
                        } else if (currentState == TransportState.DISCONNECTED || currentState == TransportState.HOTSPOT_UNSUPPORTED) {
                            startP2pDiscovery()
                        }
                    }
                    WifiP2pManager.WIFI_P2P_PEERS_CHANGED_ACTION -> {
                        if (hasP2pPermissions()) {
                            wifiP2pManager?.requestPeers(p2pChannel) { peerList ->
                                onPeersDiscovered(peerList.deviceList)
                            }
                        }
                    }
                    WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION -> {
                        @Suppress("DEPRECATION")
                        val networkInfo = intent.getParcelableExtra<NetworkInfo>(WifiP2pManager.EXTRA_NETWORK_INFO)
                        Log.d(TAG, "WIFI_P2P_CONNECTION_CHANGED: isConnected=${networkInfo?.isConnected}")
                        if (networkInfo?.isConnected == true) {
                            wifiP2pManager?.requestConnectionInfo(p2pChannel) { info ->
                                onConnectionInfoAvailable(info)
                            }
                        } else {
                            if (currentState == TransportState.READY || currentState == TransportState.AUTHENTICATED || currentState == TransportState.CONNECTING) {
                                disconnectActiveSession("Wi-Fi Direct link disconnected")
                                startP2pDiscovery()
                            }
                        }
                    }
                    WifiP2pManager.WIFI_P2P_THIS_DEVICE_CHANGED_ACTION -> {
                        @Suppress("DEPRECATION")
                        val device = intent.getParcelableExtra<WifiP2pDevice>(WifiP2pManager.EXTRA_WIFI_P2P_DEVICE)
                        Log.d(TAG, "This P2P device: ${device?.deviceName} status=${device?.status}")
                    }
                }
            }
        }

        try {
            registerReceiver(p2pReceiver, filter)
            Log.i(TAG, "Wi-Fi P2P broadcast receiver registered successfully.")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to register P2P receiver: ${e.message}")
        }
    }

    private fun hasP2pPermissions(): Boolean {
        val fineLoc = ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED
        val nearby = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            ContextCompat.checkSelfPermission(this, Manifest.permission.NEARBY_WIFI_DEVICES) == PackageManager.PERMISSION_GRANTED
        } else true
        return fineLoc && nearby
    }

    // Peer Discovery & Targeted Connection
    @Synchronized
    private fun startP2pDiscovery() {
        if (currentState == TransportState.AUTHENTICATED || currentState == TransportState.READY || currentState == TransportState.CONNECTING) {
            return
        }

        if (!hasP2pPermissions()) {
            Log.w(TAG, "Cannot start P2P discovery: missing required location/nearby permissions.")
            currentState = TransportState.DISCONNECTED
            return
        }

        currentState = TransportState.DISCOVERING

        // Fast path: Attempt connection to saved host IP if manually specified or previously saved
        val savedHostIp = getSharedPreferences("tether_secure_prefs", MODE_PRIVATE)
            .getString("saved_host_ip", null)
        if (!savedHostIp.isNullOrBlank()) {
            Log.i(TAG, "Attempting connection to saved target host IP: $savedHostIp")
            connectToTcpHost(savedHostIp)
        }

        try {
            wifiP2pManager?.discoverPeers(p2pChannel, object : WifiP2pManager.ActionListener {
                override fun onSuccess() {
                    Log.i(TAG, "Wi-Fi Direct peer discovery initiated successfully.")
                }

                override fun onFailure(reason: Int) {
                    Log.e(TAG, "Wi-Fi Direct peer discovery failed with reason: $reason")
                }
            })
        } catch (e: SecurityException) {
            Log.e(TAG, "SecurityException during discoverPeers: ${e.message}")
        }
    }

    private fun onPeersDiscovered(peers: Collection<WifiP2pDevice>) {
        Log.d(TAG, "Discovered ${peers.size} Wi-Fi Direct peer(s)")
        if (currentState == TransportState.AUTHENTICATED || currentState == TransportState.READY) return

        // Target devices advertising names matching "TetherWindows*" or similar filter criteria
        val targetDevice = peers.firstOrNull { device ->
            val name = device.deviceName.orEmpty()
            name.contains("TetherWindows", ignoreCase = true) ||
            name.contains("Tether", ignoreCase = true) ||
            name.startsWith("Tether", ignoreCase = true)
        }

        if (targetDevice != null) {
            Log.i(TAG, "Discovered target Windows peer: ${targetDevice.deviceName} (${targetDevice.deviceAddress}) status=${targetDevice.status}")
            if (currentState == TransportState.DISCOVERING || currentState == TransportState.DISCONNECTED || currentState == TransportState.HOST_FOUND) {
                currentState = TransportState.HOST_FOUND
                connectToP2pPeer(targetDevice)
            }
        }
    }

    @SuppressLint("MissingPermission")
    private fun connectToP2pPeer(device: WifiP2pDevice) {
        if (isP2pConnecting || currentState == TransportState.AUTHENTICATING || currentState == TransportState.AUTHENTICATED || currentState == TransportState.READY) {
            return
        }

        if (device.status == WifiP2pDevice.CONNECTED) {
            Log.i(TAG, "Device ${device.deviceName} already connected at P2P layer. Requesting connection info...")
            wifiP2pManager?.requestConnectionInfo(p2pChannel) { info ->
                onConnectionInfoAvailable(info)
            }
            return
        }

        val config = WifiP2pConfig().apply {
            deviceAddress = device.deviceAddress
            wps.setup = WpsInfo.PBC
            groupOwnerIntent = 0 // Prefer Windows host to act as Group Owner (GO)
        }

        currentState = TransportState.CONNECTING
        isP2pConnecting = true

        try {
            wifiP2pManager?.connect(p2pChannel, config, object : WifiP2pManager.ActionListener {
                override fun onSuccess() {
                    Log.i(TAG, "P2P connection request sent to ${device.deviceName} (${device.deviceAddress})")
                }

                override fun onFailure(reason: Int) {
                    Log.e(TAG, "P2P connect failed with reason code: $reason")
                    isP2pConnecting = false
                    disconnectActiveSession("P2P connect failed ($reason)")
                    mainHandler.postDelayed({ startP2pDiscovery() }, 3000)
                }
            })
        } catch (e: SecurityException) {
            Log.e(TAG, "SecurityException initiating P2P connection: ${e.message}")
            isP2pConnecting = false
        }
    }

    // Group Negotiation & IP Addressing Callback
    private fun onConnectionInfoAvailable(info: WifiP2pInfo) {
        Log.i(TAG, "P2P Connection info: groupFormed=${info.groupFormed}, isGroupOwner=${info.isGroupOwner}, GO Address=${info.groupOwnerAddress?.hostAddress}")
        isP2pConnecting = false

        if (!info.groupFormed) return

        if (info.isGroupOwner) {
            // Android device became Group Owner -> bind ServerSocket(37123) and await Windows peer
            startServerSocketListener()
        } else {
            // Windows host is Group Owner -> extract info.groupOwnerAddress.hostAddress and connect TCP socket
            val goIp = info.groupOwnerAddress?.hostAddress
            if (!goIp.isNullOrBlank()) {
                connectedHostAddress = goIp
                connectToTcpHost(goIp)
            }
        }
    }

    private fun startServerSocketListener() {
        if (serverSocket != null && !serverSocket!!.isClosed) return

        networkExecutor.execute {
            try {
                serverSocket?.close()
                val server = ServerSocket(DEFAULT_PORT)
                serverSocket = server
                Log.i(TAG, "Android is Group Owner. ServerSocket listening on port $DEFAULT_PORT...")

                currentState = TransportState.CONNECTING
                val socket = server.accept()
                socket.soTimeout = 15000
                connectedHostAddress = socket.inetAddress?.hostAddress ?: "P2P_CLIENT"
                Log.i(TAG, "Accepted TCP connection from Windows peer: $connectedHostAddress")

                setupSocketAndStartHandshake(socket)
            } catch (e: Exception) {
                Log.e(TAG, "ServerSocket error: ${e.message}")
            }
        }
    }

    private fun connectToTcpHost(hostAddress: String, port: Int = DEFAULT_PORT) {
        if (currentState == TransportState.AUTHENTICATING || currentState == TransportState.AUTHENTICATED || currentState == TransportState.READY) return
        currentState = TransportState.CONNECTING

        networkExecutor.execute {
            try {
                Log.i(TAG, "Connecting TCP socket to $hostAddress:$port...")
                val socket = Socket()
                socket.connect(InetSocketAddress(hostAddress, port), 5000)
                socket.soTimeout = 15000

                connectedHostAddress = hostAddress
                connectedHostPort = port
                setupSocketAndStartHandshake(socket)
            } catch (e: Exception) {
                Log.e(TAG, "TCP Connection failed to $hostAddress:$port: ${e.message}")
                disconnectActiveSession("TCP connection failed")
                mainHandler.postDelayed({
                    startP2pDiscovery()
                }, 3000)
            }
        }
    }

    private fun setupSocketAndStartHandshake(socket: Socket) {
        activeSocket = socket
        dataInputStream = DataInputStream(socket.getInputStream())
        dataOutputStream = DataOutputStream(socket.getOutputStream())

        Log.i(TAG, "Direct TCP socket connected over P2P link. Initiating cryptographic handshake...")
        performCryptographicHandshake()
    }

    // Cryptographic Handshake & Session Encryption
    private fun performCryptographicHandshake() {
        currentState = TransportState.AUTHENTICATING
        try {
            val phoneNonceBytes = ByteArray(32)
            SecureRandom().nextBytes(phoneNonceBytes)
            val phoneNonceBase64 = Base64.encodeToString(phoneNonceBytes, Base64.NO_WRAP)

            val phonePublicKeyBase64 = Base64.encodeToString(securityEngine.getPublicKeyBytes(), Base64.NO_WRAP)

            val pinnedKeyBytes = securityEngine.getPinnedKeyDecrypted(this)

            val isPairingReq = (pinnedKeyBytes == null && (trustState == TrustState.PAIRING_REQUESTED || trustState == TrustState.REPAIRING))

            val handshakeReq = JSONObject().apply {
                put("type", "INIT_HANDSHAKE")
                put("phonePublicKey", phonePublicKeyBase64)
                put("phoneNonce", phoneNonceBase64)
                put("pairingRequest", isPairingReq)
            }

            Log.i(TAG, "Sending INIT_HANDSHAKE (pairingRequest=$isPairingReq)...")
            sendRawFrame(handshakeReq.toString())

            val responseStr = readRawFrame() ?: throw IllegalStateException("No handshake response from host")
            val respJson = JSONObject(responseStr)

            if (respJson.optString("type") != "HANDSHAKE_RESPONSE") {
                throw IllegalStateException("Invalid handshake response type: ${respJson.optString("type")}")
            }

            val encSessionKeyBase64 = respJson.getString("encryptedSessionKey")
            val winPubKeyBase64 = respJson.getString("windowsPublicKey")
            val winNonceBase64 = respJson.getString("windowsNonce")
            val winSigBase64 = respJson.getString("signature")
            val pairingAccepted = respJson.optBoolean("pairingAccepted", false)

            val winPubKeyBytes = Base64.decode(winPubKeyBase64, Base64.NO_WRAP)
            val winSigBytes = Base64.decode(winSigBase64, Base64.NO_WRAP)
            val winNonceBytes = Base64.decode(winNonceBase64, Base64.NO_WRAP)

            // Step 1: Verify Windows Host Signature over (phoneNonce + winNonce)
            val dataToVerify = phoneNonceBytes + winNonceBytes
            val sigValid = securityEngine.verifySignature(dataToVerify, winSigBytes, winPubKeyBytes)
            if (!sigValid) {
                throw SecurityException("Windows Host signature verification failed.")
            }

            // Step 2: Decrypt Session Key using RSA Private Key in AndroidKeyStore
            val encSessionKeyBytes = Base64.decode(encSessionKeyBase64, Base64.NO_WRAP)
            val decryptedSessionKey = securityEngine.decryptSessionKey(encSessionKeyBytes)

            // Step 3: Enforce Trust and Key Pinning
            if (pinnedKeyBytes != null) {
                if (!winPubKeyBytes.contentEquals(pinnedKeyBytes)) {
                    trustState = TrustState.KEY_MISMATCH
                    val presentedFp = securityEngine.computePublicKeyFingerprint(winPubKeyBytes)
                    val pinnedFp = securityEngine.computePublicKeyFingerprint(pinnedKeyBytes)
                    Log.e(TAG, "SECURITY ALERT: Windows host key mismatch! Presented: $presentedFp, Pinned: $pinnedFp")
                    throw SecurityException("Windows Host Public Key mismatch against pinned identity. Failing closed.")
                }
                trustState = TrustState.PAIRED
            } else {
                if (!pairingAccepted) {
                    trustState = TrustState.PAIRING_DENIED
                    Log.w(TAG, "Pairing request was denied or rejected by Windows host.")
                    throw SecurityException("Pairing rejected by Windows host (pairingAccepted=false).")
                }

                Log.i(TAG, "First pairing accepted by Windows and cryptographically verified. Pinning Windows public key.")
                securityEngine.storePinnedKeySecurely(this, winPubKeyBytes)
                trustState = TrustState.PAIRED
            }

            this.sessionKey = decryptedSessionKey

            // Step 4: Send AUTH_CONFIRM frame
            val authConfirmData = winNonceBytes + decryptedSessionKey
            val confirmSig = securityEngine.computeHmac(authConfirmData, decryptedSessionKey)
            val authConfirmReq = JSONObject().apply {
                put("type", "AUTH_CONFIRM")
                put("signature", Base64.encodeToString(confirmSig, Base64.NO_WRAP))
            }
            sendRawFrame(authConfirmReq.toString())

            Log.i(TAG, "Cryptographic handshake completed successfully over Wi-Fi Direct! Session authenticated.")
            currentState = TransportState.AUTHENTICATED

            mainHandler.postDelayed({
                currentState = TransportState.READY
            }, 200)

            networkExecutor.execute { listenSocketLoop() }

        } catch (e: Exception) {
            Log.e(TAG, "Handshake failed: ${e.message}", e)
            disconnectActiveSession("Handshake failed: ${e.message}")
            if (trustState != TrustState.KEY_MISMATCH && trustState != TrustState.PAIRING_DENIED) {
                currentState = TransportState.FAILED
            }
            mainHandler.postDelayed({
                startP2pDiscovery()
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

    // Command Dispatcher
    fun dispatchCommand(actionCommand: String) {
        networkExecutor.execute {
            try {
                if (currentState != TransportState.READY && currentState != TransportState.AUTHENTICATED) {
                    Log.w(TAG, "Transport not ready ($currentState). Queuing command and starting P2P discovery...")
                    startP2pDiscovery()
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
                Log.i(TAG, "Dispatched command frame over secure P2P: $actionCommand (reqId=$reqId)")

            } catch (e: Exception) {
                Log.e(TAG, "Failed to dispatch command ($actionCommand): ${e.message}")
            }
        }
    }

    private fun disconnectActiveSession(reason: String) {
        Log.w(TAG, "Disconnecting active session: $reason")
        sessionKey = null
        try { activeSocket?.close() } catch (_: Exception) {}
        try { serverSocket?.close() } catch (_: Exception) {}
        activeSocket = null
        serverSocket = null
        dataInputStream = null
        dataOutputStream = null
        currentState = TransportState.DISCONNECTED
        isP2pConnecting = false
    }

    private fun restartP2pTransport() {
        disconnectActiveSession("Transport restart requested")
        startP2pDiscovery()
    }

    private fun performHealthCheck() {
        if (currentState == TransportState.DISCONNECTED || currentState == TransportState.FAILED) {
            startP2pDiscovery()
        } else if (currentState == TransportState.READY || currentState == TransportState.AUTHENTICATED) {
            dispatchCommand("PING")
        }
    }

    private fun notifyStateToInterface() {
        val isConn = (currentState == TransportState.READY || currentState == TransportState.AUTHENTICATED)
        val count = if (isConn) 1 else 0

        val phoneKeyBytes = securityEngine.getPublicKeyBytes()
        val phoneFp = securityEngine.computePublicKeyFingerprint(phoneKeyBytes)

        val pinnedKeyBytes = securityEngine.getPinnedKeyDecrypted(this)
        val winFp = securityEngine.computePublicKeyFingerprint(pinnedKeyBytes)

        val intent = Intent(ACTION_LAN_STATE_CHANGED).apply {
            putExtra(EXTRA_CONNECTION_COUNT, count)
            putExtra(EXTRA_TRANSPORT_STATE, currentState.name)
            putExtra(EXTRA_TRUST_STATE, trustState.name)
            putExtra(EXTRA_PHONE_FINGERPRINT, phoneFp)
            putExtra(EXTRA_WINDOWS_FINGERPRINT, winFp)
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
        try { unregisterReceiver(powerSaveReceiver) } catch (_: Exception) {}
        try { p2pReceiver?.let { unregisterReceiver(it) } } catch (_: Exception) {}

        try {
            p2pChannel?.close()
        } catch (_: Exception) {}

        cancelAlarm()
        disconnectActiveSession("Service destroyed")

        wakeLock?.let { if (it.isHeld) it.release() }
        wakeLock = null

        mainHandler.removeCallbacksAndMessages(null)
        networkExecutor.shutdown()
        super.onDestroy()
    }
}
