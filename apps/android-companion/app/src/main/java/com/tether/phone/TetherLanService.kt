@file:Suppress("DEPRECATION", "unused")

package com.tether.phone

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
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.PowerManager
import android.os.SystemClock
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.content.edit
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancelChildren
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.nio.charset.StandardCharsets
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

enum class TransportState {
    DISCONNECTED,
    DISCOVERING,
    HOST_FOUND,
    CONNECTING,
    TLS_HANDSHAKE,
    AUTHENTICATING,
    PAIRING_REQUIRED,
    AUTHENTICATED,
    READY,
    FAILED
}

class TetherLanService : Service(), TetherDiscoveryListener {

    companion object {
        const val TAG = "TetherLanService"

        const val ACTION_LAN_STATE_CHANGED = "com.tether.phone.ACTION_GATT_STATE_CHANGED"
        const val ACTION_COMMAND_CONFIRMED = "com.tether.phone.ACTION_COMMAND_CONFIRMED"
        const val ACTION_CONNECT_DIRECT = "com.tether.phone.ACTION_CONNECT_DIRECT"
        const val ACTION_INITIATE_PAIRING = "com.tether.phone.ACTION_INITIATE_PAIRING"
        const val ACTION_CANCEL_PAIRING = "com.tether.phone.ACTION_CANCEL_PAIRING"
        const val ACTION_FORGET_TRUST = "com.tether.phone.ACTION_FORGET_TRUST"
        const val ACTION_CONFIRM_PAIRING = "com.tether.phone.ACTION_CONFIRM_PAIRING"
        const val ACTION_REJECT_PAIRING = "com.tether.phone.ACTION_REJECT_PAIRING"
        const val ACTION_SHOW_PAIRING_PROMPT = "com.tether.phone.ACTION_SHOW_PAIRING_PROMPT"

        const val EXTRA_CONNECTION_COUNT = "extra_connection_count"
        const val EXTRA_TRANSPORT_STATE = "extra_transport_state"
        const val EXTRA_TRUST_STATE = "extra_trust_state"
        const val EXTRA_PHONE_FINGERPRINT = "extra_phone_fingerprint"
        const val EXTRA_WINDOWS_FINGERPRINT = "extra_windows_fingerprint"
        const val EXTRA_PAIRING_REQUEST_ID = "extra_pairing_request_id"
        const val EXTRA_PAIRING_PIN = "extra_pairing_pin"
        const val EXTRA_PAIRING_SAS_CODE = "extra_pairing_sas_code"
        const val EXTRA_PEER_DEVICE_NAME = "extra_peer_device_name"

        const val ALARM_ACTION = "com.tether.phone.ALARM_HEALTH_CHECK"
        const val ACTION_RESTART_SERVER = "com.tether.phone.ACTION_RESTART_SERVER"

        private const val CHANNEL_ID = "tether_lan_channel"
        private const val NOTIFICATION_ID = 1
        private const val HEALTH_CHECK_INTERVAL_MS = 60000L
        private const val WAKE_LOCK_TAG = "tether:LanWakeLock"

        // SECURITY FIX: CWE-117 Defensive log sanitizer stripping control chars
        fun sanitizeLog(input: String?): String {
            if (input == null) return "null"
            return input
                .replace("\r", "\\r")
                .replace("\n", "\\n")
                .replace("\t", "\\t")
                .filter { it.code in 0x20..0x7E || it.code > 0x7F }
                .take(256)
        }
    }

    private val serviceJob = SupervisorJob()
    private val serviceScope = CoroutineScope(Dispatchers.IO + serviceJob)

    private val mainHandler = Handler(Looper.getMainLooper())
    private val networkExecutor = Executors.newCachedThreadPool()

    private lateinit var securityEngine: ProductionSecurityEngine
    private lateinit var discoveryManager: TetherDiscoveryManager
    private lateinit var pairingManager: TetherPairingManager
    private lateinit var capabilityManager: TetherCapabilityManager
    private lateinit var connectivityManager: ConnectivityManager
    private var activeTransport: TetherTransport? = null

    private lateinit var powerManager: PowerManager
    private var wakeLock: PowerManager.WakeLock? = null

    private var alarmManager: AlarmManager? = null
    private var alarmPendingIntent: PendingIntent? = null

    private var reconnectJob: Job? = null
    private var reconnectAttempt = 0

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
    private var currentVolumeLevel: Int = 50

    @Volatile
    private var connectedHostPort: Int = TetherDiscoveryManager.DEFAULT_PORT

    @Volatile
    private var pendingRequestId: String? = null

    @Volatile
    private var pendingWinEcPubKey: ByteArray? = null

    @Volatile
    private var pendingTranscriptHash: ByteArray? = null

    private val processedRequestIds = ConcurrentHashMap<String, Long>()

    private val powerSaveReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            when (intent?.action) {
                PowerManager.ACTION_POWER_SAVE_MODE_CHANGED -> {
                    if (currentState == TransportState.DISCONNECTED) {
                        startDiscovery()
                    }
                }
            }
        }
    }

    private val wifiNetworkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            Log.i(TAG, "Wi-Fi network AVAILABLE. Resetting reconnect backoff...")
            resetReconnectBackoff()
            if ((currentState == TransportState.DISCONNECTED) || (currentState == TransportState.FAILED)) {
                startDiscovery()
            }
        }

        override fun onLost(network: Network) {
            Log.w(TAG, "Wi-Fi network LOST. Tearing down transport and discovery...")
            resetReconnectBackoff()
            discoveryManager.stopDiscovery()
            discoveryManager.stopAdvertising()
            disconnectActiveSession("Wi-Fi lost")
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

        discoveryManager = TetherDiscoveryManager(this, securityEngine)
        discoveryManager.setDiscoveryListener(this)

        pairingManager = TetherPairingManager(this, securityEngine)
        capabilityManager = TetherCapabilityManager()

        val pinnedKey = securityEngine.getPinnedKeyDecrypted(this)
        trustState = if (pinnedKey != null) TrustState.PAIRED else TrustState.UNPAIRED

        powerManager = getSystemService(POWER_SERVICE) as PowerManager
        wakeLock = powerManager.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, WAKE_LOCK_TAG)
        try {
            wakeLock?.acquire(10 * 60 * 1000L)
        } catch (_: Exception) {}

        connectivityManager = getSystemService(CONNECTIVITY_SERVICE) as ConnectivityManager
        val wifiRequest = NetworkRequest.Builder()
            .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
            .build()
        try {
            connectivityManager.registerNetworkCallback(wifiRequest, wifiNetworkCallback)
        } catch (e: Exception) {
            Log.e(TAG, "Failed registering Wi-Fi NetworkCallback: ${e.message}")
        }

        registerReceiver(powerSaveReceiver, IntentFilter(PowerManager.ACTION_POWER_SAVE_MODE_CHANGED))
        scheduleAlarmForHealthCheck()
        startRequestIdCleanup()
    }

    // SECURITY FIX: CWE-400 Bounded processedRequestIds with periodic cleanup
    private fun startRequestIdCleanup() {
        serviceScope.launch {
            while (isActive) {
                delay(60_000L)
                val cutoff = System.currentTimeMillis() - 5 * 60_000L
                val iterator = processedRequestIds.entries.iterator()
                while (iterator.hasNext()) {
                    if (iterator.next().value < cutoff) iterator.remove()
                }
            }
        }
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
        Log.d(TAG, "onStartCommand action: ${sanitizeLog(action)}")

        when (action) {
            ALARM_ACTION -> {
                performHealthCheck()
                scheduleAlarmForHealthCheck()
                return START_STICKY
            }
            "ACTION_GET_STATUS" -> {
                notifyStateToInterface()
                if ((currentState == TransportState.DISCONNECTED) || (currentState == TransportState.FAILED)) {
                    startDiscovery()
                }
                return START_STICKY
            }
            ACTION_RESTART_SERVER -> {
                Log.w(TAG, "Manual server/transport restart requested")
                resetReconnectBackoff()
                restartTransport()
                return START_STICKY
            }
            ACTION_CONNECT_DIRECT -> {
                val targetIp = intent.getStringExtra("target_ip")
                val targetPort = intent.getIntExtra("target_port", TetherDiscoveryManager.DEFAULT_PORT)
                if (!targetIp.isNullOrBlank()) {
                    Log.i(TAG, "Direct target connection requested: ${sanitizeLog(targetIp)}:$targetPort")
                    getSharedPreferences("tether_secure_prefs", MODE_PRIVATE).edit {
                        putString("saved_host_ip", targetIp)
                    }
                    resetReconnectBackoff()
                    connectToHost(targetIp, targetPort)
                } else {
                    resetReconnectBackoff()
                    restartTransport()
                }
                return START_STICKY
            }
            ACTION_INITIATE_PAIRING -> {
                Log.i(TAG, "Explicit pairing requested by user.")
                trustState = TrustState.PAIRING_REQUESTED
                resetReconnectBackoff()
                restartTransport()
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
            ACTION_CONFIRM_PAIRING -> {
                val reqId = intent.getStringExtra(EXTRA_PAIRING_REQUEST_ID) ?: pendingRequestId ?: ""
                val userPin = intent.getStringExtra(EXTRA_PAIRING_PIN) ?: ""
                Log.i(TAG, "Confirm pairing action received for reqId=$reqId")
                confirmPairing(reqId, userPin)
                return START_STICKY
            }
            ACTION_REJECT_PAIRING -> {
                val reqId = intent.getStringExtra(EXTRA_PAIRING_REQUEST_ID) ?: pendingRequestId ?: ""
                Log.i(TAG, "Reject pairing action received for reqId=$reqId")
                rejectPairing(reqId)
                return START_STICKY
            }
            null -> {
                if (currentState == TransportState.DISCONNECTED) {
                    startDiscovery()
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

    @Synchronized
    fun startDiscovery() {
        if ((currentState == TransportState.AUTHENTICATED) || (currentState == TransportState.READY) || (currentState == TransportState.CONNECTING)) {
            return
        }
        currentState = TransportState.DISCOVERING
        Log.i(TAG, "Starting mDNS local discovery & advertisement...")

        discoveryManager.startDiscovery()
        discoveryManager.advertiseService()

        val savedHostIp = getSharedPreferences("tether_secure_prefs", MODE_PRIVATE)
            .getString("saved_host_ip", null)
        if (!savedHostIp.isNullOrBlank()) {
            Log.i(TAG, "Attempting connection to saved target host IP: ${sanitizeLog(savedHostIp)}")
            connectToHost(savedHostIp)
        }
    }

    override fun onDeviceDiscovered(device: DiscoveredDevice) {
        val safeName = sanitizeLog(device.name)
        val safeAddr = sanitizeLog(device.hostAddress)
        Log.i(TAG, "mDNS Discovered Tether device: $safeName at $safeAddr:${device.port}")
        if ((currentState == TransportState.DISCOVERING) || (currentState == TransportState.DISCONNECTED)) {
            currentState = TransportState.HOST_FOUND
            connectToHost(device.hostAddress, device.port)
        }
    }

    override fun onDeviceLost(deviceId: String) {
        val safeDevId = sanitizeLog(deviceId)
        Log.i(TAG, "mDNS Device lost: $safeDevId")
    }

    override fun onDiscoveryError(errorCode: Int, message: String) {
        Log.e(TAG, "mDNS Discovery error: $errorCode - ${sanitizeLog(message)}")
        val savedHostIp = getSharedPreferences("tether_secure_prefs", MODE_PRIVATE)
            .getString("saved_host_ip", null)
        if (!savedHostIp.isNullOrBlank() && ((currentState == TransportState.DISCOVERING) || (currentState == TransportState.DISCONNECTED))) {
            Log.i(TAG, "mDNS discovery error; attempting direct connection to saved host IP: ${sanitizeLog(savedHostIp)}")
            connectToHost(savedHostIp)
        }
    }

    fun connectToHost(hostAddress: String, port: Int = TetherDiscoveryManager.DEFAULT_PORT) {
        if ((currentState == TransportState.AUTHENTICATING) || (currentState == TransportState.AUTHENTICATED) || (currentState == TransportState.READY)) return

        currentState = TransportState.CONNECTING
        connectedHostAddress = hostAddress
        connectedHostPort = port

        serviceScope.launch {
            val transport = TetherTlsTransport(this@TetherLanService, securityEngine)
            try {
                currentState = TransportState.TLS_HANDSHAKE
                transport.connect(hostAddress, port)

                activeTransport = transport
                currentState = TransportState.AUTHENTICATING

                val result = pairingManager.executeHandshake(
                    transport = transport,
                    isUserInitiatedPairing = ((trustState == TrustState.PAIRING_REQUESTED) || (trustState == TrustState.REPAIRING)),
                )

                when (result) {
                    is PairingResult.Authenticated -> {
                        Log.i(TAG, "Successfully authenticated with Windows host ${sanitizeLog(result.peerDeviceId)}!")
                        resetReconnectBackoff()
                        trustState = TrustState.PAIRED
                        currentState = TransportState.AUTHENTICATED
                        // SECURITY FIX: Negotiate capabilities based on peer advertisement
                        capabilityManager.negotiateCapabilities(result.peerCapabilities.ifBlank { "" })

                        mainHandler.postDelayed(
                            {
                                currentState = TransportState.READY
                            },
                            200,
                        )

                        listenSocketLoop(transport)
                    }
                    is PairingResult.PairingPending -> {
                        Log.i(TAG, "Pairing pending for requestId=${result.requestId}. Launching PairingConfirmationActivity...")
                        resetReconnectBackoff()
                        pendingRequestId = result.requestId
                        pendingWinEcPubKey = result.winEcPubKeyBytes
                        pendingTranscriptHash = result.transcriptHash

                        trustState = TrustState.PAIRING_REQUESTED
                        currentState = TransportState.PAIRING_REQUIRED

                        val promptIntent = Intent(this@TetherLanService, PairingConfirmationActivity::class.java).apply {
                            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
                            putExtra(EXTRA_PAIRING_REQUEST_ID, result.requestId)
                            putExtra(EXTRA_PEER_DEVICE_NAME, result.peerName)
                            putExtra(EXTRA_WINDOWS_FINGERPRINT, result.peerFingerprint)
                        }
                        startActivity(promptIntent)
                    }
                    is PairingResult.PairingDenied -> {
                        Log.w(TAG, "Pairing denied by Windows host: ${sanitizeLog(result.reason)}")
                        trustState = TrustState.PAIRING_DENIED
                        disconnectActiveSession("Pairing denied")
                    }
                    is PairingResult.KeyMismatch -> {
                        Log.e(TAG, "SECURITY ALERT: Public key mismatch for Windows host! Failing closed.")
                        trustState = TrustState.KEY_MISMATCH
                        disconnectActiveSession("Key mismatch")
                    }
                    is PairingResult.Error -> {
                        Log.e(TAG, "Pairing/Handshake error: ${sanitizeLog(result.message)}")
                        currentState = TransportState.FAILED
                        disconnectActiveSession(result.message)
                        scheduleReconnectWithBackoff("Handshake error: ${result.message}")
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Connection failed to ${sanitizeLog(hostAddress)}:$port: ${e.message}", e)
                currentState = TransportState.FAILED
                disconnectActiveSession("Connection error: ${e.message}")
                scheduleReconnectWithBackoff("Connection exception: ${e.message}")
            }
        }
    }

    fun confirmPairing(requestId: String, userPin: String) {
        serviceScope.launch {
            val transport = activeTransport
            if ((transport == null) || !transport.isConnected()) {
                Log.e(TAG, "Cannot confirm pairing: active transport is null or disconnected.")
                disconnectActiveSession("Transport lost before confirmation")
                return@launch
            }

            val transcriptHash = pendingTranscriptHash
            if (transcriptHash == null) {
                Log.e(TAG, "Cannot confirm pairing: pending transcript hash is null.")
                disconnectActiveSession("Transcript hash lost")
                return@launch
            }

            Log.i(TAG, "Finalizing pairing with Windows host for requestId=$requestId...")
            val result = pairingManager.finalizePairing(
                transport = transport,
                requestId = requestId,
                userEnteredPin = userPin,
                winEcPubKeyBytes = pendingWinEcPubKey,
                transcriptHash = transcriptHash,
            )

            when (result) {
                is PairingResult.Authenticated -> {
                    Log.i(TAG, "Pairing successfully finalized and keys pinned! Entering READY state...")
                    resetReconnectBackoff()
                    pendingRequestId = null
                    pendingWinEcPubKey = null
                    pendingTranscriptHash = null
                    trustState = TrustState.PAIRED
                    currentState = TransportState.AUTHENTICATED
                    // SECURITY FIX: Negotiate capabilities based on peer advertisement
                    capabilityManager.negotiateCapabilities(result.peerCapabilities.ifBlank { "" })

                    mainHandler.postDelayed(
                        {
                            currentState = TransportState.READY
                        },
                        200,
                    )

                    listenSocketLoop(transport)
                }
                is PairingResult.Error -> {
                    Log.e(TAG, "Failed finalizing pairing: ${sanitizeLog(result.message)}")
                    disconnectActiveSession("Finalize pairing error: ${result.message}")
                    scheduleReconnectWithBackoff("Finalize pairing error")
                }
                else -> {
                    disconnectActiveSession("Unexpected finalize pairing result: $result")
                }
            }
        }
    }

    fun rejectPairing(requestId: String) {
        serviceScope.launch {
            val transport = activeTransport
            if ((transport != null) && transport.isConnected()) {
                try {
                    val rejectJson = JSONObject().apply {
                        put("type", "PAIRING_REJECTED")
                        put("requestId", requestId)
                    }
                    transport.sendFrame(rejectJson.toString().toByteArray(StandardCharsets.UTF_8))
                } catch (e: Exception) {
                    Log.w(TAG, "Error sending PAIRING_REJECTED frame: ${e.message}")
                }
            }
            pendingRequestId = null
            pendingWinEcPubKey = null
            pendingTranscriptHash = null
            disconnectActiveSession("Pairing rejected by user")
        }
    }

    private fun listenSocketLoop(transport: TetherTransport) {
        try {
            while ((currentState == TransportState.AUTHENTICATED) || (currentState == TransportState.READY)) {
                val frameBytes = transport.readFrame()
                if (frameBytes == null) {
                    if (!transport.isConnected()) {
                        break
                    }
                    continue
                }
                val jsonStr = String(frameBytes, StandardCharsets.UTF_8)
                processIncomingFrame(JSONObject(jsonStr), transport)
            }
        } catch (e: Exception) {
            Log.w(TAG, "Transport socket loop terminated: ${e.message}")
        } finally {
            if (activeTransport?.generationId == transport.generationId) {
                disconnectActiveSession("Socket loop terminated")
                scheduleReconnectWithBackoff("Socket loop ended")
            }
        }
    }

    private fun processIncomingFrame(json: JSONObject, transport: TetherTransport) {
        // SECURITY FIX: CWE-400 Bounded processedRequestIds map
        if (processedRequestIds.size > 10_000) {
            Log.w(TAG, "processedRequestIds exceeded cap; clearing oldest half")
            val sorted = processedRequestIds.entries.sortedBy { it.value }
            sorted.take(sorted.size / 2).forEach { processedRequestIds.remove(it.key) }
        }

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

        val safeType = sanitizeLog(type)
        val safeCmd = sanitizeLog(command)
        Log.d(TAG, "Incoming frame type=$safeType command=$safeCmd")

        when (type) {
            "PING" -> {
                Log.d(TAG, "Received PING probe from Windows host. Responding with PONG...")
                serviceScope.launch {
                    try {
                        val pongJson = JSONObject().apply {
                            put("type", "PONG")
                            put("timestamp", System.currentTimeMillis())
                        }
                        transport.sendFrame(pongJson.toString().toByteArray(StandardCharsets.UTF_8))
                    } catch (e: Exception) {
                        Log.w(TAG, "Failed sending PONG frame: ${e.message}")
                    }
                }
            }
            "CONFIRM_COMMAND" -> {
                val confirmedCmd = json.optString("confirmedCommand", command)
                val success = json.optBoolean("success", true)
                val errorReason = json.optString("reason", "")
                val vol = json.optInt("volumeLevel", -1)
                if (vol in 0..100) {
                    currentVolumeLevel = vol
                }
                val safeConfirmed = sanitizeLog(confirmedCmd)
                Log.i(TAG, "Command response from Windows host: $safeConfirmed (success=$success, reason=$errorReason, vol=$currentVolumeLevel)")
                mainHandler.post {
                    val intent = Intent(ACTION_COMMAND_CONFIRMED).apply {
                        putExtra("confirmed_command", confirmedCmd)
                        putExtra("success", success)
                        putExtra("reason", errorReason)
                        putExtra("volume_level", currentVolumeLevel)
                        setPackage(packageName)
                    }
                    sendBroadcast(intent)
                }
            }
            "HARDWARE_METRICS" -> {
                val vol = json.optInt("volumeLevel", -1)
                val bright = json.optInt("brightnessLevel", -1)
                if (vol in 0..100) {
                    currentVolumeLevel = vol
                }
                if ((vol >= 0) || (bright >= 0)) {
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

    fun dispatchCommand(actionCommand: String) {
        serviceScope.launch {
            try {
                if ((currentState != TransportState.READY) && (currentState != TransportState.AUTHENTICATED)) {
                    Log.w(TAG, "Transport not ready ($currentState). Queuing command and starting discovery...")
                    startDiscovery()
                    delay(1.seconds)
                }

                if (!capabilityManager.canExecuteCommand(actionCommand)) {
                    Log.w(TAG, "Capability check failed for command: ${sanitizeLog(actionCommand)}")
                    return@launch
                }

                val reqId = UUID.randomUUID().toString()
                val cmdJson = JSONObject().apply {
                    put("type", "COMMAND_EXECUTE")
                    put("requestId", reqId)
                    put("command", actionCommand)
                    put("timestamp", System.currentTimeMillis())
                }

                val transport = activeTransport
                if ((transport != null) && transport.isConnected()) {
                    transport.sendFrame(cmdJson.toString().toByteArray(StandardCharsets.UTF_8))
                    // SECURITY FIX: CWE-117 Sanitize actionCommand in logs
                    Log.i(TAG, "Dispatched command frame over TLS 1.3: ${sanitizeLog(actionCommand)} (reqId=$reqId)")
                } else {
                    Log.w(TAG, "Active transport disconnected. Re-initiating discovery...")
                    startDiscovery()
                }

            } catch (e: Exception) {
                Log.e(TAG, "Failed to dispatch command (${sanitizeLog(actionCommand)}): ${e.message}")
            }
        }
    }

    fun disconnectActiveSession(reason: String) {
        val safeReason = sanitizeLog(reason)
        Log.w(TAG, "Disconnecting active session: $safeReason")
        try { activeTransport?.disconnect(reason) } catch (_: Exception) {}
        activeTransport = null
        currentState = TransportState.DISCONNECTED
    }

    private fun restartTransport() {
        disconnectActiveSession("Transport restart requested")
        startDiscovery()
    }

    private fun scheduleReconnectWithBackoff(reason: String) {
        if ((currentState == TransportState.AUTHENTICATED) || (currentState == TransportState.READY) || (currentState == TransportState.CONNECTING)) {
            return
        }
        reconnectJob?.cancel()
        reconnectJob = serviceScope.launch {
            reconnectAttempt++
            val baseDelayMs = 5000L
            val expDelay = baseDelayMs * (1 shl (reconnectAttempt - 1).coerceAtMost(4))
            val jitter = (Math.random() * 1000).toLong()
            val delayMs = (expDelay + jitter).coerceAtMost(60000L)
            Log.i(TAG, "Scheduling controlled reconnect attempt #$reconnectAttempt in ${delayMs}ms (reason: ${sanitizeLog(reason)})...")
            delay(delayMs.milliseconds)
            if (isActive && ((currentState == TransportState.DISCONNECTED) || (currentState == TransportState.FAILED))) {
                startDiscovery()
            }
        }
    }

    private fun resetReconnectBackoff() {
        reconnectAttempt = 0
        reconnectJob?.cancel()
        reconnectJob = null
    }

    private fun performHealthCheck() {
        if ((currentState == TransportState.DISCONNECTED) || (currentState == TransportState.FAILED)) {
            startDiscovery()
        } else if ((currentState == TransportState.READY) || (currentState == TransportState.AUTHENTICATED)) {
            dispatchCommand("PING")
        }
    }

    private fun notifyStateToInterface() {
        val isConn = ((currentState == TransportState.READY) || (currentState == TransportState.AUTHENTICATED))
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
            putExtra("extra_host_address", sanitizeLog(connectedHostAddress))
            putExtra("extra_granted_capabilities", capabilityManager.getNegotiatedCapabilitiesString())
            putExtra("extra_volume_level", currentVolumeLevel)
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
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        alarmPendingIntent = pendingIntent

        alarmManager?.setAndAllowWhileIdle(
            AlarmManager.ELAPSED_REALTIME_WAKEUP,
            SystemClock.elapsedRealtime() + HEALTH_CHECK_INTERVAL_MS,
            pendingIntent,
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
            NotificationManager.IMPORTANCE_LOW,
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
        serviceJob.cancelChildren()

        try { unregisterReceiver(powerSaveReceiver) } catch (_: Exception) {}
        try { connectivityManager.unregisterNetworkCallback(wifiNetworkCallback) } catch (_: Exception) {}

        discoveryManager.stopDiscovery()
        discoveryManager.stopAdvertising()

        cancelAlarm()
        disconnectActiveSession("Service destroyed")

        wakeLock?.let { if (it.isHeld) it.release() }
        wakeLock = null

        mainHandler.removeCallbacksAndMessages(null)
        networkExecutor.shutdown()
        super.onDestroy()
    }
}
