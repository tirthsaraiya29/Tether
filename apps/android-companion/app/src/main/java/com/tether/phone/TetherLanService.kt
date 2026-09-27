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
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.PowerManager
import android.os.SystemClock
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.content.edit
import org.json.JSONObject
import java.nio.charset.StandardCharsets
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors

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
        const val EXTRA_PAIRING_SAS_CODE = "extra_pairing_sas_code"
        const val EXTRA_PEER_DEVICE_NAME = "extra_peer_device_name"

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
    private lateinit var discoveryManager: TetherDiscoveryManager
    private lateinit var pairingManager: TetherPairingManager
    private lateinit var capabilityManager: TetherCapabilityManager
    private var activeTransport: TetherTransport? = null

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
    private var connectedHostPort: Int = TetherDiscoveryManager.DEFAULT_PORT

    @Volatile
    private var pendingRequestId: String? = null

    @Volatile
    private var pendingWinEcPubKey: ByteArray? = null

    @Volatile
    private var pendingWinDsaPubKey: ByteArray? = null

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

        registerReceiver(powerSaveReceiver, IntentFilter(PowerManager.ACTION_POWER_SAVE_MODE_CHANGED))
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
                    startDiscovery()
                }
                return START_STICKY
            }
            ACTION_RESTART_SERVER -> {
                Log.w(TAG, "Manual server/transport restart requested")
                restartTransport()
                return START_STICKY
            }
            ACTION_CONNECT_DIRECT -> {
                val targetIp = intent.getStringExtra("target_ip")
                val targetPort = intent.getIntExtra("target_port", TetherDiscoveryManager.DEFAULT_PORT)
                if (!targetIp.isNullOrBlank()) {
                    Log.i(TAG, "Direct target connection requested: $targetIp:$targetPort")
                    getSharedPreferences("tether_secure_prefs", MODE_PRIVATE).edit {
                        putString("saved_host_ip", targetIp)
                    }
                    connectToHost(targetIp, targetPort)
                } else {
                    restartTransport()
                }
                return START_STICKY
            }
            ACTION_INITIATE_PAIRING -> {
                Log.i(TAG, "Explicit pairing requested by user.")
                trustState = TrustState.PAIRING_REQUESTED
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
                Log.i(TAG, "Confirm pairing action received for reqId=$reqId")
                confirmPairing(reqId)
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
            Log.i(TAG, "Attempting connection to saved target host IP: $savedHostIp")
            connectToHost(savedHostIp)
        }
    }

    override fun onDeviceDiscovered(device: DiscoveredDevice) {
        Log.i(TAG, "mDNS Discovered Tether device: ${device.name} at ${device.hostAddress}:${device.port}")
        if ((currentState == TransportState.DISCOVERING) || (currentState == TransportState.DISCONNECTED)) {
            currentState = TransportState.HOST_FOUND
            connectToHost(device.hostAddress, device.port)
        }
    }

    override fun onDeviceLost(deviceId: String) {
        Log.i(TAG, "mDNS Device lost: $deviceId")
    }

    override fun onDiscoveryError(errorCode: Int, message: String) {
        Log.e(TAG, "mDNS Discovery error: $errorCode - $message")
    }

    fun connectToHost(hostAddress: String, port: Int = TetherDiscoveryManager.DEFAULT_PORT) {
        if ((currentState == TransportState.AUTHENTICATING) || (currentState == TransportState.AUTHENTICATED) || (currentState == TransportState.READY)) return

        currentState = TransportState.CONNECTING
        connectedHostAddress = hostAddress
        connectedHostPort = port

        networkExecutor.execute {
            try {
                val transport = TetherTlsTransport(securityEngine)
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
                        Log.i(TAG, "Successfully authenticated with Windows host ${result.peerDeviceId}!")
                        trustState = TrustState.PAIRED
                        currentState = TransportState.AUTHENTICATED
                        capabilityManager.negotiateCapabilities("CLIPBOARD,FILES,NOTIFICATIONS,MEDIA,TERMINAL,POWER_ELEVATED")

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
                        pendingRequestId = result.requestId
                        pendingWinEcPubKey = result.winEcPubKeyBytes
                        pendingWinDsaPubKey = result.winDsaPubKeyBytes

                        trustState = TrustState.PAIRING_REQUESTED
                        currentState = TransportState.PAIRING_REQUIRED

                        val promptIntent = Intent(this, PairingConfirmationActivity::class.java).apply {
                            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
                            putExtra(EXTRA_PAIRING_REQUEST_ID, result.requestId)
                            putExtra(EXTRA_PEER_DEVICE_NAME, result.peerName)
                            putExtra(EXTRA_WINDOWS_FINGERPRINT, result.peerFingerprint)
                            putExtra(EXTRA_PAIRING_SAS_CODE, result.sasCode)
                        }
                        startActivity(promptIntent)
                        // Note: Keep socket open and activeTransport set, do NOT enter listenSocketLoop or disconnect yet!
                    }
                    is PairingResult.PairingDenied -> {
                        Log.w(TAG, "Pairing denied by Windows host: ${result.reason}")
                        trustState = TrustState.PAIRING_DENIED
                        disconnectActiveSession("Pairing denied")
                    }
                    is PairingResult.KeyMismatch -> {
                        Log.e(TAG, "SECURITY ALERT: Public key mismatch for Windows host! Failing closed.")
                        trustState = TrustState.KEY_MISMATCH
                        disconnectActiveSession("Key mismatch")
                    }
                    is PairingResult.Error -> {
                        Log.e(TAG, "Pairing/Handshake error: ${result.message}")
                        currentState = TransportState.FAILED
                        disconnectActiveSession(result.message)
                        mainHandler.postDelayed({ startDiscovery() }, 5000)
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Connection failed to $hostAddress:$port: ${e.message}", e)
                currentState = TransportState.FAILED
                disconnectActiveSession("Connection error: ${e.message}")
                mainHandler.postDelayed({ startDiscovery() }, 5000)
            }
        }
    }

    fun confirmPairing(requestId: String) {
        networkExecutor.execute {
            val transport = activeTransport
            if ((transport == null) || !transport.isConnected()) {
                Log.e(TAG, "Cannot confirm pairing: active transport is null or disconnected.")
                disconnectActiveSession("Transport lost before confirmation")
                return@execute
            }

            Log.i(TAG, "Finalizing pairing with Windows host for requestId=$requestId...")
            val result = pairingManager.finalizePairing(
                transport = transport,
                requestId = requestId,
                winEcPubKeyBytes = pendingWinEcPubKey,
                winDsaPubKeyBytes = pendingWinDsaPubKey,
            )

            when (result) {
                is PairingResult.Authenticated -> {
                    Log.i(TAG, "Pairing successfully finalized and keys pinned! Entering READY state...")
                    trustState = TrustState.PAIRED
                    currentState = TransportState.AUTHENTICATED
                    capabilityManager.negotiateCapabilities("CLIPBOARD,FILES,NOTIFICATIONS,MEDIA,TERMINAL,POWER_ELEVATED")

                    mainHandler.postDelayed(
                        {
                            currentState = TransportState.READY
                        },
                        200,
                    )

                    listenSocketLoop(transport)
                }
                is PairingResult.Error -> {
                    Log.e(TAG, "Failed finalizing pairing: ${result.message}")
                    disconnectActiveSession("Finalize pairing error: ${result.message}")
                }
                else -> {
                    disconnectActiveSession("Unexpected finalize pairing result: $result")
                }
            }
        }
    }

    fun rejectPairing(requestId: String) {
        networkExecutor.execute {
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
            disconnectActiveSession("Pairing rejected by user")
        }
    }

    private fun listenSocketLoop(transport: TetherTransport) {
        try {
            while ((currentState == TransportState.AUTHENTICATED) || (currentState == TransportState.READY)) {
                val frameBytes = transport.readFrame() ?: break
                val jsonStr = String(frameBytes, StandardCharsets.UTF_8)
                processIncomingFrame(JSONObject(jsonStr))
            }
        } catch (e: Exception) {
            Log.w(TAG, "Transport socket loop terminated: ${e.message}")
        } finally {
            disconnectActiveSession("Socket loop terminated")
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
        networkExecutor.execute {
            try {
                if ((currentState != TransportState.READY) && (currentState != TransportState.AUTHENTICATED)) {
                    Log.w(TAG, "Transport not ready ($currentState). Queuing command and starting discovery...")
                    startDiscovery()
                    Thread.sleep(1000)
                }

                if (!capabilityManager.canExecuteCommand(actionCommand)) {
                    Log.w(TAG, "Capability check failed for command: $actionCommand")
                    return@execute
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
                    Log.i(TAG, "Dispatched command frame over TLS 1.3: $actionCommand (reqId=$reqId)")
                } else {
                    Log.w(TAG, "Active transport disconnected. Re-initiating discovery...")
                    startDiscovery()
                }

            } catch (e: Exception) {
                Log.e(TAG, "Failed to dispatch command ($actionCommand): ${e.message}")
            }
        }
    }

    fun disconnectActiveSession(reason: String) {
        Log.w(TAG, "Disconnecting active session: $reason")
        try { activeTransport?.disconnect(reason) } catch (_: Exception) {}
        activeTransport = null
        currentState = TransportState.DISCONNECTED
    }

    private fun restartTransport() {
        disconnectActiveSession("Transport restart requested")
        startDiscovery()
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
        try { unregisterReceiver(powerSaveReceiver) } catch (_: Exception) {}

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
