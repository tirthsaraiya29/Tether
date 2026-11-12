package com.tether.phone

import android.app.AlarmManager
import android.app.Notification
import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.ClipData
import android.content.ClipboardManager
import java.security.MessageDigest
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.PowerManager
import android.os.SystemClock
import android.util.Base64
import android.util.Log
import androidx.core.app.ActivityCompat
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import androidx.core.content.edit
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancelChildren
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.nio.charset.StandardCharsets
import java.util.Locale
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
        const val ACTION_DISMISS_LOCK_SESSION = "com.tether.phone.ACTION_DISMISS_LOCK_SESSION"
        const val ACTION_PAIRING_INVALID_PIN = "com.tether.phone.ACTION_PAIRING_INVALID_PIN"
        const val EXTRA_REMAINING_ATTEMPTS = "com.tether.phone.EXTRA_REMAINING_ATTEMPTS"
        const val EXTRA_ERROR_MESSAGE = "com.tether.phone.EXTRA_ERROR_MESSAGE"
        const val EXTRA_LOCK_SESSION_ID = "com.tether.phone.EXTRA_LOCK_SESSION_ID"

        const val EXTRA_CONNECTION_COUNT = "extra_connection_count"
        const val EXTRA_TRANSPORT_STATE = "extra_transport_state"
        const val EXTRA_TRUST_STATE = "extra_trust_state"
        const val EXTRA_PHONE_FINGERPRINT = "extra_phone_fingerprint"
        const val EXTRA_WINDOWS_FINGERPRINT = "extra_windows_fingerprint"
        const val EXTRA_PAIRING_REQUEST_ID = "extra_pairing_request_id"
        const val EXTRA_PAIRING_PIN = "extra_pairing_pin"
        const val EXTRA_PAIRING_SAS_CODE = "extra_pairing_sas_code"
        const val EXTRA_PEER_DEVICE_NAME = "extra_peer_device_name"

        const val EXTRA_LAPTOP_POWER_STATE = "extra_laptop_power_state"
        const val EXTRA_LAPTOP_BATTERY_PERCENT = "extra_laptop_battery_percent"
        const val EXTRA_LAPTOP_IS_CHARGING = "extra_laptop_is_charging"
        const val EXTRA_LAPTOP_WALLPAPER_PATH = "extra_laptop_wallpaper_path"
        const val EXTRA_LAPTOP_LAST_SEEN_MS = "extra_laptop_last_seen_ms"
        const val EXTRA_LAPTOP_LAST_POWER_CMD = "extra_laptop_last_power_cmd"
        const val EXTRA_LAPTOP_LAST_POWER_CMD_MS = "extra_laptop_last_power_cmd_ms"

        const val ACTION_RESET_LAPTOP_STATE = "com.tether.phone.ACTION_RESET_LAPTOP_STATE"
        const val DEBUG_INJECT_LAPTOP_STATE = "com.tether.phone.DEBUG_INJECT_LAPTOP_STATE"

        const val ALARM_ACTION = "com.tether.phone.ALARM_HEALTH_CHECK"
        const val ACTION_RESTART_SERVER = "com.tether.phone.ACTION_RESTART_SERVER"
        const val ACTION_CLIPBOARD_SYNC = "com.tether.phone.ACTION_CLIPBOARD_SYNC"
        const val ACTION_NOTIFICATION_SYNC = "com.tether.phone.ACTION_NOTIFICATION_SYNC"
        const val ACTION_TERMINAL_OUTPUT = "com.tether.phone.ACTION_TERMINAL_OUTPUT"
        const val ACTION_TERMINAL_SESSION = "com.tether.phone.ACTION_TERMINAL_SESSION"
        const val ACTION_MEDIA_UPDATE = "com.tether.phone.ACTION_MEDIA_UPDATE"
        const val ACTION_AUDIO_SESSIONS_UPDATE = "com.tether.phone.ACTION_AUDIO_SESSIONS_UPDATE"
        const val ACTION_ADMIN_TELEMETRY = "com.tether.phone.ACTION_ADMIN_TELEMETRY"
        const val ACTION_BATTERY_HEALTH = "com.tether.phone.ACTION_BATTERY_HEALTH"
        const val ACTION_POWER_PLANS = "com.tether.phone.ACTION_POWER_PLANS"
        const val ACTION_PRINTERS = "com.tether.phone.ACTION_PRINTERS"
        const val ACTION_USB_DEVICES = "com.tether.phone.ACTION_USB_DEVICES"
        const val ACTION_SERVICES = "com.tether.phone.ACTION_SERVICES"
        const val ACTION_UPDATES = "com.tether.phone.ACTION_UPDATES"
        const val ACTION_WORKFLOWS = "com.tether.phone.ACTION_WORKFLOWS"
        const val ACTION_WORKFLOW_STATUS = "com.tether.phone.ACTION_WORKFLOW_STATUS"
        const val ACTION_WINDOWS_LIST = "com.tether.phone.ACTION_WINDOWS_LIST"
        const val ACTION_INSTALLED_APPS = "com.tether.phone.ACTION_INSTALLED_APPS"
        const val ACTION_BATTERY_REPORT = "com.tether.phone.ACTION_BATTERY_REPORT"
        const val ACTION_HARDWARE_SPECS = "com.tether.phone.ACTION_HARDWARE_SPECS"

        private const val CHANNEL_ID = "tether_lan_channel"
        private const val NOTIFICATION_ID = 1
        private const val NOTIFICATION_PAIRING_ID = 1002
        private const val HEALTH_CHECK_INTERVAL_MS = 60000L
        private const val WAKE_LOCK_TAG = "tether:LanWakeLock"

        fun sanitizeLog(input: String?): String {
            if (input == null) return "null"
            return input
                .replace("\r", "\\r")
                .replace("\n", "\\n")
                .replace("\t", "\\t")
                .filter { (it.code >= 0x20) && (it.code != 0x7F) }
                .take(256)
        }

        fun normalizeCommand(cmd: String): String {
            return when (cmd.trim().uppercase()) {
                "PWR_SHUTDOWN", "SHUTDOWN", "HALT" -> "shutdown"
                "PWR_REBOOT", "REBOOT", "PWR_RESTART", "RESTART" -> "reboot"
                "PWR_SLEEP", "SLEEP", "HIBERNATE" -> "sleep"
                "LOCK_NOW", "LOCK" -> "lock_now"
                "UNLOCK" -> "unlock"
                else -> cmd.trim().lowercase()
            }
        }

        @Volatile
        var instance: TetherLanService? = null
            private set
    }

    private val serviceJob = SupervisorJob()
    private val serviceScope = CoroutineScope(Dispatchers.IO + serviceJob)

    private val mainHandler = Handler(Looper.getMainLooper())
    private val networkExecutor = Executors.newCachedThreadPool()

    lateinit var securityEngine: ProductionSecurityEngine
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
    private var lastClipboardHash: String = ""
    private var clipboardListener: ClipboardManager.OnPrimaryClipChangedListener? = null

    private val notificationMirrorReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == TetherNotificationListenerService.ACTION_NOTIFICATION_POSTED) {
                val id = intent.getLongExtra(TetherNotificationListenerService.EXTRA_NOTIF_ID, 0L)
                val pkg = intent.getStringExtra(TetherNotificationListenerService.EXTRA_NOTIF_PKG) ?: ""
                val title = intent.getStringExtra(TetherNotificationListenerService.EXTRA_NOTIF_TITLE) ?: ""
                val text = intent.getStringExtra(TetherNotificationListenerService.EXTRA_NOTIF_TEXT) ?: ""
                val time = intent.getLongExtra(TetherNotificationListenerService.EXTRA_NOTIF_TIME, System.currentTimeMillis())
                sendNotificationMirror(id, pkg, title, text, time)
            }
        }
    }

    @Volatile var currentPowerState: LaptopPowerState = LaptopPowerState.UNKNOWN
    @Volatile var batteryPercent: Int = -1
    @Volatile var isCharging: Boolean = false
    @Volatile var wallpaperPath: String? = null
    @Volatile var lastSeenAtMs: Long = 0L
    @Volatile var lastPowerCommand: String? = null
    @Volatile var lastPowerCommandAtMs: Long = 0L

    @Volatile var lastPowerEventType: String? = null
    @Volatile var lastPowerEventTimestampMs: Long = 0L

    private var rebootTimeoutJob: Job? = null
    private var shutdownTimeoutJob: Job? = null
    private var connectJob: Job? = null
    private var readyTransitionJob: Job? = null
    private val connectLock = Any()
    private val wallpaperWriteMutex = kotlinx.coroutines.sync.Mutex()
    @Volatile private var lastNotifiedLockSessionId: String? = null
    @Volatile private var lastNotifiedLockAtMs: Long = 0L
    @Volatile private var pendingUnlockUntilMs: Long = 0L

    @Volatile var connectedPeerName: String = "Windows PC"

    @Volatile
    var currentState: TransportState = TransportState.DISCONNECTED
        private set(value) {
            val oldState = field
            field = value
            Log.i(TAG, "Transport state changed to: $value")
            if (((value == TransportState.READY) || (value == TransportState.AUTHENTICATED)) &&
                ((oldState != TransportState.READY) && (oldState != TransportState.AUTHENTICATED))) {
                onHostConnected()
            } else if (((value == TransportState.DISCONNECTED) || (value == TransportState.FAILED)) &&
                ((oldState == TransportState.READY) || (oldState == TransportState.AUTHENTICATED))) {
                onHostDisconnected()
            }
            notifyStateToInterface()
        }

    private fun onHostConnected() {
        while (inputFrameChannel.tryReceive().isSuccess) { /* flush stale frames before reconnect */ }
        pendingUnlockRequests.clear()
        lastPowerCommand = null
        lastPowerCommandAtMs = 0L
        rebootTimeoutJob?.cancel()
        shutdownTimeoutJob?.cancel()

        startInputPump()

        currentPowerState = LaptopPowerState.UNKNOWN
        getSharedPreferences("tether_secure_prefs", MODE_PRIVATE).edit {
            remove("last_power_command")
            remove("last_power_command_at_ms")
            putString("laptop_power_state", LaptopPowerState.UNKNOWN.name)
        }
        updateUnlockNotificationState()
    }

    private fun onHostDisconnected() {
        readyTransitionJob?.cancel()
        readyTransitionJob = null
        while (inputFrameChannel.tryReceive().isSuccess) { /* flush stale frames on link loss */ }
        pendingUnlockRequests.clear()
        if ((currentPowerState != LaptopPowerState.POWERED_OFF) && (currentPowerState != LaptopPowerState.RESTARTING)) {
            currentPowerState = when (lastPowerCommand) {
                "shutdown" -> LaptopPowerState.POWERED_OFF
                "reboot" -> LaptopPowerState.RESTARTING
                else -> LaptopPowerState.DISCONNECTED
            }
        }
        getSharedPreferences("tether_secure_prefs", MODE_PRIVATE).edit {
            putString("laptop_power_state", currentPowerState.name)
        }
        updateUnlockNotificationState()
    }

    fun updateUnlockNotificationState() {
        UnlockPromptNotifier.cancelUnlockPrompt(this)
    }

    private fun saveWallpaperBase64(base64Str: String) {
        serviceScope.launch(Dispatchers.IO) {
            wallpaperWriteMutex.lock()
            try {
                val cleanB64 = base64Str.trim().replace("\r", "").replace("\n", "")
                if (cleanB64.isEmpty()) return@launch
                val imageBytes = Base64.decode(cleanB64, Base64.DEFAULT)
                if (imageBytes.isEmpty()) return@launch

                val oldPng = File(filesDir, "laptop_wallpaper.png")
                if (oldPng.exists()) try { oldPng.delete() } catch (_: Exception) {}

                val file = File(filesDir, "laptop_wallpaper.jpg")
                val tmpFile = File(filesDir, "laptop_wallpaper.jpg.tmp")
                tmpFile.writeBytes(imageBytes)
                if (tmpFile.exists()) {
                    tmpFile.renameTo(file)
                }
                wallpaperPath = file.absolutePath
                Log.i(TAG, "Successfully saved wallpaper file (${imageBytes.size} bytes) to ${file.absolutePath}")
                notifyStateToInterface()
            } catch (e: Exception) {
                Log.w(TAG, "Failed to save decoded wallpaper: ${e.message}")
            } finally {
                wallpaperWriteMutex.unlock()
            }
        }
    }

    private val debugStateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == DEBUG_INJECT_LAPTOP_STATE && BuildConfig.DEBUG) {
                val stateStr = intent.getStringExtra("powerState")
                val bat = intent.getIntExtra("batteryPercent", batteryPercent)
                val charging = intent.getBooleanExtra("isCharging", isCharging)
                val lockStr = intent.getStringExtra("lockState")
                val wpPath = intent.getStringExtra("wallpaperPath")

                if (!stateStr.isNullOrEmpty()) {
                    try { currentPowerState = LaptopPowerState.valueOf(stateStr) } catch (_: Exception) {}
                } else if (!lockStr.isNullOrEmpty()) {
                    currentPowerState = if (lockStr.equals("UNLOCKED", ignoreCase = true)) {
                        LaptopPowerState.CONNECTED_UNLOCKED
                    } else {
                        LaptopPowerState.CONNECTED_LOCKED
                    }
                }
                batteryPercent = bat
                isCharging = charging
                if (!wpPath.isNullOrEmpty()) {
                    wallpaperPath = wpPath
                }
                lastSeenAtMs = System.currentTimeMillis()
                Log.i(TAG, "Debug injected laptop state: powerState=$currentPowerState, battery=$batteryPercent, charging=$isCharging")
                notifyStateToInterface()
            }
        }
    }

    @Volatile
    var trustState: TrustState = TrustState.UNPAIRED
        private set(value) {
            field = value
            Log.i(TAG, "Trust state changed to: $value")
            notifyStateToInterface()
        }

    @Volatile
    private var isExplicitPairingRequested: Boolean = false

    @Volatile
    var connectedHostAddress: String? = null

    @Volatile
    private var currentVolumeLevel: Int = 50

    @Volatile
    private var currentBrightnessLevel: Int = 50

    @Volatile
    private var connectedHostPort: Int = TetherDiscoveryManager.DEFAULT_PORT

    @Volatile
    var pendingRequestId: String? = null
        private set

    @Volatile
    private var pendingWinEcPubKey: ByteArray? = null

    @Volatile
    private var pendingTranscriptHash: ByteArray? = null

    private fun savePendingPairingState(requestId: String, winPubKey: ByteArray?, transcriptHash: ByteArray?) {
        pendingRequestId = requestId
        pendingWinEcPubKey = winPubKey
        pendingTranscriptHash = transcriptHash
        getSharedPreferences("tether_secure_prefs", MODE_PRIVATE).edit {
            putString("pending_pairing_req_id", requestId)
            if (winPubKey != null) putString("pending_win_ec_pub_key", Base64.encodeToString(winPubKey, Base64.NO_WRAP))
            if (transcriptHash != null) putString("pending_transcript_hash", Base64.encodeToString(transcriptHash, Base64.NO_WRAP))
        }
    }

    /**
     * Starts the single background consumer of [inputFrameChannel] that actually
     * transmits queued input frames over the active transport. Idempotent: the
     * pump was previously launched only from the interactive pairing flow, so
     * pinned-key reconnects (the normal path) silently dropped every input.
     */
    @Volatile
    var isHeavyTaskActive: Boolean = false

    @Volatile
    var currentActiveScreen: String? = null

    @Synchronized
    private fun startInputPump() {
        if (inputPumpJob?.isActive == true) return
        inputPumpJob = serviceScope.launch(Dispatchers.IO) {
            for (firstFrame in inputFrameChannel) {
                try {
                    val transport = activeTransport
                    if (transport != null && transport.isConnected()) {
                        var frameToSend = firstFrame
                        // High-speed move coalescing: aggregate micro mouse deltas if queued under backpressure
                        if (frameToSend.size == 6 && frameToSend[0] == 0x05.toByte() && frameToSend[1] == 0x01.toByte()) {
                            var dx = (frameToSend[2].toInt() shl 8) or (frameToSend[3].toInt() and 0xFF)
                            var dy = (frameToSend[4].toInt() shl 8) or (frameToSend[5].toInt() and 0xFF)
                            if (dx > 32767) dx -= 65536
                            if (dy > 32767) dy -= 65536

                            while (true) {
                                val next = inputFrameChannel.tryReceive().getOrNull() ?: break
                                if (next.size == 6 && next[0] == 0x05.toByte() && next[1] == 0x01.toByte()) {
                                    var ndx = (next[2].toInt() shl 8) or (next[3].toInt() and 0xFF)
                                    var ndy = (next[4].toInt() shl 8) or (next[5].toInt() and 0xFF)
                                    if (ndx > 32767) ndx -= 65536
                                    if (ndy > 32767) ndy -= 65536
                                    dx = (dx + ndx).coerceIn(-32000, 32000)
                                    dy = (dy + ndy).coerceIn(-32000, 32000)
                                } else {
                                    val b = ByteArray(6)
                                    b[0] = 0x05
                                    b[1] = 0x01
                                    b[2] = ((dx shr 8) and 0xFF).toByte()
                                    b[3] = (dx and 0xFF).toByte()
                                    b[4] = ((dy shr 8) and 0xFF).toByte()
                                    b[5] = (dy and 0xFF).toByte()
                                    transport.sendFrame(b)
                                    frameToSend = next
                                    break
                                }
                            }

                            if (frameToSend === firstFrame) {
                                val b = ByteArray(6)
                                b[0] = 0x05
                                b[1] = 0x01
                                b[2] = ((dx shr 8) and 0xFF).toByte()
                                b[3] = (dx and 0xFF).toByte()
                                b[4] = ((dy shr 8) and 0xFF).toByte()
                                b[5] = (dy and 0xFF).toByte()
                                frameToSend = b
                            }
                        }
                        transport.sendFrame(frameToSend)
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "Sequential input transmission error: ${e.message}")
                }
            }
        }
    }

    fun triggerFullSyncIfNeeded() {
        if (isHeavyTaskActive) {
            Log.i(TAG, "Heavy task active. Skipping background full sync.")
            return
        }
        serviceScope.launch(Dispatchers.IO) {
            try {
                if (isHeavyTaskActive) return@launch
                dispatchCommand("laptop_state_get")
                delay(120)
                if (isHeavyTaskActive) return@launch
                dispatchCommand("volume_get")
                dispatchCommand("brightness_get")
                delay(120)
                if (isHeavyTaskActive) return@launch
                requestAudioSessions()
                requestAudioDevices()
                delay(120)
                if (isHeavyTaskActive) return@launch
                requestAdminTelemetry()
                requestHardwareSpecs()
                requestBatteryHealth()
                delay(120)
                if (isHeavyTaskActive) return@launch
                requestPowerPlans()
                requestRunningWindows()
                requestInstalledApps()
                delay(150)
                if (isHeavyTaskActive) return@launch
                requestWindowsServices()
                requestWindowsUpdates()
            } catch (e: Exception) {
                Log.w(TAG, "Background sync error: ${e.message}")
            }
        }
    }

    private fun loadPendingPairingState() {
        val prefs = getSharedPreferences("tether_secure_prefs", MODE_PRIVATE)
        prefs.edit { remove("is_unlock_prompt_dismissed") }

        startInputPump()
        if (pendingRequestId.isNullOrBlank()) pendingRequestId = prefs.getString("pending_pairing_req_id", null)
        if (pendingWinEcPubKey == null) {
            val pubB64 = prefs.getString("pending_win_ec_pub_key", null)
            if (!pubB64.isNullOrBlank()) try { pendingWinEcPubKey = Base64.decode(pubB64, Base64.NO_WRAP) } catch (_: Exception) {}
        }
        if (pendingTranscriptHash == null) {
            val hashB64 = prefs.getString("pending_transcript_hash", null)
            if (!hashB64.isNullOrBlank()) try { pendingTranscriptHash = Base64.decode(hashB64, Base64.NO_WRAP) } catch (_: Exception) {}
        }
    }

    private fun clearPendingPairingState() {
        pendingRequestId = null
        pendingWinEcPubKey = null
        pendingTranscriptHash = null
        getSharedPreferences("tether_secure_prefs", MODE_PRIVATE).edit {
            remove("pending_pairing_req_id")
            remove("pending_win_ec_pub_key")
            remove("pending_transcript_hash")
        }
    }

    private val processedRequestIds = ConcurrentHashMap<String, Long>()
    private val pendingTokenRequests = ConcurrentHashMap<String, kotlinx.coroutines.CompletableDeferred<String>>()

    data class PendingUnlockRequest(
        val requestId: String,
        val createdAtMs: Long,
        val peerAddress: String?,
        val transport: TetherTransport?
    )
    val pendingUnlockRequests = ConcurrentHashMap<String, PendingUnlockRequest>()

    fun cleanExpiredUnlockRequests() {
        val cutoff = System.currentTimeMillis() - 30_000L
        val iterator = pendingUnlockRequests.entries.iterator()
        while (iterator.hasNext()) {
            if (iterator.next().value.createdAtMs < cutoff) {
                iterator.remove()
            }
        }
    }

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
            if ((currentState == TransportState.DISCONNECTED) || (currentState == TransportState.FAILED) || (currentState == TransportState.DISCOVERING)) {
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
        instance = this
        val prefs = getSharedPreferences("tether_secure_prefs", MODE_PRIVATE)
        val isPaired = try {
            securityEngine = ProductionSecurityEngine()
            securityEngine.getPinnedKeyDecrypted(this) != null
        } catch (_: Exception) { false }
        val hasUnlockedOnce = prefs.getBoolean("has_unlocked_app_once", false)

        if (!isPaired && !hasUnlockedOnce) {
            Log.w(TAG, "Tether app has not been unlocked/authorized by user yet; refusing to start service.")
            stopSelf()
            return
        }

        TetherNotificationChannels.createAllChannels(this)
        setupClipboardSync()
        try {
            ContextCompat.registerReceiver(
                this,
                notificationMirrorReceiver,
                IntentFilter(TetherNotificationListenerService.ACTION_NOTIFICATION_POSTED),
                ContextCompat.RECEIVER_NOT_EXPORTED,
            )
        } catch (e: Exception) {
            Log.w(TAG, "Failed to register notification mirror receiver: ${e.message}")
        }

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

        ContextCompat.registerReceiver(
            this,
            powerSaveReceiver,
            IntentFilter(PowerManager.ACTION_POWER_SAVE_MODE_CHANGED),
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )

        lastPowerCommand = prefs.getString("last_power_command", null)
        lastPowerCommandAtMs = prefs.getLong("last_power_command_at_ms", 0L)
        lastPowerEventType = prefs.getString("last_power_event_type", null)
        lastPowerEventTimestampMs = prefs.getLong("last_power_event_timestamp_ms", 0L)
        val savedPowerState = prefs.getString("laptop_power_state", null)
        if (savedPowerState != null) {
            try { currentPowerState = LaptopPowerState.valueOf(savedPowerState) } catch (_: Exception) {}
        } else if (lastPowerCommand == "shutdown") {
            currentPowerState = LaptopPowerState.POWERED_OFF
        } else if (lastPowerCommand == "reboot") {
            currentPowerState = LaptopPowerState.RESTARTING
        } else {
            currentPowerState = LaptopPowerState.DISCONNECTED
        }

        val oldPng = File(filesDir, "laptop_wallpaper.png")
        if (oldPng.exists()) try { oldPng.delete() } catch (_: Exception) {}

        val wpFile = File(filesDir, "laptop_wallpaper.jpg")
        if (wpFile.exists() && wpFile.length() > 0) {
            wallpaperPath = wpFile.absolutePath
        }

        if (BuildConfig.DEBUG) {
            ContextCompat.registerReceiver(
                this,
                debugStateReceiver,
                IntentFilter(DEBUG_INJECT_LAPTOP_STATE),
                ContextCompat.RECEIVER_EXPORTED,
            )
        }

        android.os.Handler(android.os.Looper.getMainLooper()).postDelayed({
            if (instance != null) {
                scheduleAlarmForHealthCheck()
                startRequestIdCleanup()
                startTelemetryPolling()
            }
        }, 200L)
    }

    private fun startTelemetryPolling() {
        serviceScope.launch {
            while (isActive) {
                delay(3.seconds)
                if (currentState == TransportState.READY || currentState == TransportState.AUTHENTICATED) {
                    dispatchCommand("laptop_state_get")
                }
            }
        }
    }

    private fun startRequestIdCleanup() {
        serviceScope.launch {
            while (isActive) {
                delay(60.seconds)
                val cutoff = System.currentTimeMillis() - (5 * 60_000L)
                val iterator = processedRequestIds.entries.iterator()
                while (iterator.hasNext()) {
                    if (iterator.next().value < cutoff) iterator.remove()
                }
                cleanExpiredUnlockRequests()
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val prefs = getSharedPreferences("tether_secure_prefs", MODE_PRIVATE)
        val isPaired = try {
            if (!::securityEngine.isInitialized) {
                securityEngine = ProductionSecurityEngine()
            }
            securityEngine.getPinnedKeyDecrypted(this) != null
        } catch (_: Exception) { false }
        val hasUnlockedOnce = prefs.getBoolean("has_unlocked_app_once", false)

        if (!isPaired && !hasUnlockedOnce) {
            Log.w(TAG, "Tether app has not been unlocked/authorized by user yet; refusing to run service.")
            stopSelf()
            return START_NOT_STICKY
        }

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
                if (trustState != TrustState.PAIRING_REQUESTED && currentState != TransportState.PAIRING_REQUIRED && ((currentState == TransportState.DISCONNECTED) || (currentState == TransportState.FAILED))) {
                    resetReconnectBackoff()
                    startDiscovery()
                }
                return START_STICKY
            }
            ACTION_RESTART_SERVER -> {
                Log.w(TAG, "Manual server/transport restart requested")
                resetReconnectBackoff()
                restartTransport()
                notifyStateToInterface()
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
                isExplicitPairingRequested = true
                resetReconnectBackoff()
                if ((trustState == TrustState.PAIRING_REQUESTED) && (activeTransport?.isConnected() == true)) {
                    Log.i(TAG, "Already awaiting pairing on active session. Not restarting transport.")
                } else {
                    restartTransport()
                }
                notifyStateToInterface()
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
                val safeReqId = sanitizeLog(reqId)
                Log.i(TAG, "Confirm pairing action received for reqId=$safeReqId")
                confirmPairing(reqId, userPin)
                return START_STICKY
            }
            ACTION_REJECT_PAIRING -> {
                val reqId = intent.getStringExtra(EXTRA_PAIRING_REQUEST_ID) ?: pendingRequestId ?: ""
                val safeReqId = sanitizeLog(reqId)
                Log.i(TAG, "Reject pairing action received for reqId=$safeReqId")
                rejectPairing(reqId)
                return START_STICKY
            }
            ACTION_DISMISS_LOCK_SESSION -> {
                val dismissedId = intent.getStringExtra(EXTRA_LOCK_SESSION_ID) ?: activeLockSessionId
                dismissedLockSessionId = dismissedId
                getSharedPreferences("tether_secure_prefs", MODE_PRIVATE).edit {
                    remove("is_unlock_prompt_dismissed")
                }
                Log.i(TAG, "Recorded dismissed lock session: $dismissedLockSessionId")
                return START_STICKY
            }
            ACTION_RESET_LAPTOP_STATE -> {
                Log.i(TAG, "Manual reset of laptop state requested")
                lastPowerCommand = null
                lastPowerCommandAtMs = 0L
                rebootTimeoutJob?.cancel()
                shutdownTimeoutJob?.cancel()
                currentPowerState = if (currentState == TransportState.READY || currentState == TransportState.AUTHENTICATED) {
                    LaptopPowerState.CONNECTED_LOCKED
                } else {
                    LaptopPowerState.DISCONNECTED
                }
                getSharedPreferences("tether_secure_prefs", MODE_PRIVATE).edit {
                    remove("last_power_command")
                    remove("last_power_command_at_ms")
                    remove("laptop_power_state")
                }
                notifyStateToInterface()
                return START_STICKY
            }
            null -> {
                if (trustState != TrustState.PAIRING_REQUESTED && currentState != TransportState.PAIRING_REQUIRED && currentState == TransportState.DISCONNECTED) {
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
        if ((currentState == TransportState.AUTHENTICATED) || (currentState == TransportState.READY) || (currentState == TransportState.CONNECTING) || (currentState == TransportState.PAIRING_REQUIRED) || (trustState == TrustState.PAIRING_REQUESTED)) {
            return
        }
        currentState = TransportState.DISCOVERING
        Log.i(TAG, "Starting mDNS local discovery & UDP advertisement...")

        discoveryManager.stopDiscovery()
        discoveryManager.startDiscovery()
        discoveryManager.advertiseService()

        val savedHostIp = getSharedPreferences("tether_secure_prefs", MODE_PRIVATE)
            .getString("saved_host_ip", null)
        if (!savedHostIp.isNullOrBlank()) {
            Log.i(TAG, "Attempting background connection to saved target host IP: ${sanitizeLog(savedHostIp)}")
            serviceScope.launch {
                if (currentState == TransportState.DISCOVERING) {
                    connectToHost(savedHostIp)
                }
            }
        }
    }

    override fun onDeviceDiscovered(device: DiscoveredDevice) {
        val activeCount = getDiscoveredDevices().size
        val safeName = sanitizeLog(device.name)
        val safeAddr = sanitizeLog(device.hostAddress)
        Log.i(TAG, "mDNS/UDP Discovered Tether device ($activeCount active): $safeName at $safeAddr:${device.port}")

        val isConnectedToTarget = ((currentState == TransportState.AUTHENTICATED) || (currentState == TransportState.READY))
                && (connectedHostAddress == device.hostAddress)

        if (isConnectedToTarget) {
            return
        }

        if ((currentState == TransportState.PAIRING_REQUIRED || trustState == TrustState.PAIRING_REQUESTED) && (activeTransport?.isConnected() == true)) {
            Log.d(TAG, "Pairing is currently pending on active transport. Skipping connectToHost from onDeviceDiscovered for $safeAddr.")
            return
        }

        if ((currentState == TransportState.CONNECTING) || (currentState == TransportState.TLS_HANDSHAKE) || (currentState == TransportState.AUTHENTICATING)) {
            if (connectedHostAddress != device.hostAddress) {
                Log.i(TAG, "Discovered new host $safeAddr while connecting to $connectedHostAddress. Disconnecting stale connection...")
                disconnectActiveSession("Switching to newly discovered host $safeAddr")
            } else {
                return
            }
        }

        currentState = TransportState.HOST_FOUND
        connectToHost(device.hostAddress, device.port)
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
        synchronized(connectLock) {
            if ((currentState == TransportState.AUTHENTICATING) || (currentState == TransportState.AUTHENTICATED) || (currentState == TransportState.READY)) return
            if ((currentState == TransportState.PAIRING_REQUIRED || trustState == TrustState.PAIRING_REQUESTED) && (activeTransport?.isConnected() == true)) {
                Log.d(TAG, "Pairing is currently pending on active transport. Skipping connectToHost.")
                return
            }
            if ((currentState == TransportState.CONNECTING || currentState == TransportState.TLS_HANDSHAKE) &&
                (connectedHostAddress == hostAddress) && (connectedHostPort == port) && (connectJob?.isActive == true)) {
                Log.d(TAG, "Already connecting to ${sanitizeLog(hostAddress)}:$port. Skipping duplicate.")
                return
            }

            currentState = TransportState.CONNECTING
            connectedHostAddress = hostAddress
            connectedHostPort = port

            connectJob?.cancel()
            connectJob = serviceScope.launch {
            try {
                activeTransport?.disconnect("Replaced by new connection")
            } catch (_: Exception) {}
            activeTransport = null
            val transport = TetherTlsTransport(this@TetherLanService, securityEngine)
            try {
                currentState = TransportState.TLS_HANDSHAKE
                transport.connect(hostAddress, port)

                activeTransport = transport
                currentState = TransportState.AUTHENTICATING

                val isPairingReq = isExplicitPairingRequested || (trustState == TrustState.PAIRING_REQUESTED) || (trustState == TrustState.REPAIRING)
                isExplicitPairingRequested = false

                val result = pairingManager.executeHandshake(
                    transport = transport,
                    isUserInitiatedPairing = isPairingReq,
                )

                when (result) {
                    is PairingResult.Authenticated -> {
                        Log.i(TAG, "Successfully authenticated with Windows host ${sanitizeLog(result.peerDeviceId)}!")
                        resetReconnectBackoff()
                        getSharedPreferences("tether_secure_prefs", MODE_PRIVATE).edit {
                            putString("saved_host_ip", hostAddress)
                        }
                        connectedPeerName = result.peerDeviceId.ifBlank { "Windows PC" }
                        trustState = TrustState.PAIRED
                        currentState = TransportState.AUTHENTICATED
                        try { discoveryManager.stopDiscovery() } catch (_: Exception) {}
                        capabilityManager.negotiateCapabilities(result.peerCapabilities.ifBlank { "" })

                        readyTransitionJob?.cancel()
                        readyTransitionJob = serviceScope.launch {
                            delay(150)
                            if (isActive && activeTransport?.generationId == transport.generationId && transport.isConnected()) {
                                currentState = TransportState.READY
                                dispatchCommand("volume_get")
                                dispatchCommand("brightness_get")
                                if (pendingUnlockUntilMs > System.currentTimeMillis()) {
                                    pendingUnlockUntilMs = 0L
                                    dispatchCommand("unlock")
                                }
                                triggerFullSyncIfNeeded()
                            }
                        }

                        listenSocketLoop(transport)
                    }
                    is PairingResult.PairingPending -> {
                        val safeReqId = sanitizeLog(result.requestId)
                        Log.i(TAG, "Pairing pending for requestId=$safeReqId. Launching PairingConfirmationActivity...")
                        resetReconnectBackoff()

                        val isNewPairingRequest = (pendingRequestId != result.requestId) || (trustState != TrustState.PAIRING_REQUESTED)

                        savePendingPairingState(result.requestId, result.winEcPubKeyBytes, result.transcriptHash)

                        trustState = TrustState.PAIRING_REQUESTED
                        currentState = TransportState.PAIRING_REQUIRED

                        if (isNewPairingRequest) {
                            showPairingNotification(result)

                            val promptIntent = Intent(this@TetherLanService, PairingConfirmationActivity::class.java).apply {
                                action = ACTION_SHOW_PAIRING_PROMPT
                                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
                                putExtra(EXTRA_PAIRING_REQUEST_ID, result.requestId)
                                putExtra(EXTRA_PEER_DEVICE_NAME, result.peerName)
                                putExtra(EXTRA_WINDOWS_FINGERPRINT, result.peerFingerprint)
                                putExtra(EXTRA_PAIRING_SAS_CODE, result.peerFingerprint.take(6))
                            }
                            try {
                                startActivity(promptIntent)
                            } catch (e: Exception) {
                                Log.w(TAG, "Direct startActivity failed (background launch restriction); relying on heads-up notification: ${e.message}")
                            }
                        } else {
                            Log.i(TAG, "Pairing prompt already active for requestId=$safeReqId; waiting for user input.")
                        }
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
                    is PairingResult.InvalidPin -> {
                        Log.w(TAG, "Unexpected InvalidPin during initial handshake: ${result.message}")
                        currentState = TransportState.FAILED
                        disconnectActiveSession(result.message)
                    }
                    is PairingResult.Error -> {
                        Log.e(TAG, "Pairing/Handshake error: ${sanitizeLog(result.message)}")
                        currentState = TransportState.FAILED
                        disconnectActiveSession(result.message)
                        scheduleReconnectWithBackoff("Handshake error: ${result.message}")
                    }
                }
            } catch (e: kotlinx.coroutines.CancellationException) {
                Log.d(TAG, "Connection attempt to ${sanitizeLog(hostAddress)}:$port cancelled.")
            } catch (e: Exception) {
                Log.e(TAG, "Connection failed to ${sanitizeLog(hostAddress)}:$port: ${e.message}", e)
                if (activeTransport == null || !activeTransport!!.isConnected()) {
                    currentState = TransportState.FAILED
                    disconnectActiveSession("Connection error: ${e.message}")
                    scheduleReconnectWithBackoff("Connection exception: ${e.message}")
                }
            }
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

            loadPendingPairingState()

            val transcriptHash = pendingTranscriptHash
            if (transcriptHash == null) {
                Log.e(TAG, "Cannot confirm pairing: pending transcript hash is null.")
                disconnectActiveSession("Transcript hash lost")
                return@launch
            }

            val effectiveReqId = requestId.ifBlank { pendingRequestId ?: "" }
            val safeReqId = sanitizeLog(effectiveReqId)
            Log.i(TAG, "Finalizing pairing with Windows host for requestId=$safeReqId...")
            val result = pairingManager.finalizePairing(
                transport = transport,
                requestId = effectiveReqId,
                userEnteredPin = userPin,
                winEcPubKeyBytes = pendingWinEcPubKey,
                transcriptHash = transcriptHash,
            )

            when (result) {
                is PairingResult.Authenticated -> {
                    Log.i(TAG, "Pairing successfully finalized and keys pinned! Entering READY state...")
                    resetReconnectBackoff()
                    clearPendingPairingState()
                    
                    connectedHostAddress?.let { ip ->
                        getSharedPreferences("tether_secure_prefs", MODE_PRIVATE).edit {
                            putString("saved_host_ip", ip)
                        }
                    }
                    connectedPeerName = result.peerDeviceId.ifBlank { "Windows PC" }
                    
                    trustState = TrustState.PAIRED
                    currentState = TransportState.AUTHENTICATED
                    try { discoveryManager.stopDiscovery() } catch (_: Exception) {}
                    capabilityManager.negotiateCapabilities(result.peerCapabilities.ifBlank { "" })

                    readyTransitionJob?.cancel()
                    readyTransitionJob = serviceScope.launch {
                        delay(200)
                        if (isActive && activeTransport?.generationId == transport.generationId && transport.isConnected()) {
                            currentState = TransportState.READY
                            dispatchCommand("volume_get")
                        }
                    }

                    listenSocketLoop(transport)
                }
                is PairingResult.InvalidPin -> {
                    Log.w(TAG, "Invalid pairing PIN: ${result.message} (${result.remainingAttempts} attempts remaining)")
                    mainHandler.post {
                        val intent = Intent(ACTION_PAIRING_INVALID_PIN).apply {
                            setPackage(packageName)
                            putExtra(EXTRA_REMAINING_ATTEMPTS, result.remainingAttempts)
                            putExtra(EXTRA_ERROR_MESSAGE, result.message)
                            putExtra(EXTRA_PAIRING_REQUEST_ID, effectiveReqId)
                        }
                        sendBroadcast(intent)
                    }
                }
                is PairingResult.Error -> {
                    Log.e(TAG, "Failed finalizing pairing: ${sanitizeLog(result.message)}")
                    clearPendingPairingState()
                    trustState = TrustState.UNPAIRED
                    disconnectActiveSession("Finalize pairing error: ${result.message}")
                    scheduleReconnectWithBackoff("Finalize pairing error")
                }
                else -> {
                    clearPendingPairingState()
                    trustState = TrustState.UNPAIRED
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
            clearPendingPairingState()
            trustState = TrustState.UNPAIRED
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
                if (frameBytes.isNotEmpty() && frameBytes[0] == 0x05.toByte()) {
                    processIncomingBinaryFrame(frameBytes, transport)
                } else if (frameBytes.isNotEmpty()) {
                    val jsonStr = String(frameBytes, StandardCharsets.UTF_8).trim()
                    if (jsonStr.startsWith("{")) {
                        processIncomingFrame(JSONObject(jsonStr), transport)
                    }
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "Transport socket loop terminated: ${e.message}")
        } finally {
            if (activeTransport?.generationId == transport.generationId) {
                disconnectActiveSession("Socket loop terminated")
                Log.i(TAG, "Active session disconnected. Immediately restarting discovery for pinned Windows host...")
                resetReconnectBackoff()
                startDiscovery()
            }
        }
    }

    private fun processIncomingBinaryFrame(bytes: ByteArray, transport: TetherTransport) {
        Log.d(TAG, "Received binary input frame from transport gen=${transport.generationId}: ${bytes.size} bytes (type=0x${String.format("%02X", bytes[0])})")
    }

    private fun processIncomingFrame(json: JSONObject, transport: TetherTransport) {
        if (processedRequestIds.size > 10_000) {
            Log.w(TAG, "processedRequestIds exceeded cap; clearing oldest half")
            val sorted = processedRequestIds.entries.sortedBy { (_, timestamp) -> timestamp }
            sorted.take(sorted.size / 2).forEach { (key, _) -> processedRequestIds.remove(key) }
        }

        val requestId = json.optString("requestId", "")
        if (requestId.isNotEmpty() && processedRequestIds.containsKey(requestId)) {
            val safeReqId = sanitizeLog(requestId)
            Log.w(TAG, "Duplicate frame ignored: $safeReqId")
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
            "FILE_TRANSFER_TOKEN_RESPONSE" -> {
                val token = json.optString("token", "")
                if (requestId.isNotEmpty() && pendingTokenRequests.containsKey(requestId)) {
                    pendingTokenRequests.remove(requestId)?.complete(token)
                } else {
                    Log.w(TAG, "Discarded token response with unmatched requestId: $requestId")
                }
            }
            "POWER_EVENT" -> {
                val eventsArray = json.optJSONArray("events")
                var newestEvent: JSONObject? = null
                var newestTimestamp: Long = -1L

                val qualifyingTypes = setOf(
                    "SHUTDOWN", "RESTART", "SLEEP", "HIBERNATE", "LOCK",
                    "LOCKED", "WORKSTATION_LOCK", "SESSION_LOCK", "WTS_SESSION_LOCK",
                    "LOCK_SCREEN", "DESKTOP_LOCK", "LOCK_NOW", "LOCKED_OUT", "LOCKOUT",
                    "UNLOCK", "UNLOCKED", "WTS_SESSION_UNLOCK", "CONSOLE_CONNECT"
                )

                if (eventsArray != null && eventsArray.length() > 0) {
                    for (i in 0 until eventsArray.length()) {
                        val eventObj = eventsArray.optJSONObject(i) ?: continue
                        val eventType = eventObj.optString("eventType", "").uppercase()
                        val timestamp = eventObj.optLong("timestamp", 0L)

                        if (eventType in qualifyingTypes) {
                            if (timestamp >= newestTimestamp) {
                                newestTimestamp = timestamp
                                newestEvent = eventObj
                            }
                        }
                    }
                } else if (json.has("eventType")) {
                    val singleType = json.optString("eventType", "").uppercase()
                    if (singleType in qualifyingTypes) {
                        newestEvent = json
                        newestTimestamp = json.optLong("timestamp", System.currentTimeMillis())
                    }
                }

                if (newestEvent == null) {
                    Log.d(TAG, "Received POWER_EVENT JSON but no qualifying lock/power event found.")
                    return
                }

                val eventType = newestEvent.optString("eventType", "LOCK").uppercase()
                val timestamp = if (newestTimestamp > 0L) newestTimestamp else System.currentTimeMillis()

                lastPowerEventType = eventType
                lastPowerEventTimestampMs = timestamp

                val prefs = getSharedPreferences("tether_secure_prefs", MODE_PRIVATE)
                prefs.edit {
                    putString("last_power_event_type", eventType)
                    putLong("last_power_event_timestamp_ms", timestamp)
                }

                val lastAnsweredType = prefs.getString("last_answered_power_event_type", null)
                val lastAnsweredTs = prefs.getLong("last_answered_power_event_timestamp_ms", 0L)

                if (timestamp > 0L && eventType.equals(lastAnsweredType, ignoreCase = true) && timestamp == lastAnsweredTs) {
                    val safeEventType = sanitizeLog(eventType)
                    Log.i(TAG, "Ignoring already answered power event: $safeEventType at $timestamp")
                    return
                }

                val incomingLockSessionId = newestEvent.optString("lockSessionId", json.optString("lockSessionId", ""))

                when (eventType) {
                    "LOCK", "SLEEP", "HIBERNATE", "LOCKED", "WORKSTATION_LOCK", "SESSION_LOCK", "WTS_SESSION_LOCK", "LOCK_SCREEN", "DESKTOP_LOCK", "LOCK_NOW", "LOCKED_OUT", "LOCKOUT" -> {
                        activeLockSessionId = incomingLockSessionId.ifEmpty { null }
                        currentPowerState = LaptopPowerState.CONNECTED_LOCKED
                        if (activeLockSessionId == null || activeLockSessionId != dismissedLockSessionId) {
                            postPowerEventNotification(eventType, timestamp, activeLockSessionId)
                        } else {
                            val safeEventType = sanitizeLog(eventType)
                            Log.i(TAG, "Unlock prompt for $safeEventType at $timestamp is dismissed for lock session $activeLockSessionId; skipping.")
                        }
                    }
                    "UNLOCK", "UNLOCKED", "WTS_SESSION_UNLOCK", "CONSOLE_CONNECT" -> {
                        dismissedLockSessionId = null
                        activeLockSessionId = null
                        lastNotifiedLockSessionId = null
                        prefs.edit { remove("is_unlock_prompt_dismissed") }
                        currentPowerState = LaptopPowerState.CONNECTED_UNLOCKED
                        val nm = androidx.core.app.NotificationManagerCompat.from(this)
                        nm.cancel(PowerEventActionReceiver.POWER_EVENT_NOTIFICATION_ID)
                        nm.cancel(UnlockPromptNotifier.UNLOCK_NOTIFICATION_ID)
                    }
                    "SHUTDOWN", "POWER_OFF" -> {
                        currentPowerState = LaptopPowerState.POWERED_OFF
                    }
                    "RESTART", "REBOOT" -> {
                        currentPowerState = LaptopPowerState.RESTARTING
                    }
                }
                updateUnlockNotificationState()
            }
            "CONFIRM_COMMAND" -> {
                val confirmedCmd = json.optString("confirmedCommand", command)
                val success = json.optBoolean("success", true)
                val errorReason = json.optString("reason", "")
                val vol = json.optInt("volumeLevel", -1)
                val bright = json.optInt("brightnessLevel", -1)
                val responseReqId = json.optString("requestId", "")
                if ((vol >= 0) && (vol <= 100)) {
                    currentVolumeLevel = vol
                }
                if ((bright >= 0) && (bright <= 100)) {
                    currentBrightnessLevel = bright
                }
                val safeConfirmed = sanitizeLog(confirmedCmd)
                val safeReason = sanitizeLog(errorReason)
                val safeReqId = sanitizeLog(responseReqId)
                Log.i(TAG, "Command response from Windows host: $safeConfirmed (reqId=$safeReqId, success=$success, reason=$safeReason, vol=$currentVolumeLevel, bright=$currentBrightnessLevel)")

                if (safeConfirmed.equals("unlock", ignoreCase = true)) {
                    val isAuthenticatedTransport = (currentState == TransportState.READY || currentState == TransportState.AUTHENTICATED) && (activeTransport?.isConnected() == true)
                    if (!isAuthenticatedTransport) {
                        Log.w(TAG, "Rejected unlock confirmation: transport not in authenticated state ($currentState)")
                        return
                    }

                    val pending = if (responseReqId.isNotBlank()) pendingUnlockRequests.remove(responseReqId) else null
                    if (pending == null) {
                        Log.w(TAG, "Rejected unsolicited, duplicate, or mismatched unlock confirmation (reqId=$safeReqId)")
                        return
                    }

                    val now = System.currentTimeMillis()
                    if (now - pending.createdAtMs > 30_000L) {
                        Log.w(TAG, "Rejected stale unlock confirmation (reqId=$safeReqId, ageMs=${now - pending.createdAtMs})")
                        return
                    }

                    if (pending.peerAddress != null && connectedHostAddress != null && pending.peerAddress != connectedHostAddress) {
                        Log.w(TAG, "Rejected unlock confirmation from mismatched peer (expected=${pending.peerAddress}, actual=$connectedHostAddress)")
                        return
                    }

                    if (pending.transport != null && pending.transport !== transport) {
                        Log.w(TAG, "Rejected unlock confirmation from mismatched transport session (reqId=$safeReqId)")
                        return
                    }

                    if (success) {
                        currentPowerState = LaptopPowerState.CONNECTED_UNLOCKED
                        getSharedPreferences("tether_secure_prefs", MODE_PRIVATE).edit { putBoolean("is_unlock_prompt_dismissed", false) }
                        updateUnlockNotificationState()
                        Log.i(TAG, "Cryptographically verified and correlated unlock confirmed by host for reqId=$safeReqId")
                    } else {
                        Log.w(TAG, "Host reported unlock failure for reqId=$safeReqId: $safeReason")
                    }
                }

                mainHandler.post {
                    val intent = Intent(ACTION_COMMAND_CONFIRMED).apply {
                        putExtra("confirmed_command", confirmedCmd)
                        putExtra("success", success)
                        putExtra("reason", errorReason)
                        putExtra("volume_level", currentVolumeLevel)
                        putExtra("brightness_level", currentBrightnessLevel)
                        putExtra("requestId", responseReqId)
                        setPackage(packageName)
                    }
                    sendBroadcast(intent)
                }
            }
            "FS_LIST" -> {
                val reqPath = json.optString("path", "").trim()
                serviceScope.launch(Dispatchers.IO) {
                    try {
                        val itemsArray = JSONArray()
                        val isRootPath = reqPath.isEmpty() || reqPath == "/" || reqPath.equals("root", ignoreCase = true)

                        if (isRootPath) {
                            val roots = mutableListOf<File>()
                            val primaryStorage = Environment.getExternalStorageDirectory()
                            if (primaryStorage != null && primaryStorage.exists()) {
                                roots.add(primaryStorage)
                            }

                            try {
                                val externalDirs = getExternalFilesDirs(null)
                                for (dir in externalDirs) {
                                    if (dir != null) {
                                        val rootPath = dir.absolutePath.substringBefore("/Android/")
                                        val rootFile = File(rootPath)
                                        if (!roots.contains(rootFile) && rootFile.exists()) {
                                            roots.add(rootFile)
                                        }
                                    }
                                }
                            } catch (_: Exception) {}

                            for (root in roots) {
                                val isPrimary = root.absolutePath == Environment.getExternalStorageDirectory()?.absolutePath
                                val item = JSONObject().apply {
                                    put("name", if (isPrimary) "Primary Storage" else root.name)
                                    put("path", root.absolutePath)
                                    put("isDirectory", true)
                                    put("size", root.totalSpace)
                                    put("lastModified", root.lastModified())
                                }
                                itemsArray.put(item)
                            }
                        } else {
                            val dir = File(reqPath)
                            if (dir.exists() && dir.isDirectory) {
                                val files = dir.listFiles()
                                if (files != null) {
                                    files.sortedWith(compareBy({ !it.isDirectory }, { it.name.lowercase(Locale.US) })).forEach { file ->
                                        val item = JSONObject().apply {
                                            put("name", file.name)
                                            put("path", file.absolutePath)
                                            put("isDirectory", file.isDirectory)
                                            put("size", if (file.isDirectory) 0L else file.length())
                                            put("lastModified", file.lastModified())
                                        }
                                        itemsArray.put(item)
                                    }
                                } else {
                                    Log.w(TAG, "dir.listFiles() returned null for path: $reqPath")
                                }
                            } else {
                                Log.w(TAG, "Directory does not exist or is not a directory: $reqPath")
                            }
                        }

                        val responseJson = JSONObject().apply {
                            put("type", "FS_LIST_RESULT")
                            put("requestId", requestId)
                            put("path", reqPath)
                            put("items", itemsArray)
                        }
                        transport.sendFrame(responseJson.toString().toByteArray(StandardCharsets.UTF_8))
                    } catch (e: Exception) {
                        Log.e(TAG, "FS_LIST error: ${sanitizeLog(e.message)}", e)
                        val errorJson = JSONObject().apply {
                            put("type", "FS_LIST_RESULT")
                            put("requestId", requestId)
                            put("path", reqPath)
                            put("error", e.message ?: "Unknown error")
                        }
                        transport.sendFrame(errorJson.toString().toByteArray(StandardCharsets.UTF_8))
                    }
                }
            }
            "FS_RECEIVE_FILE" -> {
                val windowsPath = json.optString("windowsPath", "")
                val fileName = json.optString("fileName", "")
                val token = json.optString("token", "")
                
                serviceScope.launch(Dispatchers.IO) {
                    try {
                        val hostIp = connectedHostAddress ?: throw Exception("No connected host IP")
                        val safeFileName = File(fileName).name
                        if (safeFileName.isBlank() || safeFileName == ".." || safeFileName == ".") {
                            throw IllegalArgumentException("Invalid filename in file receive request")
                        }

                        val downloadsDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
                        if (!downloadsDir.exists()) {
                            downloadsDir.mkdirs()
                        }
                        val destFile = File(downloadsDir, safeFileName)
                        if (!destFile.canonicalPath.startsWith(downloadsDir.canonicalPath)) {
                            throw SecurityException("Path traversal attempt detected in file receive request")
                        }

                        val destUri = Uri.fromFile(destFile)
                        
                        FileTransferClient.downloadFile(hostIp, windowsPath, destUri, this@TetherLanService, token)
                        
                        val responseJson = JSONObject().apply {
                            put("type", "FS_TRANSFER_STATUS")
                            put("requestId", requestId)
                            put("status", "SUCCESS")
                        }
                        transport.sendFrame(responseJson.toString().toByteArray(StandardCharsets.UTF_8))
                    } catch (e: Exception) {
                        Log.e(TAG, "FS_RECEIVE_FILE error: ${sanitizeLog(e.message)}")
                        val errorJson = JSONObject().apply {
                            put("type", "FS_TRANSFER_STATUS")
                            put("requestId", requestId)
                            put("status", "ERROR")
                            put("error", e.message)
                        }
                        transport.sendFrame(errorJson.toString().toByteArray(StandardCharsets.UTF_8))
                    }
                }
            }
            "FS_SEND_FILE" -> {
                val androidPath = json.optString("androidPath", "")
                val windowsDestPath = json.optString("windowsDestPath", "")
                val token = json.optString("token", "")
                
                serviceScope.launch(Dispatchers.IO) {
                    try {
                        val hostIp = connectedHostAddress ?: throw Exception("No connected host IP")
                        val sourceFile = File(androidPath)
                        if (!sourceFile.exists() || !sourceFile.isFile) throw Exception("Source file does not exist or is not a file")

                        val canonicalPath = sourceFile.canonicalPath
                        val extStorage = Environment.getExternalStorageDirectory().canonicalPath
                        if (!canonicalPath.startsWith(extStorage)) {
                            throw SecurityException("Access to path outside storage is restricted: $canonicalPath")
                        }

                        val sourceUri = Uri.fromFile(sourceFile)
                        
                        FileTransferClient.uploadFile(hostIp, sourceUri, windowsDestPath, this@TetherLanService, token)
                        
                        val responseJson = JSONObject().apply {
                            put("type", "FS_TRANSFER_STATUS")
                            put("requestId", requestId)
                            put("status", "SUCCESS")
                        }
                        transport.sendFrame(responseJson.toString().toByteArray(StandardCharsets.UTF_8))
                    } catch (e: Exception) {
                        Log.e(TAG, "FS_SEND_FILE error: ${sanitizeLog(e.message)}")
                        val errorJson = JSONObject().apply {
                            put("type", "FS_TRANSFER_STATUS")
                            put("requestId", requestId)
                            put("status", "ERROR")
                            put("error", e.message)
                        }
                        transport.sendFrame(errorJson.toString().toByteArray(StandardCharsets.UTF_8))
                    }
                }
            }
"UNLOCK_PROMPT" -> {
                // PC-side credential provider explicitly asked the phone to surface
                // the unlock prompt. This request is authoritative: bypass the
                // dismissed-session and local power-state gates (the phone's lock
                // state can be stale relative to the actual secure desktop).
                getSharedPreferences("tether_secure_prefs", MODE_PRIVATE).edit {
                    putBoolean("is_unlock_prompt_dismissed", false)
                }
                activeLockSessionId?.let { dismissedLockSessionId = null }
                postPowerEventNotification("LOCK", System.currentTimeMillis(), activeLockSessionId, force = true)
            }
            "CLIPBOARD_SYNC" -> {
                val contentStr = json.optString("text", json.optString("content", ""))
                val hash = json.optString("hash", "")
                val resolvedHash = if (hash.isNotEmpty()) hash else computeSha256(contentStr)
                val prefs = getSharedPreferences("tether_clipboard_prefs", MODE_PRIVATE)
                val isLiveSync = prefs.getBoolean("live_sync_enabled", true)
                if (isLiveSync && !resolvedHash.equals(lastClipboardHash, ignoreCase = true) && contentStr.isNotEmpty()) {
                    lastClipboardHash = resolvedHash
                    mainHandler.post {
                        try {
                            val cb = getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
                            cb?.setPrimaryClip(ClipData.newPlainText("Tether", contentStr))
                        } catch (e: Exception) {
                            Log.w(TAG, "Error updating Android clipboard: ${e.message}")
                        }
                    }
                }
                mainHandler.post {
                    val intent = Intent(ACTION_CLIPBOARD_SYNC).apply {
                        putExtra("content", contentStr)
                        putExtra("hash", resolvedHash)
                        putExtra("timestamp", json.optLong("timestamp", System.currentTimeMillis()))
                        setPackage(packageName)
                    }
                    sendBroadcast(intent)
                }
            }
            "NOTIFICATION_EVENT" -> {
                mainHandler.post {
                    val intent = Intent(ACTION_NOTIFICATION_SYNC).apply {
                        putExtra("action", json.optString("action", "POSTED"))
                        putExtra("id", json.optLong("id", 0L))
                        putExtra("app", json.optString("app", ""))
                        putExtra("title", json.optString("title", ""))
                        putExtra("body", json.optString("body", ""))
                        putExtra("timestamp", json.optLong("timestamp", System.currentTimeMillis()))
                        setPackage(packageName)
                    }
                    sendBroadcast(intent)
                }
            }
            "TERMINAL_OUTPUT" -> {
                mainHandler.post {
                    val intent = Intent(ACTION_TERMINAL_OUTPUT).apply {
                        putExtra("sessionId", json.optString("sessionId", ""))
                        putExtra("data", json.optString("data", ""))
                        putExtra("workingDir", json.optString("workingDir", ""))
                        setPackage(packageName)
                    }
                    sendBroadcast(intent)
                }
            }
            "TERMINAL_SESSION_STARTED", "TERMINAL_START_RESPONSE", "TERMINAL_SESSION_CLOSED" -> {
                val termObj = json.optJSONObject("terminal")
                val sid = if (termObj != null) termObj.optString("id", "") else json.optString("sessionId", json.optString("terminalId", ""))
                val shell = if (termObj != null) termObj.optString("shellType", "") else json.optString("shellType", "")
                val dir = if (termObj != null) termObj.optString("workingDir", "") else json.optString("workingDir", "")
                mainHandler.post {
                    val intent = Intent(ACTION_TERMINAL_SESSION).apply {
                        putExtra("type", if (type == "TERMINAL_START_RESPONSE") "TERMINAL_SESSION_STARTED" else type)
                        putExtra("sessionId", sid)
                        putExtra("shellType", shell)
                        putExtra("workingDir", dir)
                        setPackage(packageName)
                    }
                    sendBroadcast(intent)
                }
            }
            "MEDIA_METADATA_UPDATE" -> {
                mainHandler.post {
                    val intent = Intent(ACTION_MEDIA_UPDATE).apply {
                        putExtra("title", json.optString("title", ""))
                        putExtra("artist", json.optString("artist", ""))
                        putExtra("album", json.optString("album", ""))
                        putExtra("isPlaying", json.optBoolean("isPlaying", false))
                        putExtra("position", json.optLong("position", 0L))
                        putExtra("duration", json.optLong("duration", 0L))
                        putExtra("thumbnail", json.optString("thumbnail", ""))
                        setPackage(packageName)
                    }
                    sendBroadcast(intent)
                }
            }
            "AUDIO_DEVICES_RESPONSE" -> {
                val dArr = json.optJSONArray("devices")
                if (dArr != null) {
                    val devList = mutableListOf<AudioDeviceItem>()
                    for (i in 0 until dArr.length()) {
                        val d = dArr.getJSONObject(i)
                        devList.add(AudioDeviceItem(
                            id = d.optString("id", d.optString("Id", "")),
                            name = d.optString("name", d.optString("Name", "Audio Device")),
                            isDefault = d.optBoolean("isDefault", d.optBoolean("IsDefault", false)),
                            isInput = d.optBoolean("isInput", d.optBoolean("IsInput", false))
                        ))
                    }
                    LaptopStateCache.saveAudioDevices(applicationContext, devList)
                }
                mainHandler.post {
                    val intent = Intent(ACTION_AUDIO_SESSIONS_UPDATE).apply {
                        putExtra("devicesJson", json.optJSONArray("devices")?.toString() ?: "[]")
                        setPackage(packageName)
                    }
                    sendBroadcast(intent)
                }
            }
            "AUDIO_SESSIONS_UPDATE", "AUDIO_SESSIONS_RESPONSE" -> {
                val sArr = json.optJSONArray("sessions")
                if (sArr != null) {
                    val sList = mutableListOf<AppAudioSessionItem>()
                    for (i in 0 until sArr.length()) {
                        val s = sArr.getJSONObject(i)
                        sList.add(AppAudioSessionItem(
                            pid = s.optInt("pid", s.optInt("Pid", 0)),
                            processName = s.optString("processName", s.optString("ProcessName", "Application")),
                            volumePercent = s.optInt("volumePercent", s.optInt("VolumePercent", 50)),
                            isMuted = s.optBoolean("isMuted", s.optBoolean("IsMuted", false))
                        ))
                    }
                    LaptopStateCache.saveAudioSessions(applicationContext, sList)
                }
                val dArr = json.optJSONArray("devices")
                if (dArr != null) {
                    val devList = mutableListOf<AudioDeviceItem>()
                    for (i in 0 until dArr.length()) {
                        val d = dArr.getJSONObject(i)
                        devList.add(AudioDeviceItem(
                            id = d.optString("id", d.optString("Id", "")),
                            name = d.optString("name", d.optString("Name", "Audio Device")),
                            isDefault = d.optBoolean("isDefault", d.optBoolean("IsDefault", false)),
                            isInput = d.optBoolean("isInput", d.optBoolean("IsInput", false))
                        ))
                    }
                    LaptopStateCache.saveAudioDevices(applicationContext, devList)
                }
                mainHandler.post {
                    val intent = Intent(ACTION_AUDIO_SESSIONS_UPDATE).apply {
                        putExtra("sessionsJson", json.optJSONArray("sessions")?.toString() ?: "[]")
                        putExtra("devicesJson", json.optJSONArray("devices")?.toString() ?: "[]")
                        putExtra("masterMuted", json.optBoolean("masterMuted", false))
                        putExtra("micMuted", json.optBoolean("micMuted", false))
                        putExtra("micGain", json.optInt("micGain", 50))
                        setPackage(packageName)
                    }
                    sendBroadcast(intent)
                }
            }
            "HARDWARE_SPECS_RESPONSE" -> {
                val sObj = json.optJSONObject("specs") ?: json
                val specs = HardwareSpecs(
                    processorName = sObj.optString("processorName", ""),
                    coreCount = sObj.optInt("coreCount", 0),
                    totalMemoryMb = sObj.optLong("totalMemoryMb", 0L),
                    gpuName = sObj.optString("gpuName", ""),
                    gpuVramMb = sObj.optLong("gpuVramMb", 0L),
                    systemManufacturer = sObj.optString("systemManufacturer", ""),
                    systemModel = sObj.optString("systemModel", ""),
                    biosVersion = sObj.optString("biosVersion", ""),
                    osDescription = sObj.optString("osDescription", ""),
                    uptimeSeconds = sObj.optLong("uptimeSeconds", 0L)
                )
                LaptopStateCache.saveHardwareSpecs(applicationContext, specs)
                mainHandler.post {
                    val intent = Intent(ACTION_HARDWARE_SPECS).apply {
                        putExtra("specsJson", sObj.toString())
                        setPackage(packageName)
                    }
                    sendBroadcast(intent)
                }
            }
            "BATTERY_REPORT_RESPONSE" -> {
                val rObj = json.optJSONObject("batteryReport") ?: json
                val report = BatteryReportDetails(
                    success = rObj.optBoolean("success", false),
                    batteryName = rObj.optString("batteryName", ""),
                    manufacturer = rObj.optString("manufacturer", ""),
                    serialNumber = rObj.optString("serialNumber", ""),
                    chemistry = rObj.optString("chemistry", ""),
                    designCapacityMwh = rObj.optDouble("designCapacityMwh", 0.0),
                    fullChargeCapacityMwh = rObj.optDouble("fullChargeCapacityMwh", 0.0),
                    cycleCount = rObj.optInt("cycleCount", 0),
                    healthPercent = rObj.optInt("healthPercent", 100),
                    reportTimestamp = rObj.optString("reportTimestamp", ""),
                    errorMessage = rObj.optString("errorMessage", "")
                )
                LaptopStateCache.saveBatteryReport(applicationContext, report)
                mainHandler.post {
                    val intent = Intent(ACTION_BATTERY_REPORT).apply {
                        putExtra("reportJson", rObj.toString())
                        setPackage(packageName)
                    }
                    sendBroadcast(intent)
                }
            }
            "ADMIN_TELEMETRY_RESPONSE" -> {
                val tObj = json.optJSONObject("telemetry") ?: json
                LaptopStateCache.saveAdminTelemetry(applicationContext, json.toString())
                mainHandler.post {
                    val intent = Intent(ACTION_ADMIN_TELEMETRY).apply {
                        putExtra("rawJson", json.toString())
                        putExtra("cpuUsage", tObj.optInt("cpuUsage", tObj.optInt("cpuUsagePercent", 0)))
                        putExtra("totalRamMb", tObj.optLong("totalRamMb", tObj.optLong("totalMemoryMb", 0L)))
                        putExtra("availRamMb", tObj.optLong("availRamMb", tObj.optLong("availableMemoryMb", 0L)))
                        putExtra("ramUsagePct", tObj.optInt("ramUsagePct", tObj.optInt("memoryUsagePercent", 0)))
                        putExtra("disksJson", tObj.optJSONArray("disks")?.toString() ?: "[]")
                        putExtra("networksJson", tObj.optJSONArray("networks")?.toString() ?: "[]")
                        setPackage(packageName)
                    }
                    sendBroadcast(intent)
                }
            }
            "BATTERY_HEALTH_RESPONSE" -> {
                val bObj = json.optJSONObject("batteryHealth") ?: json
                LaptopStateCache.saveBatteryHealth(applicationContext, bObj.toString())
                mainHandler.post {
                    val intent = Intent(ACTION_BATTERY_HEALTH).apply {
                        putExtra("designCapacityMwh", bObj.optDouble("designCapacityMwh", bObj.optDouble("designedCapacityMwh", 0.0)))
                        putExtra("fullChargeCapacityMwh", bObj.optDouble("fullChargeCapacityMwh", 0.0))
                        putExtra("wearLevelPct", bObj.optInt("wearLevelPct", bObj.optInt("wearLevelPercent", 0)))
                        putExtra("cycleCount", bObj.optInt("cycleCount", 0))
                        setPackage(packageName)
                    }
                    sendBroadcast(intent)
                }
            }
            "POWER_PLANS_RESPONSE" -> {
                val pArr = json.optJSONArray("powerPlans") ?: json.optJSONArray("plans")
                if (pArr != null) LaptopStateCache.savePowerPlans(applicationContext, pArr.toString())
                mainHandler.post {
                    val intent = Intent(ACTION_POWER_PLANS).apply {
                        putExtra("plansJson", pArr?.toString() ?: "[]")
                        setPackage(packageName)
                    }
                    sendBroadcast(intent)
                }
            }
            "PRINTERS_RESPONSE" -> {
                mainHandler.post {
                    val intent = Intent(ACTION_PRINTERS).apply {
                        putExtra("printersJson", json.optJSONArray("printers")?.toString() ?: "[]")
                        setPackage(packageName)
                    }
                    sendBroadcast(intent)
                }
            }
            "USB_DEVICES_RESPONSE" -> {
                val dArr = json.optJSONArray("usbDevices") ?: json.optJSONArray("devices")
                mainHandler.post {
                    val intent = Intent(ACTION_USB_DEVICES).apply {
                        putExtra("devicesJson", dArr?.toString() ?: "[]")
                        setPackage(packageName)
                    }
                    sendBroadcast(intent)
                }
            }
            "SERVICES_RESPONSE" -> {
                val sArr = json.optJSONArray("services")
                if (sArr != null) LaptopStateCache.saveServices(applicationContext, sArr.toString())
                mainHandler.post {
                    val intent = Intent(ACTION_SERVICES).apply {
                        putExtra("servicesJson", json.optJSONArray("services")?.toString() ?: "[]")
                        setPackage(packageName)
                    }
                    sendBroadcast(intent)
                }
            }
            "UPDATES_RESPONSE" -> {
                val uObj = json.optJSONObject("updates") ?: json
                LaptopStateCache.saveUpdates(applicationContext, uObj.toString())
                mainHandler.post {
                    val intent = Intent(ACTION_UPDATES).apply {
                        putExtra("pendingCount", uObj.optInt("pendingCount", uObj.optInt("pendingUpdatesCount", 0)))
                        putExtra("isAvailable", uObj.optBoolean("isAvailable", uObj.optBoolean("isUpdateAvailable", false)))
                        putExtra("titlesJson", uObj.optJSONArray("titles")?.toString() ?: "[]")
                        setPackage(packageName)
                    }
                    sendBroadcast(intent)
                }
            }
            "WORKFLOW_LIST_RESPONSE" -> {
                mainHandler.post {
                    val intent = Intent(ACTION_WORKFLOWS).apply {
                        putExtra("workflowsJson", json.optJSONArray("workflows")?.toString() ?: "[]")
                        setPackage(packageName)
                    }
                    sendBroadcast(intent)
                }
            }
            "WORKFLOW_STATUS" -> {
                mainHandler.post {
                    val intent = Intent(ACTION_WORKFLOW_STATUS).apply {
                        putExtra("id", json.optString("id", ""))
                        putExtra("status", json.optString("status", ""))
                        putExtra("timestamp", json.optLong("timestamp", System.currentTimeMillis()))
                        setPackage(packageName)
                    }
                    sendBroadcast(intent)
                }
            }
            "WINDOWS_LIST_RESPONSE", "APP_WINDOWS_RESPONSE" -> {
                val wArr = json.optJSONArray("windows")
                if (wArr != null) LaptopStateCache.saveRunningWindows(applicationContext, wArr.toString())
                mainHandler.post {
                    val intent = Intent(ACTION_WINDOWS_LIST).apply {
                        putExtra("windowsJson", json.optJSONArray("windows")?.toString() ?: "[]")
                        setPackage(packageName)
                    }
                    sendBroadcast(intent)
                }
            }
            "APP_INSTALLED_RESPONSE", "APPS_LIST_RESPONSE" -> {
                val aArr = json.optJSONArray("apps")
                if (aArr != null) LaptopStateCache.saveInstalledApps(applicationContext, aArr.toString())
                mainHandler.post {
                    val intent = Intent(ACTION_INSTALLED_APPS).apply {
                        putExtra("appsJson", json.optJSONArray("apps")?.toString() ?: "[]")
                        setPackage(packageName)
                    }
                    sendBroadcast(intent)
                }
            }
            "HARDWARE_METRICS", "LAPTOP_STATE" -> {
                LaptopStateCache.saveHardwareMetrics(applicationContext, json.toString())
                val prefs = getSharedPreferences("tether_secure_prefs", MODE_PRIVATE)
                val vol = json.optInt("volumeLevel", -1)
                val bright = json.optInt("brightnessLevel", -1)
                if ((vol >= 0) && (vol <= 100)) {
                    currentVolumeLevel = vol
                }
                if ((bright >= 0) && (bright <= 100)) {
                    currentBrightnessLevel = bright
                }
                if ((vol >= 0) || (bright >= 0)) {
                    val intent = Intent("com.tether.phone.ACTION_SYNC_HARDWARE_METRICS").apply {
                        putExtra("VOLUME_LEVEL", vol)
                        putExtra("BRIGHTNESS_LEVEL", bright)
                        setPackage(packageName)
                    }
                    sendBroadcast(intent)
                }

                val bat = if (json.has("batteryPercent")) json.optInt("batteryPercent", -1) else json.optInt("batteryLevel", -1)
                if (bat in 0..100) {
                    batteryPercent = bat
                }
                if (json.has("isCharging")) {
                    isCharging = json.optBoolean("isCharging", false)
                }
                val lockState = json.optString("lockState", "")
                if (lockState.equals("UNLOCKED", ignoreCase = true)) {
                    if (currentPowerState != LaptopPowerState.CONNECTED_UNLOCKED) {
                        prefs.edit { putBoolean("is_unlock_prompt_dismissed", false) }
                    }
                    currentPowerState = LaptopPowerState.CONNECTED_UNLOCKED
                } else if (lockState.equals("LOCKED", ignoreCase = true) || lockState.equals("SLEEP", ignoreCase = true) || lockState.equals("HIBERNATE", ignoreCase = true) || lockState.equals("WORKSTATION_LOCK", ignoreCase = true)) {
                    val wasUnlocked = (currentPowerState != LaptopPowerState.CONNECTED_LOCKED)
                    currentPowerState = LaptopPowerState.CONNECTED_LOCKED
                    val isPromptDismissed = prefs.getBoolean("is_unlock_prompt_dismissed", false)
                    if (wasUnlocked && (activeLockSessionId == null || activeLockSessionId != dismissedLockSessionId)) {
                        postPowerEventNotification("LOCK", System.currentTimeMillis(), activeLockSessionId)
                    }
                }
                updateUnlockNotificationState()
                val wpB64 = json.optString("wallpaperB64", json.optString("wallpaper", ""))
                if (wpB64.isNotEmpty()) {
                    saveWallpaperBase64(wpB64)
                }

                lastSeenAtMs = System.currentTimeMillis()
                notifyStateToInterface()
            }
        }
    }

    private fun postPowerEventNotification(
        eventType: String,
        timestamp: Long,
        lockSessionId: String? = null,
        force: Boolean = false
    ) {
        // force=true bypasses dismissal and lock-session gating: the PC-side
        // credential provider explicitly asked for this prompt, so it must show.
        if (!force && lockSessionId != null && lockSessionId == dismissedLockSessionId) {
            val safeEventType = sanitizeLog(eventType)
            Log.i(TAG, "Unlock prompt for $safeEventType at $timestamp is dismissed for lock session $lockSessionId; skipping notification.")
            return
        }
        val nowMs = System.currentTimeMillis()
        if (!force) {
            val sameSession = (lockSessionId != null && lockSessionId == lastNotifiedLockSessionId)
            val recentNoSession = (lockSessionId == null && (nowMs - lastNotifiedLockAtMs) < 3000L)
            if (sameSession || recentNoSession) {
                Log.d(TAG, "Deduplicating duplicate lock notification (session=$lockSessionId)")
                return
            }
        }
        lastNotifiedLockSessionId = lockSessionId
        lastNotifiedLockAtMs = nowMs
        val upperType = eventType.uppercase()
        val allowedTypes = setOf(
            "LOCK", "SLEEP", "HIBERNATE", "LOCKED", "WORKSTATION_LOCK",
            "SESSION_LOCK", "WTS_SESSION_LOCK", "LOCK_SCREEN", "DESKTOP_LOCK",
            "LOCK_NOW", "LOCKED_OUT", "LOCKOUT"
        )
        if (upperType !in allowedTypes) {
            val safeEventType = sanitizeLog(eventType)
            Log.i(TAG, "Power event $safeEventType does not allow unlock operation; skipping notification.")
            return
        }

        try {
            wakeLock?.acquire(5000L)
        } catch (_: Exception) {}

        val activityIntent = Intent(this, PowerEventActivity::class.java).apply {
            addFlags(
                Intent.FLAG_ACTIVITY_NEW_TASK or
                Intent.FLAG_ACTIVITY_CLEAR_TOP or
                Intent.FLAG_ACTIVITY_SINGLE_TOP or
                Intent.FLAG_ACTIVITY_REORDER_TO_FRONT
            )
            putExtra(PowerEventActionReceiver.EXTRA_POWER_EVENT_TYPE, eventType)
            putExtra(PowerEventActionReceiver.EXTRA_POWER_EVENT_TIMESTAMP, timestamp)
            putExtra(PowerEventActionReceiver.EXTRA_LOCK_SESSION_ID, lockSessionId)
        }

        val fullScreenPendingIntent = PendingIntent.getActivity(
            this,
            4001,
            activityIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                val options = android.app.ActivityOptions.makeBasic().apply {
                    setPendingIntentBackgroundActivityStartMode(android.app.ActivityOptions.MODE_BACKGROUND_ACTIVITY_START_ALLOWED)
                }
                fullScreenPendingIntent.send(this, 0, null, null, null, null, options.toBundle())
            } else {
                fullScreenPendingIntent.send()
            }
            val safeUpperType = sanitizeLog(upperType)
            Log.i(TAG, "Successfully dispatched PendingIntent for PowerEventActivity background pop-up: $safeUpperType")
        } catch (e: Exception) {
            Log.w(TAG, "PendingIntent.send() background launch failed, attempting direct startActivity: ${e.message}")
            try {
                startActivity(activityIntent)
            } catch (e2: Exception) {
                Log.e(TAG, "Direct startActivity launch failed: ${e2.message}")
            }
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ActivityCompat.checkSelfPermission(
                this,
                android.Manifest.permission.POST_NOTIFICATIONS
            ) != PackageManager.PERMISSION_GRANTED
        ) {
            Log.w(TAG, "POST_NOTIFICATIONS permission not granted; notification posting skipped")
            return
        }

        val rejectIntent = Intent(this, PowerEventActionReceiver::class.java).apply {
            action = PowerEventActionReceiver.ACTION_REJECT
            putExtra(PowerEventActionReceiver.EXTRA_POWER_EVENT_TYPE, eventType)
            putExtra(PowerEventActionReceiver.EXTRA_POWER_EVENT_TIMESTAMP, timestamp)
            putExtra(PowerEventActionReceiver.EXTRA_LOCK_SESSION_ID, lockSessionId)
        }
        val rejectPendingIntent = PendingIntent.getBroadcast(
            this,
            4003,
            rejectIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val notification = NotificationCompat.Builder(this, TetherNotificationChannels.CHANNEL_POWER_EVENTS)
            .setContentTitle("PC Lock Event Detected")
            .setContentText("Workstation locked. Tap to authorize unlock.")
            .setSmallIcon(R.drawable.ic_shortcut_unlock)
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setAutoCancel(true)
            .setOngoing(false)
            .setDefaults(Notification.DEFAULT_ALL)
            .setContentIntent(fullScreenPendingIntent)
            .setFullScreenIntent(fullScreenPendingIntent, true)
            .setDeleteIntent(rejectPendingIntent)
            .build()

        NotificationManagerCompat.from(this)
            .notify(PowerEventActionReceiver.POWER_EVENT_NOTIFICATION_ID, notification)
    }

    suspend fun sendCommand(command: String): Result<Unit> = kotlinx.coroutines.withContext(Dispatchers.IO) {
        try {
            if ((currentState != TransportState.READY) && (currentState != TransportState.AUTHENTICATED)) {
                return@withContext Result.failure(IllegalStateException("TLS session not connected (state=$currentState)"))
            }
            val normCmd = normalizeCommand(command)
            val reqId = UUID.randomUUID().toString()
            val transport = activeTransport
                ?: return@withContext Result.failure(IllegalStateException("Active transport is null"))
            if (!transport.isConnected()) {
                return@withContext Result.failure(IllegalStateException("Transport socket is disconnected"))
            }
            if (normCmd.equals("unlock", ignoreCase = true)) {
                cleanExpiredUnlockRequests()
                pendingUnlockRequests[reqId] = PendingUnlockRequest(
                    requestId = reqId,
                    createdAtMs = System.currentTimeMillis(),
                    peerAddress = connectedHostAddress,
                    transport = transport
                )
            }
            val cmdJson = JSONObject().apply {
                put("type", "COMMAND_EXECUTE")
                put("requestId", reqId)
                put("command", normCmd)
                put("timestamp", System.currentTimeMillis())
            }
            transport.sendFrame(cmdJson.toString().toByteArray(StandardCharsets.UTF_8))
            Log.i(TAG, "Dispatched command frame over TLS 1.3: $normCmd (reqId=$reqId)")
            Result.success(Unit)
        } catch (e: Exception) {
            Log.e(TAG, "Failed sending command $command: ${e.message}", e)
            Result.failure(e)
        }
    }

    suspend fun requestFileTransferToken(): String = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
        if ((currentState != TransportState.READY) && (currentState != TransportState.AUTHENTICATED)) {
            throw IllegalStateException("TLS session not connected")
        }
        val reqId = UUID.randomUUID().toString()
        val deferred = kotlinx.coroutines.CompletableDeferred<String>()
        pendingTokenRequests[reqId] = deferred
        val cmdJson = JSONObject().apply {
            put("type", "FILE_TRANSFER_TOKEN_REQUEST")
            put("requestId", reqId)
            put("timestamp", System.currentTimeMillis())
        }
        val transport = activeTransport ?: throw IllegalStateException("Active transport is null")
        if (!transport.isConnected()) {
            throw IllegalStateException("Transport socket is disconnected")
        }
        transport.sendFrame(cmdJson.toString().toByteArray(StandardCharsets.UTF_8))
        
        kotlinx.coroutines.withTimeout(10000L) {
            deferred.await()
        }
    }

    fun getActivePeerPublicKeyBytes(): ByteArray? {
        val transport = activeTransport ?: return null
        if (!transport.isConnected()) return null
        return transport.getPeerCertificate()?.publicKey?.encoded
    }

    fun getActivePeerCertificate(): java.security.cert.X509Certificate? {
        val transport = activeTransport ?: return null
        if (!transport.isConnected()) return null
        return transport.getPeerCertificate()
    }

    fun dispatchCommand(actionCommand: String) {
        serviceScope.launch {
            try {
                val normCmd = normalizeCommand(actionCommand)

                if ((currentState != TransportState.READY) && (currentState != TransportState.AUTHENTICATED)) {
                    if (normCmd.equals("unlock", ignoreCase = true) &&
                        (currentState == TransportState.CONNECTING || currentState == TransportState.TLS_HANDSHAKE || currentState == TransportState.AUTHENTICATING || currentState == TransportState.DISCOVERING || currentState == TransportState.HOST_FOUND)) {
                        pendingUnlockUntilMs = System.currentTimeMillis() + 8000L
                        Log.i(TAG, "Transport connecting ($currentState); queued pending unlock for up to 8s.")
                        return@launch
                    }
                    Log.w(TAG, "Transport not ready ($currentState). Command '$normCmd' discarded.")
                    return@launch
                }

                if (!capabilityManager.canExecuteCommand(normCmd)) {
                    Log.w(TAG, "Capability check failed for command: ${sanitizeLog(normCmd)}")
                    return@launch
                }

                val reqId = UUID.randomUUID().toString()
                val cmdJson = JSONObject().apply {
                    put("type", "COMMAND_EXECUTE")
                    put("requestId", reqId)
                    put("command", normCmd)
                    put("timestamp", System.currentTimeMillis())
                }

                val transport = activeTransport
                if ((transport != null) && transport.isConnected()) {
                    if (normCmd.equals("unlock", ignoreCase = true)) {
                        cleanExpiredUnlockRequests()
                        pendingUnlockRequests[reqId] = PendingUnlockRequest(
                            requestId = reqId,
                            createdAtMs = System.currentTimeMillis(),
                            peerAddress = connectedHostAddress,
                            transport = transport
                        )
                    }
                    transport.sendFrame(cmdJson.toString().toByteArray(StandardCharsets.UTF_8))
                    Log.i(TAG, "Dispatched command frame over TLS 1.3: ${sanitizeLog(normCmd)} (reqId=$reqId)")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to dispatch command (${sanitizeLog(actionCommand)}): ${e.message}")
            }
        }
    }

    fun disconnectActiveSession(reason: String) {
        val safeReason = sanitizeLog(reason)
        Log.w(TAG, "Disconnecting active session: $safeReason")
        dismissPairingNotification()
        try { activeTransport?.disconnect(reason) } catch (_: Exception) {}
        activeTransport = null
        connectedHostAddress = null
        if (currentState == TransportState.PAIRING_REQUIRED || trustState == TrustState.PAIRING_REQUESTED) {
            clearPendingPairingState()
            trustState = TrustState.UNPAIRED
        }
        currentState = TransportState.DISCONNECTED
    }

    private fun showPairingNotification(result: PairingResult.PairingPending) {
        TetherNotificationChannels.createAllChannels(this)
        val promptIntent = Intent(this, PairingConfirmationActivity::class.java).apply {
            action = ACTION_SHOW_PAIRING_PROMPT
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
            putExtra(EXTRA_PAIRING_REQUEST_ID, result.requestId)
            putExtra(EXTRA_PEER_DEVICE_NAME, result.peerName)
            putExtra(EXTRA_WINDOWS_FINGERPRINT, result.peerFingerprint)
            putExtra(EXTRA_PAIRING_SAS_CODE, result.peerFingerprint.take(6))
        }

        val pendingIntent = PendingIntent.getActivity(
            this,
            result.requestId.hashCode(),
            promptIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val notification = NotificationCompat.Builder(this, TetherNotificationChannels.CHANNEL_PAIRING_PROMPT)
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setContentTitle("Pairing Request from ${result.peerName}")
            .setContentText("Tap to enter the 6-digit PIN displayed on your PC")
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setCategory(NotificationCompat.CATEGORY_CALL)
            .setFullScreenIntent(pendingIntent, true)
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)
            .setDefaults(NotificationCompat.DEFAULT_ALL)
            .build()

        if (ActivityCompat.checkSelfPermission(this, android.Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED || Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            try {
                NotificationManagerCompat.from(this).notify(NOTIFICATION_PAIRING_ID, notification)
            } catch (e: Exception) {
                Log.e(TAG, "Failed posting pairing notification: ${e.message}")
            }
        }
    }

    private fun dismissPairingNotification() {
        try {
            NotificationManagerCompat.from(this).cancel(NOTIFICATION_PAIRING_ID)
        } catch (_: Exception) {}
    }

    private fun restartTransport() {
        disconnectActiveSession("Transport restart requested")
        startDiscovery()
    }

    private fun scheduleReconnectWithBackoff(reason: String) {
        if ((currentState == TransportState.AUTHENTICATED) || (currentState == TransportState.READY) || (currentState == TransportState.CONNECTING) || (currentState == TransportState.PAIRING_REQUIRED) || (trustState == TrustState.PAIRING_REQUESTED)) {
            return
        }
        reconnectJob?.cancel()
        reconnectJob = serviceScope.launch {
            reconnectAttempt++
            val baseDelayMs = 3000L
            val expDelay = baseDelayMs * (1 shl (reconnectAttempt - 1).coerceAtMost(3))
            val jitter = (Math.random() * 500).toLong()
            val delayMs = (expDelay + jitter).coerceAtMost(25000L)
            Log.i(TAG, "Scheduling discovery refresh attempt #$reconnectAttempt in ${delayMs}ms (reason: ${sanitizeLog(reason)})...")
            delay(delayMs.milliseconds)
            if (isActive && ((currentState == TransportState.DISCONNECTED) || (currentState == TransportState.FAILED) || (currentState == TransportState.DISCOVERING))) {
                startDiscovery()
            }
        }
    }

    private fun resetReconnectBackoff() {
        reconnectAttempt = 0
        reconnectJob?.cancel()
        reconnectJob = null
    }

    private fun sendPingProbe() {
        val transport = activeTransport ?: return
        if (!transport.isConnected()) return
        serviceScope.launch {
            try {
                val pingJson = JSONObject().apply {
                    put("type", "PING")
                    put("timestamp", System.currentTimeMillis())
                }
                transport.sendFrame(pingJson.toString().toByteArray(StandardCharsets.UTF_8))
                Log.d(TAG, "Health check: Sent PING probe to Windows host.")
            } catch (e: Exception) {
                Log.w(TAG, "Health check: Failed sending PING probe: ${e.message}")
            }
        }
    }

    private fun performHealthCheck() {
        if ((currentState == TransportState.DISCONNECTED) || (currentState == TransportState.FAILED) || (currentState == TransportState.DISCOVERING)) {
            if (trustState != TrustState.PAIRING_REQUESTED && currentState != TransportState.PAIRING_REQUIRED) {
                Log.i(TAG, "Health check: Transport state is $currentState. Refreshing discovery...")
                startDiscovery()
            }
        } else if ((currentState == TransportState.READY) || (currentState == TransportState.AUTHENTICATED)) {
            sendPingProbe()
        }
    }

    private fun computeEffectivePowerState(): LaptopPowerState {
        val isConn = (currentState == TransportState.READY || currentState == TransportState.AUTHENTICATED)
        return if (isConn) {
            when (currentPowerState) {
                LaptopPowerState.SHUTTING_DOWN -> LaptopPowerState.SHUTTING_DOWN
                LaptopPowerState.RESTARTING -> LaptopPowerState.RESTARTING
                LaptopPowerState.CONNECTED_UNLOCKED -> LaptopPowerState.CONNECTED_UNLOCKED
                else -> LaptopPowerState.CONNECTED_LOCKED
            }
        } else {
            when {
                lastPowerCommand == "shutdown" || currentPowerState == LaptopPowerState.POWERED_OFF -> LaptopPowerState.POWERED_OFF
                lastPowerCommand == "reboot" || currentPowerState == LaptopPowerState.RESTARTING -> LaptopPowerState.RESTARTING
                else -> LaptopPowerState.DISCONNECTED
            }
        }
    }

    private fun notifyStateToInterface() {
        val effectivePowerState = computeEffectivePowerState()
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
            putExtra("extra_brightness_level", currentBrightnessLevel)

            putExtra(EXTRA_LAPTOP_POWER_STATE, effectivePowerState.name)
            putExtra(EXTRA_LAPTOP_BATTERY_PERCENT, batteryPercent)
            putExtra(EXTRA_LAPTOP_IS_CHARGING, isCharging)
            putExtra(EXTRA_LAPTOP_WALLPAPER_PATH, wallpaperPath ?: "")
            putExtra(EXTRA_LAPTOP_LAST_SEEN_MS, lastSeenAtMs)
            putExtra(EXTRA_LAPTOP_LAST_POWER_CMD, lastPowerCommand ?: "")
            putExtra(EXTRA_LAPTOP_LAST_POWER_CMD_MS, lastPowerCommandAtMs)

            setPackage(packageName)
        }
        sendBroadcast(intent)
    }

    private fun scheduleAlarmForHealthCheck() {
        alarmManager = getSystemService(ALARM_SERVICE) as AlarmManager
        val intent = Intent(this, TetherAlarmReceiver::class.java).apply {
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

    private fun createNotification(): Notification = NotificationCompat.Builder(this, CHANNEL_ID)
        .setContentTitle(getString(R.string.notification_title))
        .setContentText(getString(R.string.notification_text))
        .setSmallIcon(R.drawable.ic_shortcut_unlock)
        .setPriority(NotificationCompat.PRIORITY_MIN)
        .setCategory(NotificationCompat.CATEGORY_SERVICE)
        .setOngoing(true)
        .setSilent(true)
        .build()

    inner class LocalBinder : android.os.Binder() {
        fun getService(): TetherLanService = this@TetherLanService
    }
    private val binder = LocalBinder()

    override fun onBind(intent: Intent?): IBinder = binder

    private var lastNotReadyInputLogMs = 0L
    private var inputFramesSent = 0L
    private var dismissedLockSessionId: String? = null
    private var activeLockSessionId: String? = null
    private val inputFrameChannel = kotlinx.coroutines.channels.Channel<ByteArray>(kotlinx.coroutines.channels.Channel.UNLIMITED)
    private var inputPumpJob: Job? = null

    fun sendInputFrame(data: ByteArray) {
        val transport = activeTransport
        val isReady = transport != null && transport.isConnected() &&
                (currentState == TransportState.READY || currentState == TransportState.AUTHENTICATED)

        if (!isReady) {
            val now = System.currentTimeMillis()
            if (now - lastNotReadyInputLogMs > 5000L) {
                lastNotReadyInputLogMs = now
                Log.w(TAG, "Input frame discarded locally: Session not ready (transport=$transport, connected=${transport?.isConnected()}, state=$currentState)")
            }
            return
        }

        if (BuildConfig.DEBUG) {
            val count = ++inputFramesSent
            if (count % 500L == 0L) {
                Log.d(TAG, "DEBUG: Input frames transmitted: $count framesSent")
            }
        }

        inputFrameChannel.trySend(data)
    }

    fun sendDirectControlFrame(data: ByteArray) {
        val transport = activeTransport
        val isReady = transport != null && transport.isConnected() &&
                (currentState == TransportState.READY || currentState == TransportState.AUTHENTICATED)
        if (!isReady) return
        serviceScope.launch(Dispatchers.IO) {
            try {
                transport?.sendFrame(data)
            } catch (e: Exception) {
                Log.w(TAG, "sendDirectControlFrame failed: ${e.message}")
            }
        }
    }

    fun getDiscoveredDevices(): List<DiscoveredDevice> = discoveryManager.getDiscoveredDevices()

    val activeHostAddress: String?
        get() = connectedHostAddress

    override fun onDestroy() {
        instance = null
        serviceJob.cancelChildren()

        try { unregisterReceiver(powerSaveReceiver) } catch (_: Exception) {}
        try { unregisterReceiver(notificationMirrorReceiver) } catch (_: Exception) {}
        clipboardListener?.let {
            val cb = getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
            cb?.removePrimaryClipChangedListener(it)
        }
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

    private fun computeSha256(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val bytes = digest.digest(input.toByteArray(StandardCharsets.UTF_8))
        return bytes.joinToString("") { "%02x".format(it) }
    }

    private fun setupClipboardSync() {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager ?: return
        clipboardListener = ClipboardManager.OnPrimaryClipChangedListener {
            try {
                val clip = clipboard.primaryClip
                if (clip != null && clip.itemCount > 0) {
                    val text = clip.getItemAt(0).text?.toString() ?: ""
                    if (text.isNotEmpty()) {
                        val hash = computeSha256(text)
                        if (hash != lastClipboardHash) {
                            lastClipboardHash = hash
                            sendClipboardSyncFrame(text, hash)
                        }
                    }
                }
            } catch (e: Exception) {
                Log.w(TAG, "Error in onPrimaryClipChanged: ${e.message}")
            }
        }
        clipboard.addPrimaryClipChangedListener(clipboardListener)
    }

    fun sendClipboardSyncFrame(text: String, hash: String = computeSha256(text)) {
        val json = JSONObject().apply {
            put("type", "CLIPBOARD_SYNC")
            put("content", text)
            put("hash", hash)
            put("timestamp", System.currentTimeMillis())
        }
        sendInputFrame(json.toString().toByteArray(StandardCharsets.UTF_8))
    }

    fun sendRemoteCopy() {
        val json = JSONObject().apply {
            put("type", "CLIPBOARD_SIMULATE_COPY")
            put("requestId", UUID.randomUUID().toString())
            put("timestamp", System.currentTimeMillis())
        }
        sendInputFrame(json.toString().toByteArray(StandardCharsets.UTF_8))
    }

    fun sendRemotePaste() {
        val json = JSONObject().apply {
            put("type", "CLIPBOARD_SIMULATE_PASTE")
            put("requestId", UUID.randomUUID().toString())
            put("timestamp", System.currentTimeMillis())
        }
        sendInputFrame(json.toString().toByteArray(StandardCharsets.UTF_8))
    }

    fun sendNotificationMirror(id: Long, app: String, title: String, body: String, timestamp: Long) {
        val prefs = getSharedPreferences("tether_secure_prefs", MODE_PRIVATE)
        if (!prefs.getBoolean("mirror_phone_to_pc", true)) return
        val json = JSONObject().apply {
            put("type", "NOTIFICATION_EVENT")
            put("action", "POSTED")
            put("id", id)
            put("app", app)
            put("title", title)
            put("body", body)
            put("timestamp", timestamp)
        }
        sendInputFrame(json.toString().toByteArray(StandardCharsets.UTF_8))
    }

    fun sendNotificationDismiss(id: Long) {
        val json = JSONObject().apply {
            put("type", "NOTIFICATION_DISMISS")
            put("requestId", UUID.randomUUID().toString())
            put("id", id)
            put("timestamp", System.currentTimeMillis())
        }
        sendDirectControlFrame(json.toString().toByteArray(StandardCharsets.UTF_8))
    }

    fun requestAudioSessions() {
        val json = JSONObject().apply {
            put("type", "AUDIO_SESSIONS_GET")
            put("requestId", UUID.randomUUID().toString())
        }
        sendDirectControlFrame(json.toString().toByteArray(StandardCharsets.UTF_8))
    }

    fun requestAudioDevices(isInput: Boolean = false) {
        val json = JSONObject().apply {
            put("type", "AUDIO_DEVICES_GET")
            put("requestId", UUID.randomUUID().toString())
            put("isInput", isInput)
        }
        sendDirectControlFrame(json.toString().toByteArray(StandardCharsets.UTF_8))
    }

    fun requestMicState() {
        val json = JSONObject().apply {
            put("type", "MIC_GET_STATE")
            put("requestId", UUID.randomUUID().toString())
        }
        sendDirectControlFrame(json.toString().toByteArray(StandardCharsets.UTF_8))
    }

    fun sendTerminalStart(shellType: String = "powershell", workingDir: String = "") {
        val json = JSONObject().apply {
            put("type", "TERMINAL_START")
            put("requestId", UUID.randomUUID().toString())
            put("shellType", shellType)
            put("workingDir", workingDir)
        }
        sendDirectControlFrame(json.toString().toByteArray(StandardCharsets.UTF_8))
    }

    fun sendTerminalInput(sessionId: String, data: String) {
        val json = JSONObject().apply {
            put("type", "TERMINAL_INPUT")
            put("sessionId", sessionId)
            put("data", data)
        }
        sendDirectControlFrame(json.toString().toByteArray(StandardCharsets.UTF_8))
    }

    fun sendTerminalClose(sessionId: String) {
        val json = JSONObject().apply {
            put("type", "TERMINAL_CLOSE")
            put("sessionId", sessionId)
        }
        sendDirectControlFrame(json.toString().toByteArray(StandardCharsets.UTF_8))
    }

    fun sendMediaControl(action: String, seekSeconds: Long? = null) {
        val json = JSONObject().apply {
            put("type", "MEDIA_CONTROL")
            put("requestId", UUID.randomUUID().toString())
            put("action", action)
            if (seekSeconds != null) {
                put("seekSeconds", seekSeconds)
            }
        }
        sendDirectControlFrame(json.toString().toByteArray(StandardCharsets.UTF_8))
    }

    fun sendSetAppVolume(pid: Int, volume: Int) {
        val json = JSONObject().apply {
            put("type", "SET_APP_VOLUME")
            put("requestId", UUID.randomUUID().toString())
            put("pid", pid)
            put("volume", volume)
        }
        sendDirectControlFrame(json.toString().toByteArray(StandardCharsets.UTF_8))
    }

    fun sendSetAppMute(pid: Int, mute: Boolean) {
        val json = JSONObject().apply {
            put("type", "SET_APP_MUTE")
            put("requestId", UUID.randomUUID().toString())
            put("pid", pid)
            put("mute", mute)
        }
        sendDirectControlFrame(json.toString().toByteArray(StandardCharsets.UTF_8))
    }

    fun sendSetAudioDevice(deviceId: String, isInput: Boolean) {
        val json = JSONObject().apply {
            put("type", "SET_AUDIO_DEVICE")
            put("requestId", UUID.randomUUID().toString())
            put("deviceId", deviceId)
            put("isInput", isInput)
        }
        sendDirectControlFrame(json.toString().toByteArray(StandardCharsets.UTF_8))
    }

    fun sendSetMicGain(gain: Int) {
        val json = JSONObject().apply {
            put("type", "SET_MIC_GAIN")
            put("requestId", UUID.randomUUID().toString())
            put("gain", gain)
        }
        sendDirectControlFrame(json.toString().toByteArray(StandardCharsets.UTF_8))
    }

    fun sendSetMasterMute(mute: Boolean) {
        dispatchCommand("volume_mute")
    }

    fun sendSetMicMute(mute: Boolean) {
        val json = JSONObject().apply {
            put("type", "SET_MIC_MUTE")
            put("requestId", UUID.randomUUID().toString())
            put("mute", mute)
        }
        sendDirectControlFrame(json.toString().toByteArray(StandardCharsets.UTF_8))
    }

    fun requestAdminTelemetry() {
        val json = JSONObject().apply {
            put("type", "GET_ADMIN_TELEMETRY")
            put("requestId", UUID.randomUUID().toString())
        }
        sendDirectControlFrame(json.toString().toByteArray(StandardCharsets.UTF_8))
    }

    fun requestBatteryHealth() {
        val json = JSONObject().apply {
            put("type", "GET_BATTERY_HEALTH")
            put("requestId", UUID.randomUUID().toString())
        }
        sendDirectControlFrame(json.toString().toByteArray(StandardCharsets.UTF_8))
    }

    fun requestHardwareSpecs() {
        val json = JSONObject().apply {
            put("type", "GET_HARDWARE_SPECS")
            put("requestId", UUID.randomUUID().toString())
        }
        sendDirectControlFrame(json.toString().toByteArray(StandardCharsets.UTF_8))
    }

    fun requestGenerateBatteryReport() {
        val json = JSONObject().apply {
            put("type", "GENERATE_BATTERY_REPORT")
            put("requestId", UUID.randomUUID().toString())
        }
        sendDirectControlFrame(json.toString().toByteArray(StandardCharsets.UTF_8))
    }

    fun requestPowerPlans() {
        val json = JSONObject().apply {
            put("type", "GET_POWER_PLANS")
            put("requestId", UUID.randomUUID().toString())
        }
        sendDirectControlFrame(json.toString().toByteArray(StandardCharsets.UTF_8))
    }

    fun sendSetPowerPlan(guid: String) {
        val json = JSONObject().apply {
            put("type", "SET_POWER_PLAN")
            put("requestId", UUID.randomUUID().toString())
            put("guid", guid)
        }
        sendDirectControlFrame(json.toString().toByteArray(StandardCharsets.UTF_8))
    }

    fun requestPrinters() {
        val json = JSONObject().apply {
            put("type", "GET_PRINTERS")
            put("requestId", UUID.randomUUID().toString())
        }
        sendDirectControlFrame(json.toString().toByteArray(StandardCharsets.UTF_8))
    }

    fun requestUsbDevices() {
        val json = JSONObject().apply {
            put("type", "GET_USB_DEVICES")
            put("requestId", UUID.randomUUID().toString())
        }
        sendDirectControlFrame(json.toString().toByteArray(StandardCharsets.UTF_8))
    }

    fun requestWindowsServices(filter: String = "") {
        val json = JSONObject().apply {
            put("type", "GET_SERVICES")
            put("requestId", UUID.randomUUID().toString())
            put("filter", filter)
        }
        sendDirectControlFrame(json.toString().toByteArray(StandardCharsets.UTF_8))
    }

    fun sendControlService(serviceName: String, action: String) {
        val json = JSONObject().apply {
            put("type", "CONTROL_SERVICE")
            put("requestId", UUID.randomUUID().toString())
            put("serviceName", serviceName)
            put("action", action)
        }
        sendDirectControlFrame(json.toString().toByteArray(StandardCharsets.UTF_8))
    }

    fun requestWindowsUpdates() {
        val json = JSONObject().apply {
            put("type", "CHECK_UPDATES")
            put("requestId", UUID.randomUUID().toString())
        }
        sendDirectControlFrame(json.toString().toByteArray(StandardCharsets.UTF_8))
    }

    fun sendClipboardGet() {
        val json = JSONObject().apply {
            put("type", "CLIPBOARD_GET")
            put("requestId", java.util.UUID.randomUUID().toString())
        }
        sendDirectControlFrame(json.toString().toByteArray(StandardCharsets.UTF_8))
    }

    fun requestInstalledApps() {
        val json = JSONObject().apply {
            put("type", "APP_GET_INSTALLED")
            put("requestId", java.util.UUID.randomUUID().toString())
        }
        sendDirectControlFrame(json.toString().toByteArray(StandardCharsets.UTF_8))
    }

    fun sendLaunchApp(path: String, args: String = "") {
        val json = JSONObject().apply {
            put("type", "APP_LAUNCH")
            put("requestId", UUID.randomUUID().toString())
            put("path", path)
            put("args", args)
        }
        sendDirectControlFrame(json.toString().toByteArray(StandardCharsets.UTF_8))
    }

    fun sendWindowFocus(hwnd: Long) {
        val json = JSONObject().apply {
            put("type", "WINDOW_FOCUS")
            put("requestId", UUID.randomUUID().toString())
            put("hwnd", hwnd)
        }
        sendDirectControlFrame(json.toString().toByteArray(StandardCharsets.UTF_8))
    }

    fun sendWindowSnap(hwnd: Long, direction: String) {
        val json = JSONObject().apply {
            put("type", "WINDOW_SNAP")
            put("requestId", UUID.randomUUID().toString())
            put("hwnd", hwnd)
            put("direction", direction)
        }
        sendDirectControlFrame(json.toString().toByteArray(StandardCharsets.UTF_8))
    }

    fun sendWindowState(hwnd: Long, state: String) {
        val json = JSONObject().apply {
            put("type", "WINDOW_STATE")
            put("requestId", UUID.randomUUID().toString())
            put("hwnd", hwnd)
            put("state", state)
        }
        sendDirectControlFrame(json.toString().toByteArray(StandardCharsets.UTF_8))
    }

    fun sendWindowClose(hwnd: Long, forceKill: Boolean = false) {
        val json = JSONObject().apply {
            put("type", "WINDOW_CLOSE")
            put("requestId", UUID.randomUUID().toString())
            put("hwnd", hwnd)
            put("force", forceKill)
        }
        sendDirectControlFrame(json.toString().toByteArray(StandardCharsets.UTF_8))
    }

    fun requestRunningWindows() {
        val json = JSONObject().apply {
            put("type", "GET_RUNNING_WINDOWS")
            put("requestId", UUID.randomUUID().toString())
        }
        sendDirectControlFrame(json.toString().toByteArray(StandardCharsets.UTF_8))
    }

    fun requestWorkflows() {
        val json = JSONObject().apply {
            put("type", "GET_WORKFLOWS")
            put("requestId", UUID.randomUUID().toString())
        }
        sendDirectControlFrame(json.toString().toByteArray(StandardCharsets.UTF_8))
    }

    fun sendSaveWorkflow(workflowJson: JSONObject) {
        val json = JSONObject().apply {
            put("type", "SAVE_WORKFLOW")
            put("requestId", UUID.randomUUID().toString())
            put("workflow", workflowJson)
        }
        sendDirectControlFrame(json.toString().toByteArray(StandardCharsets.UTF_8))
    }

    fun sendDeleteWorkflow(id: String) {
        val json = JSONObject().apply {
            put("type", "DELETE_WORKFLOW")
            put("requestId", UUID.randomUUID().toString())
            put("id", id)
        }
        sendDirectControlFrame(json.toString().toByteArray(StandardCharsets.UTF_8))
    }

    fun sendTriggerWorkflow(id: String) {
        val json = JSONObject().apply {
            put("type", "RUN_WORKFLOW")
            put("requestId", UUID.randomUUID().toString())
            put("id", id)
        }
        sendDirectControlFrame(json.toString().toByteArray(StandardCharsets.UTF_8))
    }
}