@file:Suppress("DEPRECATION")

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
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.Socket
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

class TetherLanService : Service() {

    companion object {
        const val TAG = "TetherLanService"

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

    private var activeSocket: Socket? = null
    private var dataInputStream: DataInputStream? = null
    private var dataOutputStream: DataOutputStream? = null

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
                if (!targetIp.isNullOrBlank()) {
                    Log.i(TAG, "Direct target connection requested: $targetIp")
                    getSharedPreferences("tether_secure_prefs", MODE_PRIVATE).edit {
                        putString("saved_host_ip", targetIp)
                    }
                    connectToHost(targetIp)
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
        if (currentState == TransportState.AUTHENTICATED || currentState == TransportState.READY || currentState == TransportState.CONNECTING) {
            return
        }
        currentState = TransportState.DISCOVERING
        Log.i(TAG, "Local discovery initiated.")
    }

    fun connectToHost(hostAddress: String, port: Int = DEFAULT_PORT) {
        if (currentState == TransportState.AUTHENTICATING || currentState == TransportState.AUTHENTICATED || currentState == TransportState.READY) return
        currentState = TransportState.CONNECTING
        connectedHostAddress = hostAddress
        connectedHostPort = port
    }

    fun dispatchCommand(actionCommand: String) {
        networkExecutor.execute {
            try {
                if (currentState != TransportState.READY && currentState != TransportState.AUTHENTICATED) {
                    Log.w(TAG, "Transport not ready ($currentState). Queuing command and starting discovery...")
                    startDiscovery()
                }
                val reqId = UUID.randomUUID().toString()
                Log.i(TAG, "Dispatched command: $actionCommand (reqId=$reqId)")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to dispatch command ($actionCommand): ${e.message}")
            }
        }
    }

    fun disconnectActiveSession(reason: String) {
        Log.w(TAG, "Disconnecting active session: $reason")
        try { activeSocket?.close() } catch (_: Exception) {}
        activeSocket = null
        dataInputStream = null
        dataOutputStream = null
        currentState = TransportState.DISCONNECTED
    }

    private fun restartTransport() {
        disconnectActiveSession("Transport restart requested")
        startDiscovery()
    }

    private fun performHealthCheck() {
        if (currentState == TransportState.DISCONNECTED || currentState == TransportState.FAILED) {
            startDiscovery()
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

        cancelAlarm()
        disconnectActiveSession("Service destroyed")

        wakeLock?.let { if (it.isHeld) it.release() }
        wakeLock = null

        mainHandler.removeCallbacksAndMessages(null)
        networkExecutor.shutdown()
        super.onDestroy()
    }
}
