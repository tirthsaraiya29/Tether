// apps/android-companion/app/src/main/java/com/tether/phone/BleGattServerService.kt
package com.tether.phone

import android.Manifest
import android.annotation.SuppressLint
import android.app.AlarmManager
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.BluetoothLeAdvertiser
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.ParcelUuid
import android.os.PowerManager
import android.os.SystemClock
import android.util.Log
import androidx.core.app.NotificationCompat
import org.json.JSONObject
import java.security.SecureRandom
import java.util.Arrays
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class BleGattServerService : Service() {

    private var bluetoothGattServer: BluetoothGattServer? = null
    private var bluetoothAdapter: BluetoothAdapter? = null
    private var advertiser: BluetoothLeAdvertiser? = null
    private var isAdvertising = false

    private val advertisingLock = Any()

    private lateinit var securityEngine: ProductionSecurityEngine
    private var commandCharacteristic: BluetoothGattCharacteristic? = null

    private val authenticatedDevicesMap = ConcurrentHashMap<String, BluetoothDevice>()
    private val unauthenticatedConnections = ConcurrentHashMap<String, Long>()

    private val mainHandler = Handler(Looper.getMainLooper())
    private val deviceChallenges = ConcurrentHashMap<String, ByteArray>()
    private val notificationSubscriptions = ConcurrentHashMap<String, Boolean>()
    private val sessionKeysMap = ConcurrentHashMap<String, ByteArray>()
    private val deviceMtuMap = ConcurrentHashMap<String, Int>()
    private val windowsPublicKeys = ConcurrentHashMap<String, ByteArray>()
    private val pendingNonces = ConcurrentHashMap<String, ByteArray>()

    private data class WriteSession(val uuid: UUID, val payload: ByteArray) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false
            other as WriteSession
            if (uuid != other.uuid) return false
            return payload.contentEquals(other.payload)
        }

        override fun hashCode(): Int {
            var result = uuid.hashCode()
            result = (31 * result) + payload.contentHashCode()
            return result
        }
    }
    private val pendingExecuteWrites = ConcurrentHashMap<String, WriteSession>()

    private val selfHealingHandler = Handler(Looper.getMainLooper())
    private val gattLock = Any()
    private var lastStackRefreshTime = SystemClock.elapsedRealtime()

    @Volatile
    private var activeCommandPayload = byteArrayOf()

    private lateinit var powerManager: PowerManager
    private var wakeLock: PowerManager.WakeLock? = null

    private var alarmManager: AlarmManager? = null
    private var alarmPendingIntent: PendingIntent? = null

    private fun bumpGeneration(address: String): Long {
        val g = generationCounter.incrementAndGet()
        connectionGenerations[address] = g
        return g
    }

    private fun currentGeneration(address: String): Long = connectionGenerations[address] ?: 0L

    private fun invalidateGeneration(address: String) {
        connectionGenerations[address] = generationCounter.incrementAndGet()
    }

    private val bluetoothStateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            when (intent?.action) {
                BluetoothAdapter.ACTION_STATE_CHANGED -> {
                    when (intent.getIntExtra(BluetoothAdapter.EXTRA_STATE, BluetoothAdapter.ERROR)) {
                        BluetoothAdapter.STATE_ON -> {
                            Log.i("TetherBle", "Bluetooth Adapter ON - Restarting stack")
                            mainHandler.post { restartGattServer() }
                        }
                        BluetoothAdapter.STATE_TURNING_OFF -> {
                            Log.i("TetherBle", "Bluetooth Adapter TURNING OFF - Closing GATT server")
                            synchronized(gattLock) {
                                try {
                                    bluetoothGattServer?.close()
                                } catch (_: SecurityException) {} catch (_: Exception) {}
                                bluetoothGattServer = null
                                isAdvertising = false
                            }
                        }
                        BluetoothAdapter.STATE_OFF -> {
                            Log.i("TetherBle", "Bluetooth Adapter OFF")
                            stopAdvertising()
                        }
                    }
                }
                Intent.ACTION_SCREEN_ON -> {
                    if (authenticatedDevicesMap.isEmpty() && !isAdvertising) {
                        startAdvertisingWithRetry(3)
                    }
                }
                PowerManager.ACTION_POWER_SAVE_MODE_CHANGED -> {
                    val isPowerSaveMode = powerManager.isPowerSaveMode
                    Log.i("TetherBle", "Power Save Mode Changed: $isPowerSaveMode")
                    if (!isPowerSaveMode && !isAdvertising && authenticatedDevicesMap.isEmpty()) {
                        startAdvertisingWithRetry(3)
                    }
                }
            }
        }
    }

    private val healthCheckRunnable = Runnable {
        try {
            val bluetoothManager = getSystemService(BluetoothManager::class.java) ?: return@Runnable
            val adapter = bluetoothManager.adapter
            if (adapter?.isEnabled != true) return@Runnable

            val now = SystemClock.elapsedRealtime()

            unauthenticatedConnections.forEach { (address, connectionTime) ->
                if ((now - connectionTime) > 45000L) {
                    unauthenticatedConnections.remove(address)
                    synchronized(gattLock) {
                        try {
                            @SuppressLint("MissingPermission")
                            val connectedDevices = bluetoothManager.getConnectedDevices(BluetoothProfile.GATT_SERVER)
                            val device = connectedDevices.find { it.address == address }
                            @SuppressLint("MissingPermission")
                            device?.let { bluetoothGattServer?.cancelConnection(it) }
                        } catch (_: Exception) {}
                    }
                }
            }

            if ((now - lastStackRefreshTime) > 3600000L) {
                if (authenticatedDevicesMap.isEmpty()) {
                    Log.i("TetherBle", "Hourly health check: Idle stack refresh initiated.")
                    restartGattServer()
                } else {
                    lastStackRefreshTime = now - 1800000L
                    Log.i("TetherBle", "Hourly health check postponed: Active connection detected.")
                }
                return@Runnable
            }

            if (authenticatedDevicesMap.isEmpty() && !isAdvertising) {
                startAdvertisingWithRetry(3)
            }
        } catch (e: Exception) {
            Log.e("TetherBle", "Health check error: ${e.message}")
        }
    }

    companion object {
        val SERVICE_UUID: UUID = UUID.fromString("0000FFE0-0000-1000-8000-00805F9B34FB")
        private val CHALLENGE_CHAR_UUID = UUID.fromString("0000FFE3-0000-1000-8000-00805F9B34FB")
        private val COMMAND_CHAR_UUID = UUID.fromString("0000FFE5-0000-1000-8000-00805F9B34FB")
        private val PUBLIC_KEY_CHAR_UUID = UUID.fromString("0000FFE6-0000-1000-8000-00805F9B34FB")
        private val WINDOWS_PUBLIC_KEY_CHAR_UUID = UUID.fromString("0000FFE7-0000-1000-8000-00805F9B34FB")
        private val AUTH_CHALLENGE_CHAR_UUID = UUID.fromString("0000FFE8-0000-1000-8000-00805F9B34FB")
        private val AUTH_SIGNATURE_CHAR_UUID = UUID.fromString("0000FFE9-0000-1000-8000-00805F9B34FB")
        private val CCCD_UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")

        const val ACTION_GATT_STATE_CHANGED = "com.tether.phone.ACTION_GATT_STATE_CHANGED"
        const val ACTION_COMMAND_CONFIRMED = "com.tether.phone.ACTION_COMMAND_CONFIRMED"
        const val EXTRA_CONNECTION_COUNT = "extra_connection_count"

        private const val CHANNEL_ID = "tether_proximity_channel"
        private const val NOTIFICATION_ID = 1

        const val ALARM_ACTION = "com.tether.phone.ALARM_HEALTH_CHECK"
        const val ACTION_RESTART_SERVER = "com.tether.phone.RESTART_SERVER"
        private const val HEALTH_CHECK_INTERVAL_MS = 60000L
        private const val WAKE_LOCK_TAG = "tether:BleWakeLock"

        private const val REQ_CODE_HEALTH_CHECK = 0x7E71
        private const val REQ_CODE_TASK_REMOVED = 0x7E72
        const val ACTION_TASK_REMOVED_RESTART = "com.tether.phone.ACTION_TASK_REMOVED_RESTART"

        private val connectionGenerations = ConcurrentHashMap<String, Long>()
        private val generationCounter = AtomicLong(0)
    }

    private fun ensureForeground() {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                startForeground(NOTIFICATION_ID, createNotification(), ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE)
            } else {
                startForeground(NOTIFICATION_ID, createNotification())
            }
        } catch (e: Exception) {
            Log.e("TetherBle", "Failed to start foreground service: ${e.message}")
        }
    }

    @SuppressLint("MissingPermission")
    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        ensureForeground()

        if (!hasRequiredRuntimePermissions()) {
            Log.w("TetherBle", "Missing runtime permissions. Stopping service.")
            stopSelf()
            return
        }

        securityEngine = try {
            ProductionSecurityEngine()
        } catch (e: Exception) {
            Log.e("TetherBle", "Failed to initialize security engine: ${e.message}")
            stopSelf()
            return
        }

        powerManager = getSystemService(POWER_SERVICE) as PowerManager
        wakeLock = powerManager.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, WAKE_LOCK_TAG)
        try {
            wakeLock?.acquire(10 * 60 * 1000L)
        } catch (_: Exception) {}

        val filter = IntentFilter().apply {
            addAction(BluetoothAdapter.ACTION_STATE_CHANGED)
            addAction(Intent.ACTION_SCREEN_ON)
            addAction(Intent.ACTION_SCREEN_OFF)
            addAction(PowerManager.ACTION_POWER_SAVE_MODE_CHANGED)
        }
        registerReceiver(bluetoothStateReceiver, filter)

        val bluetoothManager = getSystemService(BluetoothManager::class.java)
        bluetoothAdapter = bluetoothManager?.adapter

        if (bluetoothAdapter?.isEnabled != true) {
            Log.w("TetherBle", "Bluetooth adapter not enabled. Stopping service.")
            stopSelf()
            return
        }

        synchronized(gattLock) {
            bluetoothGattServer = try {
                bluetoothManager?.openGattServer(this, gattServerCallback)
            } catch (e: Exception) {
                Log.e("TetherBle", "Failed to open GATT server: ${e.message}")
                stopSelf()
                return
            }

            if (bluetoothGattServer == null) {
                Log.e("TetherBle", "Failed to open GATT server. Bluetooth might be busy or disabled.")
                mainHandler.postDelayed({ stopSelf() }, 1000)
                return
            }

            setupGattServer()
            startAdvertising()
        }

        scheduleAlarmForHealthCheck()
    }

    @SuppressLint("MissingPermission")
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        ensureForeground()

        if (!hasRequiredRuntimePermissions()) {
            stopSelf()
            return START_NOT_STICKY
        }

        if (wakeLock?.isHeld == false) {
            try {
                wakeLock?.acquire(10 * 60 * 1000L)
            } catch (_: Exception) {}
        }

        val action = intent?.action
        if (action == ALARM_ACTION) {
            Log.i("TetherBle", "Alarm Health Check triggered via onStartCommand")
            mainHandler.post { healthCheckRunnable.run() }
            scheduleAlarmForHealthCheck()
            return START_STICKY
        }

        if (action == "ACTION_GET_STATUS") {
            notifyStateToInterface()
            return START_STICKY
        }

        if (action == ACTION_RESTART_SERVER) {
            Log.w("TetherBle", "Manual server restart requested via onStartCommand")
            mainHandler.post { restartGattServer() }
            return START_STICKY
        }

        if (action == ACTION_TASK_REMOVED_RESTART) {
            return START_STICKY
        }

        if ((action == Intent.ACTION_SCREEN_ON) || (action == Intent.ACTION_SCREEN_OFF)) {
            if (authenticatedDevicesMap.isEmpty() && !isAdvertising) {
                startAdvertisingWithRetry(3)
            }
            return START_STICKY
        }

        // Only push recognized control action strings as BLE commands
        if ((action != null) && isControlCommandAction(action)) {
            val value = action.toByteArray(Charsets.UTF_8)
            activeCommandPayload = value
            pushCommandToSubscribedDevices(value)
        }

        return START_STICKY
    }

    private fun isControlCommandAction(action: String): Boolean {
        val prefixes = listOf("volume", "media:", "app_launch:", "power_plan:", "brightness")
        val exact = setOf("mute_toggle", "lock_now", "unlock", "screen_unlock", "panic", "shutdown", "sleep", "reboot", "get_apps", "get_battery", "get_power_plans")
        return (action in exact) || prefixes.any { action.startsWith(it) }
    }

    @SuppressLint("MissingPermission")
    private fun setupGattServer() {
        val server = bluetoothGattServer ?: return
        val service = BluetoothGattService(SERVICE_UUID, BluetoothGattService.SERVICE_TYPE_PRIMARY)

        commandCharacteristic = BluetoothGattCharacteristic(
            COMMAND_CHAR_UUID,
            BluetoothGattCharacteristic.PROPERTY_READ or BluetoothGattCharacteristic.PROPERTY_NOTIFY or
                    BluetoothGattCharacteristic.PROPERTY_WRITE or BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE,
            BluetoothGattCharacteristic.PERMISSION_READ or BluetoothGattCharacteristic.PERMISSION_WRITE,
        )

        val cccdDescriptor = BluetoothGattDescriptor(
            CCCD_UUID,
            BluetoothGattDescriptor.PERMISSION_READ or BluetoothGattDescriptor.PERMISSION_WRITE,
        )
        @Suppress("DEPRECATION")
        cccdDescriptor.value = BluetoothGattDescriptor.DISABLE_NOTIFICATION_VALUE
        commandCharacteristic?.addDescriptor(cccdDescriptor)

        val challengeChar = BluetoothGattCharacteristic(
            CHALLENGE_CHAR_UUID,
            BluetoothGattCharacteristic.PROPERTY_WRITE,
            BluetoothGattCharacteristic.PERMISSION_WRITE,
        )
        val publicKeyChar = BluetoothGattCharacteristic(
            PUBLIC_KEY_CHAR_UUID,
            BluetoothGattCharacteristic.PROPERTY_READ,
            BluetoothGattCharacteristic.PERMISSION_READ,
        )
        val windowsPublicKeyChar = BluetoothGattCharacteristic(
            WINDOWS_PUBLIC_KEY_CHAR_UUID,
            BluetoothGattCharacteristic.PROPERTY_WRITE,
            BluetoothGattCharacteristic.PERMISSION_WRITE,
        )

        val authChallengeChar = BluetoothGattCharacteristic(
            AUTH_CHALLENGE_CHAR_UUID,
            BluetoothGattCharacteristic.PROPERTY_READ or BluetoothGattCharacteristic.PROPERTY_NOTIFY,
            BluetoothGattCharacteristic.PERMISSION_READ,
        )

        val authCccdDescriptor = BluetoothGattDescriptor(
            CCCD_UUID,
            BluetoothGattDescriptor.PERMISSION_READ or BluetoothGattDescriptor.PERMISSION_WRITE,
        )
        @Suppress("DEPRECATION")
        authCccdDescriptor.value = BluetoothGattDescriptor.DISABLE_NOTIFICATION_VALUE
        authChallengeChar.addDescriptor(authCccdDescriptor)

        val authSignatureChar = BluetoothGattCharacteristic(
            AUTH_SIGNATURE_CHAR_UUID,
            BluetoothGattCharacteristic.PROPERTY_WRITE,
            BluetoothGattCharacteristic.PERMISSION_WRITE,
        )

        commandCharacteristic?.let { service.addCharacteristic(it) }
        service.addCharacteristic(challengeChar)
        service.addCharacteristic(publicKeyChar)
        service.addCharacteristic(windowsPublicKeyChar)
        service.addCharacteristic(authChallengeChar)
        service.addCharacteristic(authSignatureChar)

        try {
            server.addService(service)
        } catch (_: SecurityException) {}
    }

    private val gattServerCallback = object : BluetoothGattServerCallback() {
        override fun onServiceAdded(status: Int, service: BluetoothGattService?) {}

        @SuppressLint("MissingPermission")
        override fun onConnectionStateChange(device: BluetoothDevice?, status: Int, newState: Int) {
            if (device == null) return
            val address = device.address
            Log.d("TetherBle", "onConnectionStateChange: $address status=$status newState=$newState")

            if (newState == BluetoothProfile.STATE_CONNECTED) {
                val gen = bumpGeneration(address)
                unauthenticatedConnections[address] = SystemClock.elapsedRealtime()

                mainHandler.postDelayed({
                    // Stale-callback guard.
                    if (currentGeneration(address) != gen) return@postDelayed
                    if (!authenticatedDevicesMap.containsKey(address) && unauthenticatedConnections.containsKey(address)) {
                        Log.w("TetherBle", "Validation window expired. Purging $address")
                        unauthenticatedConnections.remove(address)
                        invalidateGeneration(address)
                        synchronized(gattLock) {
                            try { bluetoothGattServer?.cancelConnection(device) } catch (_: Exception) {}
                        }
                    }
                }, 45000L)

                mainHandler.post { startAdvertising(connectable = false) }

            } else if (newState == BluetoothProfile.STATE_DISCONNECTED || status != BluetoothGatt.GATT_SUCCESS) {
                invalidateGeneration(address)
                authenticatedDevicesMap.remove(address)
                unauthenticatedConnections.remove(address)
                deviceChallenges.remove(address)
                pendingNonces.remove(address)

                // Wipe session key bytes before dropping reference.
                sessionKeysMap.remove(address)?.let { key ->
                    Arrays.fill(key, 0)
                }

                val stale = notificationSubscriptions.keys().asSequence().filter { it.startsWith("$address-") }.toList()
                stale.forEach { notificationSubscriptions.remove(it) }
                deviceMtuMap.remove(address)
                val pendingKeys = pendingExecuteWrites.keys().asSequence().filter { it.startsWith("$address-") }.toList()
                pendingKeys.forEach { pendingExecuteWrites.remove(it) }
                windowsPublicKeys.remove(address)

                if (authenticatedDevicesMap.isEmpty()) {
                    mainHandler.postDelayed({ startAdvertising(connectable = true) }, 300)
                }
            }
            notifyStateToInterface()
        }

        override fun onMtuChanged(device: BluetoothDevice?, mtu: Int) {
            device?.let { deviceMtuMap[it.address] = mtu }
        }

        @SuppressLint("MissingPermission")
        override fun onCharacteristicWriteRequest(
            device: BluetoothDevice?,
            requestId: Int,
            characteristic: BluetoothGattCharacteristic?,
            preparedWrite: Boolean,
            responseNeeded: Boolean,
            offset: Int,
            value: ByteArray?,
        ) {
            if ((device == null) || (characteristic == null) || (value == null)) {
                if (responseNeeded && (device != null)) {
                    try { synchronized(gattLock) { bluetoothGattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, offset, null) } } catch (_: Exception) {}
                }
                return
            }

            val address = device.address
            val uuid = characteristic.uuid
            val storageKey = "$address-$uuid"

            if (preparedWrite) {
                val currentPayload = pendingExecuteWrites[storageKey]?.payload ?: byteArrayOf()
                pendingExecuteWrites[storageKey] = WriteSession(uuid, if (offset == 0) value else currentPayload + value)
                if (responseNeeded) {
                    try { synchronized(gattLock) { bluetoothGattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, value) } } catch (_: Exception) {}
                }
                return
            }

            // Security-relevant characteristics: validate before ACK so the client knows
            // whether the server accepted the payload.
            val securityRelevant = (uuid == AUTH_SIGNATURE_CHAR_UUID) ||
                                   (uuid == CHALLENGE_CHAR_UUID) ||
                                   (uuid == WINDOWS_PUBLIC_KEY_CHAR_UUID)

            if (securityRelevant) {
                val accepted = processCompletePayloadSync(device, uuid, value)
                if (responseNeeded) {
                    try {
                        synchronized(gattLock) {
                            bluetoothGattServer?.sendResponse(
                                device, requestId,
                                if (accepted) BluetoothGatt.GATT_SUCCESS else BluetoothGatt.GATT_FAILURE,
                                offset, null,
                            )
                        }
                    } catch (_: Exception) {}
                }
                return
            }

            if (responseNeeded) {
                try { synchronized(gattLock) {
                    bluetoothGattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, value)
                } } catch (_: Exception) {}
            }
            mainHandler.post { processCompletePayload(device, uuid, value) }
        }

        override fun onCharacteristicReadRequest(device: BluetoothDevice?, requestId: Int, offset: Int, characteristic: BluetoothGattCharacteristic?) {
            if (device == null) return
            Log.d("TetherBle", "onCharacteristicReadRequest: ${characteristic?.uuid} from ${device.address} offset=$offset")
            try {
                when (characteristic?.uuid) {
                    AUTH_CHALLENGE_CHAR_UUID -> {
                        val nonce = pendingNonces[device.address]
                        Log.d("TetherBle", "Reading Auth Challenge. Available: ${nonce != null}")
                        nonce?.let {
                            sendSlicedResponse(device, requestId, offset, it)
                        } ?: synchronized(gattLock) {
                            bluetoothGattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, offset, null)
                        }
                    }
                    COMMAND_CHAR_UUID -> {
                        if (!authenticatedDevicesMap.containsKey(device.address)) {
                            synchronized(gattLock) {
                                bluetoothGattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, offset, null)
                            }
                        } else {
                            sendSlicedResponse(device, requestId, offset, activeCommandPayload)
                        }
                    }
                    PUBLIC_KEY_CHAR_UUID -> { sendSlicedResponse(device, requestId, offset, securityEngine.getPublicKeyBytes()) }
                    else -> {
                        synchronized(gattLock) { bluetoothGattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_REQUEST_NOT_SUPPORTED, offset, null) }
                    }
                }
            } catch (_: SecurityException) {}
        }

        @SuppressLint("MissingPermission")
        override fun onDescriptorWriteRequest(
            device: BluetoothDevice?,
            requestId: Int,
            descriptor: BluetoothGattDescriptor?,
            preparedWrite: Boolean,
            responseNeeded: Boolean,
            offset: Int,
            value: ByteArray?,
        ) {
            if ((device == null) || (descriptor == null) || (value == null)) {
                if (responseNeeded && (device != null)) {
                    try { synchronized(gattLock) { bluetoothGattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, offset, null) } } catch (_: Exception) {}
                }
                return
            }

            val address = device.address
            val uuid = descriptor.uuid
            val parentCharUuid = descriptor.characteristic?.uuid ?: UUID.randomUUID()
            Log.d("TetherBle", "onDescriptorWriteRequest: $uuid from $address value=${value.contentToString()}")

            val storageKey = "$address-$parentCharUuid-$uuid"

            if (preparedWrite) {
                val currentPayload = pendingExecuteWrites[storageKey]?.payload ?: byteArrayOf()
                pendingExecuteWrites[storageKey] = WriteSession(uuid, if (offset == 0) value else currentPayload + value)
                if (responseNeeded) {
                    try { synchronized(gattLock) { bluetoothGattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, value) } } catch (_: SecurityException) {}
                }
                return
            }

            if (uuid == CCCD_UUID) {
                var accepted = false
                if (value.isNotEmpty()) {
                    val controlByte = value[0].toInt()
                    if ((controlByte and 0x03) != 0) {
                        notificationSubscriptions["$address-$parentCharUuid"] = true
                        accepted = true
                    } else if (controlByte == 0) {
                        notificationSubscriptions.remove("$address-$parentCharUuid")
                        accepted = true
                    }
                }
                if (responseNeeded) {
                    try {
                        synchronized(gattLock) {
                            bluetoothGattServer?.sendResponse(device, requestId, if (accepted) BluetoothGatt.GATT_SUCCESS else BluetoothGatt.GATT_FAILURE, 0, null)
                        }
                    } catch (_: SecurityException) {}
                }
            }
        }

        override fun onDescriptorReadRequest(device: BluetoothDevice?, requestId: Int, offset: Int, descriptor: BluetoothGattDescriptor?) {
            if ((device == null) || (descriptor == null)) return
            try {
                val address = device.address
                val parentCharUuid = descriptor.characteristic?.uuid ?: UUID.randomUUID()
                val value = if ((descriptor.uuid == CCCD_UUID) && (notificationSubscriptions["$address-$parentCharUuid"] == true)) {
                    BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
                } else {
                    BluetoothGattDescriptor.DISABLE_NOTIFICATION_VALUE
                }
                sendSlicedResponse(device, requestId, offset, value)
            } catch (_: SecurityException) {}
        }

        override fun onExecuteWrite(device: BluetoothDevice?, requestId: Int, execute: Boolean) {
            if (device == null) return
            val address = device.address
            val targetKeys = pendingExecuteWrites.keys().asSequence().filter { it.startsWith("$address-") }.toList()

            try {
                synchronized(gattLock) {
                    bluetoothGattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, null)
                }
            } catch (_: SecurityException) {}

            for (storageKey in targetKeys) {
                val session = pendingExecuteWrites.remove(storageKey)
                if (execute && (session != null)) {
                    mainHandler.post { processCompletePayload(device, session.uuid, session.payload) }
                }
            }
        }
    }

    private fun processCompletePayload(device: BluetoothDevice, uuid: UUID, payload: ByteArray) {
        processCompletePayloadSync(device, uuid, payload)
    }

    @SuppressLint("MissingPermission")
    private fun processCompletePayloadSync(device: BluetoothDevice, uuid: UUID, payload: ByteArray): Boolean {
        val address = device.address
        Log.d("TetherBle", "Processing payload for $uuid from $address, size=${payload.size}")
        try {
            when (uuid) {
                WINDOWS_PUBLIC_KEY_CHAR_UUID -> {
                    if (payload.isEmpty() || payload.size > 4096) {
                        Log.w("TetherBle", "Rejected Windows public key: size=${payload.size}")
                        return false
                    }
                    windowsPublicKeys[address] = payload
                    Log.d("TetherBle", "Received Windows Public Key for $address (${payload.size} bytes)")
                    initiateAuthChallengeIfPossible(device)
                    return true
                }

                CHALLENGE_CHAR_UUID -> {
                    if (payload.isEmpty() || payload.size > 512) {
                        Log.w("TetherBle", "Rejected Challenge: size=${payload.size}")
                        return false
                    }
                    if (payload.size >= 256) {
                        Log.d("TetherBle", "Received encrypted session key")
                        return try {
                            val sessionKey = securityEngine.decryptSessionKey(payload)
                            sessionKeysMap[address] = sessionKey
                            Log.d("TetherBle", "Session key decrypted successfully")
                            true
                        } catch (e: Exception) {
                            Log.e("TetherBle", "Failed to decrypt session key: ${e.message}")
                            false
                        }
                    } else {
                        Log.d("TetherBle", "Received direct challenge token from client")
                        deviceChallenges[address] = payload
                        initiateAuthChallengeIfPossible(device)
                        return true
                    }
                }

                AUTH_SIGNATURE_CHAR_UUID -> {
                    Log.d("TetherBle", "Received signature for auth verification from $address")
                    val nonce = pendingNonces.remove(address)
                    if (nonce == null) {
                        Log.e("TetherBle", "No pending nonce found for $address")
                        return false
                    }

                    val prefs = getSharedPreferences("tether_secure_prefs", MODE_PRIVATE)
                    val pinnedKeyBytes = securityEngine.getPinnedKeyDecrypted(this)

                    val pairingTimestamp = prefs.getLong("pairing_window_start_time", 0L)
                    val currentTime = System.currentTimeMillis()
                    val isPairingWindowOpen = (currentTime - pairingTimestamp) < 180000

                    val freshKey = windowsPublicKeys[address]
                    if (freshKey == null) {
                        Log.e("TetherBle", "Handshake failed: No public key transmitted by client for $address")
                        synchronized(gattLock) {
                            try { bluetoothGattServer?.cancelConnection(device) } catch (_: SecurityException) {} catch (_: Exception) {}
                        }
                        return false
                    }

                    val isKeyTrusted = if (pinnedKeyBytes != null) {
                        freshKey.contentEquals(pinnedKeyBytes)
                    } else {
                        isPairingWindowOpen
                    }

                    if (isKeyTrusted && securityEngine.verifySignature(nonce, payload, freshKey)) {
                        val gen = currentGeneration(address)
                        if (gen == 0L || gen != connectionGenerations[address]) {
                            Log.w("TetherBle", "Auth completed for stale generation. Dropping.")
                            return false
                        }
                        if (pinnedKeyBytes == null) {
                            Log.i("TetherBle", "Initial pairing successful. Pinning trusted Windows public key via Hardware Keystore Encryption.")
                            securityEngine.storePinnedKeySecurely(this, freshKey)
                        }
                        Log.i("TetherBle", "Auth Succeeded for $address")
                        unauthenticatedConnections.remove(address)
                        authenticatedDevicesMap[address] = device
                        notifyStateToInterface()

                        mainHandler.postDelayed(
                            {
                                val commandChar = commandCharacteristic
                                val server = bluetoothGattServer
                                if ((server != null) && (commandChar != null)) {
                                    synchronized(gattLock) {
                                        val reply = "auth_ok".toByteArray(Charsets.UTF_8)
                                        @Suppress("DEPRECATION")
                                        commandChar.value = reply
                                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                                            server.notifyCharacteristicChanged(device, commandChar, false, reply)
                                        } else {
                                            @Suppress("DEPRECATION")
                                            server.notifyCharacteristicChanged(device, commandChar, false)
                                        }
                                    }
                                }
                            },
                            50L,
                        )
                        return true
                    } else {
                        Log.e("TetherBle", "Handshake failed: Signature verification rejected. Trusted: $isKeyTrusted")
                        synchronized(gattLock) {
                            try { bluetoothGattServer?.cancelConnection(device) } catch (_: SecurityException) {} catch (_: Exception) {}
                        }
                        return false
                    }
                }

                COMMAND_CHAR_UUID -> {
                    if (!authenticatedDevicesMap.containsKey(address)) return false

                    if (payload.size < 29) {
                        Log.w("TetherBle", "Rejected command payload: too short for GCM framing (${payload.size} bytes)")
                        return false
                    }

                    val sessionKey = sessionKeysMap[address]
                    if ((sessionKey == null) || (sessionKey.size != 32)) {
                        Log.w("TetherBle", "Rejected command payload: no valid AES session key for $address")
                        return false
                    }

                    val decryptedString: String = try {
                        val nonce = payload.copyOfRange(0, 12)
                        val ciphertextWithTag = payload.copyOfRange(12, payload.size)

                        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                        cipher.init(
                            Cipher.DECRYPT_MODE,
                            SecretKeySpec(sessionKey, "AES"),
                            GCMParameterSpec(128, nonce),
                        )
                        String(cipher.doFinal(ciphertextWithTag), Charsets.UTF_8)
                    } catch (_: AEADBadTagException) {
                        Log.e("TetherBle", "GCM authentication tag verification failed for $address — frame rejected")
                        return false
                    } catch (e: Exception) {
                        Log.e("TetherBle", "GCM decryption error for $address: ${e.message}")
                        return false
                    }

                    if (decryptedString.startsWith("confirm_")) {
                        val intent = Intent(ACTION_COMMAND_CONFIRMED).apply {
                            putExtra("confirmed_command", decryptedString.substringAfter("confirm_"))
                            setPackage(packageName)
                        }
                        sendBroadcast(intent)
                    } else if (decryptedString.startsWith("media_state:")) {
                        val intent = Intent("com.tether.phone.ACTION_SYNC_MEDIA_STATE").apply {
                            putExtra("MEDIA_JSON", decryptedString.substringAfter("media_state:"))
                            setPackage(packageName)
                        }
                        sendBroadcast(intent)
                    } else if (decryptedString.startsWith("app_list:")) {
                        val intent = Intent("com.tether.phone.ACTION_SYNC_APP_LIST").apply {
                            putExtra("APP_LIST_JSON", decryptedString.substringAfter("app_list:"))
                            setPackage(packageName)
                        }
                        sendBroadcast(intent)
                    } else if (decryptedString.startsWith("hardware_state:") || decryptedString.startsWith("metrics:")) {
                        val jsonPayload = if (decryptedString.startsWith("hardware_state:")) {
                            decryptedString.substringAfter("hardware_state:")
                        } else {
                            decryptedString.substringAfter("metrics:")
                        }
                        try {
                            val jsonObj = JSONObject(jsonPayload)
                            val vol = jsonObj.optInt("volume", jsonObj.optInt("volume_level", -1))
                            val bright = jsonObj.optInt("brightness", jsonObj.optInt("brightness_level", -1))
                            val isMuted = jsonObj.optBoolean("is_muted", jsonObj.optBoolean("muted", false))
                            val intent = Intent("com.tether.phone.ACTION_SYNC_HARDWARE_METRICS").apply {
                                if (vol != -1) putExtra("VOLUME_LEVEL", vol)
                                if (bright != -1) putExtra("BRIGHTNESS_LEVEL", bright)
                                putExtra("IS_MUTED", isMuted)
                                setPackage(packageName)
                            }
                            sendBroadcast(intent)
                        } catch (e: Exception) {
                            Log.e("TetherBle", "Failed to parse hardware metrics JSON: ${e.message}")
                        }
                    } else if (decryptedString.startsWith("power_plans:")) {
                        val intent = Intent("com.tether.phone.ACTION_SYNC_POWER_PLANS").apply {
                            putExtra("POWER_PLANS_JSON", decryptedString.substringAfter("power_plans:"))
                            setPackage(packageName)
                        }
                        sendBroadcast(intent)
                    } else if (decryptedString.startsWith("battery_state:")) {
                        val intent = Intent("com.tether.phone.ACTION_SYNC_BATTERY_STATE").apply {
                            putExtra("BATTERY_JSON", decryptedString.substringAfter("battery_state:"))
                            setPackage(packageName)
                        }
                        sendBroadcast(intent)
                    }
                    return true
                }
                else -> return false
            }
        } catch (_: AEADBadTagException) {
            Log.w("TetherBle", "GCM tag verification failed for $address")
            return false
        } catch (e: Exception) {
            Log.e("TetherBle", "Payload processing failed: ${e.message}", e)
            return false
        }
    }

    @SuppressLint("MissingPermission")
    private fun pushCommandToSubscribedDevices(value: ByteArray) {
        val characteristic = commandCharacteristic ?: return
        val server = bluetoothGattServer ?: return

        for (device in authenticatedDevicesMap.values) {
            if (notificationSubscriptions["${device.address}-$COMMAND_CHAR_UUID"] != true) continue
            val sessionKey = sessionKeysMap[device.address]
            val payloadToSend = if ((sessionKey != null) && (sessionKey.size == 32)) {
                try {
                    val nonce = ByteArray(12)
                    SecureRandom().nextBytes(nonce)
                    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                    cipher.init(
                        Cipher.ENCRYPT_MODE,
                        SecretKeySpec(sessionKey, "AES"),
                        GCMParameterSpec(128, nonce),
                    )
                    val ciphertext = cipher.doFinal(value)
                    val combined = ByteArray(nonce.size + ciphertext.size)
                    System.arraycopy(nonce, 0, combined, 0, nonce.size)
                    System.arraycopy(ciphertext, 0, combined, nonce.size, ciphertext.size)
                    combined
                } catch (e: Exception) {
                    Log.e("TetherBle", "Failed to encrypt for ${device.address}: ${e.message}")
                    // Drop this device from the authenticated set so the next command doesn't silently fail.
                    authenticatedDevicesMap.remove(device.address)
                    sessionKeysMap.remove(device.address)?.let { Arrays.fill(it, 0) }
                    continue
                }
            } else {
                Log.w("TetherBle", "Skipping notification to ${device.address}: no valid session key")
                continue
            }

            try {
                synchronized(gattLock) {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        server.notifyCharacteristicChanged(device, characteristic, false, payloadToSend)
                    } else {
                        @Suppress("DEPRECATION")
                        characteristic.value = payloadToSend
                        @Suppress("DEPRECATION")
                        server.notifyCharacteristicChanged(device, characteristic, false)
                    }
                }
            } catch (_: SecurityException) {} catch (_: Exception) {}
        }
    }

    @SuppressLint("MissingPermission")
    private fun initiateAuthChallengeIfPossible(device: BluetoothDevice) {
        val address = device.address
        val prefs = getSharedPreferences("tether_secure_prefs", MODE_PRIVATE)

        val hasPinnedKey = securityEngine.getPinnedKeyDecrypted(this) != null
        val pairingTimestamp = prefs.getLong("pairing_window_start_time", 0L)
        val currentTime = System.currentTimeMillis()
        val isPairingWindowOpen = (currentTime - pairingTimestamp) < 180000

        if (pendingNonces.containsKey(address)) {
            Log.d("TetherBle", "Auth challenge already pending for $address. Re-notifying client.")
            val existingNonce = pendingNonces[address] ?: return
            sendAuthChallengeNotification(device, existingNonce)
            return
        }

        if (windowsPublicKeys.containsKey(address) || hasPinnedKey) {
            if (!hasPinnedKey && !isPairingWindowOpen) {
                Log.w("TetherBle", "Authentication rejected for $address: No pinned key and pairing window is closed.")
                synchronized(gattLock) {
                    try { bluetoothGattServer?.cancelConnection(device) } catch (_: SecurityException) {}
                }
                return
            }

            val nonce = ByteArray(16)
            SecureRandom().nextBytes(nonce)
            pendingNonces[address] = nonce
            Log.d("TetherBle", "Generated 16-byte auth challenge nonce for $address")

            sendAuthChallengeNotification(device, nonce)
        } else {
            Log.d("TetherBle", "Auth challenge skipped: No trust anchor available for $address")
        }
    }

    @SuppressLint("MissingPermission")
    private fun sendAuthChallengeNotification(device: BluetoothDevice, nonce: ByteArray) {
        val server = bluetoothGattServer ?: return
        val service = server.getService(SERVICE_UUID) ?: return
        val challengeChar = service.getCharacteristic(AUTH_CHALLENGE_CHAR_UUID) ?: return

        synchronized(gattLock) {
            Log.d("TetherBle", "Notifying client ${device.address} of auth challenge (${nonce.size} bytes)")
            @Suppress("DEPRECATION")
            challengeChar.value = nonce
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                server.notifyCharacteristicChanged(device, challengeChar, false, nonce)
            } else {
                @Suppress("DEPRECATION")
                challengeChar.value = nonce
                @Suppress("DEPRECATION")
                server.notifyCharacteristicChanged(device, challengeChar, false)
            }
        }
    }

    private fun sendSlicedResponse(device: BluetoothDevice, requestId: Int, offset: Int, fullValue: ByteArray?) {
        synchronized(gattLock) {
            if (bluetoothGattServer == null) return
            if (fullValue == null) {
                try {
                    bluetoothGattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, offset, null)
                } catch (_: SecurityException) {}
                return
            }
            if (offset >= fullValue.size) {
                try {
                    bluetoothGattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, byteArrayOf())
                } catch (_: SecurityException) {}
                return
            }

            val currentMtu = deviceMtuMap[device.address] ?: 23
            val maxPayloadSize = currentMtu - 1
            val remainingLength = fullValue.size - offset
            val safeChunkSize = minOf(remainingLength, maxPayloadSize)

            val slicedValue = ByteArray(safeChunkSize)
            System.arraycopy(fullValue, offset, slicedValue, 0, safeChunkSize)

            try {
                bluetoothGattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, slicedValue)
            } catch (_: SecurityException) {}
        }
    }

    private fun notifyStateToInterface() {
        val count = authenticatedDevicesMap.size
        val intent = Intent(ACTION_GATT_STATE_CHANGED).apply {
            putExtra(EXTRA_CONNECTION_COUNT, count)
            setPackage(packageName)
        }
        sendBroadcast(intent)
    }

    @SuppressLint("MissingPermission")
    private fun startAdvertising(connectable: Boolean = true) {
        synchronized(advertisingLock) {
            if (isAdvertising) {
                try { advertiser?.stopAdvertising(advertiseCallback) } catch (_: Exception) {}
                isAdvertising = false
            }

            val serverAdvertiser = bluetoothAdapter?.bluetoothLeAdvertiser ?: return
            advertiser = serverAdvertiser

            val settings = AdvertiseSettings.Builder()
                .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
                .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_HIGH)
                .setConnectable(connectable)
                .setTimeout(0)
                .build()

            val advertiseData = AdvertiseData.Builder()
                .setIncludeDeviceName(true)
                .addServiceUuid(ParcelUuid(SERVICE_UUID))
                .build()

            val scanResponseData = AdvertiseData.Builder()
                .setIncludeTxPowerLevel(true)
                .build()

            try {
                advertiser?.startAdvertising(settings, advertiseData, scanResponseData, advertiseCallback)
                Log.i("TetherBle", "Proximity Advertisement Deployed (Connectable: $connectable)")
            } catch (e: Exception) {
                Log.e("TetherBle", "Advertise failed: ${e.message}")
            }
        }
    }

    private fun startAdvertisingWithRetry(retries: Int, delayMs: Long = 1000) {
        if (retries <= 0) return
        val bluetoothManager = getSystemService(BluetoothManager::class.java)
        val adapter = bluetoothManager?.adapter
        if ((adapter == null) || !adapter.isEnabled) {
            mainHandler.postDelayed({ startAdvertisingWithRetry(retries - 1, delayMs * 2) }, delayMs)
            return
        }

        startAdvertising(connectable = true)
        mainHandler.postDelayed(
            {
                if (!isAdvertising) {
                    startAdvertisingWithRetry(retries - 1, delayMs * 2)
                }
            },
            delayMs,
        )
    }

    private val advertiseCallback = object : AdvertiseCallback() {
        override fun onStartSuccess(settingsInEffect: AdvertiseSettings?) {
            isAdvertising = true
            Log.i("TetherBle", "Advertising started successfully.")
        }
        override fun onStartFailure(errorCode: Int) {
            isAdvertising = false
            Log.e("TetherBle", "Advertising start failed with error: $errorCode")
        }
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        super.onTaskRemoved(rootIntent)
        Log.w("TetherBle", "Task removed - scheduling immediate restart")

        val restartIntent = Intent(applicationContext, BleGattServerService::class.java).apply {
            action = ACTION_TASK_REMOVED_RESTART
            setPackage(packageName)
        }

        val pendingIntent = PendingIntent.getForegroundService(
            this,
            REQ_CODE_TASK_REMOVED,
            restartIntent,
            PendingIntent.FLAG_ONE_SHOT or PendingIntent.FLAG_IMMUTABLE,
        )

        val am = getSystemService(ALARM_SERVICE) as? AlarmManager
        am?.set(
            AlarmManager.ELAPSED_REALTIME_WAKEUP,
            SystemClock.elapsedRealtime() + 1000L,
            pendingIntent,
        )
    }

    private fun scheduleAlarmForHealthCheck() {
        alarmManager = getSystemService(ALARM_SERVICE) as AlarmManager

        val intent = Intent(this, TetherServiceReceiver::class.java).apply {
            action = ALARM_ACTION
            setPackage(packageName)
        }

        val pendingIntent = PendingIntent.getBroadcast(
            this,
            REQ_CODE_HEALTH_CHECK,
            intent,
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
        val intent = Intent(this, TetherServiceReceiver::class.java).apply {
            action = ALARM_ACTION
            setPackage(packageName)
        }

        val pendingIntent = PendingIntent.getBroadcast(
            this,
            REQ_CODE_HEALTH_CHECK,
            intent,
            PendingIntent.FLAG_NO_CREATE or PendingIntent.FLAG_IMMUTABLE,
        )

        if (pendingIntent != null) {
            alarmManager?.cancel(pendingIntent)
        }
        alarmPendingIntent = null
    }

    @SuppressLint("MissingPermission")
    private fun stopAdvertising() {
        synchronized(advertisingLock) {
            try {
                advertiser?.stopAdvertising(advertiseCallback)
            } catch (_: SecurityException) {} catch (_: Exception) {}
            isAdvertising = false
        }
    }

    private fun restartGattServer() {
        synchronized(gattLock) {
            Log.w("TetherBle", "Purging GATT server infrastructure to reclaim leaked OS resource handles.")
            lastStackRefreshTime = SystemClock.elapsedRealtime()

            try {
                bluetoothGattServer?.clearServices()
            } catch (_: SecurityException) {} catch (_: Exception) {}

            authenticatedDevicesMap.clear()
            unauthenticatedConnections.clear()
            deviceChallenges.clear()
            notificationSubscriptions.clear()
            sessionKeysMap.values.forEach { key -> Arrays.fill(key, 0) }
            sessionKeysMap.clear()
            deviceMtuMap.clear()
            pendingExecuteWrites.clear()
            windowsPublicKeys.clear()
            pendingNonces.clear()

            try {
                bluetoothGattServer?.close()
            } catch (_: SecurityException) {} catch (_: Exception) {}
            bluetoothGattServer = null

            try {
                advertiser?.stopAdvertising(advertiseCallback)
            } catch (_: SecurityException) {} catch (_: Exception) {}
            advertiser = null
            isAdvertising = false

            val bluetoothManager = getSystemService(BluetoothManager::class.java)
            bluetoothGattServer = try {
                bluetoothManager?.openGattServer(this, gattServerCallback)
            } catch (_: SecurityException) { null } catch (_: Exception) { null }

            if (bluetoothGattServer == null) {
                Log.e("TetherBle", "GATT server allocation rejected by the Android OS framework layer.")
                return
            }
            setupGattServer()
            startAdvertising()
        }
    }

    private fun hasRequiredRuntimePermissions(): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return true
        val advertise = checkSelfPermission(Manifest.permission.BLUETOOTH_ADVERTISE)
        val connect = checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT)
        val scan = checkSelfPermission(Manifest.permission.BLUETOOTH_SCAN)
        return (advertise == PackageManager.PERMISSION_GRANTED) &&
                (connect == PackageManager.PERMISSION_GRANTED) &&
                (scan == PackageManager.PERMISSION_GRANTED)
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(CHANNEL_ID, getString(R.string.notification_channel_name), NotificationManager.IMPORTANCE_HIGH)
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    private fun createNotification(): Notification {
        val contentIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_SINGLE_TOP
                setPackage(packageName)
            },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.notification_title))
            .setContentText(getString(R.string.notification_text))
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setContentIntent(contentIntent)
            .build()
    }

    @Suppress("DEPRECATION")
    override fun onTrimMemory(level: Int) {
        super.onTrimMemory(level)
        Log.w("TetherBle", "onTrimMemory level=$level")
        if (level >= TRIM_MEMORY_RUNNING_MODERATE) {
            deviceChallenges.clear()
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    @SuppressLint("MissingPermission")
    override fun onDestroy() {
        try { unregisterReceiver(bluetoothStateReceiver) } catch (_: Exception) {}

        cancelAlarm()
        wakeLock?.let { if (it.isHeld) it.release() }
        wakeLock = null

        mainHandler.removeCallbacksAndMessages(null)
        selfHealingHandler.removeCallbacksAndMessages(null)

        synchronized(gattLock) {
            try {
                advertiser?.stopAdvertising(advertiseCallback)
            } catch (_: SecurityException) {} catch (_: Exception) {}
            isAdvertising = false
            authenticatedDevicesMap.clear()
            deviceChallenges.clear()
            notificationSubscriptions.clear()
            sessionKeysMap.values.forEach { key -> Arrays.fill(key, 0) }
            sessionKeysMap.clear()
            deviceMtuMap.clear()
            pendingExecuteWrites.clear()
            windowsPublicKeys.clear()
            pendingNonces.clear()
            try {
                bluetoothGattServer?.close()
            } catch (_: SecurityException) {} catch (_: Exception) {}
            bluetoothGattServer = null
        }
        super.onDestroy()
    }
}
