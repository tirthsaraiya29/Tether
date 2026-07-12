package com.tether.phone

import android.app.Notification
import android.annotation.SuppressLint
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.bluetooth.*
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.BluetoothLeAdvertiser
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.os.ParcelUuid
import android.util.Log
import androidx.core.app.NotificationCompat
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import android.os.PowerManager
import android.app.AlarmManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.IntentFilter
import android.os.SystemClock

class BleGattServerService : Service() {

    private var bluetoothGattServer: BluetoothGattServer? = null
    private var bluetoothAdapter: BluetoothAdapter? = null
    private var advertiser: BluetoothLeAdvertiser? = null
    private var isAdvertising = false

    private lateinit var securityEngine: ProductionSecurityEngine
    private var commandCharacteristic: BluetoothGattCharacteristic? = null

    private val connectedDevicesMap = ConcurrentHashMap<String, BluetoothDevice>()
    private val mainHandler = android.os.Handler(android.os.Looper.getMainLooper())
    private val deviceChallenges = ConcurrentHashMap<String, ByteArray>()
    private val notificationSubscriptions = ConcurrentHashMap<String, Boolean>()
    private val computedSignaturesMap = ConcurrentHashMap<String, ByteArray>()
    private val sessionKeysMap = ConcurrentHashMap<String, ByteArray>()
    private val deviceMtuMap = ConcurrentHashMap<String, Int>()

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

    private val selfHealingHandler = android.os.Handler(android.os.Looper.getMainLooper())
    private val gattLock = Any()
    private var lastStackRefreshTime = SystemClock.elapsedRealtime()

    @Volatile
    private var activeCommandPayload = byteArrayOf()

    private lateinit var powerManager: PowerManager
    private var wakeLock: PowerManager.WakeLock? = null

    private var alarmManager: AlarmManager? = null
    private var alarmPendingIntent: PendingIntent? = null

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
                                } catch (_: Exception) {}
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
                    if (connectedDevicesMap.isEmpty() && !isAdvertising) {
                        startAdvertisingWithRetry(3)
                    }
                }
                PowerManager.ACTION_POWER_SAVE_MODE_CHANGED -> {
                    val isPowerSaveMode = powerManager.isPowerSaveMode
                    Log.i("TetherBle", "Power Save Mode Changed: $isPowerSaveMode")
                    if (!isPowerSaveMode && !isAdvertising && connectedDevicesMap.isEmpty()) {
                        startAdvertisingWithRetry(3)
                    }
                }
            }
        }
    }

    private val alarmReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == ALARM_ACTION) {
                Thread { healthCheckRunnable.run() }.start()
            }
        }
    }

    private val healthCheckRunnable = object : Runnable {
        override fun run() {
            try {
                val bluetoothManager = getSystemService(BluetoothManager::class.java)
                val adapter = bluetoothManager?.adapter
                if (adapter?.isEnabled != true) {
                    Log.w("TetherBle", "Health check: Bluetooth adapter disabled. Waiting for enable.")
                    return
                }

                val now = SystemClock.elapsedRealtime()
                if (now - lastStackRefreshTime > 3600000L) {
                    Log.i("TetherBle", "Forced stack refresh: 1 hour elapsed since last reset.")
                    lastStackRefreshTime = now
                    mainHandler.post { restartGattServer() }
                    return
                }

                if (connectedDevicesMap.isEmpty() && !isAdvertising) {
                    Log.i("TetherBle", "Health check: no connections, restarting advertising.")
                    startAdvertisingWithRetry(3)
                } else if (connectedDevicesMap.isNotEmpty() && !isAdvertising) {
                    Log.w("TetherBle", "Health check: connections exist but advertising stopped. Restarting.")
                    startAdvertisingWithRetry(3)
                } else if (connectedDevicesMap.isNotEmpty()) {
                    Log.d("TetherBle", "Health check: ${connectedDevicesMap.size} connections, advertising active.")
                }
            } catch (e: Exception) {
                Log.e("TetherBle", "Health check error: ${e.message}")
            } finally {
                selfHealingHandler.postDelayed(this, 300000)
            }
        }
    }

    companion object {
        val SERVICE_UUID: UUID = UUID.fromString("0000FFE0-0000-1000-8000-00805F9B34FB")
        private val CHALLENGE_CHAR_UUID = UUID.fromString("0000FFE3-0000-1000-8000-00805F9B34FB")
        private val SIGNATURE_CHAR_UUID = UUID.fromString("0000FFE4-0000-1000-8000-00805F9B34FB")
        private val COMMAND_CHAR_UUID = UUID.fromString("0000FFE5-0000-1000-8000-00805F9B34FB")
        private val PUBLIC_KEY_CHAR_UUID = UUID.fromString("0000FFE6-0000-1000-8000-00805F9B34FB")
        private val CCCD_UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")

        const val ACTION_GATT_STATE_CHANGED = "com.tether.phone.ACTION_GATT_STATE_CHANGED"
        const val ACTION_COMMAND_CONFIRMED = "com.tether.phone.ACTION_COMMAND_CONFIRMED"
        const val EXTRA_CONNECTION_COUNT = "extra_connection_count"

        private const val CHANNEL_ID = "tether_proximity_channel"
        private const val NOTIFICATION_ID = 1

        private const val ALARM_ACTION = "com.tether.phone.ALARM_HEALTH_CHECK"
        private const val HEALTH_CHECK_INTERVAL_MS = 300000L
        private const val WAKE_LOCK_TAG = "tether:BleWakeLock"
    }

    @SuppressLint("MissingPermission")
    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()

        if (!hasRequiredRuntimePermissions()) {
            stopSelf()
            return
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
        } catch (_: Exception) {
            stopSelf()
            return
        }

        powerManager = getSystemService(POWER_SERVICE) as PowerManager
        wakeLock = powerManager.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, WAKE_LOCK_TAG)
        // Keep WakeLock for the lifetime of the service to prevent Doze mode throttling
        wakeLock?.acquire()

        val filter = IntentFilter().apply {
            addAction(BluetoothAdapter.ACTION_STATE_CHANGED)
            addAction(Intent.ACTION_SCREEN_ON)
            addAction(Intent.ACTION_SCREEN_OFF)
            addAction(PowerManager.ACTION_POWER_SAVE_MODE_CHANGED)
        }
        registerReceiver(bluetoothStateReceiver, filter)
        androidx.core.content.ContextCompat.registerReceiver(
            this,
            alarmReceiver,
            IntentFilter(ALARM_ACTION),
            androidx.core.content.ContextCompat.RECEIVER_NOT_EXPORTED
        )

        val bluetoothManager = getSystemService(BluetoothManager::class.java)
        bluetoothAdapter = bluetoothManager?.adapter

        if (bluetoothAdapter?.isEnabled != true) {
            stopSelf()
            return
        }

        synchronized(gattLock) {
            bluetoothGattServer = try {
                bluetoothManager?.openGattServer(this, gattServerCallback)
            } catch (_: SecurityException) {
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
        selfHealingHandler.postDelayed(healthCheckRunnable, 300000)
    }

    @SuppressLint("MissingPermission")
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (!hasRequiredRuntimePermissions()) {
            try {
                startForeground(NOTIFICATION_ID, createNotification())
            } catch (_: Exception) {}
            stopSelf()
            return START_NOT_STICKY
        }

        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                startForeground(NOTIFICATION_ID, createNotification(), ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE)
            } else {
                startForeground(NOTIFICATION_ID, createNotification())
            }
        } catch (e: Exception) {
            Log.e("TetherBle", "Failed to start foreground: ${e.message}")
            try {
                startForeground(NOTIFICATION_ID, createNotification())
            } catch (_: Exception) {}
        }

        // Keep service alive
        if (wakeLock?.isHeld == false) {
            wakeLock?.acquire()
        }

        try {
            val action = intent?.action
            if (action == "ACTION_GET_STATUS") {
                notifyStateToInterface()
                return START_STICKY
            }

            if (action == Intent.ACTION_SCREEN_ON || action == Intent.ACTION_SCREEN_OFF) {
                if (connectedDevicesMap.isEmpty() && !isAdvertising) {
                    startAdvertisingWithRetry(3)
                }
                return START_STICKY
            }

            if (action != null) {
                val value = action.toByteArray(Charsets.UTF_8)
                activeCommandPayload = value
                pushCommandToSubscribedDevices(value)
            }
        } finally {
            // Do not release wakeLock here, we want it for the service lifetime
        }

        return START_STICKY
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

        val challengeChar = BluetoothGattCharacteristic(CHALLENGE_CHAR_UUID, BluetoothGattCharacteristic.PROPERTY_WRITE, BluetoothGattCharacteristic.PERMISSION_WRITE)
        val signatureChar = BluetoothGattCharacteristic(SIGNATURE_CHAR_UUID, BluetoothGattCharacteristic.PROPERTY_READ, BluetoothGattCharacteristic.PERMISSION_READ)
        val publicKeyChar = BluetoothGattCharacteristic(PUBLIC_KEY_CHAR_UUID, BluetoothGattCharacteristic.PROPERTY_READ, BluetoothGattCharacteristic.PERMISSION_READ)

        commandCharacteristic?.let { service.addCharacteristic(it) }
        service.addCharacteristic(challengeChar)
        service.addCharacteristic(signatureChar)
        service.addCharacteristic(publicKeyChar)

        try {
            server.addService(service)
        } catch (_: SecurityException) {}
    }

    private val gattServerCallback = object : BluetoothGattServerCallback() {
        override fun onServiceAdded(status: Int, service: BluetoothGattService?) {
            Log.d("TetherBle", "onServiceAdded: status=$status, service=${service?.uuid}")
        }

        override fun onConnectionStateChange(device: BluetoothDevice?, status: Int, newState: Int) {
            if (device == null) return
            val address = device.address
            Log.d("TetherBle", "onConnectionStateChange: device=$address, status=$status, newState=$newState")

            if (newState == BluetoothProfile.STATE_CONNECTED) {
                connectedDevicesMap[address] = device

                try {
                    bluetoothGattServer?.setPreferredPhy(device, BluetoothDevice.PHY_LE_2M_MASK, BluetoothDevice.PHY_LE_2M_MASK, BluetoothDevice.PHY_OPTION_NO_PREFERRED)
                } catch (_: SecurityException) {
                } catch (_: Exception) {}
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED || status != BluetoothGatt.GATT_SUCCESS) {
                val isStale = status != BluetoothGatt.GATT_SUCCESS && status != 19 && status != 62 && status != 8
                if (isStale) {
                    Log.w("TetherBle", "Connection error status=$status, possible stale state.")
                    if (connectedDevicesMap.size <= 1) {
                         mainHandler.post { restartGattServer() }
                    }
                }

                connectedDevicesMap.remove(address)
                deviceChallenges.remove(address)
                notificationSubscriptions.remove(address)
                computedSignaturesMap.remove(address)
                sessionKeysMap.remove(address)
                deviceMtuMap.remove(address)
                pendingExecuteWrites.remove("$address-$CHALLENGE_CHAR_UUID")
                pendingExecuteWrites.remove("$address-$COMMAND_CHAR_UUID")
                pendingExecuteWrites.remove("$address-$CCCD_UUID")

                // If no more connections, resume advertising
                if (connectedDevicesMap.isEmpty()) {
                    mainHandler.postDelayed({
                        startAdvertisingWithRetry(3)
                    }, 500)
                }
            }
            notifyStateToInterface()
        }

        override fun onMtuChanged(device: BluetoothDevice?, mtu: Int) {
            device?.let {
                deviceMtuMap[it.address] = mtu
                Log.i("TetherBle", "MTU state established natively for context address ${it.address}: $mtu bytes")
            }
        }

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
                if (responseNeeded && device != null) {
                    try {
                        synchronized(gattLock) {
                            bluetoothGattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, offset, null)
                        }
                    } catch (_: SecurityException) {}
                }
                return
            }

            val address = device.address
            val uuid = characteristic.uuid
            val storageKey = "$address-$uuid"

            val currentSession = pendingExecuteWrites[storageKey]
            val accumulatedPayload = if (offset == 0) value else (currentSession?.payload ?: byteArrayOf()) + value
            pendingExecuteWrites[storageKey] = WriteSession(uuid, accumulatedPayload)

            if (preparedWrite) {
                if (responseNeeded) {
                    try {
                        synchronized(gattLock) {
                            bluetoothGattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, value)
                        }
                    } catch (_: SecurityException) {}
                }
                return
            }

            var shouldProcessImmediately = true
            if (uuid == CHALLENGE_CHAR_UUID) {
                val hasSessionKey = sessionKeysMap.containsKey(address)
                if (!hasSessionKey && accumulatedPayload.size < 256) {
                    shouldProcessImmediately = false
                } else if (hasSessionKey && accumulatedPayload.size < 16) {
                    shouldProcessImmediately = false
                }
            }

            if (shouldProcessImmediately) {
                val finalPayload = pendingExecuteWrites.remove(storageKey)?.payload ?: accumulatedPayload
                processCompletePayload(address, uuid, finalPayload)
            }

            if (responseNeeded) {
                try {
                    synchronized(gattLock) {
                        bluetoothGattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, null)
                    }
                } catch (_: SecurityException) {}
            }
        }

        override fun onCharacteristicReadRequest(device: BluetoothDevice?, requestId: Int, offset: Int, characteristic: BluetoothGattCharacteristic?) {
            if (device == null) return
            try {
                when (characteristic?.uuid) {
                    SIGNATURE_CHAR_UUID -> {
                        computedSignaturesMap[device.address]?.let {
                            sendSlicedResponse(device, requestId, offset, it)
                        } ?: synchronized(gattLock) {
                            bluetoothGattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, offset, null)
                        }
                    }
                    COMMAND_CHAR_UUID -> {
                        sendSlicedResponse(device, requestId, offset, activeCommandPayload)
                    }
                    PUBLIC_KEY_CHAR_UUID -> {
                        val publicKeyBytes = securityEngine.getPublicKeyBytes()
                        sendSlicedResponse(device, requestId, offset, publicKeyBytes)
                    }
                    else -> {
                        synchronized(gattLock) {
                            bluetoothGattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_REQUEST_NOT_SUPPORTED, offset, null)
                        }
                    }
                }
            } catch (_: SecurityException) {}
        }

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
                    try {
                        synchronized(gattLock) {
                            bluetoothGattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, offset, null)
                        }
                    } catch (_: SecurityException) {
                    } catch (_: Exception) {}
                }
                return
            }

            val address = device.address
            val uuid = descriptor.uuid
            val storageKey = "$address-$uuid"
            Log.d("TetherBle", "onDescriptorWriteRequest: device=$address, uuid=$uuid, prepared=$preparedWrite, value=${value.contentToString()}")

            if (preparedWrite) {
                val currentPayload = pendingExecuteWrites[storageKey]?.payload ?: byteArrayOf()
                val assembledPayload = if (offset == 0) value else currentPayload + value
                pendingExecuteWrites[storageKey] = WriteSession(uuid, assembledPayload)

                if (responseNeeded) {
                    try {
                        synchronized(gattLock) {
                            bluetoothGattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, value)
                        }
                    } catch (_: SecurityException) {}
                }
                return
            }

            if (uuid == CCCD_UUID) {
                var accepted = false
                if (value.isNotEmpty()) {
                    val controlByte = value[0].toInt()
                    if ((controlByte and 0x03) != 0) {
                        notificationSubscriptions[address] = true
                        accepted = true
                    } else if (controlByte == 0) {
                        notificationSubscriptions.remove(address)
                        accepted = true
                    }
                }

                if (responseNeeded) {
                    try {
                        synchronized(gattLock) {
                            bluetoothGattServer?.sendResponse(
                                device,
                                requestId,
                                if (accepted) BluetoothGatt.GATT_SUCCESS else BluetoothGatt.GATT_FAILURE,
                                0,
                                null
                            )
                        }
                    } catch (_: SecurityException) {}
                }
            } else {
                if (responseNeeded) {
                    try {
                        synchronized(gattLock) {
                            bluetoothGattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_REQUEST_NOT_SUPPORTED, 0, null)
                        }
                    } catch (_: SecurityException) {}
                }
            }
        }

        override fun onDescriptorReadRequest(device: BluetoothDevice?, requestId: Int, offset: Int, descriptor: BluetoothGattDescriptor?) {
            if ((device == null) || (descriptor == null)) return
            try {
                val value = if (descriptor.uuid == CCCD_UUID && notificationSubscriptions[device.address] == true) {
                    BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
                } else if (descriptor.uuid == CCCD_UUID) {
                    BluetoothGattDescriptor.DISABLE_NOTIFICATION_VALUE
                } else {
                    byteArrayOf(0, 0)
                }
                sendSlicedResponse(device, requestId, offset, value)
            } catch (_: SecurityException) {}
        }

        override fun onExecuteWrite(device: BluetoothDevice?, requestId: Int, execute: Boolean) {
            super.onExecuteWrite(device, requestId, execute)
            if (device == null) return

            val address = device.address
            val targetKeys = pendingExecuteWrites.keys().asSequence().filter { it.startsWith("$address-") }

            for (storageKey in targetKeys) {
                val session = pendingExecuteWrites.remove(storageKey)
                if (execute && (session != null)) {
                    processCompletePayload(address, session.uuid, session.payload)
                }
            }

            try {
                synchronized(gattLock) {
                    bluetoothGattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, null)
                }
            } catch (_: SecurityException) {}
        }
    }

    private fun processCompletePayload(address: String, uuid: UUID, payload: ByteArray) {
        try {
            when (uuid) {
                CHALLENGE_CHAR_UUID -> {
                    if (payload.size >= 256) {
                        try {
                            val sessionKey = securityEngine.decryptSessionKey(payload)
                            sessionKeysMap[address] = sessionKey
                        } catch (_: Exception) {}
                    } else {
                        deviceChallenges[address] = payload
                        val sessionKey = sessionKeysMap[address]

                        if (sessionKey != null) {
                            computedSignaturesMap[address] = securityEngine.computeHmac(payload, sessionKey)
                        } else {
                            Log.e("TetherBle", "Handshake Refused: Attempt to read signature prior to establishing safe symmetric session keys.")
                            computedSignaturesMap[address] = byteArrayOf()
                        }
                    }
                }

                COMMAND_CHAR_UUID -> {
                    if (payload.size in 3..15) {
                        val opcode = payload[0].toInt()
                        val dataA = payload[1].toInt()
                        val dataB = payload[2].toInt()

                        when (opcode) {
                            0x01 -> {
                                val stateUpdateBroadcast = Intent("com.tether.phone.ACTION_SYNC_HARDWARE_METRICS").apply {
                                    putExtra("VOLUME_LEVEL", dataA)
                                    putExtra("BRIGHTNESS_LEVEL", dataB)
                                    setPackage(packageName)
                                }
                                sendBroadcast(stateUpdateBroadcast)
                            }
                        }
                    } else if (payload.size > 16) {
                        val sessionKey = sessionKeysMap[address]
                        if (sessionKey != null) {
                            try {
                                val iv = payload.copyOfRange(0, 16)
                                val ciphertext = payload.copyOfRange(16, payload.size)

                                val cipher = Cipher.getInstance("AES/CBC/PKCS7Padding")
                                val keySpec = SecretKeySpec(sessionKey, "AES")
                                val ivSpec = IvParameterSpec(iv)

                                cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec)
                                val decrypted = cipher.doFinal(ciphertext)
                                val decryptedString = String(decrypted, Charsets.UTF_8)

                                if (decryptedString.startsWith("confirm_")) {
                                    val confirmedCommand = decryptedString.substringAfter("confirm_")
                                    val intent = Intent(ACTION_COMMAND_CONFIRMED).apply {
                                        putExtra("confirmed_command", confirmedCommand)
                                        setPackage(packageName)
                                    }
                                    sendBroadcast(intent)
                                }
                            } catch (e: Exception) {
                                Log.e("TetherBle", "Handshake decryption failure: ${e.message}")
                            }
                        }
                    }
                }

                CCCD_UUID -> {
                    if (payload.isNotEmpty()) {
                        val controlByte = payload[0].toInt()
                        if ((controlByte and 0x03) != 0) {
                            notificationSubscriptions[address] = true
                        } else if (controlByte == 0) {
                            notificationSubscriptions.remove(address)
                        }
                    }
                }
            }
        } catch (_: Exception) {}
    }

    @SuppressLint("MissingPermission")
    private fun pushCommandToSubscribedDevices(value: ByteArray) {
        val characteristic = commandCharacteristic ?: return
        val server = bluetoothGattServer ?: return

        for (device in connectedDevicesMap.values) {
            if (notificationSubscriptions[device.address] != true) continue
            try {
                synchronized(gattLock) {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        server.notifyCharacteristicChanged(device, characteristic, false, value)
                    } else {
                        // Suppress deprecation for older APIs as we provide a T+ alternative above
                        @Suppress("DEPRECATION")
                        characteristic.value = value
                        @Suppress("DEPRECATION")
                        server.notifyCharacteristicChanged(device, characteristic, false)
                    }
                }
            } catch (_: Exception) {}
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
        val count = connectedDevicesMap.size
        val intent = Intent(ACTION_GATT_STATE_CHANGED).apply {
            putExtra(EXTRA_CONNECTION_COUNT, count)
            setPackage(packageName)
        }
        sendBroadcast(intent)
    }

    @SuppressLint("MissingPermission")
    private fun startAdvertising() {
        if (isAdvertising) return
        val serverAdvertiser = bluetoothAdapter?.bluetoothLeAdvertiser ?: return
        advertiser = serverAdvertiser

        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_HIGH)
            .setConnectable(true)
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
            advertiser?.stopAdvertising(advertiseCallback)
        } catch (_: Exception) {}

        try {
            advertiser?.startAdvertising(settings, advertiseData, scanResponseData, advertiseCallback)
            Log.i("TetherBle", "🚀 Advanced Dual-Packet Advertisement Array deployed successfully.")
        } catch (e: Exception) {
            Log.e("TetherBle", "Failed to initialize advertiser array: ${e.message}")
        }
    }

    private fun startAdvertisingWithRetry(retries: Int, delayMs: Long = 1000) {
        if (retries <= 0) {
            Log.e("TetherBle", "Advertisement start failed after all retries.")
            return
        }
        val bluetoothManager = getSystemService(BluetoothManager::class.java)
        val adapter = bluetoothManager?.adapter
        if (adapter == null || !adapter.isEnabled) {
            Log.w("TetherBle", "Bluetooth not enabled, cannot start advertising.")
            mainHandler.postDelayed({ startAdvertisingWithRetry(retries - 1, delayMs * 2) }, delayMs)
            return
        }

        startAdvertising()
        mainHandler.postDelayed(
            {
                if (!isAdvertising) {
                    Log.w("TetherBle", "Advertising not active, retrying (${retries - 1} retries left)")
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

    private fun acquireWakeLock() {
        wakeLock?.acquire(30 * 1000L)
    }

    private fun releaseWakeLock() {
        wakeLock?.let { if (it.isHeld) it.release() }
    }

    private fun scheduleAlarmForHealthCheck() {
        alarmManager = getSystemService(ALARM_SERVICE) as AlarmManager
        val intent = Intent(ALARM_ACTION)
        val pendingIntent = PendingIntent.getBroadcast(
            this, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        alarmPendingIntent = pendingIntent
        alarmManager?.setInexactRepeating(
            AlarmManager.ELAPSED_REALTIME_WAKEUP,
            SystemClock.elapsedRealtime() + HEALTH_CHECK_INTERVAL_MS,
            HEALTH_CHECK_INTERVAL_MS,
            pendingIntent
        )
    }

    private fun cancelAlarm() {
        alarmPendingIntent?.let {
            alarmManager?.cancel(it)
        }
        alarmPendingIntent = null
    }

    private fun stopAdvertising() {
        try {
            advertiser?.stopAdvertising(advertiseCallback)
        } catch (_: SecurityException) {
        } catch (_: Exception) {}
        isAdvertising = false
    }

    @Synchronized
    private fun restartGattServer() {
        Log.w("TetherBle", "Restarting GATT server due to stale state or adapter cycle")
        lastStackRefreshTime = SystemClock.elapsedRealtime()
        
        // Clear all states
        connectedDevicesMap.clear()
        deviceChallenges.clear()
        notificationSubscriptions.clear()
        computedSignaturesMap.clear()
        sessionKeysMap.clear()
        deviceMtuMap.clear()
        pendingExecuteWrites.clear()

        try {
            bluetoothGattServer?.close()
        } catch (_: SecurityException) {
        } catch (_: Exception) {}
        bluetoothGattServer = null

        val bluetoothManager = getSystemService(BluetoothManager::class.java)
        bluetoothGattServer = try {
            bluetoothManager?.openGattServer(this, gattServerCallback)
        } catch (_: SecurityException) {
            null
        } catch (_: Exception) {
            null
        }
        if (bluetoothGattServer == null) {
            Log.e("TetherBle", "Failed to reopen GATT server")
            return
        }
        setupGattServer()
        startAdvertising()
    }

    private fun hasRequiredRuntimePermissions(): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return true
        val advertise = checkSelfPermission(android.Manifest.permission.BLUETOOTH_ADVERTISE)
        val connect = checkSelfPermission(android.Manifest.permission.BLUETOOTH_CONNECT)
        val scan = checkSelfPermission(android.Manifest.permission.BLUETOOTH_SCAN)
        return advertise == android.content.pm.PackageManager.PERMISSION_GRANTED &&
                connect == android.content.pm.PackageManager.PERMISSION_GRANTED &&
                scan == android.content.pm.PackageManager.PERMISSION_GRANTED
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(CHANNEL_ID, getString(R.string.notification_channel_name), NotificationManager.IMPORTANCE_HIGH)
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    private fun createNotification(): Notification = NotificationCompat.Builder(this, CHANNEL_ID)
        .setContentTitle(getString(R.string.notification_title))
        .setContentText(getString(R.string.notification_text))
        .setSmallIcon(android.R.drawable.ic_lock_lock)
        .setPriority(NotificationCompat.PRIORITY_HIGH)
        .build()

    override fun onTrimMemory(level: Int) {
        super.onTrimMemory(level)
        Log.w("TetherBle", "onTrimMemory level=$level")
        if (level >= TRIM_MEMORY_RUNNING_LOW) {
            // Clear computed signatures as they can be re-generated
            computedSignaturesMap.clear()
            deviceChallenges.clear()
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    @SuppressLint("MissingPermission")
    override fun onDestroy() {
        try { unregisterReceiver(bluetoothStateReceiver) } catch (_: Exception) {}
        try { unregisterReceiver(alarmReceiver) } catch (_: Exception) {}

        cancelAlarm()
        wakeLock?.let { if (it.isHeld) it.release() }
        wakeLock = null

        mainHandler.removeCallbacksAndMessages(null)
        selfHealingHandler.removeCallbacksAndMessages(null)

        synchronized(gattLock) {
            try {
                advertiser?.stopAdvertising(advertiseCallback)
            } catch (_: Exception) {}
            isAdvertising = false
            connectedDevicesMap.clear()
            deviceChallenges.clear()
            notificationSubscriptions.clear()
            computedSignaturesMap.clear()
            sessionKeysMap.clear()
            deviceMtuMap.clear()
            pendingExecuteWrites.clear()
            try {
                bluetoothGattServer?.close()
            } catch (_: SecurityException) {
            } catch (_: Exception) {}
            bluetoothGattServer = null
        }
        super.onDestroy()
    }
}