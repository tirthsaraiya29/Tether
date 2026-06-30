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
import androidx.core.content.ContextCompat
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

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

    companion object {
        val SERVICE_UUID: UUID = UUID.fromString("0000FFE0-0000-1000-8000-00805F9B34FB")
        private val CHALLENGE_CHAR_UUID = UUID.fromString("0000FFE3-0000-1000-8000-00805F9B34FB")
        private val SIGNATURE_CHAR_UUID = UUID.fromString("0000FFE4-0000-1000-8000-00805F9B34FB")
        private val COMMAND_CHAR_UUID = UUID.fromString("0000FFE5-0000-1000-8000-00805F9B34FB")
        private val PUBLIC_KEY_CHAR_UUID = UUID.fromString("0000FFE6-0000-1000-8000-00805F9B34FB")
        private val CCCD_UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")

        const val ACTION_GATT_STATE_CHANGED = "com.tether.phone.ACTION_GATT_STATE_CHANGED"
        const val EXTRA_CONNECTION_COUNT = "extra_connection_count"

        private const val CHANNEL_ID = "tether_proximity_channel"
        private const val NOTIFICATION_ID = 1
        private const val TAG = "TetherGattService"
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(NOTIFICATION_ID, createNotification(), ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE)
        } else {
            startForeground(NOTIFICATION_ID, createNotification())
        }

        try {
            securityEngine = ProductionSecurityEngine()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to initialize security engine", e)
            stopSelf()
            return
        }

        val bluetoothManager = getSystemService(BluetoothManager::class.java)
        bluetoothAdapter = bluetoothManager?.adapter

        if (bluetoothAdapter == null || bluetoothAdapter?.isEnabled == false) {
            stopSelf()
            return
        }

        setupGattServer()
        startAdvertising()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action
        if (action != null && commandCharacteristic != null) {
            val value = action.toByteArray(Charsets.UTF_8)
            @Suppress("DEPRECATION")
            commandCharacteristic?.value = value

            for (device in connectedDevicesMap.values) {
                try {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        bluetoothGattServer?.notifyCharacteristicChanged(device, commandCharacteristic!!, false, value)
                    } else {
                        @Suppress("DEPRECATION")
                        bluetoothGattServer?.notifyCharacteristicChanged(device, commandCharacteristic, false)
                    }
                } catch (_: SecurityException) {}
            }
        }
        return START_STICKY
    }

    @SuppressLint("MissingPermission")
    private fun setupGattServer() {
        val bluetoothManager = getSystemService(BluetoothManager::class.java)
        try {
            bluetoothGattServer = bluetoothManager?.openGattServer(this, gattServerCallback)
            val service = BluetoothGattService(SERVICE_UUID, BluetoothGattService.SERVICE_TYPE_PRIMARY)

            val challengeChar = BluetoothGattCharacteristic(
                CHALLENGE_CHAR_UUID,
                BluetoothGattCharacteristic.PROPERTY_WRITE,
                BluetoothGattCharacteristic.PERMISSION_WRITE
            )
            val signatureChar = BluetoothGattCharacteristic(
                SIGNATURE_CHAR_UUID,
                BluetoothGattCharacteristic.PROPERTY_READ,
                BluetoothGattCharacteristic.PERMISSION_READ
            )
            val commandChar = BluetoothGattCharacteristic(
                COMMAND_CHAR_UUID,
                BluetoothGattCharacteristic.PROPERTY_READ or BluetoothGattCharacteristic.PROPERTY_NOTIFY,
                BluetoothGattCharacteristic.PERMISSION_READ
            )
            val publicKeyChar = BluetoothGattCharacteristic(
                PUBLIC_KEY_CHAR_UUID,
                BluetoothGattCharacteristic.PROPERTY_READ,
                BluetoothGattCharacteristic.PERMISSION_READ
            )

            commandChar.addDescriptor(BluetoothGattDescriptor(
                CCCD_UUID,
                BluetoothGattDescriptor.PERMISSION_READ or BluetoothGattDescriptor.PERMISSION_WRITE
            ))

            service.addCharacteristic(challengeChar)
            service.addCharacteristic(signatureChar)
            service.addCharacteristic(commandChar)
            service.addCharacteristic(publicKeyChar)

            commandCharacteristic = commandChar
            bluetoothGattServer?.addService(service)
        } catch (e: Exception) {
            Log.e(TAG, "GATT Setup Critical Exception", e)
            stopSelf()
        }
    }

    private val gattServerCallback = object : BluetoothGattServerCallback() {
        override fun onConnectionStateChange(device: BluetoothDevice?, status: Int, newState: Int) {
            super.onConnectionStateChange(device, status, newState)
            if (device == null) return

            if (newState == BluetoothProfile.STATE_CONNECTED) {
                connectedDevicesMap.remove(device.address)
                connectedDevicesMap[device.address] = device

                try {
                    val bluetoothManager = getSystemService(BluetoothManager::class.java)
                    bluetoothManager?.adapter?.getRemoteDevice(device.address)
                } catch (_: Exception) {}

            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                connectedDevicesMap.remove(device.address)
                deviceChallenges.remove(device.address)
            }
            notifyStateToInterface()
        }

        override fun onCharacteristicWriteRequest(device: BluetoothDevice?, requestId: Int, characteristic: BluetoothGattCharacteristic?, preparedWrite: Boolean, responseNeeded: Boolean, offset: Int, value: ByteArray?) {
            super.onCharacteristicWriteRequest(device, requestId, characteristic, preparedWrite, responseNeeded, offset, value)
            if (characteristic?.uuid == CHALLENGE_CHAR_UUID && value != null && device != null) {
                deviceChallenges[device.address] = value
                if (responseNeeded) {
                    try { bluetoothGattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, null) } catch (_: SecurityException) {}
                }
            }
        }

        override fun onCharacteristicReadRequest(device: BluetoothDevice?, requestId: Int, offset: Int, characteristic: BluetoothGattCharacteristic?) {
            super.onCharacteristicReadRequest(device, requestId, offset, characteristic)
            if (device == null) return

            try {
                when (characteristic?.uuid) {
                    SIGNATURE_CHAR_UUID -> {
                        val challenge = deviceChallenges.remove(device.address)
                        if (challenge != null) {
                            val signatureBytes = securityEngine.signChallenge(challenge)
                            sendSlicedResponse(device, requestId, offset, signatureBytes)
                        } else {
                            bluetoothGattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, offset, null)
                        }
                    }
                    COMMAND_CHAR_UUID -> {
                        @Suppress("DEPRECATION")
                        val currentCommand = commandCharacteristic?.value ?: byteArrayOf()
                        sendSlicedResponse(device, requestId, offset, currentCommand)
                    }
                    PUBLIC_KEY_CHAR_UUID -> {
                        val publicKeyBytes = securityEngine.getPublicKeyBytes()
                        sendSlicedResponse(device, requestId, offset, publicKeyBytes)
                    }
                }
            } catch (_: SecurityException) {}
        }

        override fun onDescriptorWriteRequest(device: BluetoothDevice?, requestId: Int, descriptor: BluetoothGattDescriptor?, preparedWrite: Boolean, responseNeeded: Boolean, offset: Int, value: ByteArray?) {
            super.onDescriptorWriteRequest(device, requestId, descriptor, preparedWrite, responseNeeded, offset, value)
            if (responseNeeded && device != null) {
                try { bluetoothGattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, null) } catch (_: SecurityException) {}
            }
        }

        override fun onDescriptorReadRequest(device: BluetoothDevice?, requestId: Int, offset: Int, descriptor: BluetoothGattDescriptor?) {
            super.onDescriptorReadRequest(device, requestId, offset, descriptor)
            if (device != null) {
                try {
                    val value = if (descriptor?.uuid == CCCD_UUID) BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE else byteArrayOf(0, 0)
                    sendSlicedResponse(device, requestId, offset, value)
                } catch (_: SecurityException) {}
            }
        }
    }

    private fun sendSlicedResponse(device: BluetoothDevice, requestId: Int, offset: Int, fullValue: ByteArray) {
        try {
            if (offset >= fullValue.size) {
                bluetoothGattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, byteArrayOf())
                return
            }
            val slicedValue = fullValue.copyOfRange(offset, fullValue.size)
            bluetoothGattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, slicedValue)
        } catch (_: SecurityException) {}
    }

    private fun notifyStateToInterface() {
        val intent = Intent(ACTION_GATT_STATE_CHANGED).apply {
            putExtra(EXTRA_CONNECTION_COUNT, connectedDevicesMap.size)
        }
        sendBroadcast(intent)
    }

    private fun startAdvertising() {
        advertiser = bluetoothAdapter?.bluetoothLeAdvertiser ?: return
        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_HIGH)
            .setConnectable(true)
            .build()

        val advertiseData = AdvertiseData.Builder()
            .setIncludeDeviceName(false)
            .addServiceUuid(ParcelUuid(SERVICE_UUID))
            .build()

        try {
            advertiser?.startAdvertising(settings, advertiseData, null, advertiseCallback)
        } catch (_: Exception) {}
    }

    private val advertiseCallback = object : AdvertiseCallback() {
        override fun onStartSuccess(settingsInEffect: AdvertiseSettings?) { isAdvertising = true }
        override fun onStartFailure(errorCode: Int) { isAdvertising = false }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(CHANNEL_ID, "Tether Proximity Services", NotificationManager.IMPORTANCE_LOW)
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
    }

    private fun createNotification(): Notification = NotificationCompat.Builder(this, CHANNEL_ID)
        .setContentTitle("🔒 Tether Shield Active")
        .setContentText("Maintaining local cryptographically continuous background radio mesh links...")
        .setSmallIcon(android.R.drawable.ic_lock_lock)
        .build()

    override fun onBind(intent: Intent?): IBinder? = null

    @SuppressLint("MissingPermission")
    override fun onDestroy() {
        mainHandler.removeCallbacksAndMessages(null)
        try { advertiser?.stopAdvertising(advertiseCallback) } catch (_: Exception) {}
        bluetoothGattServer?.close()
        super.onDestroy()
    }
}