package com.tether.phone

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.BluetoothLeAdvertiser
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.ParcelUuid
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import java.util.UUID

class BleGattServerService : Service() {

    private var bluetoothGattServer: BluetoothGattServer? = null
    private var bluetoothAdapter: BluetoothAdapter? = null
    private var advertiser: BluetoothLeAdvertiser? = null
    private var isAdvertising = false
    private var connectedDevice: BluetoothDevice? = null
    private val mainHandler = Handler(Looper.getMainLooper())

    companion object {
        private val SERVICE_UUID = UUID.fromString("0000FFE0-0000-1000-8000-00805F9B34FB")
        private val RSSI_CHAR_UUID = UUID.fromString("0000FFE1-0000-1000-8000-00805F9B34FB")
        private val PANIC_CHAR_UUID = UUID.fromString("0000FFE2-0000-1000-8000-00805F9B34FB")
        private const val CHANNEL_ID = "tether_proximity_channel"
        private const val NOTIFICATION_ID = 1
    }

    private lateinit var panicCharacteristic: BluetoothGattCharacteristic

    override fun onCreate() {
        super.onCreate()
        val bluetoothManager = getSystemService(BluetoothManager::class.java)
        bluetoothAdapter = bluetoothManager?.adapter

        if (bluetoothAdapter == null || !bluetoothAdapter!!.isEnabled) {
            Log.e("TetherBLE", "Bluetooth disabled – shutting down service gracefully")
            stopSelf()
            return
        }

        createNotificationChannel()
        startForeground(NOTIFICATION_ID, createNotification())
        setupGattServer()
        startAdvertising()
    }

    private fun setupGattServer() {
        val bluetoothManager = getSystemService(BluetoothManager::class.java)

        try {
            bluetoothGattServer = bluetoothManager?.openGattServer(this, gattServerCallback)

            val rssiChar = BluetoothGattCharacteristic(
                RSSI_CHAR_UUID,
                BluetoothGattCharacteristic.PROPERTY_READ,
                BluetoothGattCharacteristic.PERMISSION_READ
            )
            panicCharacteristic = BluetoothGattCharacteristic(
                PANIC_CHAR_UUID,
                BluetoothGattCharacteristic.PROPERTY_NOTIFY,
                BluetoothGattCharacteristic.PERMISSION_READ
            )
            val service = BluetoothGattService(SERVICE_UUID, BluetoothGattService.SERVICE_TYPE_PRIMARY)
            service.addCharacteristic(rssiChar)
            service.addCharacteristic(panicCharacteristic)

            bluetoothGattServer?.addService(service)
        } catch (e: SecurityException) {
            Log.e("TetherBLE", "SecurityException setting up GATT server: ${e.message}")
        }
    }

    private fun startAdvertising() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
            ContextCompat.checkSelfPermission(this, android.Manifest.permission.BLUETOOTH_ADVERTISE) != PackageManager.PERMISSION_GRANTED) {
            return
        }

        advertiser = bluetoothAdapter?.bluetoothLeAdvertiser ?: return

        // Always ensure previous broadcast is stopped to prevent ADVERTISE_FAILED_ALREADY_STARTED (Error 3)
        stopAdvertising()

        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_HIGH)
            .setConnectable(true)
            .setTimeout(0) // 0 = Infinite advertising
            .build()

        val advertiseData = AdvertiseData.Builder()
            .setIncludeDeviceName(true)
            .build()

        val scanResponse = AdvertiseData.Builder()
            .addServiceUuid(ParcelUuid(SERVICE_UUID))
            .build()

        try {
            advertiser?.startAdvertising(settings, advertiseData, scanResponse, advertiseCallback)
        } catch (e: SecurityException) {
            Log.e("TetherBLE", "Advertising security exception: ${e.message}")
        } catch (e: Exception) {
            Log.e("TetherBLE", "Advertising general exception: ${e.message}")
        }
    }

    private fun stopAdvertising() {
        if (isAdvertising) {
            try {
                advertiser?.stopAdvertising(advertiseCallback)
            } catch (e: SecurityException) {
                Log.e("TetherBLE", "Stop advertising security exception: ${e.message}")
            }
            isAdvertising = false
        }
    }

    private val gattServerCallback = object : BluetoothGattServerCallback() {
        override fun onConnectionStateChange(device: BluetoothDevice, status: Int, newState: Int) {
            when (newState) {
                BluetoothProfile.STATE_CONNECTED -> {
                    connectedDevice = device
                    Log.d("TetherBLE", "✅ PC Connected: ${device.address}")
                }
                BluetoothProfile.STATE_DISCONNECTED -> {
                    connectedDevice = null
                    Log.d("TetherBLE", "❌ PC Disconnected. Restarting beacon in 1s...")

                    // Delay restarts to let the Bluetooth hardware fully clear the connection handle
                    mainHandler.postDelayed({
                        startAdvertising()
                    }, 1000)
                }
            }
        }

        override fun onCharacteristicReadRequest(
            device: BluetoothDevice,
            requestId: Int,
            offset: Int,
            characteristic: BluetoothGattCharacteristic
        ) {
            // Fulfill dummy read requests to prevent Windows COMExceptions/Timeouts
            if (characteristic.uuid == RSSI_CHAR_UUID) {
                try {
                    bluetoothGattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, byteArrayOf(0x01))
                } catch (e: SecurityException) {
                    Log.e("TetherBLE", "Failed to send read response: ${e.message}")
                }
            }
        }
    }

    private val advertiseCallback = object : AdvertiseCallback() {
        override fun onStartSuccess(settingsInEffect: AdvertiseSettings?) {
            Log.d("TetherBLE", "📡 Advertising beacon active successfully.")
            isAdvertising = true
        }

        override fun onStartFailure(errorCode: Int) {
            Log.e("TetherBLE", "⚠️ Advertising failed with error code: $errorCode")
            isAdvertising = false

            if (errorCode == ADVERTISE_FAILED_ALREADY_STARTED) {
                Log.d("TetherBLE", "Already advertising. Resetting...")
                stopAdvertising()
            } else if (errorCode == ADVERTISE_FAILED_DATA_TOO_LARGE) {
                Log.d("TetherBLE", "Data too large. Retrying without UUID...")
                retryAdvertisingWithoutUuid()
                return
            }

            // Fallback cooldown retry for hardware busy errors (Error 2, 4, 5)
            mainHandler.postDelayed({
                Log.d("TetherBLE", "Retrying advertising after cooldown...")
                startAdvertising()
            }, 3000)
        }
    }

    private fun retryAdvertisingWithoutUuid() {
        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_HIGH)
            .setConnectable(true)
            .build()

        val data = AdvertiseData.Builder().setIncludeDeviceName(true).build()

        try {
            advertiser?.startAdvertising(settings, data, advertiseCallback)
        } catch (e: SecurityException) {
            Log.e("TetherBLE", "Fallback advertising failed: ${e.message}")
        }
    }

    private fun sendPanicNotification() {
        connectedDevice?.let { device ->
            try {
                panicCharacteristic.value = byteArrayOf(0x01)
                bluetoothGattServer?.notifyCharacteristicChanged(device, panicCharacteristic, false)
                Log.d("TetherBLE", "Panic signal transmitted.")
            } catch (e: SecurityException) {
                Log.e("TetherBLE", "Failed to transmit panic: ${e.message}")
            }
        } ?: Log.w("TetherBLE", "Cannot send panic: No PC connected.")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == "PANIC") {
            sendPanicNotification()
        }
        return START_STICKY
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(CHANNEL_ID, "Tether Proximity", NotificationManager.IMPORTANCE_LOW)
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
    }

    private fun createNotification(): Notification = NotificationCompat.Builder(this, CHANNEL_ID)
        .setContentTitle("🔒 Tether Active")
        .setContentText("Proximity security active")
        .setSmallIcon(android.R.drawable.ic_lock_lock)
        .build()

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        stopAdvertising()

        try {
            // Force cleanup to ensure GATT table clears up for the next session
            bluetoothGattServer?.clearServices()
            bluetoothGattServer?.close()
        } catch (e: SecurityException) {
            Log.e("TetherBLE", "Cleanup security exception: ${e.message}")
        }

        super.onDestroy()
    }
}