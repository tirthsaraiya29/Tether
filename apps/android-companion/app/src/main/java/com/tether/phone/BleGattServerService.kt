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

        private const val MANUFACTURER_ID = 0xFFFF
        private const val DEVICE_ID = 0x01
    }

    private lateinit var panicCharacteristic: BluetoothGattCharacteristic

    override fun onCreate() {
        super.onCreate()
        val bluetoothManager = getSystemService(BluetoothManager::class.java)
        bluetoothAdapter = bluetoothManager?.adapter

        if (bluetoothAdapter == null || !bluetoothAdapter!!.isEnabled) {
            Log.e("TetherBLE", "Bluetooth disabled – shutting down")
            stopSelf()
            return
        }

        createNotificationChannel()
        startForeground(NOTIFICATION_ID, createNotification())
        setupGattServer()
        startAdvertising() // Start with default idle state
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            "PANIC" -> updateAdvertisement(trustState = 0x02)
            "LOCK_NOW" -> updateAdvertisement(trustState = 0x01)
            "UNLOCK" -> updateAdvertisement(trustState = 0x03)
        }
        return START_STICKY
    }

    private fun setupGattServer() {
        val bluetoothManager = getSystemService(BluetoothManager::class.java)
        try {
            bluetoothGattServer = bluetoothManager?.openGattServer(this, gattServerCallback)
            val rssiChar = BluetoothGattCharacteristic(RSSI_CHAR_UUID, BluetoothGattCharacteristic.PROPERTY_READ, BluetoothGattCharacteristic.PERMISSION_READ)
            panicCharacteristic = BluetoothGattCharacteristic(PANIC_CHAR_UUID, BluetoothGattCharacteristic.PROPERTY_NOTIFY, BluetoothGattCharacteristic.PERMISSION_READ)
            val service = BluetoothGattService(SERVICE_UUID, BluetoothGattService.SERVICE_TYPE_PRIMARY)
            service.addCharacteristic(rssiChar)
            service.addCharacteristic(panicCharacteristic)
            bluetoothGattServer?.addService(service)
        } catch (e: SecurityException) {
            Log.e("TetherBLE", "GATT Setup failed: ${e.message}")
        }
    }

    private fun startAdvertising() {
        updateAdvertisement(trustState = 0x00) // Default "Idle/Safe" state
    }

    private fun updateAdvertisement(trustState: Byte) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
            ContextCompat.checkSelfPermission(this, android.Manifest.permission.BLUETOOTH_ADVERTISE) != PackageManager.PERMISSION_GRANTED) {
            return
        }

        advertiser = bluetoothAdapter?.bluetoothLeAdvertiser ?: return

        // Stop previous broadcast before starting a new one with updated data
        stopAdvertising()

        // Construct 5-byte payload: [DeviceID, TrustState, HMAC1, HMAC2, HMAC3]
        val manufacturerData = ByteArray(5)
        manufacturerData[0] = DEVICE_ID.toByte()
        manufacturerData[1] = trustState
        // Placeholder for future HMAC implementation
        manufacturerData[2] = 0xAA.toByte()
        manufacturerData[3] = 0xBB.toByte()
        manufacturerData[4] = 0xCC.toByte()

        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_HIGH)
            .setConnectable(true)
            .build()

        val advertiseData = AdvertiseData.Builder()
            .setIncludeDeviceName(true) // Disabled to ensure enough room for ManufacturerData
            .addManufacturerData(MANUFACTURER_ID, manufacturerData)
            .build()

        // Include UUID in scan response so laptop can filter by Service UUID first
        val scanResponse = AdvertiseData.Builder()
            .addServiceUuid(ParcelUuid(SERVICE_UUID))
            .build()

        try {
            advertiser?.startAdvertising(settings, advertiseData, scanResponse, advertiseCallback)
        } catch (e: Exception) {
            Log.e("TetherBLE", "Adv failed: ${e.message}")
        }
    }

    private fun stopAdvertising() {
        try {
            advertiser?.stopAdvertising(advertiseCallback)
        } catch (e: Exception) { /* Ignore */ }
        isAdvertising = false
    }

    private val gattServerCallback = object : BluetoothGattServerCallback() {
        override fun onConnectionStateChange(device: BluetoothDevice, status: Int, newState: Int) {
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                connectedDevice = device
                Log.d("TetherBLE", "✅ PC Connected via GATT")
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                connectedDevice = null
                mainHandler.postDelayed({ updateAdvertisement(0x00) }, 1000)
            }
        }
    }

    private val advertiseCallback = object : AdvertiseCallback() {
        override fun onStartSuccess(settingsInEffect: AdvertiseSettings?) {
            isAdvertising = true
        }
        override fun onStartFailure(errorCode: Int) {
            Log.e("TetherBLE", "Adv Failure: $errorCode")
            isAdvertising = false
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(CHANNEL_ID, "Tether Proximity", NotificationManager.IMPORTANCE_LOW)
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
    }

    private fun createNotification(): Notification = NotificationCompat.Builder(this, CHANNEL_ID)
        .setContentTitle("🔒 Tether Active")
        .setContentText("Broadcasting security state")
        .setSmallIcon(android.R.drawable.ic_lock_lock)
        .build()

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        stopAdvertising()
        bluetoothGattServer?.close()
        super.onDestroy()
    }
}