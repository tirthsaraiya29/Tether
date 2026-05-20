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
import android.content.Intent
import android.os.Build
import android.os.IBinder
import android.os.ParcelUuid
import android.util.Log
import java.util.UUID

class BleGattServerService : Service() {

    private var bluetoothGattServer: BluetoothGattServer? = null
    private var bluetoothAdapter: BluetoothAdapter? = null
    private var isAdvertising = false

    companion object {
        private const val SERVICE_UUID = "0000ffe0-0000-1000-8000-00805f9b34fb"
        private const val PING_CHAR_UUID = "0000ffe1-0000-1000-8000-00805f9b34fb"
        private const val PONG_CHAR_UUID = "0000ffe2-0000-1000-8000-00805f9b34fb"
        private const val CHANNEL_ID = "tether_channel"
        private const val NOTIFICATION_ID = 1
    }

    private lateinit var pingCharacteristic: BluetoothGattCharacteristic
    private lateinit var pongCharacteristic: BluetoothGattCharacteristic

    override fun onCreate() {
        super.onCreate()
        Log.d("TetherBLE", "Service creating")

        val bluetoothManager = getSystemService(BluetoothManager::class.java)
        bluetoothAdapter = bluetoothManager?.adapter

        if (bluetoothAdapter == null || !bluetoothAdapter!!.isEnabled) {
            Log.e("TetherBLE", "Bluetooth is not available or disabled")
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

        bluetoothGattServer = bluetoothManager?.openGattServer(this, gattServerCallback)

        pingCharacteristic = BluetoothGattCharacteristic(
            UUID.fromString(PING_CHAR_UUID),
            BluetoothGattCharacteristic.PROPERTY_WRITE,
            BluetoothGattCharacteristic.PERMISSION_WRITE
        )

        pongCharacteristic = BluetoothGattCharacteristic(
            UUID.fromString(PONG_CHAR_UUID),
            BluetoothGattCharacteristic.PROPERTY_NOTIFY,
            BluetoothGattCharacteristic.PERMISSION_READ
        )

        val service = BluetoothGattService(UUID.fromString(SERVICE_UUID), BluetoothGattService.SERVICE_TYPE_PRIMARY)
        service.addCharacteristic(pingCharacteristic)
        service.addCharacteristic(pongCharacteristic)
        bluetoothGattServer?.addService(service)

        Log.d("TetherBLE", "GATT server setup complete")
    }

    private fun startAdvertising() {
        val advertiser = bluetoothAdapter?.bluetoothLeAdvertiser
        if (advertiser == null) {
            Log.e("TetherBLE", "BluetoothLE Advertiser not available")
            return
        }

        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_HIGH)
            .setConnectable(true)
            .build()

        val data = AdvertiseData.Builder()
            .setIncludeDeviceName(true)
            .addServiceUuid(ParcelUuid(UUID.fromString(SERVICE_UUID)))
            .build()

        advertiser.startAdvertising(settings, data, advertiseCallback)
        isAdvertising = true
        Log.d("TetherBLE", "Advertising started")
    }

    private val gattServerCallback = object : BluetoothGattServerCallback() {
        override fun onConnectionStateChange(device: BluetoothDevice, status: Int, newState: Int) {
            when (newState) {
                BluetoothProfile.STATE_CONNECTED -> {
                    Log.d("TetherBLE", "Connected: ${device.address}")
                }
                BluetoothProfile.STATE_DISCONNECTED -> {
                    Log.d("TetherBLE", "Disconnected: ${device.address}")
                }
            }
        }

        override fun onCharacteristicWriteRequest(
            device: BluetoothDevice,
            requestId: Int,
            characteristic: BluetoothGattCharacteristic,
            preparedWrite: Boolean,
            responseNeeded: Boolean,
            offset: Int,
            value: ByteArray
        ) {
            if (characteristic.uuid == UUID.fromString(PING_CHAR_UUID)) {
                val received = String(value)
                Log.d("TetherBLE", "Received ping: $received")

                // Send pong response
                val pongValue = "pong".toByteArray()
                pongCharacteristic.setValue(pongValue)
                bluetoothGattServer?.notifyCharacteristicChanged(device, pongCharacteristic, false)

                if (responseNeeded) {
                    bluetoothGattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, null)
                }
            }
        }
    }

    private val advertiseCallback = object : AdvertiseCallback() {
        override fun onStartSuccess(settingsInEffect: AdvertiseSettings?) {
            Log.d("TetherBLE", "Advertising started successfully")
        }

        override fun onStartFailure(errorCode: Int) {
            Log.e("TetherBLE", "Advertising failed: errorCode=$errorCode")
            isAdvertising = false
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Tether Proximity Service",
                NotificationManager.IMPORTANCE_LOW
            )
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }

    private fun createNotification(): Notification {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
                .setContentTitle("Tether Phone")
                .setContentText("Proximity security active")
                .setSmallIcon(android.R.drawable.ic_menu_info_details)
                .build()
        } else {
            Notification.Builder(this)
                .setContentTitle("Tether Phone")
                .setContentText("Proximity security active")
                .setSmallIcon(android.R.drawable.ic_menu_info_details)
                .build()
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        if (isAdvertising) {
            bluetoothAdapter?.bluetoothLeAdvertiser?.stopAdvertising(advertiseCallback)
        }
        bluetoothGattServer?.close()
        super.onDestroy()
        Log.d("TetherBLE", "Service destroyed")
    }
}