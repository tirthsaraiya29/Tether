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
import android.os.IBinder
import android.os.ParcelUuid
import android.util.Log
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import java.util.UUID

class BleGattServerService : Service() {

    private var bluetoothGattServer: BluetoothGattServer? = null
    private var bluetoothAdapter: BluetoothAdapter? = null
    private var advertiser: BluetoothLeAdvertiser? = null
    private var isAdvertising = false

    companion object {
        private val SERVICE_UUID = UUID.fromString("0000FFE0-0000-1000-8000-00805F9B34FB")
        private val RSSI_CHAR_UUID = UUID.fromString("0000FFE1-0000-1000-8000-00805F9B34FB")

        private const val CHANNEL_ID = "tether_proximity_channel"
        private const val NOTIFICATION_ID = 1
        private const val DEVICE_NAME = "TetherPhone"
    }

    private lateinit var rssiCharacteristic: BluetoothGattCharacteristic

    override fun onCreate() {
        super.onCreate()
        Log.d("TetherBLE", "Service creating on Android ${Build.VERSION.SDK_INT}")

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

        rssiCharacteristic = BluetoothGattCharacteristic(
            RSSI_CHAR_UUID,
            BluetoothGattCharacteristic.PROPERTY_READ,
            BluetoothGattCharacteristic.PERMISSION_READ
        )

        val service = BluetoothGattService(SERVICE_UUID, BluetoothGattService.SERVICE_TYPE_PRIMARY)
        service.addCharacteristic(rssiCharacteristic)
        bluetoothGattServer?.addService(service)

        Log.d("TetherBLE", "GATT server setup complete with service: $SERVICE_UUID")
    }

    private fun startAdvertising() {
        // Check for BLUETOOTH_ADVERTISE permission (Android 12+)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            if (ContextCompat.checkSelfPermission(this, android.Manifest.permission.BLUETOOTH_ADVERTISE)
                != PackageManager.PERMISSION_GRANTED) {
                Log.e("TetherBLE", "Missing BLUETOOTH_ADVERTISE permission")
                return
            }
        }

        advertiser = bluetoothAdapter?.bluetoothLeAdvertiser

        if (advertiser == null) {
            Log.e("TetherBLE", "BluetoothLE Advertiser not available")
            return
        }

        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_HIGH)
            .setConnectable(true)
            .setTimeout(0)
            .build()

        // Only include device name to keep packet small
        val advertiseData = AdvertiseData.Builder()
            .setIncludeDeviceName(true)
            .build()

        // Put service UUID in scan response
        val scanResponseData = AdvertiseData.Builder()
            .setIncludeDeviceName(false)
            .addServiceUuid(ParcelUuid(SERVICE_UUID))
            .build()

        try {
            advertiser?.startAdvertising(settings, advertiseData, scanResponseData, advertiseCallback)
            isAdvertising = true
            Log.d("TetherBLE", "✅ Advertising started with name: $DEVICE_NAME")
        } catch (e: SecurityException) {
            Log.e("TetherBLE", "Security exception during advertising: ${e.message}")
            e.printStackTrace()
        }
    }

    private val gattServerCallback = object : BluetoothGattServerCallback() {
        override fun onConnectionStateChange(device: BluetoothDevice, status: Int, newState: Int) {
            // Check BLUETOOTH_CONNECT permission for device info (Android 12+)
            val hasConnectPermission = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                ContextCompat.checkSelfPermission(
                    this@BleGattServerService,
                    android.Manifest.permission.BLUETOOTH_CONNECT
                ) == PackageManager.PERMISSION_GRANTED
            } else {
                true
            }

            val deviceInfo = if (hasConnectPermission) {
                device.name ?: device.address
            } else {
                device.address
            }

            when (newState) {
                BluetoothProfile.STATE_CONNECTED -> {
                    Log.d("TetherBLE", "✅ PC Connected: $deviceInfo")
                    sendConnectionBroadcast(true)
                }
                BluetoothProfile.STATE_DISCONNECTED -> {
                    Log.d("TetherBLE", "❌ PC Disconnected: $deviceInfo")
                    sendConnectionBroadcast(false)
                }
            }
        }

        override fun onCharacteristicReadRequest(
            device: BluetoothDevice,
            requestId: Int,
            offset: Int,
            characteristic: BluetoothGattCharacteristic
        ) {
            // Check BLUETOOTH_CONNECT permission for responding (Android 12+)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                if (ContextCompat.checkSelfPermission(this@BleGattServerService, android.Manifest.permission.BLUETOOTH_CONNECT)
                    != PackageManager.PERMISSION_GRANTED) {
                    Log.e("TetherBLE", "Missing BLUETOOTH_CONNECT permission for read request")
                    return
                }
            }

            if (characteristic.uuid == RSSI_CHAR_UUID) {
                val value = byteArrayOf(0x01)
                try {
                    bluetoothGattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, value)
                    Log.d("TetherBLE", "Keep-alive read request received and responded")
                } catch (e: SecurityException) {
                    Log.e("TetherBLE", "Security exception sending response: ${e.message}")
                }
            }
        }

        override fun onNotificationSent(device: BluetoothDevice, status: Int) {
            Log.d("TetherBLE", "Notification sent, status: $status")
        }

        override fun onServiceAdded(status: Int, service: BluetoothGattService) {
            Log.d("TetherBLE", "Service added, status: $status")
        }
    }

    private val advertiseCallback = object : AdvertiseCallback() {
        override fun onStartSuccess(settingsInEffect: AdvertiseSettings?) {
            Log.d("TetherBLE", "✅ Advertising started successfully!")
            Log.d("TetherBLE", "  Device name: $DEVICE_NAME")
            Log.d("TetherBLE", "  Mode: ${settingsInEffect?.mode}")
            Log.d("TetherBLE", "  TX Power: ${settingsInEffect?.txPowerLevel}")
            isAdvertising = true
        }

        override fun onStartFailure(errorCode: Int) {
            Log.e("TetherBLE", "❌ Advertising failed: errorCode=$errorCode")
            when (errorCode) {
                ADVERTISE_FAILED_DATA_TOO_LARGE -> {
                    Log.e("TetherBLE", "  Cause: Data too large")
                    retryAdvertisingWithoutUuid()
                }
                ADVERTISE_FAILED_FEATURE_UNSUPPORTED -> Log.e("TetherBLE", "  Cause: Feature unsupported")
                ADVERTISE_FAILED_INTERNAL_ERROR -> Log.e("TetherBLE", "  Cause: Internal error")
                ADVERTISE_FAILED_TOO_MANY_ADVERTISERS -> Log.e("TetherBLE", "  Cause: Too many advertisers")
                ADVERTISE_FAILED_ALREADY_STARTED -> Log.e("TetherBLE", "  Cause: Already started")
            }
        }
    }

    private fun retryAdvertisingWithoutUuid() {
        Log.d("TetherBLE", "Retrying advertising without UUID...")

        // Check permission again
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            if (ContextCompat.checkSelfPermission(this, android.Manifest.permission.BLUETOOTH_ADVERTISE)
                != PackageManager.PERMISSION_GRANTED) {
                Log.e("TetherBLE", "Missing BLUETOOTH_ADVERTISE permission for retry")
                return
            }
        }

        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_HIGH)
            .setConnectable(true)
            .setTimeout(0)
            .build()

        val advertiseData = AdvertiseData.Builder()
            .setIncludeDeviceName(true)
            .build()

        try {
            advertiser?.startAdvertising(settings, advertiseData, advertiseCallback)
            Log.d("TetherBLE", "Retry started with name only (no UUID)")
        } catch (e: SecurityException) {
            Log.e("TetherBLE", "Retry failed: ${e.message}")
        }
    }

    private fun sendConnectionBroadcast(isConnected: Boolean) {
        val intent = Intent("com.tether.phone.CONNECTION_STATUS")
        intent.putExtra("connected", isConnected)
        try {
            sendBroadcast(intent)
        } catch (e: SecurityException) {
            Log.e("TetherBLE", "Failed to send broadcast: ${e.message}")
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Tether Proximity Security",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Keeps your PC locked when phone is away"
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }

    private fun createNotification(): Notification {
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            Notification.Builder(this)
        }

        return builder
            .setContentTitle("🔒 Tether Active")
            .setContentText("Proximity security protecting your PC")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setPriority(Notification.PRIORITY_LOW)
            .build()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        if (isAdvertising) {
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                    if (ContextCompat.checkSelfPermission(this, android.Manifest.permission.BLUETOOTH_ADVERTISE)
                        == PackageManager.PERMISSION_GRANTED) {
                        advertiser?.stopAdvertising(advertiseCallback)
                    }
                } else {
                    advertiser?.stopAdvertising(advertiseCallback)
                }
            } catch (e: SecurityException) {
                Log.e("TetherBLE", "Stop advertise failed: ${e.message}")
            } catch (e: Exception) {
                Log.e("TetherBLE", "Stop advertise error: ${e.message}")
            }
        }

        try {
            bluetoothGattServer?.close()
        } catch (e: Exception) {
            Log.e("TetherBLE", "Error closing GATT server: ${e.message}")
        }

        super.onDestroy()
        Log.d("TetherBLE", "Service destroyed")
    }
}