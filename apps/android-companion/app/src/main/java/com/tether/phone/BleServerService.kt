package com.tether.phone

import android.content.pm.ServiceInfo
import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.BluetoothLeAdvertiser
import android.content.pm.PackageManager
import android.os.Build
import android.os.IBinder
import android.os.ParcelUuid
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import java.util.UUID

class BleServerService : Service() {

    private lateinit var bluetoothAdapter: BluetoothAdapter
    private var advertiser: BluetoothLeAdvertiser? = null

    companion object {
        private const val CHANNEL_ID = "ble_tether_channel"
    }

    override fun onCreate() {
        super.onCreate()

        createNotificationChannel()

        val notification: Notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Tether BLE")
            .setContentText("BLE advertising running")
            .setSmallIcon(android.R.drawable.stat_sys_data_bluetooth)
            .build()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(
                1,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE
            )
        } else {
            startForeground(1, notification)
        }

        val bluetoothManager = getSystemService(BluetoothManager::class.java)
        bluetoothAdapter = bluetoothManager.adapter

        if (!bluetoothAdapter.isEnabled) {
            Log.e("TetherBLE", "Bluetooth disabled")
            stopSelf()
            return
        }

        if (!bluetoothAdapter.isMultipleAdvertisementSupported) {
            Log.e("TetherBLE", "BLE advertising not supported")
            stopSelf()
            return
        }

        advertiser = bluetoothAdapter.bluetoothLeAdvertiser

        startAdvertising()
    }

    private fun hasPermission(): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            ContextCompat.checkSelfPermission(
                this,
                Manifest.permission.BLUETOOTH_ADVERTISE
            ) == PackageManager.PERMISSION_GRANTED
        } else {
            true
        }
    }

    private fun startAdvertising() {

        if (!hasPermission()) {
            Log.e("TetherBLE", "Missing BLUETOOTH_ADVERTISE permission")
            return
        }

        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_HIGH)
            .setConnectable(true)
            .build()

        val data = AdvertiseData.Builder()
            .setIncludeDeviceName(true)
            .addServiceUuid(
                ParcelUuid(
                    UUID.fromString("0000FFE0-0000-1000-8000-00805F9B34FB")
                )
            )
            .build()

        try {
            advertiser?.startAdvertising(settings, data, advertiseCallback)
        } catch (e: SecurityException) {
            Log.e("TetherBLE", "Security exception: ${e.message}")
        }
    }

    private val advertiseCallback = object : AdvertiseCallback() {

        override fun onStartSuccess(settingsInEffect: AdvertiseSettings?) {
            Log.d("TetherBLE", "BLE advertising started")
        }

        override fun onStartFailure(errorCode: Int) {
            Log.e("TetherBLE", "BLE advertising failed: $errorCode")
        }
    }

    private fun createNotificationChannel() {

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {

            val channel = NotificationChannel(
                CHANNEL_ID,
                "BLE Service",
                NotificationManager.IMPORTANCE_LOW
            )

            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }

    override fun onDestroy() {

        if (hasPermission()) {
            try {
                advertiser?.stopAdvertising(advertiseCallback)
            } catch (e: SecurityException) {
                Log.e("TetherBLE", "Stop advertise failed")
            }
        }

        super.onDestroy()
    }

    override fun onBind(intent: android.content.Intent?): IBinder? = null
}