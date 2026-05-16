package com.tether.phone

import android.app.Service
import android.bluetooth.*
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.content.Intent
import android.os.IBinder
import android.util.Log
import java.util.*

class BleGattServerService : Service() {
    private lateinit var bluetoothManager: BluetoothManager
    private lateinit var bluetoothAdapter: BluetoothAdapter
    private lateinit var bluetoothGattServer: BluetoothGattServer
    private val random = Random()
    private var currentNonce: ByteArray? = null

    // GATT UUIDs
    private val SERVICE_UUID = UUID.fromString("0000ffe0-0000-1000-8000-00805f9b34fb")
    private val NONCE_CHAR_UUID = UUID.fromString("0000ffe1-0000-1000-8000-00805f9b34fb")
    private val RESPONSE_CHAR_UUID = UUID.fromString("0000ffe2-0000-1000-8000-00805f9b34fb")

    private lateinit var nonceCharacteristic: BluetoothGattCharacteristic
    private lateinit var responseCharacteristic: BluetoothGattCharacteristic

    override fun onCreate() {
        super.onCreate()
        bluetoothManager = getSystemService(BluetoothManager::class.java)
        bluetoothAdapter = bluetoothManager.adapter
        startAdvertisingAndServer()
    }

    private fun startAdvertisingAndServer() {
        // Open GATT server
        bluetoothGattServer = bluetoothAdapter.openGattServer(this, gattServerCallback)

        // Build characteristics
        nonceCharacteristic = BluetoothGattCharacteristic(
            NONCE_CHAR_UUID,
            BluetoothGattCharacteristic.PROPERTY_WRITE or BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE,
            BluetoothGattCharacteristic.PERMISSION_WRITE
        )
        responseCharacteristic = BluetoothGattCharacteristic(
            RESPONSE_CHAR_UUID,
            BluetoothGattCharacteristic.PROPERTY_NOTIFY,
            BluetoothGattCharacteristic.PERMISSION_READ
        )

        // Build service
        val service = BluetoothGattService(SERVICE_UUID, BluetoothGattService.SERVICE_TYPE_PRIMARY)
        service.addCharacteristic(nonceCharacteristic)
        service.addCharacteristic(responseCharacteristic)
        bluetoothGattServer.addService(service)

        // Start advertising
        val advertiseSettings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_HIGH)
            .setConnectable(true)
            .build()

        val advertiseData = AdvertiseData.Builder()
            .setIncludeDeviceName(true)
            .addServiceUuid(ParcelUuid(SERVICE_UUID))
            .build()

        bluetoothAdapter.bluetoothLeAdvertiser.startAdvertising(advertiseSettings, advertiseData, advertiseCallback)
        Log.d("TetherBLE", "GATT server and advertising started")
    }

    private val gattServerCallback = object : BluetoothGattServerCallback() {
        override fun onCharacteristicWriteRequest(
            device: BluetoothDevice,
            requestId: Int,
            characteristic: BluetoothGattCharacteristic,
            preparedWrite: Boolean,
            responseNeeded: Boolean,
            offset: Int,
            value: ByteArray
        ) {
            when (characteristic.uuid) {
                NONCE_CHAR_UUID -> {
                    // Received nonce from laptop
                    currentNonce = value
                    Log.d("TetherBLE", "Received nonce: ${value.joinToString()}")
                    // Send back a signed response (dummy: just nonce inverted)
                    val response = value.reversedArray()
                    responseCharacteristic.setValue(response)
                    bluetoothGattServer.notifyCharacteristicChanged(device, responseCharacteristic, false)
                    if (responseNeeded) {
                        bluetoothGattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, null)
                    }
                }
                else -> super.onCharacteristicWriteRequest(device, requestId, characteristic, preparedWrite, responseNeeded, offset, value)
            }
        }
    }

    private val advertiseCallback = object : AdvertiseCallback() {
        override fun onStartSuccess(settingsInEffect: AdvertiseSettings?) {
            Log.d("TetherBLE", "Advertising started successfully")
        }
        override fun onStartFailure(errorCode: Int) {
            Log.e("TetherBLE", "Advertising failed: $errorCode")
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        bluetoothGattServer.close()
        bluetoothAdapter.bluetoothLeAdvertiser.stopAdvertising(advertiseCallback)
        super.onDestroy()
    }
}