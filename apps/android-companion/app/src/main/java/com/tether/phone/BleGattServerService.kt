package com.tether.phone

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.bluetooth.*
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.BluetoothLeAdvertiser
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.IBinder
import android.os.ParcelUuid
import android.util.Base64
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import java.util.UUID

class BleGattServerService : Service() {

    private var bluetoothGattServer: BluetoothGattServer? = null
    private var bluetoothAdapter: BluetoothAdapter? = null
    private var advertiser: BluetoothLeAdvertiser? = null
    private var isAdvertising = false

    // Core Cryptographic Engine
    private lateinit var securityEngine: ProductionSecurityEngine
    private var activeChallenge: ByteArray? = null

    // Reference to the command characteristic for notifications
    private var commandCharacteristic: BluetoothGattCharacteristic? = null

    companion object {
        private val SERVICE_UUID = UUID.fromString("0000FFE0-0000-1000-8000-00805F9B34FB")

        // Characteristic where the laptop writes its random challenge token
        private val CHALLENGE_CHAR_UUID = UUID.fromString("0000FFE3-0000-1000-8000-00805F9B34FB")

        // Characteristic where the laptop reads back the hardware signature
        private val SIGNATURE_CHAR_UUID = UUID.fromString("0000FFE4-0000-1000-8000-00805F9B34FB")

        // New Characteristic: Phone writes manual button action overrides here to notify Windows
        private val COMMAND_CHAR_UUID = UUID.fromString("0000FFE5-0000-1000-8000-00805F9B34FB")

        // Standard Client Characteristic Configuration Descriptor (CCCD)
        private val CCCD_UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")

        private const val CHANNEL_ID = "tether_proximity_channel"
        private const val NOTIFICATION_ID = 1
        private const val TAG = "TetherGattService"
    }

    override fun onCreate() {
        super.onCreate()

        // Initialize the hardware-isolated cryptographic key pair engine
        securityEngine = ProductionSecurityEngine()

        // EXTRACTION UTILITY: Export and dump your phone's real public key to Logcat
        logDevicePublicKey()

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
        startAdvertising()
    }

    /**
     * Extracts your hardware-isolated public key from the Android KeyStore,
     * formats it to a clean Base64 token string, and prints it out to Logcat.
     */
    private fun logDevicePublicKey() {
        try {
            val publicKeyBytes = securityEngine.getPublicKeyBytes()
            val base64PublicKey = Base64.encodeToString(publicKeyBytes, Base64.NO_WRAP)

            Log.i(TAG, "=====================================================================")
            Log.i(TAG, "🔒 TETHER AUTH ACTIVATION: COPY BASE64 PUBLIC KEY FOR DESKTOP ENGINE")
            Log.i(TAG, base64PublicKey)
            Log.i(TAG, "=====================================================================")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to extract public cryptographic parameter metadata: ${e.message}", e)
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action
        if (action != null && commandCharacteristic != null) {
            Log.d("TetherBLE", "Processing local UI button action pipeline: $action")

            // Update characteristic value buffer locally
            commandCharacteristic?.value = action.toByteArray(Charsets.UTF_8)

            // Push notification to all explicitly paired/connected GATT client nodes
            val bluetoothManager = getSystemService(BluetoothManager::class.java)
            val connectedDevices = bluetoothManager?.getConnectedDevices(BluetoothProfile.GATT)
            if (connectedDevices != null) {
                for (device in connectedDevices) {
                    if (device == null) continue
                    try {
                        bluetoothGattServer?.notifyCharacteristicChanged(device, commandCharacteristic, false)
                    } catch (e: SecurityException) {
                        Log.e("TetherBLE", "Notification permission violation: ${e.message}")
                    }
                }
            }
        }
        return START_STICKY
    }

    private fun setupGattServer() {
        val bluetoothManager = getSystemService(BluetoothManager::class.java)
        try {
            bluetoothGattServer = bluetoothManager?.openGattServer(this, gattServerCallback)

            val service = BluetoothGattService(SERVICE_UUID, BluetoothGattService.SERVICE_TYPE_PRIMARY)

            // Challenge Characteristic: Laptop must WRITE a 32-byte secure random chunk here
            val challengeChar = BluetoothGattCharacteristic(
                CHALLENGE_CHAR_UUID,
                BluetoothGattCharacteristic.PROPERTY_WRITE,
                BluetoothGattCharacteristic.PERMISSION_WRITE_ENCRYPTED // Enforces system bonding requirement automatically
            )

            // Signature Characteristic: Laptop reads back the proof verification bytes
            val signatureChar = BluetoothGattCharacteristic(
                SIGNATURE_CHAR_UUID,
                BluetoothGattCharacteristic.PROPERTY_READ,
                BluetoothGattCharacteristic.PERMISSION_READ_ENCRYPTED // Enforces system bonding requirement automatically
            )

            // Command Characteristic: Phone broadcasts manual panel interactions instantly via Notify
            val commandChar = BluetoothGattCharacteristic(
                COMMAND_CHAR_UUID,
                BluetoothGattCharacteristic.PROPERTY_READ or BluetoothGattCharacteristic.PROPERTY_NOTIFY,
                BluetoothGattCharacteristic.PERMISSION_READ_ENCRYPTED
            )

            // Attach standard configuration descriptor required for Windows client event subscriptions
            val cccdDescriptor = BluetoothGattDescriptor(CCCD_UUID, BluetoothGattDescriptor.PERMISSION_WRITE)
            commandChar.addDescriptor(cccdDescriptor)

            service.addCharacteristic(challengeChar)
            service.addCharacteristic(signatureChar)
            service.addCharacteristic(commandChar)

            this.commandCharacteristic = commandChar

            bluetoothGattServer?.addService(service)
        } catch (e: SecurityException) {
            Log.e("TetherBLE", "GATT Setup failed: ${e.message}")
        }
    }

    private val gattServerCallback = object : BluetoothGattServerCallback() {

        // Invoked when the laptop sends a random challenge sequence
        override fun onCharacteristicWriteRequest(
            device: BluetoothDevice?,
            requestId: Int,
            characteristic: BluetoothGattCharacteristic?,
            preparedWrite: Boolean,
            responseNeeded: Boolean,
            offset: Int,
            value: ByteArray?
        ) {
            super.onCharacteristicWriteRequest(device, requestId, characteristic, preparedWrite, responseNeeded, offset, value)

            if (characteristic?.uuid == CHALLENGE_CHAR_UUID && value != null) {
                // Store the transaction challenge in temporary secure app state memory
                activeChallenge = value

                if (responseNeeded && device != null) {
                    try {
                        bluetoothGattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, null)
                    } catch (_: SecurityException) {}
                }
                Log.d("TetherSecurity", "Received secure challenge token from laptop node.")
            }
        }

        // Invoked when the laptop reads back the generated proof signature
        override fun onCharacteristicReadRequest(
            device: BluetoothDevice?,
            requestId: Int,
            offset: Int,
            characteristic: BluetoothGattCharacteristic?
        ) {
            super.onCharacteristicReadRequest(device, requestId, offset, characteristic)

            if (characteristic?.uuid == SIGNATURE_CHAR_UUID) {
                val challenge = activeChallenge
                if (challenge != null) {
                    // Sign the verification token inside the phone's hardware isolation zone
                    val signatureBytes = securityEngine.signChallenge(challenge)

                    if (device != null) {
                        try {
                            bluetoothGattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, signatureBytes)
                        } catch (_: SecurityException) {}
                    }
                    Log.d("TetherSecurity", "Cryptographic signature successfully dispatched.")

                    // Consume the challenge immediately to prevent replay attempts
                    activeChallenge = null
                } else {
                    // Fail if laptop attempts to read signature before writing a challenge
                    if (device != null) {
                        try {
                            bluetoothGattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, offset, null)
                        } catch (_: SecurityException) {}
                    }
                }
            } else if (characteristic?.uuid == COMMAND_CHAR_UUID) {
                val currentCommand = commandCharacteristic?.value ?: byteArrayOf()
                if (device != null) {
                    try {
                        bluetoothGattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, currentCommand)
                    } catch (_: SecurityException) {}
                }
            }
        }

        override fun onDescriptorWriteRequest(
            device: BluetoothDevice?,
            requestId: Int,
            descriptor: BluetoothGattDescriptor?,
            preparedWrite: Boolean,
            responseNeeded: Boolean,
            offset: Int,
            value: ByteArray?
        ) {
            super.onDescriptorWriteRequest(device, requestId, descriptor, preparedWrite, responseNeeded, offset, value)
            if (responseNeeded && device != null) {
                try {
                    bluetoothGattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, null)
                } catch (_: SecurityException) {}
            }
        }
    }

    private fun startAdvertising() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
            ContextCompat.checkSelfPermission(this, android.Manifest.permission.BLUETOOTH_ADVERTISE) != PackageManager.PERMISSION_GRANTED) {
            return
        }

        advertiser = bluetoothAdapter?.bluetoothLeAdvertiser ?: return

        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_HIGH)
            .setConnectable(true)
            .build()

        // FIX: Put the Service UUID directly into the primary advertisement packet
        // This ensures it gets blasted over the air even if Windows doesn't request a scan response.
        val advertiseData = AdvertiseData.Builder()
            .setIncludeDeviceName(false)
            .addServiceUuid(ParcelUuid(SERVICE_UUID))
            .build()

        try {
            // Pass advertiseData as the primary payload, scanResponse can be null or empty
            advertiser?.startAdvertising(settings, advertiseData, null, advertiseCallback)
        } catch (e: Exception) {
            Log.e("TetherBLE", "Adv failed: ${e.message}")
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
        .setContentText("Awaiting cryptographic verification step...")
        .setSmallIcon(android.R.drawable.ic_lock_lock)
        .build()

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        try {
            if (ContextCompat.checkSelfPermission(this, android.Manifest.permission.BLUETOOTH_ADVERTISE) == PackageManager.PERMISSION_GRANTED) {
                advertiser?.stopAdvertising(advertiseCallback)
            }
        } catch (_: Exception) {}
        bluetoothGattServer?.close()
        super.onDestroy()
    }
}