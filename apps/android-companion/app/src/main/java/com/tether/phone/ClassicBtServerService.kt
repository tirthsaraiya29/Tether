package com.tether.phone

import android.app.Service
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothServerSocket
import android.bluetooth.BluetoothSocket
import android.content.Intent
import android.os.IBinder
import android.util.Log
import java.io.IOException
import java.io.OutputStream
import java.util.UUID
import java.util.concurrent.Executors

class ClassicBtServerService : Service() {

    private var bluetoothAdapter: BluetoothAdapter? = null
    private var serverSocket: BluetoothServerSocket? = null
    private var activeClientSocket: BluetoothSocket? = null
    private var outputStream: OutputStream? = null

    private val pqcEngine = PqcEncryptionEngine()
    private val executor = Executors.newSingleThreadExecutor()

    companion object {
        private const val TAG = "TetherClassicBT"
        // Unique RFCOMM SPP Channel UUID for the Post-Quantum stream
        private val CLASSIC_BT_UUID = UUID.fromString("8ce255c0-200a-11ec-9621-0242ac130002")
        private const val NAME = "TetherPqcSppServer"

        const val ACTION_SEND_STREAM = "com.tether.phone.ACTION_SEND_STREAM"
        const val EXTRA_PAYLOAD = "extra_payload"
    }

    override fun onCreate() {
        super.onCreate()
        val bluetoothManager = getSystemService(BluetoothManager::class.java)
        bluetoothAdapter = bluetoothManager?.adapter
        startRfcommServer()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_SEND_STREAM) {
            val rawPayload = intent.getStringExtra(EXTRA_PAYLOAD)
            if (rawPayload != null) {
                executor.execute { dispatchEncryptedFrame(rawPayload) }
            }
        }
        return START_STICKY
    }

    private fun startRfcommServer() {
        executor.execute {
            try {
                serverSocket = bluetoothAdapter?.listenUsingRfcommWithServiceRecord(NAME, CLASSIC_BT_UUID)
                Log.i(TAG, "Classic RFCOMM Server Socket opened. Waiting for connection...")

                while (true) {
                    val socket = serverSocket?.accept()
                    if (socket != null) {
                        Log.i(TAG, "Laptop connected successfully via Classic RFCOMM.")
                        activeClientSocket = socket
                        outputStream = socket.outputStream
                        break
                    }
                }
            } catch (e: SecurityException) {
                Log.e(TAG, "Permission error starting RFCOMM: ${e.message}")
            } catch (e: IOException) {
                Log.e(TAG, "RFCOMM accept loop exception: ${e.message}")
            }
        }
    }

    private fun dispatchEncryptedFrame(message: String) {
        val stream = outputStream
        if (stream == null) {
            Log.w(TAG, "Cannot send parameter frame: No laptop client connected via Classic RFCOMM.")
            return
        }
        try {
            // Apply Post-Quantum Hybrid Encryption layer
            val encryptedPayload = pqcEngine.encryptMessage(message)
            val packetBytes = (encryptedPayload + "\n").toByteArray(Charsets.UTF_8)

            stream.write(packetBytes)
            stream.flush()
            Log.d(TAG, "Dispatched PQC Encrypted Frame: $encryptedPayload")
        } catch (e: IOException) {
            Log.e(TAG, "Write error to RFCOMM stream: ${e.message}")
            // Reset state to listen for reconnect attempts
            outputStream = null
            activeClientSocket = null
            startRfcommServer()
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        try {
            serverSocket?.close()
            activeClientSocket?.close()
        } catch (_: Exception) {}
        super.onDestroy()
    }
}