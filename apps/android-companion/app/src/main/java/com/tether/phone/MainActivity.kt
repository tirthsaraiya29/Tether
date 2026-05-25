package com.tether.phone

import android.Manifest
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.tether.phone.ui.theme.*

class MainActivity : ComponentActivity() {
    private val REQUEST_BLUETOOTH_PERMISSIONS = 1

    // Reactive UI States linking your backend to the Compose frontend
    private var uiStatusText = mutableStateOf("Initializing...")
    private var uiStatusColor = mutableStateOf(TextSecondary)
    private var uiConnectionStatusText = mutableStateOf("Not connected")

    private val bluetoothStateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action == BluetoothAdapter.ACTION_STATE_CHANGED) {
                when (intent.getIntExtra(BluetoothAdapter.EXTRA_STATE, BluetoothAdapter.ERROR)) {
                    BluetoothAdapter.STATE_OFF -> {
                        uiStatusText.value = "Bluetooth Disabled"
                        uiStatusColor.value = NeonRed
                        uiConnectionStatusText.value = "Waiting for Bluetooth to turn on..."
                        stopService(Intent(this@MainActivity, BleGattServerService::class.java))
                    }
                    BluetoothAdapter.STATE_ON -> {
                        if (checkPermissions()) {
                            startBleService()
                        }
                    }
                }
            }
        }
    }

    private val enableBluetoothLauncher = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == RESULT_OK) {
            startBleService()
        } else {
            uiStatusText.value = "Bluetooth required"
            uiStatusColor.value = NeonRed
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Render the new Futuristic UI
        setContent {
            TetherTheme {
                TetherAppScreen(
                    statusText = uiStatusText.value,
                    statusColor = uiStatusColor.value,
                    connectionStatus = uiConnectionStatusText.value,
                    onLockClick = { triggerBleAction("LOCK_NOW", "🔒 Manual Lock Sent!") },
                    onPanicClick = { triggerBleAction("PANIC", "🚨 Panic Sent! Locking PC...") }
                )
            }
        }

        registerReceiver(bluetoothStateReceiver, IntentFilter(BluetoothAdapter.ACTION_STATE_CHANGED))

        if (checkPermissions()) {
            checkAndEnableBluetooth()
        } else {
            requestPermissions()
        }
    }

    private fun triggerBleAction(action: String, toastMessage: String) {
        Toast.makeText(this, toastMessage, Toast.LENGTH_SHORT).show()
        val serviceIntent = Intent(this, BleGattServerService::class.java).apply {
            this.action = action
        }
        startService(serviceIntent)
    }

    override fun onDestroy() {
        super.onDestroy()
        try {
            unregisterReceiver(bluetoothStateReceiver)
        } catch (e: Exception) {
            // Receiver might not be registered
        }
    }

    private fun checkPermissions(): Boolean {
        val permissions = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            listOf(
                Manifest.permission.BLUETOOTH_SCAN,
                Manifest.permission.BLUETOOTH_CONNECT,
                Manifest.permission.BLUETOOTH_ADVERTISE,
                Manifest.permission.ACCESS_FINE_LOCATION
            )
        } else {
            listOf(
                Manifest.permission.ACCESS_FINE_LOCATION,
                Manifest.permission.BLUETOOTH,
                Manifest.permission.BLUETOOTH_ADMIN
            )
        }
        return permissions.all { ContextCompat.checkSelfPermission(this, it) == PackageManager.PERMISSION_GRANTED }
    }

    private fun requestPermissions() {
        val permissions = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            arrayOf(
                Manifest.permission.BLUETOOTH_SCAN,
                Manifest.permission.BLUETOOTH_CONNECT,
                Manifest.permission.BLUETOOTH_ADVERTISE,
                Manifest.permission.ACCESS_FINE_LOCATION
            )
        } else {
            arrayOf(
                Manifest.permission.ACCESS_FINE_LOCATION,
                Manifest.permission.BLUETOOTH,
                Manifest.permission.BLUETOOTH_ADMIN
            )
        }
        ActivityCompat.requestPermissions(this, permissions, REQUEST_BLUETOOTH_PERMISSIONS)
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == REQUEST_BLUETOOTH_PERMISSIONS && grantResults.all { it == PackageManager.PERMISSION_GRANTED }) {
            checkAndEnableBluetooth()
        } else {
            Toast.makeText(this, "Permissions required for background locking", Toast.LENGTH_LONG).show()
        }
    }

    private fun checkAndEnableBluetooth() {
        val bluetoothAdapter = (getSystemService(BLUETOOTH_SERVICE) as BluetoothManager).adapter
        if (bluetoothAdapter.isEnabled) {
            startBleService()
        } else {
            val enableIntent = Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE)
            enableBluetoothLauncher.launch(enableIntent)
        }
    }

    private fun startBleService() {
        uiStatusText.value = "Starting BLE service..."
        val serviceIntent = Intent(this, BleGattServerService::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(serviceIntent)
        } else {
            startService(serviceIntent)
        }
        uiStatusText.value = "TETHER ACTIVE\nSYSTEM SECURE"
        uiStatusColor.value = NeonGreen
        uiConnectionStatusText.value = "Advertising securely in background"
    }
}

// --- COMPOSE UI COMPONENTS ---

@Composable
fun TetherAppScreen(
    statusText: String,
    statusColor: Color,
    connectionStatus: String,
    onLockClick: () -> Unit,
    onPanicClick: () -> Unit
) {
    val bgBrush = Brush.verticalGradient(
        colors = listOf(SurfaceDark, SpaceDark)
    )

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(bgBrush)
            .padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Text(
            text = "TETHER",
            fontSize = 42.sp,
            fontWeight = FontWeight.Black,
            color = TextPrimary,
            letterSpacing = 12.sp,
            modifier = Modifier.padding(bottom = 8.dp)
        )

        Text(
            text = connectionStatus.uppercase(),
            fontSize = 12.sp,
            color = TextSecondary,
            letterSpacing = 2.sp,
            modifier = Modifier.padding(bottom = 64.dp)
        )

        Text(
            text = statusText,
            fontSize = 16.sp,
            fontWeight = FontWeight.Bold,
            color = statusColor,
            textAlign = TextAlign.Center,
            letterSpacing = 1.5.sp,
            modifier = Modifier.padding(bottom = 80.dp)
        )

        FuturisticButton(
            text = "MANUAL LOCK",
            glowColor = NeonCyan,
            onClick = onLockClick
        )

        Spacer(modifier = Modifier.height(24.dp))

        FuturisticButton(
            text = "PANIC OVERRIDE",
            glowColor = NeonRed,
            onClick = onPanicClick
        )
    }
}

@Composable
fun FuturisticButton(text: String, glowColor: Color, onClick: () -> Unit) {
    Button(
        onClick = onClick,
        colors = ButtonDefaults.buttonColors(
            containerColor = SurfaceLight,
            contentColor = glowColor
        ),
        shape = RoundedCornerShape(8.dp),
        modifier = Modifier
            .fillMaxWidth(0.9f)
            .height(64.dp)
            .border(
                width = 1.dp,
                color = glowColor.copy(alpha = 0.6f),
                shape = RoundedCornerShape(8.dp)
            )
    ) {
        Text(
            text = text,
            fontSize = 16.sp,
            fontWeight = FontWeight.Bold,
            letterSpacing = 3.sp
        )
    }
}