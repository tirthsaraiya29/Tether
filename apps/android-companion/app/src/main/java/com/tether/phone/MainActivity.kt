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
import androidx.compose.animation.core.*
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.tether.phone.ui.theme.*

class MainActivity : ComponentActivity() {
    private val requestBluetoothPermissionsCode = 1

    private var uiStatusText = mutableStateOf("Initializing...")
    private var uiStatusColor = mutableStateOf(TextSecondary)
    private var uiConnectionStatusText = mutableStateOf("Not connected")

    private val bluetoothStateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action == BluetoothAdapter.ACTION_STATE_CHANGED) {
                when (intent.getIntExtra(BluetoothAdapter.EXTRA_STATE, BluetoothAdapter.ERROR)) {
                    BluetoothAdapter.STATE_OFF -> {
                        uiStatusText.value = "BLUETOOTH OFFLINE"
                        uiStatusColor.value = NeonRed
                        uiConnectionStatusText.value = "Hardware link severed"
                        stopService(Intent(this@MainActivity, BleGattServerService::class.java))
                    }
                    BluetoothAdapter.STATE_ON -> {
                        if (checkPermissions()) startBleService()
                    }
                }
            }
        }
    }

    private val enableBluetoothLauncher = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == RESULT_OK) startBleService()
        else {
            uiStatusText.value = "ACCESS DENIED"
            uiStatusColor.value = NeonRed
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

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

        if (checkPermissions()) checkAndEnableBluetooth()
        else requestPermissions()
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
        try { unregisterReceiver(bluetoothStateReceiver) } catch (_: Exception) {}
    }

    private fun checkPermissions(): Boolean {
        val permissions = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            listOf(Manifest.permission.BLUETOOTH_SCAN, Manifest.permission.BLUETOOTH_CONNECT, Manifest.permission.BLUETOOTH_ADVERTISE, Manifest.permission.ACCESS_FINE_LOCATION)
        } else {
            listOf(Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.BLUETOOTH, Manifest.permission.BLUETOOTH_ADMIN)
        }
        return permissions.all { ContextCompat.checkSelfPermission(this, it) == PackageManager.PERMISSION_GRANTED }
    }

    private fun requestPermissions() {
        val permissions = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            arrayOf(Manifest.permission.BLUETOOTH_SCAN, Manifest.permission.BLUETOOTH_CONNECT, Manifest.permission.BLUETOOTH_ADVERTISE, Manifest.permission.ACCESS_FINE_LOCATION)
        } else {
            arrayOf(Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.BLUETOOTH, Manifest.permission.BLUETOOTH_ADMIN)
        }
        ActivityCompat.requestPermissions(this, permissions, requestBluetoothPermissionsCode)
    }

    @Deprecated("Deprecated in Java")
    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == requestBluetoothPermissionsCode && grantResults.all { it == PackageManager.PERMISSION_GRANTED }) {
            checkAndEnableBluetooth()
        }
    }

    private fun checkAndEnableBluetooth() {
        val bluetoothAdapter = (getSystemService(BLUETOOTH_SERVICE) as BluetoothManager).adapter
        if (bluetoothAdapter.isEnabled) startBleService()
        else enableBluetoothLauncher.launch(Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE))
    }

    private fun startBleService() {
        val serviceIntent = Intent(this, BleGattServerService::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) startForegroundService(serviceIntent)
        else startService(serviceIntent)

        uiStatusText.value = "TETHER ACTIVE\nSYSTEM SECURE"
        uiStatusColor.value = NeonGreen
        uiConnectionStatusText.value = "Secure Broadcast Active"
    }
}

// --- HIGH PERFORMANCE GPU COMPONENTS ---

@Composable
fun TetherAppScreen(
    statusText: String,
    statusColor: Color,
    connectionStatus: String,
    onLockClick: () -> Unit,
    onPanicClick: () -> Unit
) {
    val infiniteTransition = rememberInfiniteTransition(label = "GPU_Stress")

    val scanLineY by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(3000, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ), label = "ScanLine"
    )

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(SpaceDark)
            .drawBehind {
                val gridSize = 50.dp.toPx()
                val gridColor = Color(0xFF151520)

                // Grid Rendering
                for (x in 0..size.width.toInt() step gridSize.toInt()) {
                    drawLine(gridColor, Offset(x.toFloat(), 0f), Offset(x.toFloat(), size.height), 0.5f)
                }
                for (y in 0..size.height.toInt() step gridSize.toInt()) {
                    drawLine(gridColor, Offset(0f, y.toFloat()), Offset(size.width, y.toFloat()), 0.5f)
                }

                // Fragment-style glow
                drawRect(
                    brush = Brush.verticalGradient(
                        0.0f to Color.Transparent,
                        (scanLineY - 0.1f).coerceAtLeast(0f) to Color.Transparent,
                        scanLineY to NeonCyan.copy(alpha = 0.1f),
                        (scanLineY + 0.1f).coerceAtMost(1f) to Color.Transparent,
                        1.0f to Color.Transparent
                    )
                )

                drawLine(
                    color = NeonCyan.copy(alpha = 0.3f),
                    start = Offset(0f, size.height * scanLineY),
                    end = Offset(size.width, size.height * scanLineY),
                    strokeWidth = 1.dp.toPx()
                )
            }
    ) {
        Column(
            modifier = Modifier.fillMaxSize().padding(32.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.SpaceBetween
        ) {
            Text(
                text = "TETHER",
                fontSize = 12.sp,
                color = NeonCyan,
                letterSpacing = 6.sp,
                modifier = Modifier.padding(top = 24.dp)
            )

            Box(contentAlignment = Alignment.Center) {
                val rotation by infiniteTransition.animateFloat(
                    initialValue = 0f,
                    targetValue = 360f,
                    animationSpec = infiniteRepeatable(tween(8000, easing = LinearEasing)),
                    label = "Rotation"
                )

                Canvas(modifier = Modifier.size(260.dp)) {
                    drawArc(
                        color = statusColor.copy(alpha = 0.05f),
                        startAngle = 0f,
                        sweepAngle = 360f,
                        useCenter = false,
                        style = Stroke(width = 20.dp.toPx())
                    )
                    drawArc(
                        brush = Brush.sweepGradient(
                            0f to Color.Transparent,
                            0.5f to statusColor,
                            1f to Color.Transparent
                        ),
                        startAngle = rotation,
                        sweepAngle = 120f,
                        useCenter = false,
                        style = Stroke(width = 3.dp.toPx(), cap = StrokeCap.Round)
                    )
                }

                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Text(
                        text = statusText,
                        style = MaterialTheme.typography.headlineSmall.copy(
                            fontWeight = FontWeight.Black,
                            textAlign = TextAlign.Center,
                            color = statusColor
                        )
                    )
                    Text(
                        text = connectionStatus,
                        fontSize = 10.sp,
                        color = TextSecondary,
                        modifier = Modifier.padding(top = 4.dp)
                    )
                }
            }

            Column(
                modifier = Modifier.padding(bottom = 32.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                FuturisticButton("INITIATE_LOCK", NeonCyan, onLockClick)
                FuturisticButton("FORCE_TERMINATE", NeonRed, onPanicClick)
            }
        }
    }
}

@Composable
fun FuturisticButton(text: String, glowColor: Color, onClick: () -> Unit) {
    Button(
        onClick = onClick,
        colors = ButtonDefaults.buttonColors(containerColor = Color.Transparent),
        contentPadding = PaddingValues(),
        shape = RoundedCornerShape(2.dp),
        modifier = Modifier
            .fillMaxWidth()
            .height(50.dp)
            .border(0.5.dp, glowColor.copy(alpha = 0.4f), RoundedCornerShape(2.dp))
    ) {
        Box(
            modifier = Modifier.fillMaxSize().background(
                Brush.verticalGradient(listOf(glowColor.copy(alpha = 0.1f), Color.Transparent))
            ),
            contentAlignment = Alignment.Center
        ) {
            Text(text = text, color = glowColor, fontSize = 13.sp, fontWeight = FontWeight.Bold, letterSpacing = 4.sp)
        }
    }
}