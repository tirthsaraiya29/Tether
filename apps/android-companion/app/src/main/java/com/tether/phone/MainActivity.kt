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
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.core.*
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.tooling.preview.Preview
import com.tether.phone.ui.theme.*

// Premium Custom Easing for high-fidelity animations
val EaseInOutSans = CubicBezierEasing(0.42f, 0f, 0.58f, 1f)

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
        // Enable premium modern system-wide edge-to-edge drawing
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)

        setContent {
            TetherTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    TetherAppScreen(
                        statusText = uiStatusText.value,
                        statusColor = uiStatusColor.value,
                        connectionStatus = uiConnectionStatusText.value,
                        onLockClick = { triggerBleAction("LOCK_NOW", "🔒 Manual Lock Sent!") },
                        onPanicClick = { triggerBleAction("PANIC", "🚨 Panic Sent! Locking PC...") }
                    )
                }
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

@Composable
fun TetherAppScreen(
    statusText: String,
    statusColor: Color,
    connectionStatus: String,
    onLockClick: () -> Unit,
    onPanicClick: () -> Unit
) {
    val infiniteTransition = rememberInfiniteTransition(label = "TelemetryInfinitum")

    val ambientGlowAlpha by infiniteTransition.animateFloat(
        initialValue = 0.15f,
        targetValue = 0.35f,
        animationSpec = infiniteRepeatable(
            animation = tween(2500, easing = EaseInOutSans),
            repeatMode = RepeatMode.Reverse
        ), label = "AmbientGlow"
    )

    val rotation by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(
            animation = tween(12000, easing = LinearEasing)
        ), label = "TelemetryRotation"
    )

    // Performance Optimization: Cache brushes and colors to avoid allocations during draw/recomposition
    val ambientGradient = remember(statusColor) {
        Brush.radialGradient(
            colors = listOf(statusColor.copy(alpha = 0.12f), Color.Transparent),
            center = Offset.Unspecified
        )
    }

    val sweepGradient = remember(statusColor) {
        Brush.sweepGradient(
            0f to Color.Transparent,
            0.5f to statusColor,
            1f to Color.Transparent
        )
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(SpaceDark)
            .windowInsetsPadding(WindowInsets.safeDrawing)
    ) {
        // High-fidelity architectural accenting
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .fillMaxHeight(0.5f)
                .align(Alignment.TopCenter)
                .graphicsLayer { alpha = ambientGlowAlpha }
                .background(ambientGradient)
        )

        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 24.dp, vertical = 16.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.SpaceBetween
        ) {
            // Upper Micro-Branding Header Element
            Text(
                text = stringResource(id = R.string.app_name).uppercase(),
                modifier = Modifier.padding(top = 16.dp),
                style = MaterialTheme.typography.labelMedium.copy(
                    color = NeonCyan,
                    fontWeight = FontWeight.Bold
                )
            )

            // Central Cryptographic Telemetry Node
            Box(
                contentAlignment = Alignment.Center,
                modifier = Modifier
                    .weight(1f)
                    .semantics(mergeDescendants = true) {
                        contentDescription = "System status: $statusText. $connectionStatus."
                    }
            ) {
                // Static structural track
                Canvas(modifier = Modifier.size(280.dp)) {
                    drawArc(
                        color = SurfaceDark,
                        startAngle = 0f,
                        sweepAngle = 360f,
                        useCenter = false,
                        style = Stroke(width = 8.dp.toPx())
                    )
                }

                // Hardware accelerated telemetry ring
                Canvas(
                    modifier = Modifier
                        .size(280.dp)
                        .graphicsLayer { rotationZ = rotation }
                ) {
                    drawArc(
                        brush = sweepGradient,
                        startAngle = 0f, // Base position, rotated by graphicsLayer
                        sweepAngle = 140f,
                        useCenter = false,
                        style = Stroke(width = 4.dp.toPx(), cap = StrokeCap.Round)
                    )
                }

                Column(
                    horizontalAlignment = Alignment.CenterHorizontally,
                    modifier = Modifier.padding(24.dp)
                ) {
                    Text(
                        text = statusText,
                        style = MaterialTheme.typography.headlineSmall.copy(
                            fontWeight = FontWeight.Black,
                            textAlign = TextAlign.Center,
                            color = statusColor
                        )
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = connectionStatus.uppercase(),
                        style = MaterialTheme.typography.labelMedium.copy(
                            color = TextSecondary,
                            fontSize = 10.sp
                        )
                    )
                }
            }

            // Core Premium Control Interfaces
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(bottom = 16.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                PremiumControlAction(
                    label = stringResource(R.string.action_lock),
                    accentColor = NeonCyan,
                    onClick = onLockClick
                )
                PremiumControlAction(
                    label = stringResource(R.string.action_panic),
                    accentColor = NeonRed,
                    onClick = onPanicClick
                )
            }
        }
    }
}

@Preview(showBackground = true, backgroundColor = 0xFF0C0C12)
@Composable
fun TetherAppScreenPreview() {
    TetherTheme {
        TetherAppScreen(
            statusText = "TETHER ACTIVE\nSYSTEM SECURE",
            statusColor = NeonGreen,
            connectionStatus = "Secure Broadcast Active",
            onLockClick = {},
            onPanicClick = {}
        )
    }
}

@Composable
fun PremiumControlAction(
    label: String,
    accentColor: Color,
    onClick: () -> Unit
) {
    val gradientBrush = remember(accentColor) {
        Brush.verticalGradient(
            listOf(accentColor.copy(alpha = 0.06f), Color.Transparent)
        )
    }

    Button(
        onClick = onClick,
        colors = ButtonDefaults.buttonColors(containerColor = Color.Transparent),
        contentPadding = PaddingValues(),
        shape = RoundedCornerShape(4.dp),
        modifier = Modifier
            .fillMaxWidth()
            .height(56.dp)
            .border(1.dp, accentColor.copy(alpha = 0.25f), RoundedCornerShape(4.dp))
    ) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(gradientBrush),
            contentAlignment = Alignment.Center
        ) {
            Text(
                text = label,
                style = MaterialTheme.typography.labelMedium.copy(
                    color = accentColor,
                    fontWeight = FontWeight.Bold
                )
            )
        }
    }
}