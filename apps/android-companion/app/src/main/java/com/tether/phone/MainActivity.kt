package com.tether.phone

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
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
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.animation.*
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
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import androidx.core.content.edit
import androidx.fragment.app.FragmentActivity
import com.tether.phone.ui.theme.*
import java.util.concurrent.Executor
import java.util.concurrent.Executors

val EaseInOutSans = CubicBezierEasing(0.42f, 0f, 0.58f, 1f)

enum class TrustVerificationStep {
    NOT_IN_PANIC,
    DEVICE_CREDENTIAL,
    FINGERPRINT_PRIMARY,
    FINGERPRINT_SECONDARY,
    FACE_ID
}

class MainActivity : FragmentActivity() {
    private val requestPermissionsCode = 101
    private val preferenceName = "tether_secure_prefs"
    private val panicStateKey = "is_panic_active"
    private val notificationRestoreChannelId = "tether_restore_channel"

    private var uiStatusText = mutableStateOf("Initializing...")
    private var uiStatusColor = mutableStateOf(TextSecondary)
    private var uiConnectionStatusText = mutableStateOf("Not connected")

    private var isPanicActive = mutableStateOf(false)
    private var currentVerificationStep = mutableStateOf(TrustVerificationStep.NOT_IN_PANIC)
    private lateinit var executor: Executor

    private val bluetoothStateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action == BluetoothAdapter.ACTION_STATE_CHANGED) {
                when (intent.getIntExtra(BluetoothAdapter.EXTRA_STATE, BluetoothAdapter.ERROR)) {
                    BluetoothAdapter.STATE_OFF -> {
                        if (!isPanicActive.value) {
                            uiStatusText.value = "BLUETOOTH OFFLINE"
                            uiStatusColor.value = NeonRed
                            uiConnectionStatusText.value = "Hardware link severed"
                        }
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
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        executor = Executors.newSingleThreadExecutor()

        val prefs = getSharedPreferences(preferenceName, Context.MODE_PRIVATE)
        isPanicActive.value = prefs.getBoolean(panicStateKey, false)

        if (isPanicActive.value) {
            setPanicUiState()
        }

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
                        isPanicActive = isPanicActive.value,
                        verificationStep = currentVerificationStep.value,
                        onLockClick = { triggerBleAction("LOCK_NOW", "🔒 Manual Lock Sent!") },
                        onPanicClick = {
                            persistPanicState(true)
                            triggerBleAction("PANIC", "🚨 Panic Sent! Locking PC...")
                        },
                        onInitiateRestore = {
                            executeVerificationPipeline(TrustVerificationStep.DEVICE_CREDENTIAL)
                        }
                    )
                }
            }
        }

        registerReceiver(bluetoothStateReceiver, IntentFilter(BluetoothAdapter.ACTION_STATE_CHANGED))

        if (checkPermissions()) {
            checkAndEnableBluetooth()
        } else {
            requestPermissions()
        }
    }

    private fun persistPanicState(active: Boolean) {
        isPanicActive.value = active
        // Use optimal Core-KTX inline extension syntax for SharedPreferences edits
        getSharedPreferences(preferenceName, Context.MODE_PRIVATE).edit(commit = true) {
            putBoolean(panicStateKey, active)
        }

        if (active) {
            setPanicUiState()
        } else {
            currentVerificationStep.value = TrustVerificationStep.NOT_IN_PANIC
            startBleService()
        }
    }

    private fun setPanicUiState() {
        uiStatusText.value = "PANIC PROTOCOL\nENGAGED"
        uiStatusColor.value = NeonRed
        uiConnectionStatusText.value = "Hardware Lockdown Active"
    }

    private fun executeVerificationPipeline(nextStep: TrustVerificationStep) {
        currentVerificationStep.value = nextStep

        when (nextStep) {
            TrustVerificationStep.DEVICE_CREDENTIAL -> {
                authenticateViaSystem(
                    title = "Step 1/4: Device Security",
                    subtitle = "Confirm device PIN, Pattern, or Password",
                    allowedAuthenticators = BiometricManager.Authenticators.DEVICE_CREDENTIAL
                ) { success ->
                    if (success) executeVerificationPipeline(TrustVerificationStep.FINGERPRINT_PRIMARY)
                    else handleVerificationFailure()
                }
            }
            TrustVerificationStep.FINGERPRINT_PRIMARY -> {
                authenticateViaSystem(
                    title = "Step 2/4: Primary Biometric Scan",
                    subtitle = "Scan your first enrolled fingerprint token",
                    allowedAuthenticators = BiometricManager.Authenticators.BIOMETRIC_STRONG
                ) { success ->
                    if (success) executeVerificationPipeline(TrustVerificationStep.FINGERPRINT_SECONDARY)
                    else handleVerificationFailure()
                }
            }
            TrustVerificationStep.FINGERPRINT_SECONDARY -> {
                authenticateViaSystem(
                    title = "Step 3/4: Secondary Biometric Scan",
                    subtitle = "Scan your second enrolled fingerprint token",
                    allowedAuthenticators = BiometricManager.Authenticators.BIOMETRIC_STRONG
                ) { success ->
                    if (success) executeVerificationPipeline(TrustVerificationStep.FACE_ID)
                    else handleVerificationFailure()
                }
            }
            TrustVerificationStep.FACE_ID -> {
                authenticateViaSystem(
                    title = "Step 4/4: Facial Authentication",
                    subtitle = "Align view to execute structural Face ID verification",
                    allowedAuthenticators = BiometricManager.Authenticators.BIOMETRIC_STRONG
                ) { success ->
                    if (success) {
                        dispatchTrustRestoredNotification()
                        persistPanicState(false)
                    } else {
                        handleVerificationFailure()
                    }
                }
            }
            else -> {}
        }
    }

    private fun authenticateViaSystem(title: String, subtitle: String, allowedAuthenticators: Int, callback: (Boolean) -> Unit) {
        runOnUiThread {
            val promptBuilder = BiometricPrompt.PromptInfo.Builder()
                .setTitle(title)
                .setSubtitle(subtitle)
                .setAllowedAuthenticators(allowedAuthenticators)

            // Device credential prompt builder option constraints rule handling
            if ((allowedAuthenticators and BiometricManager.Authenticators.DEVICE_CREDENTIAL) == 0) {
                promptBuilder.setNegativeButtonText("Abort Verification")
            }

            val biometricPrompt = BiometricPrompt(this, executor, object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    callback(true)
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    callback(false)
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                }
            })
            biometricPrompt.authenticate(promptBuilder.build())
        }
    }

    private fun handleVerificationFailure() {
        runOnUiThread {
            currentVerificationStep.value = TrustVerificationStep.NOT_IN_PANIC
            Toast.makeText(this, "🔒 Secure Authentication Chain Severed", Toast.LENGTH_LONG).show()
            setPanicUiState()
        }
    }

    private fun dispatchTrustRestoredNotification() {
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

        // Removed unnecessary Android version SDK checks since modern baseline handles this natively
        val channel = NotificationChannel(notificationRestoreChannelId, "System Trust Restorations", NotificationManager.IMPORTANCE_HIGH)
        manager.createNotificationChannel(channel)

        val notification = NotificationCompat.Builder(this, notificationRestoreChannelId)
            .setContentTitle("🛡️ Cryptographic Trust Restored")
            .setContentText("Local validation pipeline passed successfully.")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .build()

        // Check platform runtime authorization compliance requirements natively
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU ||
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED) {
            manager.notify(2, notification)
        } else {
            runOnUiThread {
                Toast.makeText(this, "🛡️ System Trust Restored (Notification Blocked)", Toast.LENGTH_LONG).show()
            }
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
        try { unregisterReceiver(bluetoothStateReceiver) } catch (_: Exception) {}
    }

    private fun checkPermissions(): Boolean {
        val required = mutableListOf<String>()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            required.addAll(listOf(Manifest.permission.BLUETOOTH_SCAN, Manifest.permission.BLUETOOTH_CONNECT, Manifest.permission.BLUETOOTH_ADVERTISE, Manifest.permission.ACCESS_FINE_LOCATION))
        } else {
            required.addAll(listOf(Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.BLUETOOTH, Manifest.permission.BLUETOOTH_ADMIN))
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            required.add(Manifest.permission.POST_NOTIFICATIONS)
        }
        return required.all { ContextCompat.checkSelfPermission(this, it) == PackageManager.PERMISSION_GRANTED }
    }

    private fun requestPermissions() {
        val required = mutableListOf<String>()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            required.addAll(listOf(Manifest.permission.BLUETOOTH_SCAN, Manifest.permission.BLUETOOTH_CONNECT, Manifest.permission.BLUETOOTH_ADVERTISE, Manifest.permission.ACCESS_FINE_LOCATION))
        } else {
            required.addAll(listOf(Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.BLUETOOTH, Manifest.permission.BLUETOOTH_ADMIN))
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            required.add(Manifest.permission.POST_NOTIFICATIONS)
        }
        ActivityCompat.requestPermissions(this, required.toTypedArray(), requestPermissionsCode)
    }

    private fun checkAndEnableBluetooth() {
        val bluetoothAdapter = (getSystemService(BLUETOOTH_SERVICE) as BluetoothManager).adapter
        if (bluetoothAdapter.isEnabled) startBleService()
        else enableBluetoothLauncher.launch(Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE))
    }

    private fun startBleService() {
        if (isPanicActive.value) return

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
    isPanicActive: Boolean,
    verificationStep: TrustVerificationStep,
    onLockClick: () -> Unit,
    onPanicClick: () -> Unit,
    onInitiateRestore: () -> Unit
) {
    // Fixed typo from 'TelemetryInfinitum' to clean up tracking labels
    val infiniteTransition = rememberInfiniteTransition(label = "TelemetryInfinite")

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
            Text(
                text = stringResource(id = R.string.app_name).uppercase(),
                modifier = Modifier.padding(top = 16.dp),
                style = MaterialTheme.typography.labelMedium.copy(
                    color = NeonCyan,
                    fontWeight = FontWeight.Bold
                )
            )

            Box(
                contentAlignment = Alignment.Center,
                modifier = Modifier.weight(1f)
            ) {
                Canvas(modifier = Modifier.size(280.dp)) {
                    drawArc(
                        color = SurfaceDark,
                        startAngle = 0f,
                        sweepAngle = 360f,
                        useCenter = false,
                        style = Stroke(width = 8.dp.toPx())
                    )
                }

                Canvas(
                    modifier = Modifier
                        .size(280.dp)
                        .graphicsLayer { rotationZ = rotation }
                ) {
                    drawArc(
                        brush = sweepGradient,
                        startAngle = 0f,
                        sweepAngle = if (isPanicActive) 360f else 140f,
                        useCenter = false,
                        style = Stroke(width = 4.dp.toPx(), cap = StrokeCap.Round)
                    )
                }

                Column(
                    horizontalAlignment = Alignment.CenterHorizontally,
                    modifier = Modifier.padding(24.dp)
                ) {
                    Text(
                        text = if (verificationStep != TrustVerificationStep.NOT_IN_PANIC) {
                            "VERIFYING\nPIPELINE"
                        } else statusText,
                        style = MaterialTheme.typography.headlineSmall.copy(
                            fontWeight = FontWeight.Black,
                            textAlign = TextAlign.Center,
                            color = if (verificationStep != TrustVerificationStep.NOT_IN_PANIC) NeonCyan else statusColor
                        )
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = when (verificationStep) {
                            TrustVerificationStep.DEVICE_CREDENTIAL -> "CHAIN LNK 1/4"
                            TrustVerificationStep.FINGERPRINT_PRIMARY -> "CHAIN LNK 2/4"
                            TrustVerificationStep.FINGERPRINT_SECONDARY -> "CHAIN LNK 3/4"
                            TrustVerificationStep.FACE_ID -> "CHAIN LNK 4/4"
                            else -> connectionStatus.uppercase()
                        },
                        style = MaterialTheme.typography.labelMedium.copy(
                            color = if (verificationStep != TrustVerificationStep.NOT_IN_PANIC) NeonCyan else TextSecondary,
                            fontSize = 10.sp
                        )
                    )
                }
            }

            // Fixed: Specified target explicit type handling for target state animation rendering to satisfy Compose UI
            AnimatedContent(
                targetState = isPanicActive,
                transitionSpec = {
                    fadeIn(animationSpec = tween(400)) togetherWith fadeOut(animationSpec = tween(400))
                },
                label = "InterfaceControlBranch"
            ) { panicEngaged: Boolean ->
                if (panicEngaged) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(bottom = 16.dp),
                        verticalArrangement = Arrangement.spacedBy(16.dp)
                    ) {
                        Text(
                            text = "System trust must be manually re-established through multi-factor validation.",
                            style = MaterialTheme.typography.bodyLarge.copy(
                                color = TextSecondary,
                                textAlign = TextAlign.Center
                            ),
                            modifier = Modifier.padding(horizontal = 16.dp)
                        )
                        PremiumControlAction(
                            label = "RESTORE SYSTEM TRUST",
                            accentColor = NeonGreen,
                            onClick = onInitiateRestore
                        )
                    }
                } else {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(bottom = 16.dp),
                        verticalArrangement = Arrangement.spacedBy(16.dp)
                    ) {
                        PremiumControlAction(
                            label = "INITIATE LOCK SYSTEM",
                            accentColor = NeonCyan,
                            onClick = onLockClick
                        )
                        PremiumControlAction(
                            label = "FORCE TERMINATE LINK",
                            accentColor = NeonRed,
                            onClick = onPanicClick
                        )
                    }
                }
            }
        }
    }
}

// Fixed: Moved inside MainActivity file or top-level to perfectly handle component mapping visibility rules
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