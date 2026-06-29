package com.tether.phone

import android.Manifest
import android.annotation.SuppressLint
import android.app.KeyguardManager
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
import android.os.VibrationAttributes
import android.os.VibrationEffect
import android.os.Vibrator
import android.os.VibratorManager
import android.provider.Settings
import android.view.WindowManager
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
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Menu
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.draw.blur
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.nativeCanvas
import androidx.compose.ui.unit.Dp
import androidx.core.app.ActivityCompat
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import androidx.core.content.edit
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import com.tether.phone.ui.theme.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import java.io.File
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import kotlin.math.roundToInt

val EaseInOutSans = CubicBezierEasing(0.42f, 0f, 0.58f, 1f)

enum class TrustVerificationStep {
    NOT_IN_PANIC,
    DEVICE_CREDENTIAL,
    BIOMETRIC_FINGERPRINT
}

enum class AppScreen {
    TELEMETRY_DASHBOARD,
    SECURITY_SETTINGS,
    LAPTOP_CONTROL
}

enum class TrustTier(val label: String, val color: Color) {
    TRUSTED("CRYPTO-TRUSTED STATE", IntegrityGreen),
    ELEVATED_RISK("ELEVATED RISK MATRIX", MatrixGold),
    RESTRICTED("RESTRICTED ENVIRONMENT", AlertRed)
}

data class IntegrityReport(
    val score: Int,
    val tier: TrustTier,
    val isBootloaderLocked: Boolean,
    val isNotRooted: Boolean,
    val isDevOptionsDisabled: Boolean,
    val isUsbDebuggingDisabled: Boolean,
    val isAppIntegrityValid: Boolean,
    val isSecureLockscreenEnabled: Boolean
)

class MainActivity : FragmentActivity() {
    private val requestPermissionsCode = 101
    private val preferenceName = "tether_secure_prefs"
    private val panicStateKey = "is_panic_active"
    private val notificationRestoreChannelId = "tether_restore_channel"

    private val appLockEnabledKey = "app_lock_biometrics_enabled"
    private val appLockTimeoutKey = "app_lock_timeout_ms"
    private val appLockBackgroundTimestampKey = "app_lock_bg_timestamp"

    private val privacyMaskEnabledKey = "privacy_mask_enabled"
    private val blockScreenReadingKey = "block_screen_reading"
    private val hideInRecentsKey = "hide_in_recents"

    private var uiStatusText = mutableStateOf("Initializing...")
    private var uiStatusColor = mutableStateOf(TextSecondary)
    private var uiConnectionStatusText = mutableStateOf("Not connected")

    private var isPanicActive = mutableStateOf(false)
    private var currentVerificationStep = mutableStateOf(TrustVerificationStep.NOT_IN_PANIC)

    private var isAppLocked = mutableStateOf(false)
    private var isBiometricSettingEnabled = mutableStateOf(false)
    private var selectedTimeoutMs = mutableLongStateOf(0L)

    private var isPrivacyMaskEnabled = mutableStateOf(false)
    private var isBlockScreenReadingEnabled = mutableStateOf(false)
    private var isHideInRecentsEnabled = mutableStateOf(false)

    private var isEnvironmentRestricted = mutableStateOf(false)
    private var currentIntegrityScore = mutableIntStateOf(100)
    private var isLoading = mutableStateOf(true)

    private var pendingPowerAction = mutableStateOf<PowerAction?>(null)
    private data class PowerAction(val command: String, val toastMessage: String, val title: String)

    private lateinit var executor: Executor

    // Add this near your other class variables (e.g., below private lateinit var executor: Executor)
    private val gattStateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == "com.tether.phone.ACTION_GATT_STATE_CHANGED") {
                val count = intent.getIntExtra("extra_connection_count", 0)
                runOnUiThread {
                    if (count > 0) {
                        uiStatusText.value = "TETHER LINK ENFORCED"
                        uiStatusColor.value = IntegrityGreen
                        uiConnectionStatusText.value = "CONNECTED HOST NODES: $count"
                    } else {
                        if (!isPanicActive.value) {
                            uiStatusText.value = "BROADCAST ACTIVE"
                            uiStatusColor.value = LiquidCyan
                            uiConnectionStatusText.value = "AWAITING VERIFICATION STEP"
                        }
                    }
                }
            }
        }
    }

    private val bluetoothStateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action == BluetoothAdapter.ACTION_STATE_CHANGED) {
                when (intent.getIntExtra(BluetoothAdapter.EXTRA_STATE, BluetoothAdapter.ERROR)) {
                    BluetoothAdapter.STATE_OFF -> {
                        if (!isPanicActive.value) {
                            uiStatusText.value = "BLUETOOTH OFFLINE"
                            uiStatusColor.value = AlertRed
                            uiConnectionStatusText.value = "Hardware link severed"
                        }
                        stopService(Intent(this@MainActivity, BleGattServerService::class.java))
                    }
                    BluetoothAdapter.STATE_ON -> {
                        if (!isAppLocked.value && checkPermissions()) startBleService()
                    }
                }
            }
        }
    }

    private val enableBluetoothLauncher = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == RESULT_OK) startBleService()
        else {
            uiStatusText.value = "ACCESS DENIED"
            uiStatusColor.value = AlertRed
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        executor = Executors.newSingleThreadExecutor()

        val prefs = getSharedPreferences(preferenceName, MODE_PRIVATE)
        isPanicActive.value = prefs.getBoolean(panicStateKey, false)
        isBiometricSettingEnabled.value = prefs.getBoolean(appLockEnabledKey, false)
        selectedTimeoutMs.longValue = prefs.getLong(appLockTimeoutKey, 0L)

        isPrivacyMaskEnabled.value = prefs.getBoolean(privacyMaskEnabledKey, false)
        isBlockScreenReadingEnabled.value = prefs.getBoolean(blockScreenReadingKey, false)
        isHideInRecentsEnabled.value = prefs.getBoolean(hideInRecentsKey, false)

        applyWindowSecurityFlags()

        if (isPanicActive.value) {
            setPanicUiState()
        }

        // Start BLE service immediately with auto-public-key broadcast
        val shouldStartImmediately = !isBiometricSettingEnabled.value || selectedTimeoutMs.longValue > 0
        if (checkPermissions() && shouldStartImmediately) {
            startBleService()
        }

        // Run integrity check in background
        lifecycleScope.launch(Dispatchers.IO) {
            val report = DeviceIntegrityRegistry(this@MainActivity).runAttestationPipeline()
            withContext(Dispatchers.Main) {
                isLoading.value = false
                currentIntegrityScore.intValue = report.score
                if (report.score < 70) {
                    isEnvironmentRestricted.value = true
                    stopService(Intent(this@MainActivity, BleGattServerService::class.java))
                } else {
                    isEnvironmentRestricted.value = false
                    if (isBiometricSettingEnabled.value) {
                        isAppLocked.value = true
                        authenticateForAppUnlock()
                    }
                }
            }
        }

        setContent {
            TetherTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    Box(modifier = Modifier.fillMaxSize()) {
                        BackgroundGrid()
                        if (isLoading.value) {
                            Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                                CircularProgressIndicator(color = LiquidCyan, strokeWidth = 2.dp)
                                Text(
                                    "Initializing secure environment...",
                                    color = TextSecondary,
                                    style = MaterialTheme.typography.labelMedium,
                                    modifier = Modifier.padding(top = 16.dp)
                                )
                            }
                        } else if (isEnvironmentRestricted.value) {
                            CompromisedEnvironmentOverlay(score = currentIntegrityScore.intValue)
                        } else {
                            TetherNavigationShell(
                                statusText = uiStatusText.value,
                                statusColor = uiStatusColor.value,
                                connectionStatus = uiConnectionStatusText.value,
                                isPanicActive = isPanicActive.value,
                                verificationStep = currentVerificationStep.value,
                                isBiometricSettingEnabled = isBiometricSettingEnabled.value,
                                selectedTimeoutMs = selectedTimeoutMs.longValue,
                                isPrivacyMaskEnabled = isPrivacyMaskEnabled.value,
                                onUnlockClick = { triggerBleAction("unlock", "🔓 Unlock Command Sent!") },
                                onLockClick = { triggerBleAction("lock_now", "🔒 Manual Lock Sent!") },
                                onPanicClick = {
                                    persistPanicState(true)
                                    triggerBleAction("panic", "🚨 Panic Sent! Locking PC...")
                                },
                                onInitiateRestore = {
                                    executeVerificationPipeline(TrustVerificationStep.DEVICE_CREDENTIAL)
                                },
                                onSelectLaptop = { showLaptopSelectionDialog() },
                                onTriggerStepVerification = { step ->
                                    triggerSystemBiometricPrompt(step)
                                },
                                onBiometricSettingToggled = { enabled ->
                                    isBiometricSettingEnabled.value = enabled
                                    prefs.edit { putBoolean(appLockEnabledKey, enabled) }
                                    if (enabled) {
                                        isAppLocked.value = true
                                        authenticateForAppUnlock()
                                    }
                                },
                                onTimeoutChanged = { timeout ->
                                    selectedTimeoutMs.longValue = timeout
                                    prefs.edit { putLong(appLockTimeoutKey, timeout) }
                                },
                                onPrivacyMaskToggled = { enabled ->
                                    isPrivacyMaskEnabled.value = enabled
                                    isBlockScreenReadingEnabled.value = enabled
                                    isHideInRecentsEnabled.value = enabled
                                    prefs.edit {
                                        putBoolean(privacyMaskEnabledKey, enabled)
                                        putBoolean(blockScreenReadingKey, enabled)
                                        putBoolean(hideInRecentsKey, enabled)
                                    }
                                    applyWindowSecurityFlags()
                                },
                                onLaptopActionClick = { action, toastMessage ->
                                    val command = when (action) {
                                        "PWR_SLEEP" -> "sleep"
                                        "PWR_REBOOT" -> "reboot"
                                        "PWR_SHUTDOWN" -> "shutdown"
                                        "VOL_UP" -> "volume_up"
                                        "VOL_DOWN" -> "volume_down"
                                        "BRIGHT_UP" -> "brightness_up"
                                        "BRIGHT_DOWN" -> "brightness_down"
                                        else -> action.lowercase()
                                    }

                                    when (command) {
                                        "shutdown", "sleep", "reboot" -> {
                                            pendingPowerAction.value = PowerAction(
                                                command = command,
                                                toastMessage = toastMessage,
                                                title = "CONFIRM ${command.uppercase()} PROTOCOL"
                                            )
                                        }
                                        else -> {
                                            triggerBleAction(command, toastMessage)
                                        }
                                    }
                                }
                            )

                            pendingPowerAction.value?.let { action ->
                                CyberConfirmationDialog(
                                    title = action.title,
                                    message = "Are you sure you want to execute the ${action.command} directive on the target host?",
                                    onConfirm = {
                                        triggerBleAction(action.command, action.toastMessage)
                                        pendingPowerAction.value = null
                                    },
                                    onDismiss = { pendingPowerAction.value = null }
                                )
                            }

                            AnimatedVisibility(
                                visible = isAppLocked.value,
                                enter = fadeIn(animationSpec = tween(600, easing = EaseInOutSans)),
                                exit = fadeOut(animationSpec = tween(600, easing = EaseInOutSans))
                            ) {
                                FuturisticLockOverlay(
                                    onAuthorizeRequested = {
                                        authenticateForAppUnlock()
                                    }
                                )
                            }
                        }
                    }
                }
            }
        }

        ContextCompat.registerReceiver(
            this,
            bluetoothStateReceiver,
            IntentFilter(BluetoothAdapter.ACTION_STATE_CHANGED),
            ContextCompat.RECEIVER_EXPORTED
        )
        val filter = IntentFilter(Intent.ACTION_USER_PRESENT)
        ContextCompat.registerReceiver(this, screenUnlockReceiver, filter, ContextCompat.RECEIVER_EXPORTED)
        ContextCompat.registerReceiver(
            this,
            gattStateReceiver,
            IntentFilter("com.tether.phone.ACTION_GATT_STATE_CHANGED"),
            ContextCompat.RECEIVER_NOT_EXPORTED
        )
    }

    private fun applyWindowSecurityFlags() {
        runOnUiThread {
            val shouldProtectScreen = isPrivacyMaskEnabled.value && isBlockScreenReadingEnabled.value
            if (shouldProtectScreen) {
                window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
            } else {
                window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
            }
        }
    }

    private val screenUnlockReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action == Intent.ACTION_USER_PRESENT) {
                // Send "screen_unlock" command via BLE
                triggerBleAction("screen_unlock", "Screen unlocked")
            }
        }
    }

    override fun onStart() {
        super.onStart()
        if (isEnvironmentRestricted.value) return
        if (isPrivacyMaskEnabled.value && isBlockScreenReadingEnabled.value) {
            window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
        if (isBiometricSettingEnabled.value && !isAppLocked.value) {
            val prefs = getSharedPreferences(preferenceName, MODE_PRIVATE)
            val leftBackgroundAt = prefs.getLong(appLockBackgroundTimestampKey, 0L)
            if (selectedTimeoutMs.longValue == 0L) {
                isAppLocked.value = true
                authenticateForAppUnlock()
            } else if (leftBackgroundAt != 0L) {
                val elapsed = System.currentTimeMillis() - leftBackgroundAt
                if (elapsed >= selectedTimeoutMs.longValue) {
                    isAppLocked.value = true
                    authenticateForAppUnlock()
                }
            }
        }
    }

    override fun onStop() {
        super.onStop()
        if (isPrivacyMaskEnabled.value && isHideInRecentsEnabled.value) {
            window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
        if (isBiometricSettingEnabled.value) {
            val prefs = getSharedPreferences(preferenceName, MODE_PRIVATE)
            prefs.edit { putLong(appLockBackgroundTimestampKey, System.currentTimeMillis()) }
        }
    }

    override fun onDestroy() {
        try { unregisterReceiver(gattStateReceiver) } catch (_: Exception) {}
        super.onDestroy()
        unregisterReceiver(screenUnlockReceiver)
        try { unregisterReceiver(bluetoothStateReceiver) } catch (_: Exception) {}
    }

    private fun authenticateForAppUnlock() {
        authenticateViaSystem(
            title = "🌌 Cybernetic Decryption",
            subtitle = "Verify master biological sequence",
            allowedAuthenticators = BiometricManager.Authenticators.BIOMETRIC_STRONG
        ) { success ->
            if (success) {
                runOnUiThread {
                    isAppLocked.value = false
                    getSharedPreferences(preferenceName, MODE_PRIVATE).edit {
                        putLong(appLockBackgroundTimestampKey, 0L)
                    }
                    if (checkPermissions()) {
                        checkAndEnableBluetooth()
                    } else {
                        requestPermissions()
                    }
                }
            } else {
                runOnUiThread {
                    Toast.makeText(this, "🔴 Access Unauthorized", Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    private fun persistPanicState(active: Boolean) {
        isPanicActive.value = active
        getSharedPreferences(preferenceName, MODE_PRIVATE).edit(commit = true) {
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
        uiStatusColor.value = AlertRed
        uiConnectionStatusText.value = "Hardware Lockdown Active"
    }

    private fun executeVerificationPipeline(nextStep: TrustVerificationStep) {
        currentVerificationStep.value = nextStep
        if (nextStep == TrustVerificationStep.DEVICE_CREDENTIAL) {
            triggerSystemBiometricPrompt(nextStep)
        }
    }

    private fun triggerSystemBiometricPrompt(step: TrustVerificationStep) {
        when (step) {
            TrustVerificationStep.DEVICE_CREDENTIAL -> {
                authenticateViaSystem(
                    title = "Tier 1/2: Device Security",
                    subtitle = "Confirm master PIN, Pattern, or Password",
                    allowedAuthenticators = BiometricManager.Authenticators.DEVICE_CREDENTIAL
                ) { success ->
                    if (success) executeVerificationPipeline(TrustVerificationStep.BIOMETRIC_FINGERPRINT)
                    else handleVerificationFailure()
                }
            }
            TrustVerificationStep.BIOMETRIC_FINGERPRINT -> {
                authenticateViaSystem(
                    title = "Tier 2/2: Biometric Authentication",
                    subtitle = "Scan your registered security fingerprint token",
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
            if ((allowedAuthenticators and BiometricManager.Authenticators.DEVICE_CREDENTIAL) == 0) {
                promptBuilder.setNegativeButtonText("Abort")
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
        val manager = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        val channel = NotificationChannel(notificationRestoreChannelId, "System Trust Restorations", NotificationManager.IMPORTANCE_HIGH)
        manager.createNotificationChannel(channel)
        val notification = NotificationCompat.Builder(this, notificationRestoreChannelId)
            .setContentTitle("🛡️ Cryptographic Trust Restored")
            .setContentText("Local validation pipeline passed successfully.")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .setColor(IntegrityGreen.toArgb())
            .build()
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU ||
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED) {
            manager.notify(2, notification)
        } else {
            runOnUiThread {
                Toast.makeText(this, "🛡️ System Trust Restored (Notification Blocked)", Toast.LENGTH_SHORT).show()
            }
        }
    }

    @SuppressLint("MissingPermission")
    private fun showLaptopSelectionDialog() {
        try {
            val bluetoothManager = getSystemService(BluetoothManager::class.java)
            val adapter = bluetoothManager?.adapter
            if (adapter == null || !adapter.isEnabled) {
                Toast.makeText(this, "Bluetooth is off", Toast.LENGTH_SHORT).show()
                return
            }
            val pairedDevices = adapter.bondedDevices
            if (pairedDevices.isEmpty()) {
                Toast.makeText(this, "No paired devices found. Please pair your laptop first.", Toast.LENGTH_LONG).show()
                return
            }
            val deviceList = pairedDevices.map { "${it.name ?: "Unknown"} (${it.address})" }.toTypedArray()
            val deviceAddresses = pairedDevices.map { it.address }.toTypedArray()
            androidx.appcompat.app.AlertDialog.Builder(this)
                .setTitle("Select Your Laptop")
                .setItems(deviceList) { _, which ->
                    val mac = deviceAddresses[which]
                    getSharedPreferences(preferenceName, MODE_PRIVATE).edit {
                        putString("laptop_mac", mac)
                    }
                    Toast.makeText(this, "Selected: ${deviceList[which]}", Toast.LENGTH_SHORT).show()
                    Toast.makeText(this, "Make sure Tether service is running on laptop", Toast.LENGTH_LONG).show()
                }
                .setNegativeButton("Cancel", null)
                .show()
        } catch (e: Exception) {
            Toast.makeText(this, "Error: ${e.message}", Toast.LENGTH_SHORT).show()
        }
    }

    private fun triggerBleAction(action: String, toastMessage: String) {
        if (isEnvironmentRestricted.value || isAppLocked.value) return
        if (toastMessage.isNotEmpty()) {
            Toast.makeText(this, toastMessage, Toast.LENGTH_SHORT).show()
        }
        val serviceIntent = Intent(this, BleGattServerService::class.java).apply {
            this.action = action
        }
        startForegroundService(serviceIntent)
    }

    private fun checkPermissions(): Boolean {
        val required = mutableListOf<String>()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            required.addAll(listOf(
                Manifest.permission.BLUETOOTH_SCAN,
                Manifest.permission.BLUETOOTH_CONNECT,
                Manifest.permission.BLUETOOTH_ADVERTISE,
                Manifest.permission.ACCESS_FINE_LOCATION
            ))
        } else {
            required.addAll(listOf(
                Manifest.permission.ACCESS_FINE_LOCATION,
                Manifest.permission.BLUETOOTH,
                Manifest.permission.BLUETOOTH_ADMIN
            ))
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            required.add(Manifest.permission.POST_NOTIFICATIONS)
        }
        return required.all { ContextCompat.checkSelfPermission(this, it) == PackageManager.PERMISSION_GRANTED }
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == requestPermissionsCode) {
            if (grantResults.isNotEmpty() && grantResults.all { it == PackageManager.PERMISSION_GRANTED }) {
                if (!isAppLocked.value) {
                    checkAndEnableBluetooth()
                }
            } else {
                uiStatusText.value = "PERMISSIONS REQUIRED"
                uiStatusColor.value = AlertRed
                Toast.makeText(this, "BLE permissions must be granted", Toast.LENGTH_LONG).show()
            }
        }
    }

    private fun requestPermissions() {
        val required = mutableListOf<String>()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            required.addAll(listOf(
                Manifest.permission.BLUETOOTH_SCAN,
                Manifest.permission.BLUETOOTH_CONNECT,
                Manifest.permission.BLUETOOTH_ADVERTISE,
                Manifest.permission.ACCESS_FINE_LOCATION
            ))
        } else {
            required.addAll(listOf(
                Manifest.permission.ACCESS_FINE_LOCATION,
                Manifest.permission.BLUETOOTH,
                Manifest.permission.BLUETOOTH_ADMIN
            ))
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            required.add(Manifest.permission.POST_NOTIFICATIONS)
        }
        ActivityCompat.requestPermissions(this, required.toTypedArray(), requestPermissionsCode)
    }

    private fun checkAndEnableBluetooth() {
        val bluetoothManager = getSystemService(BluetoothManager::class.java)
        val bluetoothAdapter = bluetoothManager?.adapter ?: return
        if (bluetoothAdapter.isEnabled) startBleService()
        else enableBluetoothLauncher.launch(Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE))
    }

    private fun startBleService() {
        if (isPanicActive.value || isEnvironmentRestricted.value || isAppLocked.value) return

        val bleIntent = Intent(this, BleGattServerService::class.java)
        startForegroundService(bleIntent)

        uiStatusText.value = "TETHER ACTIVE\nSECURE MESH"
        uiStatusColor.value = IntegrityGreen
        uiConnectionStatusText.value = "Secure Broadcast Active"
    }
}

@Composable
fun GlassCard(
    modifier: Modifier = Modifier,
    alpha: Float = 0.08f,
    strokeAlpha: Float = 0.15f,
    edgeHighlight: Boolean = false,
    content: @Composable ColumnScope.() -> Unit
) {
    Box(
        modifier = modifier
            .clip(RoundedCornerShape(20.dp))
            .background(
                Brush.verticalGradient(
                    listOf(
                        Color.White.copy(alpha = alpha),
                        Color.White.copy(alpha = alpha * 0.5f)
                    )
                )
            )
            .border(
                width = 0.5.dp,
                brush = Brush.linearGradient(
                    listOf(
                        Color.White.copy(alpha = strokeAlpha),
                        Color.Transparent,
                        Color.White.copy(alpha = strokeAlpha * 0.3f)
                    )
                ),
                shape = RoundedCornerShape(20.dp)
            )
    ) {
        Column(
            modifier = Modifier
                .padding(20.dp)
                .fillMaxWidth(),
            content = content
        )
    }
}

@Composable
fun BackgroundGrid() {
    val infiniteTransition = rememberInfiniteTransition(label = "LiquidBackground")
    val gridAlpha by infiniteTransition.animateFloat(
        initialValue = 0.02f,
        targetValue = 0.06f,
        animationSpec = infiniteRepeatable(
            animation = tween(6000, easing = EaseInOutSans),
            repeatMode = RepeatMode.Reverse
        ), label = "Alpha"
    )
    val glowPositionX by infiniteTransition.animateFloat(
        initialValue = 0.2f,
        targetValue = 0.8f,
        animationSpec = infiniteRepeatable(
            animation = tween(15000, easing = EaseInOutSans),
            repeatMode = RepeatMode.Reverse
        ), label = "GlowX"
    )
    val glowPositionY by infiniteTransition.animateFloat(
        initialValue = 0.8f,
        targetValue = 0.2f,
        animationSpec = infiniteRepeatable(
            animation = tween(12000, easing = EaseInOutSans),
            repeatMode = RepeatMode.Reverse
        ), label = "GlowY"
    )

    Canvas(modifier = Modifier.fillMaxSize()) {
        val gridSize = 60.dp.toPx()
        val gridColor = LiquidCyan.copy(alpha = gridAlpha)
        
        var x = 0f
        while (x < size.width) {
            drawLine(gridColor, Offset(x, 0f), Offset(x, size.height), 0.5.dp.toPx())
            x += gridSize
        }
        var y = 0f
        while (y < size.height) {
            drawLine(gridColor, Offset(0f, y), Offset(size.width, y), 0.5.dp.toPx())
            y += gridSize
        }

        // Deep Liquid Glows
        drawCircle(
            brush = Brush.radialGradient(
                colors = listOf(LiquidCyan.copy(alpha = 0.05f), Color.Transparent),
                center = Offset(size.width * glowPositionX, size.height * glowPositionY),
                radius = 600.dp.toPx()
            ),
            center = Offset(size.width * glowPositionX, size.height * glowPositionY),
            radius = 600.dp.toPx()
        )
        
        drawCircle(
            brush = Brush.radialGradient(
                colors = listOf(IntegrityGreen.copy(alpha = 0.03f), Color.Transparent),
                center = Offset(size.width * (1f - glowPositionX), size.height * (1f - glowPositionY)),
                radius = 500.dp.toPx()
            ),
            center = Offset(size.width * (1f - glowPositionX), size.height * (1f - glowPositionY)),
            radius = 500.dp.toPx()
        )
    }
}

@Composable
fun CyberConfirmationDialog(
    title: String,
    message: String,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = SurfaceElevated,
        titleContentColor = TextPrimary,
        textContentColor = TextSecondary,
        modifier = Modifier.border(0.5.dp, GlassBorder, RoundedCornerShape(24.dp)),
        shape = RoundedCornerShape(24.dp),
        title = {
            Text(
                text = title,
                style = MaterialTheme.typography.titleLarge,
                color = AlertRed
            )
        },
        text = {
            Text(text = message, style = MaterialTheme.typography.bodyMedium)
        },
        confirmButton = {
            Button(
                onClick = onConfirm,
                colors = ButtonDefaults.buttonColors(containerColor = AlertRed.copy(alpha = 0.1f)),
                shape = RoundedCornerShape(12.dp),
                border = BorderStroke(0.5.dp, AlertRed)
            ) {
                Text("EXECUTE", color = AlertRed, style = MaterialTheme.typography.labelLarge)
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("ABORT", color = TextSecondary, style = MaterialTheme.typography.labelLarge)
            }
        }
    )
}

// ========================================================================
// Compose UI Components (unchanged from original - kept for completeness)
// ========================================================================

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TetherNavigationShell(
    statusText: String,
    statusColor: Color,
    connectionStatus: String,
    isPanicActive: Boolean,
    verificationStep: TrustVerificationStep,
    isBiometricSettingEnabled: Boolean,
    selectedTimeoutMs: Long,
    isPrivacyMaskEnabled: Boolean,
    onUnlockClick: () -> Unit,
    onLockClick: () -> Unit,
    onPanicClick: () -> Unit,
    onInitiateRestore: () -> Unit,
    onSelectLaptop: () -> Unit,
    onTriggerStepVerification: (TrustVerificationStep) -> Unit,
    onBiometricSettingToggled: (Boolean) -> Unit,
    onTimeoutChanged: (Long) -> Unit,
    onPrivacyMaskToggled: (Boolean) -> Unit,
    onLaptopActionClick: (String, String) -> Unit
) {
    val drawerState = rememberDrawerState(initialValue = DrawerValue.Closed)
    val scope = rememberCoroutineScope()
    var currentScreen by remember { mutableStateOf(AppScreen.TELEMETRY_DASHBOARD) }

    ModalNavigationDrawer(
        drawerState = drawerState,
        drawerContent = {
            ModalDrawerSheet(
                drawerContainerColor = Color.Transparent,
                drawerContentColor = TextSecondary,
                modifier = Modifier
                    .width(320.dp)
                    .fillMaxHeight()
            ) {
                Box(modifier = Modifier.fillMaxSize().background(DeepSpace.copy(alpha = 0.95f))) {
                    Column(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(24.dp)
                    ) {
                        Spacer(modifier = Modifier.height(48.dp))
                        Text(
                            text = "COMMAND SYSTEM",
                            style = MaterialTheme.typography.labelMedium,
                            color = LiquidCyan,
                            modifier = Modifier.padding(horizontal = 12.dp, vertical = 16.dp)
                        )
                        NavigationDrawerItem(
                            label = { Text("DASHBOARD", style = MaterialTheme.typography.labelLarge) },
                            selected = currentScreen == AppScreen.TELEMETRY_DASHBOARD,
                            icon = { Icon(Icons.Default.Home, contentDescription = null) },
                            colors = NavigationDrawerItemDefaults.colors(
                                selectedContainerColor = LiquidCyan.copy(alpha = 0.1f),
                                unselectedContainerColor = Color.Transparent,
                                selectedIconColor = LiquidCyan,
                                unselectedIconColor = TextSecondary,
                                selectedTextColor = LiquidCyan,
                                unselectedTextColor = TextSecondary
                            ),
                            shape = RoundedCornerShape(12.dp),
                            onClick = {
                                currentScreen = AppScreen.TELEMETRY_DASHBOARD
                                scope.launch { drawerState.close() }
                            }
                        )
                        NavigationDrawerItem(
                            label = { Text("HARDWARE CONTROL", style = MaterialTheme.typography.labelLarge) },
                            selected = currentScreen == AppScreen.LAPTOP_CONTROL,
                            icon = { Icon(Icons.Default.Info, contentDescription = null) },
                            colors = NavigationDrawerItemDefaults.colors(
                                selectedContainerColor = LiquidCyan.copy(alpha = 0.1f),
                                unselectedContainerColor = Color.Transparent,
                                selectedIconColor = LiquidCyan,
                                unselectedIconColor = TextSecondary,
                                selectedTextColor = LiquidCyan,
                                unselectedTextColor = TextSecondary
                            ),
                            shape = RoundedCornerShape(12.dp),
                            onClick = {
                                currentScreen = AppScreen.LAPTOP_CONTROL
                                scope.launch { drawerState.close() }
                            }
                        )
                        NavigationDrawerItem(
                            label = { Text("SECURITY VAULT", style = MaterialTheme.typography.labelLarge) },
                            selected = currentScreen == AppScreen.SECURITY_SETTINGS,
                            icon = { Icon(Icons.Default.Settings, contentDescription = null) },
                            colors = NavigationDrawerItemDefaults.colors(
                                selectedContainerColor = LiquidCyan.copy(alpha = 0.1f),
                                unselectedContainerColor = Color.Transparent,
                                selectedIconColor = LiquidCyan,
                                unselectedIconColor = TextSecondary,
                                selectedTextColor = LiquidCyan,
                                unselectedTextColor = TextSecondary
                            ),
                            shape = RoundedCornerShape(12.dp),
                            onClick = {
                                currentScreen = AppScreen.SECURITY_SETTINGS
                                scope.launch { drawerState.close() }
                            }
                        )
                    }
                }
            }
        }
    ) {
        Scaffold(
            topBar = {
                TopAppBar(
                    title = {
                        Text(
                            text = "TETHER",
                            style = MaterialTheme.typography.headlineSmall,
                            color = TextPrimary
                        )
                    },
                    navigationIcon = {
                        IconButton(onClick = { scope.launch { drawerState.open() } }) {
                            Icon(
                                imageVector = Icons.Default.Menu,
                                contentDescription = "Menu Open",
                                tint = LiquidCyan
                            )
                        }
                    },
                    actions = {
                        IconButton(onClick = onSelectLaptop) {
                            Icon(
                                imageVector = Icons.Default.Settings,
                                contentDescription = "Select Laptop",
                                tint = TextSecondary
                            )
                        }
                    },
                    colors = TopAppBarDefaults.topAppBarColors(containerColor = Color.Transparent)
                )
            },
            containerColor = Color.Transparent
        ) { paddingValues ->
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(paddingValues)
            ) {
                when (currentScreen) {
                    AppScreen.TELEMETRY_DASHBOARD -> {
                        TetherAppScreen(
                            statusText = statusText,
                            statusColor = statusColor,
                            connectionStatus = connectionStatus,
                            isPanicActive = isPanicActive,
                            verificationStep = verificationStep,
                            onUnlockClick = onUnlockClick,
                            onLockClick = onLockClick,
                            onPanicClick = onPanicClick,
                            onInitiateRestore = onInitiateRestore,
                            onSelectLaptop = onSelectLaptop,
                            onTriggerStepVerification = onTriggerStepVerification,
                            onBleActionRequested = onLaptopActionClick
                        )
                    }
                    AppScreen.SECURITY_SETTINGS -> {
                        SettingsScreen(
                            isBiometricEnabled = isBiometricSettingEnabled,
                            selectedTimeoutMs = selectedTimeoutMs,
                            isPrivacyMaskEnabled = isPrivacyMaskEnabled,
                            onBiometricToggled = onBiometricSettingToggled,
                            onTimeoutChanged = onTimeoutChanged,
                            onPrivacyMaskToggled = onPrivacyMaskToggled
                        )
                    }
                    AppScreen.LAPTOP_CONTROL -> {
                        LaptopControlScreen(onBleActionRequested = onLaptopActionClick)
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun SettingsScreen(
    isBiometricEnabled: Boolean,
    selectedTimeoutMs: Long,
    isPrivacyMaskEnabled: Boolean,
    onBiometricToggled: (Boolean) -> Unit,
    onTimeoutChanged: (Long) -> Unit,
    onPrivacyMaskToggled: (Boolean) -> Unit
) {
    val scrollState = rememberScrollState()
    val timeouts = listOf(
        "IMMEDIATE" to 0L,
        "1 MIN" to 60000L,
        "2 MIN" to 120000L,
        "10 MIN" to 600000L,
        "1 HR" to 3600000L
    )
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(scrollState)
            .padding(24.dp),
        verticalArrangement = Arrangement.Top
    ) {
        Text(
            text = "SYSTEM CONFIGURATION",
            style = MaterialTheme.typography.labelLarge,
            color = LiquidCyan,
            modifier = Modifier.padding(bottom = 24.dp)
        )
        GlassCard(
            modifier = Modifier.fillMaxWidth()
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "BIOMETRIC GATEWAY",
                        style = MaterialTheme.typography.titleLarge,
                        color = TextPrimary
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "Enforce biological pattern verification on application activation.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = TextSecondary
                    )
                }
                Switch(
                    checked = isBiometricEnabled,
                    onCheckedChange = onBiometricToggled,
                    colors = SwitchDefaults.colors(
                        checkedThumbColor = DeepSpace,
                        checkedTrackColor = LiquidCyan,
                        uncheckedThumbColor = TextMuted,
                        uncheckedTrackColor = SurfaceVeneer
                    )
                )
            }
            AnimatedVisibility(
                visible = isBiometricEnabled,
                enter = fadeIn() + expandVertically(),
                exit = fadeOut() + shrinkVertically()
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 24.dp)
                ) {
                    Text(
                        text = "LOCK INACTIVITY THRESHOLD",
                        style = MaterialTheme.typography.labelMedium,
                        color = LiquidCyan,
                        modifier = Modifier.padding(bottom = 16.dp)
                    )
                    FlowRow(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        timeouts.forEach { (label, value) ->
                            val isSelected = selectedTimeoutMs == value
                            Box(
                                modifier = Modifier
                                    .height(40.dp)
                                    .weight(1f)
                                    .clip(RoundedCornerShape(12.dp))
                                    .background(if (isSelected) LiquidCyan.copy(alpha = 0.1f) else Color.White.copy(alpha = 0.03f))
                                    .border(
                                        width = 0.5.dp,
                                        color = if (isSelected) LiquidCyan else GlassBorder,
                                        shape = RoundedCornerShape(12.dp)
                                    )
                                    .clickable { onTimeoutChanged(value) },
                                contentAlignment = Alignment.Center
                            ) {
                                Text(
                                    text = label,
                                    style = MaterialTheme.typography.labelMedium,
                                    color = if (isSelected) LiquidCyan else TextSecondary
                                )
                            }
                        }
                    }
                }
            }
        }
        Spacer(modifier = Modifier.height(24.dp))
        GlassCard(
            modifier = Modifier.fillMaxWidth()
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "UI HARDENING",
                        style = MaterialTheme.typography.titleLarge,
                        color = TextPrimary
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "Prevent interface capture and background caching.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = TextSecondary
                    )
                }
                Switch(
                    checked = isPrivacyMaskEnabled,
                    onCheckedChange = onPrivacyMaskToggled,
                    colors = SwitchDefaults.colors(
                        checkedThumbColor = DeepSpace,
                        checkedTrackColor = LiquidCyan,
                        uncheckedThumbColor = TextMuted,
                        uncheckedTrackColor = SurfaceVeneer
                    )
                )
            }
        }
        Spacer(modifier = Modifier.height(24.dp))
        DeviceAttestationCard(context = LocalContext.current)
    }
}

@Composable
fun DeviceAttestationCard(context: Context) {
    val evaluator = remember { DeviceIntegrityRegistry(context) }
    val report by produceState(
        initialValue = IntegrityReport(
            score = 100,
            tier = TrustTier.TRUSTED,
            isBootloaderLocked = true,
            isNotRooted = true,
            isDevOptionsDisabled = true,
            isUsbDebuggingDisabled = true,
            isAppIntegrityValid = true,
            isSecureLockscreenEnabled = true
        )
    ) {
        withContext(Dispatchers.IO) {
            value = evaluator.runAttestationPipeline()
        }
    }
    var showInfoDialog by remember { mutableStateOf(false) }
    GlassCard(
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Text(
                    text = "INTEGRITY CORE",
                    style = MaterialTheme.typography.labelLarge,
                    color = LiquidCyan
                )
                Spacer(modifier = Modifier.height(2.dp))
                Text(
                    text = report.tier.label,
                    style = MaterialTheme.typography.labelMedium,
                    color = report.tier.color
                )
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                IconButton(onClick = { showInfoDialog = true }) {
                    Icon(
                        imageVector = Icons.Default.Info,
                        contentDescription = "Analysis Breakdown",
                        tint = TextSecondary
                    )
                }
                Spacer(modifier = Modifier.width(8.dp))
                Column(horizontalAlignment = Alignment.End) {
                    Text(
                        text = "${report.score}",
                        style = MaterialTheme.typography.headlineMedium,
                        color = report.tier.color
                    )
                }
            }
        }
        Spacer(modifier = Modifier.height(16.dp))
        Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
            MetricRow(label = "BOOTLOADER STATE", pass = report.isBootloaderLocked)
            MetricRow(label = "ENVIRONMENT ROOT", pass = report.isNotRooted)
            MetricRow(label = "DEVELOPER MODULE", pass = report.isDevOptionsDisabled)
            MetricRow(label = "ADB INTERACTION", pass = report.isUsbDebuggingDisabled)
            MetricRow(label = "PACKAGE INTEGRITY", pass = report.isAppIntegrityValid)
            MetricRow(label = "SECURE LOCKSCREEN", pass = report.isSecureLockscreenEnabled)
        }
    }
    if (showInfoDialog) {
        AlertDialog(
            onDismissRequest = { showInfoDialog = false },
            containerColor = SurfaceElevated,
            titleContentColor = LiquidCyan,
            textContentColor = TextPrimary,
            modifier = Modifier.border(0.5.dp, GlassBorder, RoundedCornerShape(24.dp)),
            shape = RoundedCornerShape(24.dp),
            title = {
                Text(
                    text = "INTEGRITY VECTOR ANALYSIS",
                    style = MaterialTheme.typography.titleLarge
                )
            },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(20.dp)) {
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text(
                            text = "▲ VALIDATED PARAMETERS",
                            style = MaterialTheme.typography.labelMedium,
                            color = IntegrityGreen
                        )
                        if (report.isBootloaderLocked) AttestationBreakdownRow("Bootloader Secured", "+35", IntegrityGreen)
                        if (report.isNotRooted) AttestationBreakdownRow("No Root Detection", "+35", IntegrityGreen)
                        if (report.isDevOptionsDisabled) AttestationBreakdownRow("Dev Mode Halted", "+10", IntegrityGreen)
                        if (report.isUsbDebuggingDisabled) AttestationBreakdownRow("ADB Inactive", "+10", IntegrityGreen)
                        if (report.isAppIntegrityValid) AttestationBreakdownRow("Signature Verified", "+10", IntegrityGreen)
                        if (report.isSecureLockscreenEnabled) AttestationBreakdownRow("Lockscreen Active", "+10", IntegrityGreen)
                    }
                    val missingPointsExist = !report.isBootloaderLocked || !report.isNotRooted ||
                            !report.isDevOptionsDisabled || !report.isUsbDebuggingDisabled ||
                            !report.isAppIntegrityValid || !report.isSecureLockscreenEnabled
                    if (missingPointsExist) {
                        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text(
                                text = "▼ ENVIRONMENT FAULTS",
                                style = MaterialTheme.typography.labelMedium,
                                color = AlertRed
                            )
                            if (!report.isBootloaderLocked) AttestationBreakdownRow("Bootloader Unlocked", "0", AlertRed)
                            if (!report.isNotRooted) AttestationBreakdownRow("Root Rights Detected", "0", AlertRed)
                            if (!report.isDevOptionsDisabled) AttestationBreakdownRow("Developer Options Active", "0", AlertRed)
                            if (!report.isUsbDebuggingDisabled) AttestationBreakdownRow("ADB Connection Open", "0", AlertRed)
                            if (!report.isAppIntegrityValid) AttestationBreakdownRow("Invalid App Source", "0", AlertRed)
                            if (!report.isSecureLockscreenEnabled) AttestationBreakdownRow("No Pattern/PIN Lock", "0", AlertRed)
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(
                    onClick = { showInfoDialog = false }
                ) {
                    Text("DISMISS", style = MaterialTheme.typography.labelLarge, color = LiquidCyan)
                }
            }
        )
    }
}

@Composable
fun AttestationBreakdownRow(label: String, points: String, color: Color) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(text = label, color = TextSecondary, fontSize = 11.sp)
        Text(text = points, color = color, fontSize = 11.sp, fontWeight = FontWeight.Bold)
    }
}

@Composable
fun MetricRow(label: String, pass: Boolean) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
                modifier = Modifier
                    .size(8.dp)
                    .clip(CircleShape)
                    .background(if (pass) IntegrityGreen else AlertRed)
            )
            Spacer(modifier = Modifier.width(12.dp))
            Text(
                text = label,
                style = MaterialTheme.typography.bodyMedium,
                color = if (pass) TextPrimary else TextSecondary
            )
        }
        Text(
            text = if (pass) "SECURE" else "FAILED",
            style = MaterialTheme.typography.labelMedium,
            color = if (pass) IntegrityGreen else AlertRed
        )
    }
}

@Composable
fun CompromisedEnvironmentOverlay(score: Int) {
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(DeepSpace),
        contentAlignment = Alignment.Center
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            modifier = Modifier.padding(32.dp)
        ) {
            Text(
                text = "SECURITY LOCKDOWN",
                style = MaterialTheme.typography.labelLarge,
                color = AlertRed
            )
            Spacer(modifier = Modifier.height(48.dp))
            Box(
                contentAlignment = Alignment.Center,
                modifier = Modifier
                    .size(200.dp)
                    .drawBehind {
                        drawCircle(
                            color = AlertRed.copy(alpha = 0.05f),
                            radius = size.width / 2f,
                            style = Stroke(width = 1.dp.toPx())
                        )
                    }
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Text(
                        text = "$score",
                        style = MaterialTheme.typography.headlineLarge,
                        color = AlertRed
                    )
                    Text(
                        text = "TRUST INDEX",
                        style = MaterialTheme.typography.labelMedium,
                        color = TextSecondary
                    )
                }
            }
            Spacer(modifier = Modifier.height(48.dp))
            Text(
                text = "ENVIRONMENT RESTRICTED",
                style = MaterialTheme.typography.headlineMedium,
                color = TextPrimary
            )
            Spacer(modifier = Modifier.height(16.dp))
            Text(
                text = "Device integrity score has dropped below the safety threshold. All background services have been terminated to protect host systems.",
                style = MaterialTheme.typography.bodyMedium,
                color = TextSecondary,
                textAlign = TextAlign.Center
            )
            Spacer(modifier = Modifier.height(48.dp))
            GlassCard {
                Text(
                    text = "REMEDIAL ACTIONS",
                    style = MaterialTheme.typography.labelMedium,
                    color = AlertRed
                )
                Spacer(modifier = Modifier.height(12.dp))
                Text(
                    text = "• Disable Developer Options\n• Terminate ADB Debugging\n• Restore Factory Signature",
                    style = MaterialTheme.typography.bodyMedium,
                    color = TextSecondary,
                    lineHeight = 24.sp
                )
            }
        }
    }
}

@Composable
fun FuturisticLockOverlay(onAuthorizeRequested: () -> Unit) {
    val infiniteTransition = rememberInfiniteTransition(label = "LockMatrix")
    val pulse by infiniteTransition.animateFloat(
        initialValue = 0.7f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(2000, easing = EaseInOutSans),
            repeatMode = RepeatMode.Reverse
        ), label = "Pulse"
    )

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(DeepSpace.copy(alpha = 0.98f))
            .clickable(
                interactionSource = remember { MutableInteractionSource() },
                indication = null
            ) { onAuthorizeRequested() },
        contentAlignment = Alignment.Center
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Box(
                contentAlignment = Alignment.Center,
                modifier = Modifier.size(240.dp)
            ) {
                Canvas(modifier = Modifier.fillMaxSize()) {
                    drawCircle(
                        color = LiquidCyan.copy(alpha = 0.05f),
                        radius = (size.width / 2) * pulse
                    )
                    drawCircle(
                        color = LiquidCyan.copy(alpha = 0.1f),
                        radius = size.width / 2,
                        style = Stroke(width = 0.5.dp.toPx())
                    )
                }
                Text(
                    text = "🔒",
                    fontSize = 64.sp,
                    modifier = Modifier.graphicsLayer {
                        scaleX = pulse
                        scaleY = pulse
                    }
                )
            }
            Spacer(modifier = Modifier.height(32.dp))
            Text(
                text = "VAULT ENFORCED",
                style = MaterialTheme.typography.labelLarge,
                color = LiquidCyan
            )
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = "BIOLOGICAL MATRIX REQUIRED",
                style = MaterialTheme.typography.bodyMedium,
                color = TextSecondary
            )
            Spacer(modifier = Modifier.height(48.dp))
            Text(
                text = "TAP TO DECRYPT",
                style = MaterialTheme.typography.labelMedium,
                color = TextMuted,
                modifier = Modifier.graphicsLayer { alpha = pulse }
            )
        }
    }
}

@Composable
fun TetherAppScreen(
    statusText: String,
    statusColor: Color,
    connectionStatus: String,
    isPanicActive: Boolean,
    verificationStep: TrustVerificationStep,
    onUnlockClick: () -> Unit,
    onLockClick: () -> Unit,
    onPanicClick: () -> Unit,
    onInitiateRestore: () -> Unit,
    onSelectLaptop: () -> Unit,
    onTriggerStepVerification: (TrustVerificationStep) -> Unit,
    onBleActionRequested: (String, String) -> Unit
) {
    val infiniteTransition = rememberInfiniteTransition(label = "TelemetryInfinite")
    val rotation by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(
            animation = tween(12000, easing = LinearEasing)
        ), label = "TelemetryRotation"
    )
    val sweepGradient = remember(statusColor) {
        Brush.sweepGradient(
            0f to Color.Transparent,
            0.5f to statusColor,
            1f to Color.Transparent
        )
    }
    val scrollState = rememberScrollState()
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(scrollState)
            .padding(horizontal = 24.dp, vertical = 12.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Top
    ) {
        Box(
            contentAlignment = Alignment.Center,
            modifier = Modifier
                .size(300.dp)
                .padding(vertical = 24.dp)
        ) {
            // Refractive Orbitals
            Canvas(modifier = Modifier.size(260.dp)) {
                drawCircle(
                    brush = Brush.radialGradient(
                        colors = listOf(statusColor.copy(alpha = 0.05f), Color.Transparent),
                        center = center,
                        radius = size.width / 2
                    )
                )
            }
            Canvas(
                modifier = Modifier
                    .size(240.dp)
                    .graphicsLayer { rotationZ = rotation }
            ) {
                drawArc(
                    brush = sweepGradient,
                    startAngle = 0f,
                    sweepAngle = if (isPanicActive) 360f else 160f,
                    useCenter = false,
                    style = Stroke(width = 1.dp.toPx(), cap = StrokeCap.Round)
                )
            }
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                modifier = Modifier.padding(16.dp)
            ) {
                Text(
                    text = when (verificationStep) {
                        TrustVerificationStep.DEVICE_CREDENTIAL -> "VERIFYING\nMASTER CODE"
                        TrustVerificationStep.BIOMETRIC_FINGERPRINT -> "BIOMETRIC\nIDENTITY MATCH"
                        else -> statusText
                    },
                    style = MaterialTheme.typography.headlineSmall,
                    textAlign = TextAlign.Center,
                    color = if (verificationStep != TrustVerificationStep.NOT_IN_PANIC) LiquidCyan else statusColor
                )
                Spacer(modifier = Modifier.height(12.dp))
                val displayStatus = when (verificationStep) {
                    TrustVerificationStep.DEVICE_CREDENTIAL -> "PROTOCOL TIER 1"
                    TrustVerificationStep.BIOMETRIC_FINGERPRINT -> "PROTOCOL TIER 2"
                    else -> connectionStatus.uppercase()
                }
                Text(
                    text = displayStatus,
                    style = MaterialTheme.typography.labelMedium,
                    color = TextSecondary
                )
            }
        }

        Spacer(modifier = Modifier.height(12.dp))

        GlassCard {
            Text(
                text = "HOST DIRECTIVES",
                style = MaterialTheme.typography.labelMedium,
                color = TextMuted
            )
            Spacer(modifier = Modifier.height(20.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Box(modifier = Modifier.weight(1f)) {
                    PremiumControlAction(
                        label = "SLEEP",
                        accentColor = MatrixGold,
                        onClick = { onBleActionRequested("PWR_SLEEP", "💤 Dispatched: Sleep Command") }
                    )
                }
                Box(modifier = Modifier.weight(1f)) {
                    PremiumControlAction(
                        label = "REBOOT",
                        accentColor = TextPrimary,
                        onClick = { onBleActionRequested("PWR_REBOOT", "🔄 Dispatched: Reboot Command") }
                    )
                }
                Box(modifier = Modifier.weight(1f)) {
                    PremiumControlAction(
                        label = "HALT",
                        accentColor = AlertRed,
                        onClick = { onBleActionRequested("PWR_SHUTDOWN", "🚨 Dispatched: Shutdown Command") }
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(24.dp))

        AnimatedContent(
            targetState = verificationStep,
            transitionSpec = {
                fadeIn(animationSpec = tween(400)) togetherWith fadeOut(animationSpec = tween(400))
            },
            label = "ActionSuite"
        ) { step ->
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                when (step) {
                    TrustVerificationStep.NOT_IN_PANIC -> {
                        if (isPanicActive) {
                            Text(
                                text = "System trust compromised. Local validation required to restore link.",
                                style = MaterialTheme.typography.bodyMedium,
                                color = TextSecondary,
                                textAlign = TextAlign.Center,
                                modifier = Modifier.padding(horizontal = 24.dp)
                            )
                            PremiumControlAction(
                                label = "RESTORE TRUST",
                                accentColor = IntegrityGreen,
                                onClick = onInitiateRestore
                            )
                        } else {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(12.dp)
                            ) {
                                Box(modifier = Modifier.weight(1f)) {
                                    PremiumControlAction(
                                        label = "UNLOCK",
                                        accentColor = IntegrityGreen,
                                        onClick = onUnlockClick
                                    )
                                }
                                Box(modifier = Modifier.weight(1f)) {
                                    PremiumControlAction(
                                        label = "LOCK",
                                        accentColor = LiquidCyan,
                                        onClick = onLockClick
                                    )
                                }
                            }
                            PremiumControlAction(
                                label = "SELECT HOST",
                                accentColor = TextSecondary,
                                onClick = onSelectLaptop
                            )
                            PremiumControlAction(
                                label = "EMERGENCY DISCONNECT",
                                accentColor = AlertRed,
                                onClick = onPanicClick
                            )
                        }
                    }
                    TrustVerificationStep.DEVICE_CREDENTIAL -> {
                        Box(modifier = Modifier.fillMaxWidth().height(100.dp), contentAlignment = Alignment.Center) {
                            CircularProgressIndicator(color = LiquidCyan, strokeWidth = 1.dp)
                        }
                    }
                    TrustVerificationStep.BIOMETRIC_FINGERPRINT -> {
                        Text(
                            text = "Awaiting biological matrix match...",
                            style = MaterialTheme.typography.bodyMedium,
                            color = LiquidCyan,
                            textAlign = TextAlign.Center,
                            modifier = Modifier.fillMaxWidth()
                        )
                        PremiumControlAction(
                            label = "VERIFY IDENTITY",
                            accentColor = LiquidCyan,
                            onClick = { onTriggerStepVerification(TrustVerificationStep.BIOMETRIC_FINGERPRINT) }
                        )
                    }
                }
            }
        }
        Spacer(modifier = Modifier.height(32.dp))
    }
}

@Composable
fun PremiumControlAction(
    label: String,
    accentColor: Color,
    onClick: () -> Unit
) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .height(52.dp)
            .clip(RoundedCornerShape(12.dp))
            .background(accentColor.copy(alpha = 0.08f))
            .border(
                width = 0.5.dp,
                color = accentColor.copy(alpha = 0.4f),
                shape = RoundedCornerShape(12.dp)
            )
            .clickable { onClick() },
        contentAlignment = Alignment.Center
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.labelLarge,
            color = accentColor
        )
    }
}

class DeviceIntegrityRegistry(private val context: Context) {
    fun runAttestationPipeline(): IntegrityReport {
        var finalScore = 0
        val bootloaderLocked = checkBootloaderStatus()
        if (bootloaderLocked) finalScore += 35
        val notRooted = !checkRootStatus()
        if (notRooted) finalScore += 35
        val devOptionsDisabled = Settings.Global.getInt(
            context.contentResolver,
            Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0
        ) == 0
        if (devOptionsDisabled) finalScore += 10
        val usbDebuggingDisabled = Settings.Global.getInt(
            context.contentResolver,
            Settings.Global.ADB_ENABLED, 0
        ) == 0
        if (usbDebuggingDisabled) finalScore += 10
        val appIntegrityValid = verifyAppSignatureIntegrity()
        if (appIntegrityValid) finalScore += 10
        val km = context.getSystemService(KeyguardManager::class.java)
        val secureLockscreenEnabled = km?.isDeviceSecure ?: false
        if (secureLockscreenEnabled) finalScore += 10
        val assignedTier = when (finalScore) {
            in 100..110 -> TrustTier.TRUSTED
            in 85..99 -> TrustTier.ELEVATED_RISK
            else -> TrustTier.RESTRICTED
        }
        return IntegrityReport(
            score = finalScore,
            tier = assignedTier,
            isBootloaderLocked = bootloaderLocked,
            isNotRooted = notRooted,
            isDevOptionsDisabled = devOptionsDisabled,
            isUsbDebuggingDisabled = usbDebuggingDisabled,
            isAppIntegrityValid = appIntegrityValid,
            isSecureLockscreenEnabled = secureLockscreenEnabled
        )
    }
    private fun checkBootloaderStatus(): Boolean {
        val aboot = Build.BOOTLOADER.lowercase()
        return aboot.isNotEmpty() && !aboot.contains("unknown") && !aboot.contains("unlocked")
    }
    private fun checkRootStatus(): Boolean {
        val tags = Build.TAGS
        if (tags != null && tags.contains("test-keys")) return true
        val commonPaths = arrayOf(
            "/system/app/Superuser.apk", "/sbin/su", "/system/bin/su",
            "/system/xbin/su", "/data/local/xbin/su", "/data/local/bin/su",
            "/system/sd/xbin/su", "/system/bin/failsafe/su", "/data/local/su"
        )
        for (path in commonPaths) {
            if (File(path).exists()) return true
        }
        return false
    }
    private fun verifyAppSignatureIntegrity(): Boolean {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                val info = context.packageManager.getInstallSourceInfo(context.packageName)
                info.installingPackageName != null
            } else {
                @Suppress("DEPRECATION")
                val installer = context.packageManager.getInstallerPackageName(context.packageName)
                !installer.isNullOrEmpty()
            } || Build.FINGERPRINT.startsWith("generic")
        } catch (_: Exception) {
            false
        }
    }
}

@Composable
fun LaptopControlScreen(
    onBleActionRequested: (String, String) -> Unit
) {
    val context = LocalContext.current
    val vibrator = remember {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            val vibratorManager = context.getSystemService(VibratorManager::class.java)
            vibratorManager?.defaultVibrator
        } else {
            @Suppress("DEPRECATION")
            context.getSystemService(Vibrator::class.java)
        }
    }
    fun triggerSubtleSliderTick() {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                val effect = VibrationEffect.createPredefined(VibrationEffect.EFFECT_TICK)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    val attributes = VibrationAttributes.Builder()
                        .setUsage(VibrationAttributes.USAGE_TOUCH)
                        .build()
                    vibrator?.vibrate(effect, attributes)
                } else {
                    vibrator?.vibrate(effect)
                }
            } else {
                @Suppress("DEPRECATION")
                vibrator?.vibrate(8)
            }
        } catch (_: Exception) {}
    }
    var volumeValue by remember { mutableFloatStateOf(50f) }
    var brightnessValue by remember { mutableFloatStateOf(50f) }
    val scrollState = rememberScrollState()
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(scrollState)
            .padding(24.dp),
        verticalArrangement = Arrangement.Top
    ) {
        Text(
            text = "HARDWARE INTERFACE",
            style = MaterialTheme.typography.labelLarge,
            color = LiquidCyan,
            modifier = Modifier.padding(bottom = 24.dp)
        )
        GlassCard(
            modifier = Modifier.fillMaxWidth()
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "MASTER VOLUME",
                    style = MaterialTheme.typography.titleLarge,
                    color = TextPrimary
                )
                Text(
                    text = "${volumeValue.roundToInt()}%",
                    style = MaterialTheme.typography.headlineSmall,
                    color = LiquidCyan
                )
            }
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = "Synchronous host audio module adjustment.",
                style = MaterialTheme.typography.bodyMedium,
                color = TextSecondary
            )
            Spacer(modifier = Modifier.height(24.dp))
            Slider(
                value = volumeValue,
                onValueChange = { nextVolume ->
                    val oldInt = volumeValue.roundToInt()
                    val nextInt = nextVolume.roundToInt()
                    if (oldInt != nextInt) {
                        volumeValue = nextVolume
                        triggerSubtleSliderTick()
                        if (nextInt > oldInt) {
                            onBleActionRequested("VOL_UP", "")
                        } else {
                            onBleActionRequested("VOL_DOWN", "")
                        }
                    }
                },
                valueRange = 0f..100f,
                colors = SliderDefaults.colors(
                    activeTrackColor = LiquidCyan,
                    inactiveTrackColor = Color.White.copy(alpha = 0.05f),
                    thumbColor = TextPrimary
                )
            )
        }
        Spacer(modifier = Modifier.height(24.dp))
        GlassCard(
            modifier = Modifier.fillMaxWidth()
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "BRIGHTNESS MATRIX",
                    style = MaterialTheme.typography.titleLarge,
                    color = TextPrimary
                )
                Text(
                    text = "${brightnessValue.roundToInt()}%",
                    style = MaterialTheme.typography.headlineSmall,
                    color = LiquidCyan
                )
            }
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = "Backlight array intensity variable control.",
                style = MaterialTheme.typography.bodyMedium,
                color = TextSecondary
            )
            Spacer(modifier = Modifier.height(24.dp))
            Slider(
                value = brightnessValue,
                onValueChange = { nextBrightness ->
                    val oldInt = brightnessValue.roundToInt()
                    val nextInt = nextBrightness.roundToInt()
                    if (oldInt != nextInt) {
                        brightnessValue = nextBrightness
                        triggerSubtleSliderTick()
                        if (nextInt > oldInt) {
                            onBleActionRequested("BRIGHT_UP", "")
                        } else {
                            onBleActionRequested("BRIGHT_DOWN", "")
                        }
                    }
                },
                valueRange = 0f..100f,
                colors = SliderDefaults.colors(
                    activeTrackColor = LiquidCyan,
                    inactiveTrackColor = Color.White.copy(alpha = 0.05f),
                    thumbColor = TextPrimary
                )
            )
        }
    }
}