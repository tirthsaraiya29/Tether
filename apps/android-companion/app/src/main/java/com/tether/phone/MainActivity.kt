package com.tether.phone

import android.Manifest
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
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalContext
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
import kotlinx.coroutines.launch
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
    TRUSTED("TRUSTED NODAL STATE", NeonGreen),
    ELEVATED_RISK("ELEVATED RISK MATRIX", Color(0xFFFFB300)),
    RESTRICTED("RESTRICTED ENVIRONMENT", NeonRed)
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

    // Core App Lock States
    private var isAppLocked = mutableStateOf(false)
    private var isBiometricSettingEnabled = mutableStateOf(false)
    private var selectedTimeoutMs = mutableStateOf(0L)

    // Privacy Overlay States
    private var isPrivacyMaskEnabled = mutableStateOf(false)
    private var isBlockScreenReadingEnabled = mutableStateOf(false)
    private var isHideInRecentsEnabled = mutableStateOf(false)

    // Hard Environment Lockdown States
    private var isEnvironmentRestricted = mutableStateOf(false)
    private var currentIntegrityScore = mutableStateOf(100)

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
            uiStatusColor.value = NeonRed
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        executor = Executors.newSingleThreadExecutor()

        val prefs = getSharedPreferences(preferenceName, Context.MODE_PRIVATE)
        isPanicActive.value = prefs.getBoolean(panicStateKey, false)
        isBiometricSettingEnabled.value = prefs.getBoolean(appLockEnabledKey, false)
        selectedTimeoutMs.value = prefs.getLong(appLockTimeoutKey, 0L)

        isPrivacyMaskEnabled.value = prefs.getBoolean(privacyMaskEnabledKey, false)
        isBlockScreenReadingEnabled.value = prefs.getBoolean(blockScreenReadingKey, false)
        isHideInRecentsEnabled.value = prefs.getBoolean(hideInRecentsKey, false)

        applyWindowSecurityFlags()
        evaluateDeviceIntegrity()

        if (isPanicActive.value) {
            setPanicUiState()
        }

        if (isBiometricSettingEnabled.value && !isEnvironmentRestricted.value) {
            isAppLocked.value = true
            authenticateForAppUnlock()
        } else {
            if (checkPermissions()) {
                checkAndEnableBluetooth()
            } else {
                requestPermissions()
            }
        }

        setContent {
            TetherTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    Box(modifier = Modifier.fillMaxSize()) {
                        if (isEnvironmentRestricted.value) {
                            CompromisedEnvironmentOverlay(score = currentIntegrityScore.value)
                        } else {
                            TetherNavigationShell(
                                statusText = uiStatusText.value,
                                statusColor = uiStatusColor.value,
                                connectionStatus = uiConnectionStatusText.value,
                                isPanicActive = isPanicActive.value,
                                verificationStep = currentVerificationStep.value,
                                isBiometricSettingEnabled = isBiometricSettingEnabled.value,
                                selectedTimeoutMs = selectedTimeoutMs.value,
                                isPrivacyMaskEnabled = isPrivacyMaskEnabled.value,
                                isBlockScreenReadingEnabled = isBlockScreenReadingEnabled.value,
                                isHideInRecentsEnabled = isHideInRecentsEnabled.value,
                                onUnlockClick = { triggerBleAction("UNLOCK", "🔓 Unlock Command Sent!") },
                                onLockClick = { triggerBleAction("LOCK_NOW", "🔒 Manual Lock Sent!") },
                                onPanicClick = {
                                    persistPanicState(true)
                                    triggerBleAction("PANIC", "🚨 Panic Sent! Locking PC...")
                                },
                                onInitiateRestore = {
                                    executeVerificationPipeline(TrustVerificationStep.DEVICE_CREDENTIAL)
                                },
                                onTriggerStepVerification = { step ->
                                    triggerSystemBiometricPrompt(step)
                                },
                                onBiometricSettingToggled = { enabled ->
                                    isBiometricSettingEnabled.value = enabled
                                    prefs.edit().putBoolean(appLockEnabledKey, enabled).apply()
                                    if (enabled) {
                                        isAppLocked.value = true
                                        authenticateForAppUnlock()
                                    }
                                },
                                onTimeoutChanged = { timeout ->
                                    selectedTimeoutMs.value = timeout
                                    prefs.edit().putLong(appLockTimeoutKey, timeout).apply()
                                },
                                onPrivacyMaskToggled = { enabled ->
                                    isPrivacyMaskEnabled.value = enabled
                                    prefs.edit().putBoolean(privacyMaskEnabledKey, enabled).apply()
                                    if (!enabled) {
                                        isBlockScreenReadingEnabled.value = false
                                        isHideInRecentsEnabled.value = false
                                        prefs.edit().putBoolean(blockScreenReadingKey, false)
                                            .putBoolean(hideInRecentsKey, false).apply()
                                    }
                                    applyWindowSecurityFlags()
                                },
                                onBlockScreenReadingToggled = { enabled ->
                                    isBlockScreenReadingEnabled.value = enabled
                                    prefs.edit().putBoolean(blockScreenReadingKey, enabled).apply()
                                    applyWindowSecurityFlags()
                                },
                                onHideInRecentsToggled = { enabled ->
                                    isHideInRecentsEnabled.value = enabled
                                    prefs.edit().putBoolean(hideInRecentsKey, enabled).apply()
                                    applyWindowSecurityFlags()
                                },
                                onLaptopActionClick = { action, toastMessage ->
                                    triggerBleAction(action, toastMessage)
                                }
                            )

                            AnimatedVisibility(
                                visible = isAppLocked.value,
                                enter = fadeIn(animationSpec = tween(400)) + scaleIn(initialScale = 0.85f),
                                exit = fadeOut(animationSpec = tween(400)) + scaleOut(targetScale = 0.85f)
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

        registerReceiver(bluetoothStateReceiver, IntentFilter(BluetoothAdapter.ACTION_STATE_CHANGED))
    }

    private fun evaluateDeviceIntegrity() {
        val report = DeviceIntegrityRegistry(this).runAttestationPipeline()
        currentIntegrityScore.value = report.score

        if (report.score < 70) {
            isEnvironmentRestricted.value = true
            stopService(Intent(this, BleGattServerService::class.java))
        } else {
            isEnvironmentRestricted.value = false
        }
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

    override fun onStart() {
        super.onStart()
        evaluateDeviceIntegrity()

        if (isEnvironmentRestricted.value) return

        if (isPrivacyMaskEnabled.value && isBlockScreenReadingEnabled.value) {
            window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }

        if (isBiometricSettingEnabled.value && !isAppLocked.value) {
            val prefs = getSharedPreferences(preferenceName, Context.MODE_PRIVATE)
            val leftBackgroundAt = prefs.getLong(appLockBackgroundTimestampKey, 0L)

            if (selectedTimeoutMs.value == 0L) {
                isAppLocked.value = true
                stopBleServiceLeak()
                authenticateForAppUnlock()
            } else if (leftBackgroundAt != 0L) {
                val elapsed = System.currentTimeMillis() - leftBackgroundAt
                if (elapsed >= selectedTimeoutMs.value) {
                    isAppLocked.value = true
                    stopBleServiceLeak()
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
            val prefs = getSharedPreferences(preferenceName, Context.MODE_PRIVATE)
            prefs.edit().putLong(appLockBackgroundTimestampKey, System.currentTimeMillis()).apply()
        }
    }

    private fun stopBleServiceLeak() {
        stopService(Intent(this, BleGattServerService::class.java))
        uiStatusText.value = "SECURITY GATE ACTIVE"
        uiStatusColor.value = TextSecondary
        uiConnectionStatusText.value = "Awaiting verification"
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
                    getSharedPreferences(preferenceName, Context.MODE_PRIVATE).edit()
                        .putLong(appLockBackgroundTimestampKey, 0L).apply()

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
        val channel = NotificationChannel(notificationRestoreChannelId, "System Trust Restorations", NotificationManager.IMPORTANCE_HIGH)
        manager.createNotificationChannel(channel)

        val notification = NotificationCompat.Builder(this, notificationRestoreChannelId)
            .setContentTitle("🛡️ Cryptographic Trust Restored")
            .setContentText("Local validation pipeline passed successfully.")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .build()

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
        if (isEnvironmentRestricted.value || isAppLocked.value) return

        // Suppress toasts for background automated tracking operations
        if (toastMessage.isNotEmpty()) {
            Toast.makeText(this, toastMessage, Toast.LENGTH_SHORT).show()
        }

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

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == requestPermissionsCode) {
            if (grantResults.isNotEmpty() && grantResults.all { it == PackageManager.PERMISSION_GRANTED }) {
                if (!isAppLocked.value) {
                    checkAndEnableBluetooth()
                }
            } else {
                uiStatusText.value = "PERMISSIONS REQUIRED"
                uiStatusColor.value = NeonRed
                Toast.makeText(this, "BLE parameters must be manually allowed on clean launch configs", Toast.LENGTH_LONG).show()
            }
        }
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
        val bluetoothManager = getSystemService(BluetoothManager::class.java)
        val bluetoothAdapter = bluetoothManager?.adapter
        if (bluetoothAdapter == null) return

        if (bluetoothAdapter.isEnabled) startBleService()
        else enableBluetoothLauncher.launch(Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE))
    }

    private fun startBleService() {
        if (isPanicActive.value || isEnvironmentRestricted.value || isAppLocked.value) return

        val serviceIntent = Intent(this, BleGattServerService::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) startForegroundService(serviceIntent)
        else startService(serviceIntent)

        uiStatusText.value = "TETHER ACTIVE\nSYSTEM SECURE"
        uiStatusColor.value = NeonGreen
        uiConnectionStatusText.value = "Secure Broadcast Active"
    }
}

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
    isBlockScreenReadingEnabled: Boolean,
    isHideInRecentsEnabled: Boolean,
    onUnlockClick: () -> Unit,
    onLockClick: () -> Unit,
    onPanicClick: () -> Unit,
    onInitiateRestore: () -> Unit,
    onTriggerStepVerification: (TrustVerificationStep) -> Unit,
    onBiometricSettingToggled: (Boolean) -> Unit,
    onTimeoutChanged: (Long) -> Unit,
    onPrivacyMaskToggled: (Boolean) -> Unit,
    onBlockScreenReadingToggled: (Boolean) -> Unit,
    onHideInRecentsToggled: (Boolean) -> Unit,
    onLaptopActionClick: (String, String) -> Unit
) {
    val drawerState = rememberDrawerState(initialValue = DrawerValue.Closed)
    val scope = rememberCoroutineScope()
    var currentScreen by remember { mutableStateOf(AppScreen.TELEMETRY_DASHBOARD) }

    ModalNavigationDrawer(
        drawerState = drawerState,
        drawerContent = {
            ModalDrawerSheet(
                drawerContainerColor = SpaceDark,
                drawerContentColor = TextSecondary,
                modifier = Modifier
                    .width(300.dp)
                    .fillMaxHeight()
                    .border(
                        width = 1.dp,
                        brush = Brush.verticalGradient(listOf(NeonCyan, Color.Transparent)),
                        shape = RoundedCornerShape(0.dp)
                    )
            ) {
                Spacer(modifier = Modifier.height(32.dp))
                Text(
                    text = "CORE NAV SYSTEM",
                    style = MaterialTheme.typography.labelSmall,
                    color = NeonCyan,
                    modifier = Modifier.padding(horizontal = 28.dp, vertical = 16.dp),
                    fontWeight = FontWeight.Bold,
                    letterSpacing = 2.sp
                )

                NavigationDrawerItem(
                    label = { Text("TELEMETRY MAIN", fontWeight = FontWeight.Bold, letterSpacing = 1.sp) },
                    selected = currentScreen == AppScreen.TELEMETRY_DASHBOARD,
                    icon = { Icon(Icons.Default.Home, contentDescription = null) },
                    colors = NavigationDrawerItemDefaults.colors(
                        selectedContainerColor = NeonCyan.copy(alpha = 0.1f),
                        unselectedContainerColor = Color.Transparent,
                        selectedIconColor = NeonCyan,
                        unselectedIconColor = TextSecondary,
                        selectedTextColor = NeonCyan,
                        unselectedTextColor = TextSecondary
                    ),
                    shape = RoundedCornerShape(0.dp),
                    onClick = {
                        currentScreen = AppScreen.TELEMETRY_DASHBOARD
                        scope.launch { drawerState.close() }
                    },
                    modifier = Modifier.padding(horizontal = 12.dp)
                )

                NavigationDrawerItem(
                    label = { Text("SLIDERS PANEL", fontWeight = FontWeight.Bold, letterSpacing = 1.sp) },
                    selected = currentScreen == AppScreen.LAPTOP_CONTROL,
                    icon = { Icon(Icons.Default.Info, contentDescription = null) },
                    colors = NavigationDrawerItemDefaults.colors(
                        selectedContainerColor = NeonCyan.copy(alpha = 0.1f),
                        unselectedContainerColor = Color.Transparent,
                        selectedIconColor = NeonCyan,
                        unselectedIconColor = TextSecondary,
                        selectedTextColor = NeonCyan,
                        unselectedTextColor = TextSecondary
                    ),
                    shape = RoundedCornerShape(0.dp),
                    onClick = {
                        currentScreen = AppScreen.LAPTOP_CONTROL
                        scope.launch { drawerState.close() }
                    },
                    modifier = Modifier.padding(horizontal = 12.dp)
                )

                NavigationDrawerItem(
                    label = { Text("SECURITY SETTINGS", fontWeight = FontWeight.Bold, letterSpacing = 1.sp) },
                    selected = currentScreen == AppScreen.SECURITY_SETTINGS,
                    icon = { Icon(Icons.Default.Settings, contentDescription = null) },
                    colors = NavigationDrawerItemDefaults.colors(
                        selectedContainerColor = NeonCyan.copy(alpha = 0.1f),
                        unselectedContainerColor = Color.Transparent,
                        selectedIconColor = NeonCyan,
                        unselectedIconColor = TextSecondary,
                        selectedTextColor = NeonCyan,
                        unselectedTextColor = TextSecondary
                    ),
                    shape = RoundedCornerShape(0.dp),
                    onClick = {
                        currentScreen = AppScreen.SECURITY_SETTINGS
                        scope.launch { drawerState.close() }
                    },
                    modifier = Modifier.padding(horizontal = 12.dp)
                )
            }
        }
    ) {
        Scaffold(
            topBar = {
                TopAppBar(
                    title = {},
                    navigationIcon = {
                        IconButton(onClick = { scope.launch { drawerState.open() } }) {
                            Icon(
                                imageVector = Icons.Default.Menu,
                                contentDescription = "Menu Open",
                                tint = NeonCyan
                            )
                        }
                    },
                    colors = TopAppBarDefaults.topAppBarColors(containerColor = SpaceDark)
                )
            },
            containerColor = SpaceDark
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
                            onTriggerStepVerification = onTriggerStepVerification,
                            onBleActionRequested = onLaptopActionClick
                        )
                    }
                    AppScreen.SECURITY_SETTINGS -> {
                        SettingsScreen(
                            isBiometricEnabled = isBiometricSettingEnabled,
                            selectedTimeoutMs = selectedTimeoutMs,
                            isPrivacyMaskEnabled = isPrivacyMaskEnabled,
                            isBlockScreenReadingEnabled = isBlockScreenReadingEnabled,
                            isHideInRecentsEnabled = isHideInRecentsEnabled,
                            onBiometricToggled = onBiometricSettingToggled,
                            onTimeoutChanged = onTimeoutChanged,
                            onPrivacyMaskToggled = onPrivacyMaskToggled,
                            onBlockScreenReadingToggled = onBlockScreenReadingToggled,
                            onHideInRecentsToggled = onHideInRecentsToggled
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
    isBlockScreenReadingEnabled: Boolean,
    isHideInRecentsEnabled: Boolean,
    onBiometricToggled: (Boolean) -> Unit,
    onTimeoutChanged: (Long) -> Unit,
    onPrivacyMaskToggled: (Boolean) -> Unit,
    onBlockScreenReadingToggled: (Boolean) -> Unit,
    onHideInRecentsToggled: (Boolean) -> Unit
) {
    val timeouts = listOf(
        "0 SEC" to 0L,
        "1 MIN" to 60000L,
        "2 MIN" to 120000L,
        "10 MIN" to 600000L,
        "1 HR" to 3600000L
    )

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(SpaceDark)
            .padding(24.dp),
        verticalArrangement = Arrangement.Top
    ) {
        Text(
            text = "SYSTEM CONFIGURATION",
            style = MaterialTheme.typography.titleMedium.copy(
                color = NeonCyan,
                fontWeight = FontWeight.Black,
                letterSpacing = 1.5.sp
            ),
            modifier = Modifier.padding(bottom = 24.dp)
        )

        Column(
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, NeonCyan.copy(alpha = 0.2f), RoundedCornerShape(4.dp))
                .background(SurfaceDark)
                .padding(16.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "BIOMETRIC APP GATEWAY",
                        color = Color.White,
                        fontWeight = FontWeight.Bold,
                        fontSize = 14.sp
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "Enforce localized biological pattern identification check on app relaunch configurations.",
                        color = TextSecondary,
                        fontSize = 11.sp,
                        lineHeight = 14.sp
                    )
                }
                Switch(
                    checked = isBiometricEnabled,
                    onCheckedChange = onBiometricToggled,
                    colors = SwitchDefaults.colors(
                        checkedThumbColor = SpaceDark,
                        checkedTrackColor = NeonCyan,
                        uncheckedThumbColor = TextSecondary,
                        uncheckedTrackColor = SurfaceDark
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
                        .padding(top = 16.dp)
                ) {
                    Text(
                        text = "LOCK AFTER CONTINUOUS INACTIVITY?",
                        style = MaterialTheme.typography.labelMedium.copy(
                            color = NeonCyan,
                            fontWeight = FontWeight.Bold
                        ),
                        modifier = Modifier.padding(bottom = 12.dp)
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
                                    .height(46.dp)
                                    .weight(if (label == "IMMEDIATE" || label == "10 MIN") 1.2f else 1f)
                                    .border(
                                        width = 1.dp,
                                        color = if (isSelected) NeonCyan else NeonCyan.copy(alpha = 0.15f),
                                        shape = RoundedCornerShape(4.dp)
                                    )
                                    .background(if (isSelected) NeonCyan.copy(alpha = 0.12f) else SpaceDark)
                                    .clickable { onTimeoutChanged(value) },
                                contentAlignment = Alignment.Center
                            ) {
                                Text(
                                    text = label,
                                    fontSize = 10.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = if (isSelected) NeonCyan else TextSecondary
                                )
                            }
                        }
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(24.dp))

        Column(
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, NeonCyan.copy(alpha = 0.2f), RoundedCornerShape(4.dp))
                .background(SurfaceDark)
                .padding(16.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "UI HARDENING OVERLAY",
                        color = Color.White,
                        fontWeight = FontWeight.Bold,
                        fontSize = 14.sp
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "Protect the user interface from being captured by software readers or cached on device buffers.",
                        color = TextSecondary,
                        fontSize = 11.sp,
                        lineHeight = 14.sp
                    )
                }
                Switch(
                    checked = isPrivacyMaskEnabled,
                    onCheckedChange = onPrivacyMaskToggled,
                    colors = SwitchDefaults.colors(
                        checkedThumbColor = SpaceDark,
                        checkedTrackColor = NeonCyan,
                        uncheckedThumbColor = TextSecondary,
                        uncheckedTrackColor = SurfaceDark
                    )
                )
            }

            AnimatedVisibility(
                visible = isPrivacyMaskEnabled,
                enter = fadeIn() + expandVertically(),
                exit = fadeOut() + shrinkVertically()
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 16.dp),
                    verticalArrangement = Arrangement.spacedBy(16.dp)
                ) {
                    HorizontalDivider(color = NeonCyan.copy(alpha = 0.1f), thickness = 1.dp)

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "SECURE DISPLAY SHIELD",
                                color = if (isBlockScreenReadingEnabled) NeonCyan else Color.White,
                                fontWeight = FontWeight.SemiBold,
                                fontSize = 12.sp
                            )
                            Text(
                                text = "Block all forms of active background screen recording, screen scraping, and screenshots.",
                                color = TextSecondary,
                                fontSize = 11.sp,
                                lineHeight = 14.sp
                            )
                        }
                        Checkbox(
                            checked = isBlockScreenReadingEnabled,
                            onCheckedChange = onBlockScreenReadingToggled,
                            colors = CheckboxDefaults.colors(
                                checkedColor = NeonCyan,
                                uncheckedColor = TextSecondary,
                                checkmarkColor = SpaceDark
                            )
                        )
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "RECENTS BUFFER BLANKING",
                                color = if (isHideInRecentsEnabled) NeonCyan else Color.White,
                                fontWeight = FontWeight.SemiBold,
                                fontSize = 12.sp
                            )
                            Text(
                                text = "Mask active app view state layers inside the system overview switcher panel.",
                                color = TextSecondary,
                                fontSize = 11.sp,
                                lineHeight = 14.sp
                            )
                        }
                        Checkbox(
                            checked = isHideInRecentsEnabled,
                            onCheckedChange = onHideInRecentsToggled,
                            colors = CheckboxDefaults.colors(
                                checkedColor = NeonCyan,
                                uncheckedColor = TextSecondary,
                                checkmarkColor = SpaceDark
                            )
                        )
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(24.dp))
        DeviceAttestationCard(context = androidx.compose.ui.platform.LocalContext.current)
    }
}

@Composable
fun DeviceAttestationCard(context: Context) {
    val evaluator = remember { DeviceIntegrityRegistry(context) }
    val report by produceState(initialValue = evaluator.runAttestationPipeline()) {
        value = evaluator.runAttestationPipeline()
    }

    var showInfoDialog by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, report.tier.color.copy(alpha = 0.25f), RoundedCornerShape(4.dp))
            .background(SurfaceDark)
            .padding(16.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Text(
                    text = "INTEGRITY ATTESTATION CORE",
                    color = Color.White,
                    fontWeight = FontWeight.Bold,
                    fontSize = 13.sp,
                    letterSpacing = 1.sp
                )
                Spacer(modifier = Modifier.height(2.dp))
                Text(
                    text = report.tier.label,
                    color = report.tier.color,
                    fontWeight = FontWeight.Black,
                    fontSize = 11.sp,
                    letterSpacing = 1.5.sp
                )
            }

            Row(verticalAlignment = Alignment.CenterVertically) {
                IconButton(onClick = { showInfoDialog = true }) {
                    Icon(
                        imageVector = Icons.Default.Info,
                        contentDescription = "Analysis Breakdown",
                        tint = NeonCyan
                    )
                }
                Spacer(modifier = Modifier.width(4.dp))
                Column(horizontalAlignment = Alignment.End) {
                    Text(
                        text = "${report.score}",
                        color = report.tier.color,
                        fontSize = 28.sp,
                        fontWeight = FontWeight.Black
                    )
                    Text(
                        text = "INDEX SCORE",
                        color = TextSecondary,
                        fontSize = 8.sp,
                        letterSpacing = 0.5.sp
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))
        HorizontalDivider(color = report.tier.color.copy(alpha = 0.1f), thickness = 1.dp)
        Spacer(modifier = Modifier.height(16.dp))

        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            MetricRow(label = "BOOTLOADER SECURITY STATE", pass = report.isBootloaderLocked, weightPoints = "+35")
            MetricRow(label = "ENVIRONMENT ROOT DETECTION", pass = report.isNotRooted, weightPoints = "+35")
            MetricRow(label = "HOST DEVELOPER CONFIG MODULE", pass = report.isDevOptionsDisabled, weightPoints = "+10")
            MetricRow(label = "HARDWARE ADB INTERACTION LINK", pass = report.isUsbDebuggingDisabled, weightPoints = "+10")
            MetricRow(label = "CRYPTOGRAPHIC PACKAGE INTEGRITY", pass = report.isAppIntegrityValid, weightPoints = "+10")
            MetricRow(label = "SECURE DEVICE SECURITY SHIELD", pass = report.isSecureLockscreenEnabled, weightPoints = "+10")
        }
    }

    if (showInfoDialog) {
        AlertDialog(
            onDismissRequest = { showInfoDialog = false },
            containerColor = SurfaceDark,
            titleContentColor = NeonCyan,
            textContentColor = Color.White,
            modifier = Modifier.border(1.dp, NeonCyan.copy(alpha = 0.3f), RoundedCornerShape(8.dp)),
            title = {
                Text(
                    text = "ATTESTATION VECTOR ANALYSIS",
                    fontWeight = FontWeight.Bold,
                    fontSize = 14.sp,
                    letterSpacing = 1.sp
                )
            },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text(
                            text = "▲ CREDITED METRICS (PASSED)",
                            color = NeonGreen,
                            fontWeight = FontWeight.Bold,
                            fontSize = 11.sp,
                            letterSpacing = 0.5.sp
                        )
                        if (report.isBootloaderLocked) AttestationBreakdownRow("Bootloader Locked", "+35", NeonGreen)
                        if (report.isNotRooted) AttestationBreakdownRow("No Local Root Rights Detected", "+35", NeonGreen)
                        if (report.isDevOptionsDisabled) AttestationBreakdownRow("Developer Modules Halted", "+10", NeonGreen)
                        if (report.isUsbDebuggingDisabled) AttestationBreakdownRow("USB Debugging Inactive", "+10", NeonGreen)
                        if (report.isAppIntegrityValid) AttestationBreakdownRow("App Package Signature Clean", "+10", NeonGreen)
                        if (report.isSecureLockscreenEnabled) AttestationBreakdownRow("Lockscreen Protection Enabled", "+10", NeonGreen)
                    }

                    val missingPointsExist = !report.isBootloaderLocked || !report.isNotRooted ||
                            !report.isDevOptionsDisabled || !report.isUsbDebuggingDisabled ||
                            !report.isAppIntegrityValid || !report.isSecureLockscreenEnabled

                    if (missingPointsExist) {
                        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text(
                                text = "▼ ENVIRONMENT FAULTS (BLOCKED INCREASE)",
                                color = NeonRed,
                                fontWeight = FontWeight.Bold,
                                fontSize = 11.sp,
                                letterSpacing = 0.5.sp
                            )
                            if (!report.isBootloaderLocked) AttestationBreakdownRow("Bootloader State Unlocked", "Prevented +35", NeonRed)
                            if (!report.isNotRooted) AttestationBreakdownRow("Superuser / Binary Mod Detected", "Prevented +35", NeonRed)
                            if (!report.isDevOptionsDisabled) AttestationBreakdownRow("Developer Options Active", "Prevented +10", NeonRed)
                            if (!report.isUsbDebuggingDisabled) AttestationBreakdownRow("ADB Connection Node Open", "Prevented +10", NeonRed)
                            if (!report.isAppIntegrityValid) AttestationBreakdownRow("Invalid App Installation Source", "Prevented +10", NeonRed)
                            if (!report.isSecureLockscreenEnabled) AttestationBreakdownRow("No Active Host Pattern/PIN Lock", "Prevented +10", NeonRed)
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(
                    onClick = { showInfoDialog = false },
                    colors = ButtonDefaults.textButtonColors(contentColor = NeonCyan)
                ) {
                    Text("DISMISS DATA", fontWeight = FontWeight.Bold, fontSize = 12.sp)
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
fun MetricRow(label: String, pass: Boolean, weightPoints: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                text = if (pass) "✔" else "❌",
                color = if (pass) NeonGreen else NeonRed,
                fontSize = 12.sp,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.width(18.dp)
            )
            Text(
                text = label,
                color = if (pass) Color.White else TextSecondary,
                fontSize = 11.sp,
                fontWeight = FontWeight.Medium,
                letterSpacing = 0.5.sp
            )
        }
        Text(
            text = if (pass) weightPoints else "0",
            color = if (pass) NeonCyan else NeonRed.copy(alpha = 0.6f),
            fontSize = 11.sp,
            fontWeight = FontWeight.Bold
        )
    }
}

@Composable
fun CompromisedEnvironmentOverlay(score: Int) {
    val infiniteTransition = rememberInfiniteTransition(label = "BreachInfinite")
    val pulseAlpha by infiniteTransition.animateFloat(
        initialValue = 0.3f,
        targetValue = 1.0f,
        animationSpec = infiniteRepeatable(
            animation = tween(1000, easing = EaseInOutSans),
            repeatMode = RepeatMode.Reverse
        ), label = "BreachPulse"
    )

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(Color(0xFF0D0202)),
        contentAlignment = Alignment.Center
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
            modifier = Modifier.padding(32.dp)
        ) {
            Text(
                text = "⚠️ HARDWARE LOCKDOWN ENGAGED ⚠️",
                color = NeonRed,
                fontWeight = FontWeight.Black,
                fontSize = 14.sp,
                letterSpacing = 2.sp,
                modifier = Modifier.graphicsLayer { alpha = pulseAlpha }
            )

            Spacer(modifier = Modifier.height(40.dp))

            Box(
                contentAlignment = Alignment.Center,
                modifier = Modifier
                    .size(160.dp)
                    .border(2.dp, NeonRed, RoundedCornerShape(80.dp))
                    .background(NeonRed.copy(alpha = 0.05f))
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Text(
                        text = "$score",
                        color = NeonRed,
                        fontSize = 48.sp,
                        fontWeight = FontWeight.Black
                    )
                    Text(
                        text = "CRITICAL SCORE",
                        color = TextSecondary,
                        fontSize = 9.sp,
                        letterSpacing = 1.sp
                    )
                }
            }

            Spacer(modifier = Modifier.height(40.dp))

            Text(
                text = "ENVIRONMENT RESTRICTED",
                color = Color.White,
                fontWeight = FontWeight.Bold,
                fontSize = 18.sp,
                letterSpacing = 1.5.sp
            )

            Spacer(modifier = Modifier.height(12.dp))

            Text(
                text = "Your device integrity score has dropped below the threshold safety index (< 70).\n\nAll cryptographic local processes and background radio communication services have been terminated to safeguard connected hardware systems.",
                color = TextSecondary,
                textAlign = TextAlign.Center,
                fontSize = 12.sp,
                lineHeight = 20.sp,
                modifier = Modifier.padding(horizontal = 16.dp)
            )

            Spacer(modifier = Modifier.height(32.dp))

            Text(
                text = "REMEDIAL ACTIONS REQUIRED:\n• DISABLE DEVELOPER OPTIONS\n• UNPLUG USB DEBUGGING LINKS\n• RESTORE FACTORY OPERATING SYSTEM",
                color = NeonRed.copy(alpha = 0.8f),
                fontStyle = androidx.compose.ui.text.font.FontStyle.Italic,
                fontSize = 11.sp,
                lineHeight = 18.sp,
                letterSpacing = 0.5.sp
            )
        }
    }
}

@Composable
fun FuturisticLockOverlay(onAuthorizeRequested: () -> Unit) {
    val infiniteTransition = rememberInfiniteTransition(label = "LockMatrixInfinite")

    val scanLineProgress by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(2000, easing = LinearEasing),
            repeatMode = RepeatMode.Reverse
        ), label = "ScanlineMovement"
    )

    val pulseAlpha by infiniteTransition.animateFloat(
        initialValue = 0.2f,
        targetValue = 0.8f,
        animationSpec = infiniteRepeatable(
            animation = tween(1500, easing = EaseInOutSans),
            repeatMode = RepeatMode.Reverse
        ), label = "MatrixPulse"
    )

    val matrixRotation by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = -360f,
        animationSpec = infiniteRepeatable(
            animation = tween(16000, easing = LinearEasing)
        ), label = "NodeRotation"
    )

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(SpaceDark.copy(alpha = 0.98f))
            .clickable(
                interactionSource = remember { MutableInteractionSource() },
                indication = null
            ) { onAuthorizeRequested() },
        contentAlignment = Alignment.Center
    ) {
        Canvas(modifier = Modifier.fillMaxSize()) {
            val width = size.width
            val height = size.height
            val yPos = height * scanLineProgress
            drawLine(
                brush = Brush.horizontalGradient(
                    colors = listOf(Color.Transparent, NeonCyan, Color.Transparent)
                ),
                start = Offset(0f, yPos),
                end = Offset(width, yPos),
                strokeWidth = 3.dp.toPx()
            )
        }

        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
            modifier = Modifier.padding(32.dp)
        ) {
            Text(
                text = "SECURITY OVERLAY ACTIVE",
                color = NeonRed,
                fontWeight = FontWeight.Black,
                fontSize = 11.sp,
                letterSpacing = 3.sp,
                modifier = Modifier.graphicsLayer { alpha = pulseAlpha }
            )

            Spacer(modifier = Modifier.height(48.dp))

            Box(
                contentAlignment = Alignment.Center,
                modifier = Modifier
                    .size(220.dp)
                    .border(1.dp, NeonCyan.copy(alpha = 0.2f), RoundedCornerShape(110.dp))
                    .clickable { onAuthorizeRequested() }
            ) {
                Canvas(
                    modifier = Modifier
                        .size(190.dp)
                        .graphicsLayer { rotationZ = matrixRotation }
                ) {
                    drawArc(
                        brush = Brush.sweepGradient(
                            colors = listOf(Color.Transparent, NeonCyan, Color.Transparent, NeonCyan)
                        ),
                        startAngle = 0f,
                        sweepAngle = 270f,
                        useCenter = false,
                        style = Stroke(width = 2.dp.toPx(), cap = StrokeCap.Round)
                    )
                }

                Canvas(modifier = Modifier.size(150.dp)) {
                    drawCircle(
                        color = NeonCyan.copy(alpha = pulseAlpha * 0.2f),
                        style = Stroke(width = 1.dp.toPx())
                    )
                }

                Column(
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center
                ) {
                    Text(
                        text = "🧬",
                        fontSize = 42.sp,
                        modifier = Modifier.graphicsLayer { alpha = pulseAlpha }
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = "TOUCH TO SCAN",
                        color = NeonCyan,
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold,
                        letterSpacing = 1.5.sp
                    )
                }
            }

            Spacer(modifier = Modifier.height(48.dp))

            Text(
                text = "SYSTEM ACCESS INTERCEPTED\nBIOLOGICAL MATRIX MATCH REQUIRED",
                textAlign = TextAlign.Center,
                color = TextSecondary,
                fontSize = 12.sp,
                fontWeight = FontWeight.SemiBold,
                lineHeight = 18.sp,
                letterSpacing = 0.5.sp
            )

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = "DECRYPT ENGINE v4.0.26",
                color = NeonCyan.copy(alpha = 0.4f),
                fontSize = 9.sp,
                letterSpacing = 1.sp
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
    onTriggerStepVerification: (TrustVerificationStep) -> Unit,
    onBleActionRequested: (String, String) -> Unit
) {
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
    ) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .fillMaxHeight(0.4f)
                .align(Alignment.TopCenter)
                .graphicsLayer { alpha = ambientGlowAlpha }
                .background(ambientGradient)
        )

        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 24.dp, vertical = 12.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.SpaceBetween
        ) {
            Text(
                text = stringResource(id = R.string.app_name).uppercase(),
                modifier = Modifier.padding(top = 8.dp),
                style = MaterialTheme.typography.labelMedium.copy(
                    color = NeonCyan,
                    fontWeight = FontWeight.Bold
                )
            )

            // CORE HUD ELEMENT
            Box(
                contentAlignment = Alignment.Center,
                modifier = Modifier
                    .weight(1f)
                    .padding(vertical = 12.dp)
            ) {
                Canvas(modifier = Modifier.size(230.dp)) {
                    drawArc(
                        color = SurfaceDark,
                        startAngle = 0f,
                        sweepAngle = 360f,
                        useCenter = false,
                        style = Stroke(width = 6.dp.toPx())
                    )
                }

                Canvas(
                    modifier = Modifier
                        .size(230.dp)
                        .graphicsLayer { rotationZ = rotation }
                ) {
                    drawArc(
                        brush = sweepGradient,
                        startAngle = 0f,
                        sweepAngle = if (isPanicActive) 360f else 140f,
                        useCenter = false,
                        style = Stroke(width = 3.dp.toPx(), cap = StrokeCap.Round)
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
                        style = MaterialTheme.typography.headlineSmall.copy(
                            fontSize = 18.sp,
                            lineHeight = 24.sp,
                            fontWeight = FontWeight.Black,
                            textAlign = TextAlign.Center,
                            color = if (verificationStep != TrustVerificationStep.NOT_IN_PANIC) NeonCyan else statusColor
                        )
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = when (verificationStep) {
                            TrustVerificationStep.DEVICE_CREDENTIAL -> "TIER 1 OF 2"
                            TrustVerificationStep.BIOMETRIC_FINGERPRINT -> "TIER 2 OF 2"
                            else -> connectionStatus.uppercase()
                        },
                        style = MaterialTheme.typography.labelMedium.copy(
                            color = if (verificationStep != TrustVerificationStep.NOT_IN_PANIC) NeonCyan else TextSecondary,
                            fontSize = 9.sp
                        )
                    )
                }
            }

            // POWER MANAGEMENT NODE
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(bottom = 12.dp)
                    .border(1.dp, NeonRed.copy(alpha = 0.25f), RoundedCornerShape(4.dp))
                    .background(SurfaceDark)
                    .padding(12.dp)
            ) {
                Text(
                    text = "CRITICAL OPERATION DIRECTIVES",
                    color = NeonRed,
                    fontWeight = FontWeight.Bold,
                    fontSize = 12.sp,
                    letterSpacing = 1.sp
                )
                Spacer(modifier = Modifier.height(10.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Button(
                        onClick = { onBleActionRequested("PWR_SLEEP", "💤 Dispatched: Sleep Command") },
                        colors = ButtonDefaults.buttonColors(containerColor = SpaceDark),
                        shape = RoundedCornerShape(4.dp),
                        modifier = Modifier
                            .weight(1f)
                            .height(40.dp)
                            .border(1.dp, Color(0xFFFFB300).copy(alpha = 0.3f), RoundedCornerShape(4.dp))
                    ) {
                        Text("SLEEP", color = Color(0xFFFFB300), fontSize = 10.sp, fontWeight = FontWeight.Bold)
                    }
                    Button(
                        onClick = { onBleActionRequested("PWR_REBOOT", "🔄 Dispatched: Reboot Command") },
                        colors = ButtonDefaults.buttonColors(containerColor = SpaceDark),
                        shape = RoundedCornerShape(4.dp),
                        modifier = Modifier
                            .weight(1f)
                            .height(40.dp)
                            .border(1.dp, NeonRed.copy(alpha = 0.3f), RoundedCornerShape(4.dp))
                    ) {
                        Text("REBOOT", color = NeonRed, fontSize = 10.sp, fontWeight = FontWeight.Bold)
                    }
                    Button(
                        onClick = { onBleActionRequested("PWR_SHUTDOWN", "🚨 Dispatched: Shutdown Command") },
                        colors = ButtonDefaults.buttonColors(containerColor = SpaceDark),
                        shape = RoundedCornerShape(4.dp),
                        modifier = Modifier
                            .weight(1f)
                            .height(40.dp)
                            .border(1.dp, NeonRed.copy(alpha = 0.5f), RoundedCornerShape(4.dp))
                    ) {
                        Text("SHUTDOWN", color = NeonRed, fontSize = 10.sp, fontWeight = FontWeight.Bold)
                    }
                }
            }

            // CORE TRUST OPERATION MATRIX
            AnimatedContent(
                targetState = verificationStep,
                transitionSpec = {
                    fadeIn(animationSpec = tween(300)) togetherWith fadeOut(animationSpec = tween(300))
                },
                label = "DynamicActionSuite"
            ) { step ->
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(bottom = 8.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    when (step) {
                        TrustVerificationStep.NOT_IN_PANIC -> {
                            if (isPanicActive) {
                                Text(
                                    text = "System trust compromised. Device validation required.",
                                    style = MaterialTheme.typography.bodyLarge.copy(color = TextSecondary, textAlign = TextAlign.Center, fontSize = 14.sp),
                                    modifier = Modifier.padding(horizontal = 16.dp)
                                )
                                PremiumControlAction(
                                    label = "RESTORE SYSTEM TRUST",
                                    accentColor = NeonGreen,
                                    onClick = onInitiateRestore
                                )
                            } else {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                                ) {
                                    Box(modifier = Modifier.weight(1f)) {
                                        PremiumControlAction(
                                            label = "UNLOCK SYSTEM",
                                            accentColor = NeonGreen,
                                            onClick = onUnlockClick
                                        )
                                    }
                                    Box(modifier = Modifier.weight(1f)) {
                                        PremiumControlAction(
                                            label = "LOCK SYSTEM",
                                            accentColor = NeonCyan,
                                            onClick = onLockClick
                                        )
                                    }
                                }
                                PremiumControlAction(
                                    label = "FORCE TERMINATE LINK",
                                    accentColor = NeonRed,
                                    onClick = onPanicClick
                                )
                            }
                        }

                        TrustVerificationStep.DEVICE_CREDENTIAL -> {
                            Text(
                                text = "Processing secure environment overlay...",
                                style = MaterialTheme.typography.bodyLarge.copy(color = TextSecondary, textAlign = TextAlign.Center),
                                modifier = Modifier.fillMaxWidth()
                            )
                        }

                        TrustVerificationStep.BIOMETRIC_FINGERPRINT -> {
                            Text(
                                text = "Scan registered fingerprint hardware node to finish authentication.",
                                style = MaterialTheme.typography.bodyLarge.copy(color = NeonCyan, textAlign = TextAlign.Center),
                                modifier = Modifier.fillMaxWidth()
                            )
                            PremiumControlAction(
                                label = "VERIFY BIOMETRIC TOKEN",
                                accentColor = NeonCyan,
                                onClick = { onTriggerStepVerification(TrustVerificationStep.BIOMETRIC_FINGERPRINT) }
                            )
                        }
                    }
                }
            }
        }
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
            .height(48.dp)
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
                    fontWeight = FontWeight.Bold,
                    fontSize = 11.sp
                )
            )
        }
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

        val km = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        val secureLockscreenEnabled = km.isDeviceSecure
        if (secureLockscreenEnabled) finalScore += 10

        val assignedTier = when {
            finalScore in 100..110 -> TrustTier.TRUSTED
            finalScore in 90..100 -> TrustTier.ELEVATED_RISK
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
        try {
            val installer = context.packageManager.getInstallerPackageName(context.packageName)
            return !installer.isNullOrEmpty() || Build.FINGERPRINT.startsWith("generic")
        } catch (e: Exception) {
            return false
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
            val vibratorManager = context.getSystemService(Context.VIBRATOR_MANAGER_SERVICE) as? VibratorManager
            vibratorManager?.defaultVibrator
        } else {
            @Suppress("DEPRECATION")
            context.getSystemService(Context.VIBRATOR_SERVICE) as? Vibrator
        }
    }

    // Ultra-subtle haptic execution designed for real-time slider feeds on Android 16
    fun triggerSubtleSliderTick() {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                // EFFECT_TICK provides a light, microscopic mechanical click ideal for fine sliding scales
                val effect = VibrationEffect.createPredefined(VibrationEffect.EFFECT_TICK)
                val attributes = VibrationAttributes.Builder()
                    .setUsage(VibrationAttributes.USAGE_TOUCH)
                    .build()
                vibrator?.vibrate(effect, attributes)
            } else {
                @Suppress("DEPRECATION")
                vibrator?.vibrate(8)
            }
        } catch (_: Exception) {}
    }

    var volumeValue by remember { mutableStateOf(50f) }
    var brightnessValue by remember { mutableStateOf(50f) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(SpaceDark)
            .padding(24.dp),
        verticalArrangement = Arrangement.Top
    ) {
        Text(
            text = "HARDWARE ANALOG CONTROLS",
            style = MaterialTheme.typography.titleMedium.copy(
                color = NeonCyan,
                fontWeight = FontWeight.Black,
                letterSpacing = 1.5.sp
            ),
            modifier = Modifier.padding(bottom = 24.dp)
        )

        // SLIDER COMPONENT 1: VOLUME CONTROL
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, NeonCyan.copy(alpha = 0.2f), RoundedCornerShape(4.dp))
                .background(SurfaceDark)
                .padding(16.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "VOLUME COMPONENT ANALYSIS",
                    color = Color.White,
                    fontWeight = FontWeight.Bold,
                    fontSize = 13.sp,
                    letterSpacing = 1.sp
                )
                Text(
                    text = "${volumeValue.roundToInt()}%",
                    color = NeonCyan,
                    fontWeight = FontWeight.Black,
                    fontSize = 13.sp
                )
            }
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = "Dynamic fluid hardware stream adjusting system sound parameters synchronously across active modules.",
                color = TextSecondary,
                fontSize = 11.sp,
                lineHeight = 14.sp
            )
            Spacer(modifier = Modifier.height(16.dp))

            Slider(
                value = volumeValue,
                onValueChange = { nextVolume ->
                    val oldInt = volumeValue.roundToInt()
                    val nextInt = nextVolume.roundToInt()
                    if (oldInt != nextInt) {
                        volumeValue = nextVolume

                        // Fire subtle haptic on every individual numerical block shift
                        triggerSubtleSliderTick()

                        // Execute background BLE broadcast without popping layout Toasts
                        if (nextInt > oldInt) {
                            onBleActionRequested("VOL_UP", "")
                        } else {
                            onBleActionRequested("VOL_DOWN", "")
                        }
                    }
                },
                valueRange = 0f..100f,
                colors = SliderDefaults.colors(
                    activeTrackColor = NeonCyan,
                    inactiveTrackColor = SpaceDark,
                    thumbColor = NeonCyan
                )
            )
        }

        Spacer(modifier = Modifier.height(24.dp))

        // SLIDER COMPONENT 2: BRIGHTNESS MATRIX
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, NeonCyan.copy(alpha = 0.2f), RoundedCornerShape(4.dp))
                .background(SurfaceDark)
                .padding(16.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "BRIGHTNESS MATRIX INTENSITY",
                    color = Color.White,
                    fontWeight = FontWeight.Bold,
                    fontSize = 13.sp,
                    letterSpacing = 1.sp
                )
                Text(
                    text = "${brightnessValue.roundToInt()}%",
                    color = NeonCyan,
                    fontWeight = FontWeight.Black,
                    fontSize = 13.sp
                )
            }
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = "Continuous adjustments managing the host display backlight array intensity variables layout pass.",
                color = TextSecondary,
                fontSize = 11.sp,
                lineHeight = 14.sp
            )
            Spacer(modifier = Modifier.height(16.dp))

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
                    activeTrackColor = NeonCyan,
                    inactiveTrackColor = SpaceDark,
                    thumbColor = NeonCyan
                )
            )
        }
    }
}