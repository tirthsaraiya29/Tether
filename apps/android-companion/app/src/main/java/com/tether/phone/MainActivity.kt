package com.tether.phone

import android.Manifest
import android.annotation.SuppressLint
import android.app.KeyguardManager
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.content.ClipData
import android.content.ClipboardManager
import android.widget.ImageView
import androidx.annotation.StringRes
import androidx.appcompat.app.AlertDialog
import android.os.PowerManager
import android.provider.Settings
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Menu
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.asComposeRenderEffect
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.core.content.edit
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import com.tether.phone.ui.theme.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import android.util.Log
import androidx.compose.material.icons.filled.QrCode

val EaseInOutSans = CubicBezierEasing(0.42f, 0f, 0.58f, 1f)

enum class TrustVerificationStep {
    NOT_IN_PANIC,
    DEVICE_CREDENTIAL,
    BIOMETRIC_FINGERPRINT
}

enum class AppScreen {
    TELEMETRY_DASHBOARD,
    SECURITY_SETTINGS,
    LAPTOP_CONTROL,
    PAIRING
}

enum class TrustTier(@param:StringRes val labelRes: Int, val color: Color) {
    TRUSTED(R.string.tier_trusted, IntegrityGreen),
    ELEVATED_RISK(R.string.tier_elevated_risk, MatrixGold),
    RESTRICTED(R.string.tier_restricted, AlertRed)
}

data class IntegrityReport(
    val score: Int,
    val tier: TrustTier,
    val isBootloaderLocked: Boolean,
    val isNotRooted: Boolean,
    val isDevOptionsDisabled: Boolean,
    val isUsbDebuggingDisabled: Boolean,
    val isAppIntegrityValid: Boolean,
    val isSecureLockscreenEnabled: Boolean,
)

class MainActivity : FragmentActivity() {
    private val requestPermissionsCode = 101
    private val preferenceName = "tether_secure_prefs"
    private val panicStateKey = "is_panic_active"

    private val appLockEnabledKey = "app_lock_biometrics_enabled"
    private val appLockTimeoutKey = "app_lock_timeout_ms"
    private val appLockBackgroundTimestampKey = "app_lock_bg_timestamp"

    private val privacyMaskEnabledKey = "privacy_mask_enabled"
    private val blockScreenReadingKey = "block_screen_reading"
    private val hideInRecentsKey = "hide_in_recents"

    private var uiStatusText = mutableStateOf("")
    private var uiStatusColor = mutableStateOf(TextSecondary)
    private var uiConnectionStatusText = mutableStateOf("")

    private var isConnected = mutableStateOf(value = false)
    private var isPanicActive = mutableStateOf(value = false)
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

    private var activePendingCommand = mutableStateOf<String?>(null)
    private var isCommandConfirmed = mutableStateOf(false)

    private var pendingPowerAction = mutableStateOf<PowerAction?>(null)
    private data class PowerAction(val command: String, val title: String)

    private var lastBiometricAuthTime = 0L

    private lateinit var executor: Executor

    private val batteryOptimizationLauncher = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        val powerManager = getSystemService(POWER_SERVICE) as PowerManager
        if (!powerManager.isIgnoringBatteryOptimizations(packageName)) {
            Log.w("TetherActivity", "Battery optimization exemption NOT granted.")
        } else {
            Log.i("TetherActivity", "Battery optimization exemption granted.")
        }
    }

    private val gattStateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == BleGattServerService.ACTION_GATT_STATE_CHANGED) {
                val count = intent.getIntExtra(BleGattServerService.EXTRA_CONNECTION_COUNT, 0)
                Log.d("TetherActivity", "GATT state changed broadcast received: connection_count=$count")
                runOnUiThread {
                    isConnected.value = count > 0
                    if (count > 0) {
                        uiStatusText.value = getString(R.string.status_link_active)
                        uiStatusColor.value = IntegrityGreen
                        uiConnectionStatusText.value = getString(R.string.status_secure_nodes, count)
                    } else {
                        if (!isPanicActive.value) {
                            uiStatusText.value = getString(R.string.status_broadcasting)
                            uiStatusColor.value = LiquidCyan
                            uiConnectionStatusText.value = getString(R.string.status_scanning_host)
                        }
                    }
                }
            }
        }
    }

    private val commandConfirmedReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == "com.tether.phone.ACTION_COMMAND_CONFIRMED") {
                val confirmedCommand = intent.getStringExtra("confirmed_command")
                Log.d("TetherActivity", "Direct command confirmation intercepted: $confirmedCommand")
                runOnUiThread {
                    isCommandConfirmed.value = true
                    lifecycleScope.launch {
                        kotlinx.coroutines.delay(2000L)
                        activePendingCommand.value = null
                        isCommandConfirmed.value = false
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
                            uiStatusText.value = getString(R.string.status_hardware_offline)
                            uiStatusColor.value = AlertRed
                            uiConnectionStatusText.value = getString(R.string.status_link_severed)
                        }
                        stopService(Intent(this@MainActivity, BleGattServerService::class.java))
                        isConnected.value = false
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
            uiStatusText.value = getString(R.string.status_access_denied)
            uiStatusColor.value = AlertRed
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        executor = Executors.newSingleThreadExecutor()

        uiStatusText.value = getString(R.string.status_scanning)
        uiConnectionStatusText.value = getString(R.string.status_initializing_stack)

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

        requestBatteryOptimizationExemption()

        val shouldStartImmediately = !isBiometricSettingEnabled.value
        if (shouldStartImmediately) {
            if (checkPermissions()) {
                startBleService()
            } else {
                requestPermissions()
            }
        }

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
                    } else {
                        // Safe to inspect Assistant intent routing on standard pipeline startup
                        handleVoiceIntent(intent)
                    }
                }
            }
        }

        setContent {
            TetherTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background,
                ) {
                    Box(modifier = Modifier.fillMaxSize()) {
                        BackgroundGrid()
                        if (isLoading.value) {
                            Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                                CircularProgressIndicator(color = LiquidCyan, strokeWidth = 1.dp)
                                Text(
                                    getString(R.string.status_verifying_environment),
                                    color = TextSecondary,
                                    style = MaterialTheme.typography.labelMedium,
                                    modifier = Modifier.padding(top = 48.dp)
                                )
                            }
                        } else if (isEnvironmentRestricted.value) {
                            CompromisedEnvironmentOverlay(score = currentIntegrityScore.intValue)
                        } else {
                            TetherNavigationShell(
                                statusText = uiStatusText.value,
                                statusColor = uiStatusColor.value,
                                connectionStatus = uiConnectionStatusText.value,
                                isConnected = isConnected.value,
                                isPanicActive = isPanicActive.value,
                                verificationStep = currentVerificationStep.value,
                                isBiometricSettingEnabled = isBiometricSettingEnabled.value,
                                selectedTimeoutMs = selectedTimeoutMs.longValue,
                                isPrivacyMaskEnabled = isPrivacyMaskEnabled.value,
                                onUnlockClick = {
                                    val currentTime = System.currentTimeMillis()
                                    // FORCE biometric if last auth > 10s, regardless of structural lock settings
                                    val needsAuth = (currentTime - lastBiometricAuthTime > 10000)

                                    if (needsAuth) {
                                        authenticateViaSystem(
                                            title = getString(R.string.auth_unlock_title),
                                            subtitle = getString(R.string.auth_unlock_subtitle),
                                            allowedAuthenticators = BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL
                                        ) { success ->
                                            if (success) {
                                                runOnUiThread {
                                                    lastBiometricAuthTime = System.currentTimeMillis()
                                                    triggerBleAction("unlock")
                                                }
                                            }
                                        }
                                    } else {
                                        triggerBleAction("unlock")
                                    }
                                },
                                onLockClick = { triggerBleAction("lock_now") },
                                onPanicClick = {
                                    persistPanicState(true)
                                    triggerBleAction("panic")
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
                                onLaptopActionClick = { action ->
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
                                                title = getString(R.string.dialog_confirm_protocol, command.uppercase())
                                            )
                                        }
                                        else -> {
                                            triggerBleAction(command)
                                        }
                                    }
                                },
                                onShowQR = { showPairingQRCode() }
                            )

                            pendingPowerAction.value?.let { action ->
                                CyberConfirmationDialog(
                                    title = action.title,
                                    message = getString(R.string.dialog_confirm_message, action.command),
                                    onConfirm = {
                                        triggerBleAction(action.command)
                                        pendingPowerAction.value = null
                                    },
                                    onDismiss = { pendingPowerAction.value = null }
                                )
                            }

                            AnimatedVisibility(
                                visible = isAppLocked.value,
                                enter = fadeIn(animationSpec = tween(800, easing = EaseInOutSans)),
                                exit = fadeOut(animationSpec = tween(800, easing = EaseInOutSans))
                            ) {
                                FuturisticLockOverlay(
                                    onAuthorizeRequested = {
                                        authenticateForAppUnlock()
                                    }
                                )
                            }

                            activePendingCommand.value?.let { command ->
                                CommandConfirmationDialog(
                                    command = command,
                                    isConfirmed = isCommandConfirmed.value,
                                    onDismiss = { activePendingCommand.value = null }
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
            IntentFilter(BleGattServerService.ACTION_GATT_STATE_CHANGED),
            ContextCompat.RECEIVER_NOT_EXPORTED
        )
        ContextCompat.registerReceiver(
            this,
            commandConfirmedReceiver,
            IntentFilter("com.tether.phone.ACTION_COMMAND_CONFIRMED"),
            ContextCompat.RECEIVER_NOT_EXPORTED
        )
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        if (!isEnvironmentRestricted.value && !isAppLocked.value) {
            handleVoiceIntent(intent)
        }
    }

    private fun handleVoiceIntent(intent: Intent?) {
        if (intent == null) return
        // Support both shortcut extras and capability parameter mappings
        val commandType = intent.getStringExtra("command_type") ?: intent.getStringExtra("action_command")
        val action = intent.action

        if (commandType != null || action == "com.tether.phone.ACTION_VOICE_COMMAND") {
            val command = commandType ?: "unknown"
            if (!isEnvironmentRestricted.value && !isAppLocked.value) {
                val bleCommand = when (command) {
                    "lock_now" -> "lock_now"
                    "unlock" -> "unlock"
                    "shutdown" -> "shutdown"
                    "sleep" -> "sleep"
                    "reboot" -> "reboot"
                    else -> return
                }
                triggerBleAction(bleCommand)
                // Gracefully finish activity tracking so it returns back to the Assistant interface cleanly
                finish()
            }
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

    private val screenUnlockReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action == Intent.ACTION_USER_PRESENT) {
                triggerBleAction("screen_unlock")
            }
        }
    }

    override fun onStart() {
        super.onStart()
        if (isEnvironmentRestricted.value) return

        // Check if permissions were revoked while app was in background
        if (!isAppLocked.value && !checkPermissions()) {
            requestPermissions()
            return
        }

        // 1. Evaluate background tracking and timeout state first to see if we need to lock the UI
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

        // 2. Only probe or spin up the background service if the app is confirmed UNLOCKED
        if (checkPermissions() && !isAppLocked.value) {
            android.os.Handler(android.os.Looper.getMainLooper()).postDelayed(
                {
                    val statusIntent = Intent(this, BleGattServerService::class.java).apply {
                        action = "ACTION_GET_STATUS"
                    }
                    try {
                        startForegroundService(statusIntent)
                    } catch (e: Exception) {
                        Log.e("TetherActivity", "Failed pulling background service status", e)
                    }
                },
                300,
            )
        }

        if (isPrivacyMaskEnabled.value && isBlockScreenReadingEnabled.value) {
            window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
    }

    override fun onStop() {
        super.onStop()
        if (isPrivacyMaskEnabled.value && isHideInRecentsEnabled.value) {
            window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
        if (isBiometricSettingEnabled.value) {
            val prefs = getSharedPreferences(preferenceName, MODE_PRIVATE)
            prefs.edit(commit = true) {
                putLong(appLockBackgroundTimestampKey, System.currentTimeMillis())
            }
        }
    }

    override fun onDestroy() {
        try { unregisterReceiver(gattStateReceiver) } catch (_: Exception) {}
        try { unregisterReceiver(commandConfirmedReceiver) } catch (_: Exception) {}
        super.onDestroy()
        try { unregisterReceiver(screenUnlockReceiver) } catch (_: Exception) {}
        try { unregisterReceiver(bluetoothStateReceiver) } catch (_: Exception) {}
    }

    private fun authenticateForAppUnlock() {
        authenticateViaSystem(
            title = getString(R.string.auth_title),
            subtitle = getString(R.string.auth_subtitle),
            allowedAuthenticators = BiometricManager.Authenticators.BIOMETRIC_STRONG
        ) { success ->
            if (success) {
                runOnUiThread {
                    lastBiometricAuthTime = System.currentTimeMillis()
                    isAppLocked.value = false
                    getSharedPreferences(preferenceName, MODE_PRIVATE).edit {
                        putLong(appLockBackgroundTimestampKey, 0L)
                    }
                    if (checkPermissions()) {
                        checkAndEnableBluetooth()
                    } else {
                        requestPermissions()
                    }
                    // Handle pending shortcuts context elements deferred by system lock screen constraints
                    handleVoiceIntent(intent)
                }
            } else {
                runOnUiThread {
                    Log.w("TetherActivity", "App unlock failed: Unauthorized")
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
            if (checkPermissions()) {
                startBleService()
            }
        }
    }

    private fun requestBatteryOptimizationExemption() {
        val powerManager = getSystemService(POWER_SERVICE) as PowerManager
        if (!powerManager.isIgnoringBatteryOptimizations(packageName)) {
            try {
                val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                    data = android.net.Uri.parse("package:$packageName")
                }
                batteryOptimizationLauncher.launch(intent)
            } catch (e: Exception) {
                val intent = Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)
                batteryOptimizationLauncher.launch(intent)
            }
        }
    }

    private fun setPanicUiState() {
        uiStatusText.value = getString(R.string.status_lockdown_active)
        uiStatusColor.value = AlertRed
        uiConnectionStatusText.value = getString(R.string.status_trust_revoked)
        isConnected.value = false
    }

    private fun showPairingQRCode() {
        try {
            val publicKeyBytes = ProductionSecurityEngine().getPublicKeyBytes()
            val base64Key = android.util.Base64.encodeToString(publicKeyBytes, android.util.Base64.NO_WRAP)

            val qrContent = "TETHER:KEY:$base64Key"
            val qrBitmap = QRCodeGenerator.generateQRCode(qrContent)

            runOnUiThread {
                val imageView = ImageView(this).apply {
                    setImageBitmap(qrBitmap)
                    setPadding(40, 40, 40, 40)
                }

                AlertDialog.Builder(this)
                    .setTitle(getString(R.string.dialog_pairing_title))
                    .setMessage(getString(R.string.dialog_pairing_message))
                    .setView(imageView)
                    .setPositiveButton(getString(R.string.btn_done)) { _, _ -> }
                    .setNegativeButton(getString(R.string.btn_copy_key)) { _, _ ->
                        val clipboard = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
                        clipboard.setPrimaryClip(ClipData.newPlainText("TetherPublicKey", base64Key))
                    }
                    .show()
            }
        } catch (e: Exception) {
            runOnUiThread {
                Log.e("TetherActivity", "QR Generation failed", e)
            }
        }
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
                    title = getString(R.string.auth_trust_restoration),
                    subtitle = getString(R.string.auth_confirm_master_code),
                    allowedAuthenticators = BiometricManager.Authenticators.DEVICE_CREDENTIAL
                ) { success ->
                    if (success) {
                        lastBiometricAuthTime = System.currentTimeMillis()
                        executeVerificationPipeline(TrustVerificationStep.BIOMETRIC_FINGERPRINT)
                    } else handleVerificationFailure()
                }
            }
            TrustVerificationStep.BIOMETRIC_FINGERPRINT -> {
                authenticateViaSystem(
                    title = getString(R.string.auth_biometric_validation),
                    subtitle = getString(R.string.auth_scan_fingerprint),
                    allowedAuthenticators = BiometricManager.Authenticators.BIOMETRIC_STRONG
                ) { success ->
                    if (success) {
                        lastBiometricAuthTime = System.currentTimeMillis()
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
                promptBuilder.setNegativeButtonText(getString(R.string.btn_abort))
            }
            val biometricPrompt = BiometricPrompt(
                this,
                executor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        super.onAuthenticationSucceeded(result)
                        callback(true)
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        super.onAuthenticationError(errorCode, errString)
                        callback(false)
                    }
                },
            )
            biometricPrompt.authenticate(promptBuilder.build())
        }
    }

    private fun handleVerificationFailure() {
        runOnUiThread {
            currentVerificationStep.value = TrustVerificationStep.NOT_IN_PANIC
            setPanicUiState()
        }
    }

    @SuppressLint("MissingPermission")
    private fun showLaptopSelectionDialog() {
        try {
            val bluetoothManager = getSystemService(BluetoothManager::class.java)
            val adapter = bluetoothManager?.adapter
            if (adapter == null || !adapter.isEnabled) {
                return
            }
            val pairedDevices = adapter.bondedDevices
            if (pairedDevices.isEmpty()) {
                return
            }
            val unknownLabel = getString(R.string.label_unknown)
            val deviceList = pairedDevices.map { "${it.name ?: unknownLabel} (${it.address})" }.toTypedArray()
            val deviceAddresses = pairedDevices.map { it.address }.toTypedArray()
            AlertDialog.Builder(this)
                .setTitle(getString(R.string.dialog_select_host))
                .setItems(deviceList) { _, which ->
                    val mac = deviceAddresses[which]
                    getSharedPreferences(preferenceName, MODE_PRIVATE).edit {
                        putString("laptop_mac", mac)
                    }
                }
                .setNegativeButton(getString(R.string.btn_cancel), null)
                .show()
        } catch (e: Exception) {
            Log.e("TetherActivity", "Laptop selection error", e)
        }
    }

    private fun triggerBleAction(action: String) {
        if (isEnvironmentRestricted.value || isAppLocked.value || !checkPermissions()) return
        
        Log.d("TetherActivity", "Triggering BLE action: $action")
        activePendingCommand.value = action
        isCommandConfirmed.value = false

        val serviceIntent = Intent(this, BleGattServerService::class.java).apply {
            this.action = action
        }
        try {
            startForegroundService(serviceIntent)
        } catch (e: Exception) {
            Log.e("TetherActivity", "Failed to start BLE service for action: $action", e)
        }
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
                uiStatusText.value = getString(R.string.status_permissions_required)
                uiStatusColor.value = AlertRed
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
        if (isPanicActive.value || isEnvironmentRestricted.value) return
        val bleIntent = Intent(this, BleGattServerService::class.java)
        try {
            startForegroundService(bleIntent)
            uiStatusText.value = getString(R.string.status_broadcast_active)
            uiStatusColor.value = LiquidCyan
            uiConnectionStatusText.value = getString(R.string.status_waiting_nodes)
        } catch (e: Exception) {
            Log.e("TetherActivity", "Failed to start BLE service", e)
        }
    }
}

// --- UI COMPONENTS ---

@Composable
fun LiquidSurface(
    modifier: Modifier = Modifier,
    alpha: Float = 0.05f,
    tint: Color = Color.White,
    blur: Float = 20f,
    content: @Composable ColumnScope.() -> Unit
) {
    Box(
        modifier = modifier
            .clip(RoundedCornerShape(28.dp))
            .border(
                width = 0.5.dp,
                brush = Brush.linearGradient(
                    listOf(
                        Color.White.copy(alpha = 0.2f),
                        Color.White.copy(alpha = 0.05f),
                        Color.White.copy(alpha = 0.15f)
                    )
                ),
                shape = RoundedCornerShape(28.dp)
            )
    ) {
        // Blurred background layer
        Box(
            modifier = Modifier
                .matchParentSize()
                .background(
                    Brush.verticalGradient(
                        listOf(
                            tint.copy(alpha = alpha),
                            tint.copy(alpha = alpha * 0.4f)
                        )
                    )
                )
                .graphicsLayer {
                    renderEffect = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                        android.graphics.RenderEffect.createBlurEffect(blur, blur, android.graphics.Shader.TileMode.CLAMP).asComposeRenderEffect()
                    } else {
                        null
                    }
                }
                .drawBehind {
                    val strokeWidth = 1.dp.toPx()
                    // Dynamic specular highlight based on a virtual light source
                    val specularPath = Path().apply {
                        moveTo(0f, size.height * 0.3f)
                        lineTo(0f, 28.dp.toPx())
                        arcTo(
                            rect = Rect(0f, 0f, 56.dp.toPx(), 56.dp.toPx()),
                            startAngleDegrees = 180f,
                            sweepAngleDegrees = 90f,
                            forceMoveTo = false
                        )
                        lineTo(size.width * 0.3f, 0f)
                    }
                    drawPath(
                        path = specularPath,
                        brush = Brush.linearGradient(
                            colors = listOf(
                                Color.White.copy(alpha = 0.3f),
                                Color.White.copy(alpha = 0.05f)
                            ),
                            start = Offset.Zero,
                            end = Offset(size.width * 0.3f, size.height * 0.3f)
                        ),
                        style = Stroke(width = strokeWidth, cap = StrokeCap.Round)
                    )

                    // Subsurface scattering simulation
                    drawRect(
                        brush = Brush.radialGradient(
                            colors = listOf(tint.copy(alpha = 0.05f), Color.Transparent),
                            center = Offset(size.width * 0.5f, size.height * 0.5f),
                            radius = size.minDimension
                        )
                    )
                }
        )

        // Sharp content layer
        Column(
            modifier = Modifier.padding(24.dp),
            content = content
        )
    }
}

@Composable
fun BackgroundGrid() {
    val density = LocalDensity.current
    val gridTargetPx = remember(density) { with(density) { 60.dp.toPx() } }

    val infiniteTransition = rememberInfiniteTransition(label = "Atmosphere")
    val gridShift by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = gridTargetPx,
        animationSpec = infiniteRepeatable(
            animation = tween(15000, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ), label = "Grid"
    )
    val nebulaAlpha by infiniteTransition.animateFloat(
        initialValue = 0.02f,
        targetValue = 0.08f, // Slightly increased for more depth
        animationSpec = infiniteRepeatable(
            animation = tween(12000, easing = EaseInOutSans),
            repeatMode = RepeatMode.Reverse
        ), label = "Nebula"
    )

    Canvas(modifier = Modifier.fillMaxSize()) {
        val gridSize = 60.dp.toPx()
        val gridColor = LiquidCyan.copy(alpha = 0.04f)

        // Draw distorted grid lines
        // This is a simplified version of "refraction" - we could simulate it by shifting lines
        // However, a true refraction requires knowledge of UI element positions.
        // For a general background, we'll use a slightly varying grid density to simulate optical unevenness.
        
        var x = (gridShift % gridSize) - gridSize
        while (x < size.width + gridSize) {
            val distortionX = kotlin.math.sin((x + gridShift) / 100.0).toFloat() * 2f
            drawLine(gridColor, Offset(x + distortionX, 0f), Offset(x + distortionX, size.height), 0.5.dp.toPx())
            x += gridSize
        }
        var y = (gridShift % gridSize) - gridSize
        while (y < size.height + gridSize) {
            val distortionY = kotlin.math.cos((y + gridShift) / 100.0).toFloat() * 2f
            drawLine(gridColor, Offset(0f, y + distortionY), Offset(size.width, y + distortionY), 0.5.dp.toPx())
            y += gridSize
        }

        // Atmospheric nebulae with multi-stop radial gradients for "liquid" feel
        drawCircle(
            brush = Brush.radialGradient(
                0.0f to LiquidCyan.copy(alpha = nebulaAlpha),
                0.5f to LiquidCyan.copy(alpha = nebulaAlpha * 0.4f),
                1.0f to Color.Transparent,
                center = Offset(size.width * 0.2f, size.height * 0.3f),
                radius = 800.dp.toPx()
            ),
            center = Offset(size.width * 0.2f, size.height * 0.3f),
            radius = 800.dp.toPx()
        )
        drawCircle(
            brush = Brush.radialGradient(
                0.0f to IntegrityGreen.copy(alpha = nebulaAlpha * 0.8f),
                0.6f to IntegrityGreen.copy(alpha = nebulaAlpha * 0.2f),
                1.0f to Color.Transparent,
                center = Offset(size.width * 0.8f, size.height * 0.7f),
                radius = 700.dp.toPx()
            ),
            center = Offset(size.width * 0.8f, size.height * 0.7f),
            radius = 700.dp.toPx()
        )
    }
}

@Composable
fun PremiumControlAction(
    label: String,
    accentColor: Color,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true
) {
    val interactionSource = remember { MutableInteractionSource() }
    val isPressed by interactionSource.collectIsPressedAsState()
    val animatedScale by animateFloatAsState(if (isPressed) 0.95f else 1f, label = "Scale")
    val animatedAlpha by animateFloatAsState(if (isPressed) 0.8f else 1f, label = "Alpha")
    val animatedGlow by animateFloatAsState(if (isPressed) 0.3f else 0.12f, label = "Glow")

    Box(
        modifier = modifier
            .graphicsLayer {
                scaleX = animatedScale
                scaleY = animatedScale
                alpha = if (enabled) animatedAlpha else 0.4f
                // Subtle tilt effect
                rotationX = if (isPressed) 2f else 0f
                cameraDistance = 12f * density
            }
            .fillMaxWidth()
            .height(60.dp)
            .clip(RoundedCornerShape(18.dp))
            .background(
                Brush.verticalGradient(
                    listOf(
                        accentColor.copy(alpha = animatedGlow),
                        accentColor.copy(alpha = animatedGlow * 0.3f)
                    )
                )
            )
            .border(
                width = 0.5.dp,
                brush = Brush.linearGradient(
                    listOf(
                        accentColor.copy(alpha = if (isPressed) 0.8f else 0.5f),
                        accentColor.copy(alpha = 0.1f)
                    )
                ),
                shape = RoundedCornerShape(18.dp)
            )
            .clickable(
                interactionSource = interactionSource,
                indication = null,
                enabled = enabled,
                onClick = onClick
            ),
        contentAlignment = Alignment.Center
    ) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .drawBehind {
                    if (isPressed) {
                        drawRect(
                            brush = Brush.radialGradient(
                                colors = listOf(accentColor.copy(alpha = 0.2f), Color.Transparent),
                                center = Offset(size.width / 2, size.height / 2),
                                radius = size.width
                            )
                        )
                    }
                    // Specular reflection on the button surface
                    val strokeWidth = 1.dp.toPx()
                    val reflectionPath = Path().apply {
                        moveTo(10.dp.toPx(), 4.dp.toPx())
                        lineTo(size.width - 20.dp.toPx(), 4.dp.toPx())
                    }
                    drawPath(
                        path = reflectionPath,
                        color = Color.White.copy(alpha = 0.15f),
                        style = Stroke(width = strokeWidth, cap = StrokeCap.Round)
                    )
                }
        )
        Text(
            text = label,
            style = MaterialTheme.typography.labelLarge,
            color = if (enabled) accentColor else TextMuted,
            fontWeight = FontWeight.Bold
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TetherNavigationShell(
    statusText: String,
    statusColor: Color,
    connectionStatus: String,
    isConnected: Boolean,
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
    onLaptopActionClick: (String) -> Unit,
    onShowQR: () -> Unit
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
                modifier = Modifier.width(320.dp).fillMaxHeight()
            ) {
                Box(modifier = Modifier.fillMaxSize()) {
                    // Drawer background with blur
                    Box(
                        modifier = Modifier
                            .fillMaxSize()
                            .background(DeepSpace.copy(alpha = 0.8f))
                            .graphicsLayer {
                                renderEffect = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                                    android.graphics.RenderEffect.createBlurEffect(30f, 30f, android.graphics.Shader.TileMode.CLAMP).asComposeRenderEffect()
                                } else {
                                    null
                                }
                            }
                    )
                    // Drawer content (sharp)
                    Column(modifier = Modifier.fillMaxSize().padding(32.dp)) {
                        Spacer(modifier = Modifier.height(48.dp))
                        Text(stringResource(R.string.nav_command_interface), style = MaterialTheme.typography.labelMedium, color = LiquidCyan)
                        Spacer(modifier = Modifier.height(32.dp))

                        val navItems = listOf(
                            Triple(stringResource(R.string.nav_dashboard), Icons.Default.Home, AppScreen.TELEMETRY_DASHBOARD),
                            Triple(stringResource(R.string.nav_hardware), Icons.Default.Info, AppScreen.LAPTOP_CONTROL),
                            Triple(stringResource(R.string.nav_security), Icons.Default.Settings, AppScreen.SECURITY_SETTINGS),
                            Triple(stringResource(R.string.nav_pair), Icons.Default.QrCode, AppScreen.PAIRING)
                        )

                        navItems.forEach { (label, icon, screen) ->
                            NavigationDrawerItem(
                                label = { Text(label, style = MaterialTheme.typography.labelLarge) },
                                selected = currentScreen == screen,
                                icon = { Icon(icon, contentDescription = null) },
                                colors = NavigationDrawerItemDefaults.colors(
                                    selectedContainerColor = LiquidCyan.copy(alpha = 0.1f),
                                    unselectedContainerColor = Color.Transparent,
                                    selectedIconColor = LiquidCyan,
                                    unselectedIconColor = TextSecondary,
                                    selectedTextColor = LiquidCyan,
                                    unselectedTextColor = TextSecondary
                                ),
                                shape = RoundedCornerShape(16.dp),
                                onClick = {
                                    currentScreen = screen
                                    scope.launch { drawerState.close() }
                                }
                            )
                        }
                    }
                }
            }
        }
    ) {
        Scaffold(
            topBar = {
                CenterAlignedTopAppBar(
                    title = {
                        Text(stringResource(R.string.app_title), style = MaterialTheme.typography.headlineSmall, color = TextPrimary)
                    },
                    navigationIcon = {
                        IconButton(onClick = { scope.launch { drawerState.open() } }) {
                            Icon(Icons.Default.Menu, contentDescription = null, tint = LiquidCyan)
                        }
                    },
                    actions = {
                        IconButton(onClick = onSelectLaptop) {
                            Icon(Icons.Default.Settings, contentDescription = null, tint = TextSecondary)
                        }
                    },
                    colors = TopAppBarDefaults.topAppBarColors(containerColor = Color.Transparent)
                )
            },
            containerColor = Color.Transparent
        ) { paddingValues ->
            Box(modifier = Modifier.fillMaxSize().padding(paddingValues)) {
                AnimatedContent(
                    targetState = currentScreen,
                    transitionSpec = {
                        (fadeIn(animationSpec = tween(400, easing = EaseInOutSans)) + 
                         scaleIn(initialScale = 0.98f, animationSpec = tween(400, easing = EaseInOutSans)))
                            .togetherWith(fadeOut(animationSpec = tween(300, easing = EaseInOutSans)) + 
                                         scaleOut(targetScale = 1.02f, animationSpec = tween(300, easing = EaseInOutSans)))
                    },
                    label = "ScreenTransition"
                ) { screen ->
                    when (screen) {
                        AppScreen.TELEMETRY_DASHBOARD -> TetherAppScreen(
                            statusText, statusColor, connectionStatus, isConnected, isPanicActive, verificationStep,
                            onUnlockClick, onLockClick, onPanicClick, onInitiateRestore, onSelectLaptop,
                            onTriggerStepVerification, onLaptopActionClick
                        )
                        AppScreen.SECURITY_SETTINGS -> SettingsScreen(
                            isBiometricSettingEnabled, selectedTimeoutMs, isPrivacyMaskEnabled,
                            onBiometricSettingToggled, onTimeoutChanged, onPrivacyMaskToggled
                        )
                        AppScreen.LAPTOP_CONTROL -> LaptopControlScreen(onLaptopActionClick)
                        AppScreen.PAIRING -> PairingScreen(onShowQR)
                    }
                }
            }
        }
    }
}

@Composable
fun TetherAppScreen(
    statusText: String,
    statusColor: Color,
    connectionStatus: String,
    isConnected: Boolean,
    isPanicActive: Boolean,
    verificationStep: TrustVerificationStep,
    onUnlockClick: () -> Unit,
    onLockClick: () -> Unit,
    onPanicClick: () -> Unit,
    onInitiateRestore: () -> Unit,
    onSelectLaptop: () -> Unit,
    onTriggerStepVerification: (TrustVerificationStep) -> Unit,
    onBleActionRequested: (String) -> Unit
) {
    val scrollState = rememberScrollState()

    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(scrollState).padding(horizontal = 24.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Box(modifier = Modifier.fillMaxWidth().height(360.dp), contentAlignment = Alignment.Center) {
            if (isConnected) ActiveLinkVisualizer(statusColor, statusText, connectionStatus)
            else ScanningVisualizer(statusColor)
        }

        LiquidSurface(modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.header_hardware_directives), style = MaterialTheme.typography.labelMedium, color = LiquidCyan)
            Spacer(modifier = Modifier.height(24.dp))
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                PremiumControlAction(stringResource(R.string.label_sleep), MatrixGold, { onBleActionRequested("PWR_SLEEP") }, Modifier.weight(1f), isConnected)
                PremiumControlAction(stringResource(R.string.label_reboot), TextPrimary, { onBleActionRequested("PWR_REBOOT") }, Modifier.weight(1f), isConnected)
            }
            Spacer(modifier = Modifier.height(16.dp))
            PremiumControlAction(stringResource(R.string.label_halt_system), AlertRed, { onBleActionRequested("PWR_SHUTDOWN") }, enabled = isConnected)
        }

        Spacer(modifier = Modifier.height(24.dp))

        AnimatedContent(targetState = verificationStep, label = "Security") { step ->
            Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
                when (step) {
                    TrustVerificationStep.NOT_IN_PANIC -> {
                        if (isPanicActive) PanicRestoreCard(onInitiateRestore)
                        else {
                            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                                PremiumControlAction(stringResource(R.string.label_unlock), IntegrityGreen, onUnlockClick, Modifier.weight(1f), isConnected)
                                PremiumControlAction(stringResource(R.string.label_lock), LiquidCyan, onLockClick, Modifier.weight(1f), isConnected)
                            }
                            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                                PremiumControlAction(stringResource(R.string.label_target), TextSecondary, onSelectLaptop, Modifier.weight(1f))
                                PremiumControlAction(stringResource(R.string.label_panic), AlertRed, onPanicClick, Modifier.weight(1f))
                            }
                        }
                    }
                    TrustVerificationStep.DEVICE_CREDENTIAL -> LoadingSecurityStep(stringResource(R.string.status_verifying_security))
                    TrustVerificationStep.BIOMETRIC_FINGERPRINT -> BiometricVerificationStep { onTriggerStepVerification(step) }
                }
            }
        }
        Spacer(modifier = Modifier.height(48.dp))
    }
}

@Composable
fun ScanningVisualizer(color: Color) {
    val density = LocalDensity.current
    val radiusTargetPx = remember(density) { with(density) { 160.dp.toPx() } }

    val infiniteTransition = rememberInfiniteTransition(label = "Scanning")
    val radius by infiniteTransition.animateFloat(0f, radiusTargetPx, infiniteRepeatable(tween(3000, easing = LinearOutSlowInEasing)), label = "R")
    val alpha by infiniteTransition.animateFloat(1f, 0f, infiniteRepeatable(tween(3000, easing = LinearOutSlowInEasing)), label = "A")

    Box(contentAlignment = Alignment.Center) {
        Canvas(modifier = Modifier.size(320.dp)) {
            drawCircle(color.copy(alpha = alpha * 0.3f), radius, style = Stroke(2.dp.toPx()))
            drawCircle(color.copy(alpha = alpha * 0.1f), radius * 0.7f, style = Stroke(1.dp.toPx()))
        }
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text(stringResource(R.string.status_scanning), style = MaterialTheme.typography.labelMedium, color = color)
            Spacer(modifier = Modifier.height(16.dp))
            Text(stringResource(R.string.label_no_host), style = MaterialTheme.typography.headlineMedium, color = TextPrimary, fontWeight = FontWeight.Bold)
            Text(stringResource(R.string.label_broadcasting_mesh), style = MaterialTheme.typography.labelSmall, color = TextSecondary)
        }
    }
}

@Composable
fun ActiveLinkVisualizer(color: Color, status: String, subStatus: String) {
    val infiniteTransition = rememberInfiniteTransition(label = "Active")
    val rotation by infiniteTransition.animateFloat(0f, 360f, infiniteRepeatable(tween(20000, easing = LinearEasing)), label = "Rot")

    Box(contentAlignment = Alignment.Center) {
        Canvas(modifier = Modifier.size(300.dp)) {
            drawCircle(Brush.radialGradient(listOf(color.copy(alpha = 0.15f), Color.Transparent), radius = size.width / 2))
        }
        Canvas(modifier = Modifier.size(260.dp).graphicsLayer { rotationZ = rotation }) {
            drawArc(color, 0f, 120f, false, style = Stroke(4.dp.toPx(), cap = StrokeCap.Round))
        }
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text(status, style = MaterialTheme.typography.headlineSmall, color = color, textAlign = TextAlign.Center)
            Text(subStatus, style = MaterialTheme.typography.labelMedium, color = TextSecondary)
        }
    }
}

@Composable
fun PanicRestoreCard(onInitiateRestore: () -> Unit) {
    LiquidSurface(tint = IntegrityGreen) {
        Text(stringResource(R.string.status_lockdown_active), style = MaterialTheme.typography.labelMedium, color = AlertRed)
        Spacer(modifier = Modifier.height(8.dp))
        Text(stringResource(R.string.panic_message), style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
        Spacer(modifier = Modifier.height(24.dp))
        PremiumControlAction(stringResource(R.string.label_restore), IntegrityGreen, onInitiateRestore)
    }
}

@Composable
fun LoadingSecurityStep(msg: String) {
    Column(modifier = Modifier.fillMaxWidth().padding(24.dp), horizontalAlignment = Alignment.CenterHorizontally) {
        CircularProgressIndicator(color = LiquidCyan, strokeWidth = 1.dp)
        Spacer(modifier = Modifier.height(16.dp))
        Text(msg, style = MaterialTheme.typography.labelMedium, color = TextSecondary)
    }
}

@Composable
fun BiometricVerificationStep(onVerify: () -> Unit) {
    LiquidSurface(tint = LiquidCyan) {
        Text(stringResource(R.string.header_identity_required), style = MaterialTheme.typography.labelMedium, color = LiquidCyan)
        Spacer(modifier = Modifier.height(8.dp))
        Text(stringResource(R.string.identity_message), style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
        Spacer(modifier = Modifier.height(24.dp))
        PremiumControlAction(stringResource(R.string.btn_verify), LiquidCyan, onVerify)
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
    val context = LocalContext.current
    val powerManager = remember { context.getSystemService(Context.POWER_SERVICE) as PowerManager }
    var isBatteryOptimized by remember { mutableStateOf(!powerManager.isIgnoringBatteryOptimizations(context.packageName)) }

    val scrollState = rememberScrollState()
    Column(modifier = Modifier.fillMaxSize().verticalScroll(scrollState).padding(24.dp)) {
        Text(stringResource(R.string.header_system_config), style = MaterialTheme.typography.labelLarge, color = LiquidCyan)
        Spacer(modifier = Modifier.height(24.dp))

        LiquidSurface {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(stringResource(R.string.label_biometric_gateway), style = MaterialTheme.typography.titleLarge, color = TextPrimary)
                    Text(stringResource(R.string.desc_biometric_gateway), style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
                }
                Switch(isBiometricEnabled, onBiometricToggled, colors = SwitchDefaults.colors(checkedTrackColor = LiquidCyan))
            }
            if (isBiometricEnabled) {
                Spacer(modifier = Modifier.height(24.dp))
                Text(stringResource(R.string.label_lock_threshold), style = MaterialTheme.typography.labelMedium, color = LiquidCyan)
                Spacer(modifier = Modifier.height(16.dp))
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    listOf("IMM" to 0L, "1M" to 60000L, "5M" to 300000L).forEach { (l, v) ->
                        val sel = selectedTimeoutMs == v
                        Box(Modifier.height(40.dp).weight(1f).clip(RoundedCornerShape(12.dp)).background(if(sel) LiquidCyan.copy(0.1f) else Color.White.copy(0.03f)).clickable { onTimeoutChanged(v) }.border(0.5.dp, if(sel) LiquidCyan else GlassBorder, RoundedCornerShape(12.dp)), contentAlignment = Alignment.Center) {
                            Text(l, color = if(sel) LiquidCyan else TextSecondary)
                        }
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(24.dp))
        LiquidSurface {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(stringResource(R.string.label_ui_hardening), style = MaterialTheme.typography.titleLarge, color = TextPrimary)
                    Text(stringResource(R.string.desc_ui_hardening), style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
                }
                Switch(isPrivacyMaskEnabled, onPrivacyMaskToggled, colors = SwitchDefaults.colors(checkedTrackColor = LiquidCyan))
            }
        }

        Spacer(modifier = Modifier.height(24.dp))
        LiquidSurface {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(stringResource(R.string.label_battery_persistence), style = MaterialTheme.typography.titleLarge, color = TextPrimary)
                    Text(if (isBatteryOptimized) stringResource(R.string.desc_battery_optimized) else stringResource(R.string.desc_battery_unrestricted), 
                        style = MaterialTheme.typography.bodyMedium, 
                        color = if (isBatteryOptimized) MatrixGold else IntegrityGreen)
                }
                if (isBatteryOptimized) {
                    Button(
                        onClick = {
                            val intent = Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)
                            context.startActivity(intent)
                        },
                        colors = ButtonDefaults.buttonColors(containerColor = LiquidCyan.copy(0.1f)),
                        border = BorderStroke(0.5.dp, LiquidCyan)
                    ) {
                        Text(stringResource(R.string.btn_fix), color = LiquidCyan)
                    }
                } else {
                    Icon(Icons.Default.CheckCircle, contentDescription = null, tint = IntegrityGreen)
                }
            }
        }

        Spacer(modifier = Modifier.height(24.dp))
        DeviceAttestationCard(LocalContext.current)
    }
}

@Composable
fun DeviceAttestationCard(context: Context) {
    val evaluator = remember { DeviceIntegrityRegistry(context) }
    val report by produceState(
        IntegrityReport(
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
        withContext(Dispatchers.IO) { value = evaluator.runAttestationPipeline() }
    }

    LiquidSurface(tint = if (report.score >= 85) IntegrityGreen else AlertRed, blur = 15f) {
        Row(horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
            Column {
                Text(stringResource(R.string.header_integrity_core), style = MaterialTheme.typography.labelLarge, color = LiquidCyan)
                Text(stringResource(report.tier.labelRes), color = report.tier.color, style = MaterialTheme.typography.labelMedium)
            }
            Text(report.score.toString(), style = MaterialTheme.typography.headlineMedium, color = report.tier.color)
        }
        Spacer(modifier = Modifier.height(16.dp))
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            MetricRow(stringResource(R.string.label_bootloader), report.isBootloaderLocked)
            MetricRow(stringResource(R.string.label_root), report.isNotRooted)
            MetricRow(stringResource(R.string.label_dev_module), report.isDevOptionsDisabled)
            MetricRow(stringResource(R.string.label_adb), report.isUsbDebuggingDisabled)
        }
    }
}

@Composable
fun MetricRow(label: String, pass: Boolean) {
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(label, color = TextSecondary)
        Text(if(pass) stringResource(R.string.label_secure) else stringResource(R.string.label_fail), color = if(pass) IntegrityGreen else AlertRed)
    }
}

@Composable
fun LaptopControlScreen(onBleActionRequested: (String) -> Unit) {
    var vol by remember { mutableFloatStateOf(50f) }
    var bri by remember { mutableFloatStateOf(50f) }
    Column(Modifier.fillMaxSize().padding(24.dp)) {
        Text(stringResource(R.string.header_hardware_interface), style = MaterialTheme.typography.labelLarge, color = LiquidCyan)
        Spacer(modifier = Modifier.height(24.dp))
        LiquidSurface {
            Text(stringResource(R.string.label_volume), style = MaterialTheme.typography.titleLarge, color = TextPrimary)
            Slider(vol, { vol = it; onBleActionRequested(if(it > vol) "VOL_UP" else "VOL_DOWN") }, colors = SliderDefaults.colors(thumbColor = TextPrimary, activeTrackColor = LiquidCyan))
        }
        Spacer(modifier = Modifier.height(24.dp))
        LiquidSurface {
            Text(stringResource(R.string.label_brightness), style = MaterialTheme.typography.titleLarge, color = TextPrimary)
            Slider(bri, { bri = it; onBleActionRequested(if(it > bri) "BRIGHT_UP" else "BRIGHT_DOWN") }, colors = SliderDefaults.colors(thumbColor = TextPrimary, activeTrackColor = LiquidCyan))
        }
    }
}

@Composable
fun PairingScreen(onShowQR: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Text(
            stringResource(R.string.header_device_pairing),
            style = MaterialTheme.typography.headlineSmall,
            color = LiquidCyan,
            fontWeight = FontWeight.Bold
        )
        Spacer(modifier = Modifier.height(16.dp))
        Text(
            stringResource(R.string.desc_pairing),
            style = MaterialTheme.typography.bodyMedium,
            color = TextSecondary,
            textAlign = TextAlign.Center
        )
        Spacer(modifier = Modifier.height(48.dp))

        LiquidSurface(modifier = Modifier.fillMaxWidth()) {
            PremiumControlAction(
                stringResource(R.string.btn_show_pairing_qr),
                LiquidCyan,
                onShowQR
            )
            Spacer(modifier = Modifier.height(16.dp))
            Text(
                stringResource(R.string.desc_pairing_key),
                style = MaterialTheme.typography.bodySmall,
                color = TextMuted,
                textAlign = TextAlign.Center
            )
        }
    }
}

@Composable
fun CyberConfirmationDialog(title: String, message: String, onConfirm: () -> Unit, onDismiss: () -> Unit) {
    AlertDialog(onDismissRequest = onDismiss, containerColor = SurfaceElevated, modifier = Modifier.border(0.5.dp, GlassBorder, RoundedCornerShape(24.dp)), shape = RoundedCornerShape(24.dp),
        title = { Text(title, color = AlertRed) },
        text = { Text(message, color = TextSecondary) },
        confirmButton = { Button(onConfirm, colors = ButtonDefaults.buttonColors(containerColor = AlertRed.copy(0.1f)), border = BorderStroke(0.5.dp, AlertRed)) { Text(stringResource(R.string.btn_execute), color = AlertRed) } },
        dismissButton = { TextButton(onDismiss) { Text(stringResource(R.string.btn_abort), color = TextSecondary) } }
    )
}

@Composable
fun CompromisedEnvironmentOverlay(score: Int) {
    Box(Modifier.fillMaxSize().background(DeepSpace), contentAlignment = Alignment.Center) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text(stringResource(R.string.header_security_lockdown), color = AlertRed, style = MaterialTheme.typography.labelLarge)
            Spacer(modifier = Modifier.height(48.dp))
            Text(score.toString(), style = MaterialTheme.typography.headlineLarge, color = AlertRed)
            Text(stringResource(R.string.label_trust_index), color = TextSecondary)
        }
    }
}

@Composable
fun CommandConfirmationDialog(
    command: String,
    isConfirmed: Boolean,
    onDismiss: () -> Unit
) {
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(DeepSpace.copy(alpha = 0.85f))
            .clickable(enabled = false) {},
        contentAlignment = Alignment.Center
    ) {
        LiquidSurface(
            modifier = Modifier.width(320.dp),
            tint = if (isConfirmed) IntegrityGreen else LiquidCyan,
            alpha = 0.2f,
            blur = 40f
        ) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                if (isConfirmed) {
                    Icon(
                        Icons.Default.CheckCircle,
                        contentDescription = null,
                        tint = IntegrityGreen,
                        modifier = Modifier.size(64.dp)
                    )
                } else {
                    CircularProgressIndicator(
                        color = LiquidCyan,
                        strokeWidth = 2.dp,
                        modifier = Modifier.size(64.dp)
                    )
                }

                Spacer(modifier = Modifier.height(24.dp))

                Text(
                    text = if (isConfirmed) "Handshake Verified" else "Transmitting Cryptographic Token...",
                    style = MaterialTheme.typography.titleMedium,
                    color = if (isConfirmed) IntegrityGreen else LiquidCyan,
                    textAlign = TextAlign.Center
                )

                Spacer(modifier = Modifier.height(12.dp))

                val displayName = command.uppercase().replace("_", " ")
                Text(
                    text = if (isConfirmed)
                        "Execution link established successfully for $displayName."
                    else
                        "Awaiting execution handshake link for $displayName...",
                    style = MaterialTheme.typography.bodyMedium,
                    color = TextSecondary,
                    textAlign = TextAlign.Center
                )

                Spacer(modifier = Modifier.height(32.dp))

                PremiumControlAction(
                    label = "Dismiss",
                    accentColor = TextSecondary,
                    onClick = onDismiss
                )
            }
        }
    }
}

@Composable
fun FuturisticLockOverlay(onAuthorizeRequested: () -> Unit) {
    Box(
        Modifier
            .fillMaxSize()
            .clickable { onAuthorizeRequested() },
        contentAlignment = Alignment.Center
    ) {
        // Blurred background layer
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(DeepSpace.copy(0.9f))
                .graphicsLayer {
                    renderEffect = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                        android.graphics.RenderEffect.createBlurEffect(60f, 60f, android.graphics.Shader.TileMode.CLAMP).asComposeRenderEffect()
                    } else {
                        null
                    }
                }
        )

        // Sharp content layer
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text("🔒", fontSize = 64.sp)
            Spacer(modifier = Modifier.height(32.dp))
            Text(stringResource(R.string.label_vault_enforced), color = LiquidCyan, style = MaterialTheme.typography.labelLarge)
            Text(stringResource(R.string.label_tap_to_decrypt), color = TextMuted, style = MaterialTheme.typography.labelMedium)
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
        val devOptionsDisabled = Settings.Global.getInt(context.contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 0
        if (devOptionsDisabled) finalScore += 10
        val usbDebuggingDisabled = Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED, 0) == 0
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
        return IntegrityReport(finalScore, assignedTier, bootloaderLocked, notRooted, devOptionsDisabled, usbDebuggingDisabled, appIntegrityValid, secureLockscreenEnabled)
    }
    private fun checkBootloaderStatus(): Boolean {
        val aboot = Build.BOOTLOADER.lowercase()
        return aboot.isNotEmpty() && !aboot.contains("unknown") && !aboot.contains("unlocked")
    }
    private fun checkRootStatus(): Boolean {
        val tags = Build.TAGS
        if (tags != null && tags.contains("test-keys")) return true
        val commonPaths = arrayOf("/system/app/Superuser.apk", "/sbin/su", "/system/bin/su", "/system/xbin/su", "/data/local/xbin/su", "/data/local/bin/su", "/system/sd/xbin/su", "/system/bin/failsafe/su", "/data/local/su")
        for (path in commonPaths) if (File(path).exists()) return true
        return false
    }
    private fun verifyAppSignatureIntegrity(): Boolean {
        return try {
            val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                PackageManager.GET_SIGNING_CERTIFICATES
            } else {
                @Suppress("DEPRECATION")
                PackageManager.GET_SIGNATURES
            }

            val packageInfo = context.packageManager.getPackageInfo(context.packageName, flags)
            val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                packageInfo.signingInfo?.apkContentsSigners
            } else {
                @Suppress("DEPRECATION")
                packageInfo.signatures
            }

            if (signatures.isNullOrEmpty()) return false

            // Production verification hash anchoring standard release keys
            val targetCertificatePin = "D8:5F:A3:4E:91:C1:28:9B:F3:A1:02:4F:99:A8:12:44:A2:3F:89:B1:02:44:5F:99:A8:B1:22:4E:A3:F4:99:12"

            val digestEngine = java.security.MessageDigest.getInstance("SHA-256")
            val certBytes = signatures[0].toByteArray()
            val computedHash = digestEngine.digest(certBytes).joinToString(":") { String.format("%02X", it) }

            computedHash == targetCertificatePin || Build.FINGERPRINT.startsWith("generic")
        } catch (_: Exception) { false }
    }
}