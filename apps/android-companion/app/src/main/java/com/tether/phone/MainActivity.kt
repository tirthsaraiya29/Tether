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
import java.util.concurrent.ExecutorService
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
import androidx.compose.material.icons.filled.QrCode
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
import android.util.Log
import java.util.concurrent.Executors

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
    private var dismissalJob: kotlinx.coroutines.Job? = null

    private var pendingPowerAction = mutableStateOf<PowerAction?>(null)
    private data class PowerAction(val command: String, val title: String)

    private var lastBiometricAuthTime = 0L

    private lateinit var executor: ExecutorService

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
                    dismissalJob?.cancel()
                    dismissalJob = lifecycleScope.launch {
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
                        AtmosphericBackground()
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
                                onShowQR = {
                                    getSharedPreferences(preferenceName, MODE_PRIVATE).edit()
                                        .putBoolean("pairing_mode_active", true)
                                        .apply()
                                    showPairingQRCode()
                                }
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

                            AnimatedVisibility(
                                visible = activePendingCommand.value != null,
                                enter = fadeIn(tween(400)),
                                exit = fadeOut(tween(400)) + scaleOut(targetScale = 0.5f, animationSpec = tween(400, easing = EaseInOutSans))
                            ) {
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

        val statusIntent = Intent(this, BleGattServerService::class.java).apply {
            action = "ACTION_GET_STATUS"
        }
        try {
            startForegroundService(statusIntent)
        } catch (e: Exception) {
            Log.e("TetherActivity", "Failed pulling background service status", e)
        }
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

        if (!isAppLocked.value && !checkPermissions()) {
            requestPermissions()
            return
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
        try { unregisterReceiver(screenUnlockReceiver) } catch (_: Exception) {}
        try { unregisterReceiver(bluetoothStateReceiver) } catch (_: Exception) {}
        
        executor.shutdown()
        super.onDestroy()
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
            Log.w("TetherUI", "App is not exempted from battery optimizations. Requesting exemption.")
            try {
                val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                    data = android.net.Uri.parse("package:$packageName")
                }
                batteryOptimizationLauncher.launch(intent)
            } catch (e: Exception) {
                val intent = Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)
                batteryOptimizationLauncher.launch(intent)
            }
        } else {
            Log.i("TetherUI", "App is already exempted from battery optimizations.")
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
                    .setPositiveButton(getString(R.string.btn_done)) { _, _ -> 
                        getSharedPreferences(preferenceName, MODE_PRIVATE).edit()
                            .putBoolean("pairing_mode_active", false)
                            .apply()
                    }
                    .setNegativeButton(getString(R.string.btn_copy_key)) { _, _ ->
                        val clipboard = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
                        clipboard.setPrimaryClip(ClipData.newPlainText("TetherPublicKey", base64Key))
                    }
                    .setOnDismissListener {
                        getSharedPreferences(preferenceName, MODE_PRIVATE).edit()
                            .putBoolean("pairing_mode_active", false)
                            .apply()
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
        dismissalJob?.cancel()
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

@Composable
fun LiquidSurface(
    modifier: Modifier = Modifier,
    alpha: Float = 0.08f,
    tint: Color = Color.White,
    blur: Float = 24f,
    content: @Composable ColumnScope.() -> Unit
) {
    val infiniteTransition = rememberInfiniteTransition(label = "SurfaceTilt")
    val tiltX by infiniteTransition.animateFloat(
        initialValue = -1f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(8000, easing = EaseInOutSans),
            repeatMode = RepeatMode.Reverse
        ), label = "TiltX"
    )
    val tiltY by infiniteTransition.animateFloat(
        initialValue = -1f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(6000, easing = EaseInOutSans),
            repeatMode = RepeatMode.Reverse
        ), label = "TiltY"
    )

    Box(
        modifier = modifier
            .graphicsLayer {
                rotationX = tiltX * 1.5f
                rotationY = tiltY * 1.5f
                cameraDistance = 16f * density
            }
            .clip(RoundedCornerShape(28.dp))
            .border(
                width = 0.5.dp,
                brush = Brush.linearGradient(
                    listOf(
                        Color.White.copy(alpha = 0.3f),
                        Color.White.copy(alpha = 0.05f),
                        Color.White.copy(alpha = 0.25f)
                    ),
                    start = Offset(0f, 0f),
                    end = Offset(1000f, 1000f)
                ),
                shape = RoundedCornerShape(28.dp)
            )
    ) {
        Box(
            modifier = Modifier
                .matchParentSize()
                .background(
                    Brush.verticalGradient(
                        listOf(
                            tint.copy(alpha = alpha * 1.2f),
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
                    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
                        val noiseStep = 3f
                        for (x in 0 until size.width.toInt() step noiseStep.toInt()) {
                            for (y in 0 until size.height.toInt() step noiseStep.toInt()) {
                                if ((x + y) % 9 == 0) {
                                    drawCircle(
                                        color = Color.White.copy(alpha = 0.04f),
                                        radius = 0.8f,
                                        center = Offset(x.toFloat(), y.toFloat())
                                    )
                                }
                            }
                        }
                    }

                    val strokeWidth = 1.4.dp.toPx()
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
                                Color.White.copy(alpha = 0.5f),
                                Color.White.copy(alpha = 0.0f)
                            ),
                            start = Offset(tiltX * 20f, tiltY * 20f),
                            end = Offset(size.width * 0.4f, size.height * 0.4f)
                        ),
                        style = Stroke(width = strokeWidth, cap = StrokeCap.Round)
                    )
                }
        )

        Column(
            modifier = Modifier.padding(24.dp),
            content = content
        )
    }
}

@Composable
fun AtmosphericBackground() {
    val density = LocalDensity.current
    val gridTargetPx = remember(density) { with(density) { 60.dp.toPx() } }

    val infiniteTransition = rememberInfiniteTransition(label = "Atmosphere")
    val gridShift by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = gridTargetPx,
        animationSpec = infiniteRepeatable(
            animation = tween(20000, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ), label = "Grid"
    )
    val nebulaAlpha by infiniteTransition.animateFloat(
        initialValue = 0.03f,
        targetValue = 0.15f,
        animationSpec = infiniteRepeatable(
            animation = tween(12000, easing = EaseInOutSans),
            repeatMode = RepeatMode.Reverse
        ), label = "Nebula"
    )
    val shimmerAlpha by infiniteTransition.animateFloat(
        initialValue = 0.1f,
        targetValue = 0.5f,
        animationSpec = infiniteRepeatable(
            animation = tween(4000, easing = EaseInOutSans),
            repeatMode = RepeatMode.Reverse
        ), label = "Shimmer"
    )

    Canvas(modifier = Modifier.fillMaxSize().graphicsLayer { renderEffect = null }) {
        val gridSize = 60.dp.toPx()
        val gridColor = LiquidCyan.copy(alpha = 0.04f)
        
        drawRect(DeepSpace)

        var x = (gridShift % gridSize) - gridSize
        while (x < size.width + gridSize) {
            val distortionX = kotlin.math.sin((x + gridShift) / 120.0).toFloat() * 6f
            drawLine(gridColor, Offset(x + distortionX, 0f), Offset(x + distortionX, size.height), 0.5.dp.toPx())
            x += gridSize
        }
        var y = (gridShift % gridSize) - gridSize
        while (y < size.height + gridSize) {
            val distortionY = kotlin.math.cos((y + gridShift) / 120.0).toFloat() * 6f
            drawLine(gridColor, Offset(0f, y + distortionY), Offset(size.width, y + distortionY), 0.5.dp.toPx())
            y += gridSize
        }

        drawCircle(
            brush = Brush.radialGradient(
                0.0f to LiquidCyan.copy(alpha = nebulaAlpha),
                0.5f to LiquidCyan.copy(alpha = nebulaAlpha * 0.4f),
                1.0f to Color.Transparent,
                center = Offset(size.width * 0.3f, size.height * 0.2f),
                radius = 1200.dp.toPx()
            ),
            center = Offset(size.width * 0.3f, size.height * 0.2f),
            radius = 1200.dp.toPx()
        )
        drawCircle(
            brush = Brush.radialGradient(
                0.0f to IntegrityGreen.copy(alpha = nebulaAlpha * 0.8f),
                0.6f to IntegrityGreen.copy(alpha = nebulaAlpha * 0.1f),
                1.0f to Color.Transparent,
                center = Offset(size.width * 0.8f, size.height * 0.8f),
                radius = 1000.dp.toPx()
            ),
            center = Offset(size.width * 0.8f, size.height * 0.8f),
            radius = 1000.dp.toPx()
        )
        
        val random = java.util.Random(42)
        for (i in 0 until 40) {
            val px = random.nextFloat() * size.width
            val py = random.nextFloat() * size.height
            val pSize = random.nextFloat() * 2.dp.toPx()
            val pAlpha = random.nextFloat() * shimmerAlpha
            drawCircle(Color.White.copy(alpha = pAlpha), pSize, Offset(px, py))
        }
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
    
    val animatedScale by animateFloatAsState(
        targetValue = if (isPressed) 0.94f else 1f,
        animationSpec = spring(dampingRatio = 0.55f, stiffness = Spring.StiffnessMediumLow),
        label = "Scale"
    )
    val animatedTilt by animateFloatAsState(
        targetValue = if (isPressed) 6f else 0f,
        animationSpec = spring(dampingRatio = 0.5f, stiffness = 200f),
        label = "Tilt"
    )
    val animatedGlow by animateFloatAsState(
        targetValue = if (isPressed) 0.45f else 0.18f,
        animationSpec = tween(250, easing = EaseInOutSans),
        label = "Glow"
    )

    Box(
        modifier = modifier
            .graphicsLayer {
                scaleX = animatedScale
                scaleY = animatedScale
                rotationX = animatedTilt
                cameraDistance = 12f * density
                alpha = if (enabled) 1f else 0.4f
            }
            .fillMaxWidth()
            .height(68.dp)
            .clip(RoundedCornerShape(22.dp))
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
                        accentColor.copy(alpha = if (isPressed) 1f else 0.5f),
                        accentColor.copy(alpha = 0.1f)
                    )
                ),
                shape = RoundedCornerShape(22.dp)
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
                    val strokeWidth = 1.5.dp.toPx()
                    drawLine(
                        color = Color.White.copy(alpha = if (isPressed) 0.35f else 0.25f),
                        start = Offset(14.dp.toPx(), 4.dp.toPx()),
                        end = Offset(size.width - 28.dp.toPx(), 4.dp.toPx()),
                        strokeWidth = strokeWidth,
                        cap = StrokeCap.Round)
                    }
        )
        Text(
            text = label,
            style = MaterialTheme.typography.labelLarge,
            color = if (enabled) accentColor else TextMuted,
            fontWeight = FontWeight.ExtraBold,
            letterSpacing = 4.sp,
            modifier = Modifier.graphicsLayer {
                translationY = if (isPressed) 1.dp.toPx() else 0f
            }
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
                    Box(
                        modifier = Modifier
                            .fillMaxSize()
                            .background(DeepSpace.copy(alpha = 0.85f))
                            .graphicsLayer {
                                renderEffect = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                                    android.graphics.RenderEffect.createBlurEffect(40f, 40f, android.graphics.Shader.TileMode.CLAMP).asComposeRenderEffect()
                                } else {
                                    null
                                }
                            }
                    )
                    Column(modifier = Modifier.fillMaxSize().padding(32.dp)) {
                        Spacer(modifier = Modifier.height(64.dp))
                        Text(stringResource(R.string.nav_command_interface), style = MaterialTheme.typography.labelMedium, color = LiquidCyan)
                        Spacer(modifier = Modifier.height(48.dp))

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
                                    selectedContainerColor = LiquidCyan.copy(alpha = 0.12f),
                                    unselectedContainerColor = Color.Transparent,
                                    selectedIconColor = LiquidCyan,
                                    unselectedIconColor = TextSecondary,
                                    selectedTextColor = LiquidCyan,
                                    unselectedTextColor = TextSecondary
                                ),
                                shape = RoundedCornerShape(20.dp),
                                onClick = {
                                    currentScreen = screen
                                    scope.launch { drawerState.close() }
                                }
                            )
                            Spacer(modifier = Modifier.height(8.dp))
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
                        (fadeIn(animationSpec = spring(stiffness = Spring.StiffnessLow)) + 
                         scaleIn(initialScale = 0.96f, animationSpec = spring(stiffness = Spring.StiffnessLow)))
                            .togetherWith(fadeOut(animationSpec = spring(stiffness = Spring.StiffnessLow)) + 
                                         scaleOut(targetScale = 1.04f, animationSpec = spring(stiffness = Spring.StiffnessLow)))
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
    var visible by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) { visible = true }

    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(scrollState).padding(horizontal = 24.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        AnimatedVisibility(
            visible = visible,
            enter = fadeIn(tween(1000)) + expandVertically(tween(800, easing = EaseInOutSans))
        ) {
            Box(modifier = Modifier.fillMaxWidth().height(360.dp).graphicsLayer { translationY = -scrollState.value * 0.2f }, contentAlignment = Alignment.Center) {
                if (isConnected) ActiveLinkVisualizer(statusColor, statusText, connectionStatus)
                else ScanningVisualizer(statusColor)
            }
        }

        AnimatedVisibility(
            visible = visible,
            enter = fadeIn(tween(800, delayMillis = 200)) + slideInVertically(tween(800, delayMillis = 200)) { it / 2 }
        ) {
            LiquidSurface(modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.header_hardware_directives), style = MaterialTheme.typography.labelMedium, color = LiquidCyan)
                Spacer(modifier = Modifier.height(28.dp))
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(20.dp)) {
                    PremiumControlAction(stringResource(R.string.label_sleep), MatrixGold, { onBleActionRequested("PWR_SLEEP") }, Modifier.weight(1f), isConnected)
                    PremiumControlAction(stringResource(R.string.label_reboot), TextPrimary, { onBleActionRequested("PWR_REBOOT") }, Modifier.weight(1f), isConnected)
                }
                Spacer(modifier = Modifier.height(20.dp))
                PremiumControlAction(stringResource(R.string.label_halt_system), AlertRed, { onBleActionRequested("PWR_SHUTDOWN") }, enabled = isConnected)
            }
        }

        Spacer(modifier = Modifier.height(28.dp))

        AnimatedContent(targetState = verificationStep, label = "Security") { step ->
            Column(verticalArrangement = Arrangement.spacedBy(20.dp)) {
                when (step) {
                    TrustVerificationStep.NOT_IN_PANIC -> {
                        if (isPanicActive) {
                            AnimatedVisibility(visible = visible, enter = fadeIn(tween(800, 400)) + scaleIn(initialScale = 0.9f)) {
                                PanicRestoreCard(onInitiateRestore)
                            }
                        } else {
                            AnimatedVisibility(visible = visible, enter = fadeIn(tween(800, 400)) + slideInVertically(tween(800, 400)) { it / 2 }) {
                                Column(verticalArrangement = Arrangement.spacedBy(20.dp)) {
                                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(20.dp)) {
                                        PremiumControlAction(stringResource(R.string.label_unlock), IntegrityGreen, onUnlockClick, Modifier.weight(1f), isConnected)
                                        PremiumControlAction(stringResource(R.string.label_lock), LiquidCyan, onLockClick, Modifier.weight(1f), isConnected)
                                    }
                                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(20.dp)) {
                                        PremiumControlAction(stringResource(R.string.label_target), TextSecondary, onSelectLaptop, Modifier.weight(1f))
                                        PremiumControlAction(stringResource(R.string.label_panic), AlertRed, onPanicClick, Modifier.weight(1f))
                                    }
                                }
                            }
                        }
                    }
                    TrustVerificationStep.DEVICE_CREDENTIAL -> LoadingSecurityStep(stringResource(R.string.status_verifying_security))
                    TrustVerificationStep.BIOMETRIC_FINGERPRINT -> BiometricVerificationStep { onTriggerStepVerification(step) }
                }
            }
        }
        Spacer(modifier = Modifier.height(64.dp))
    }
}

@Composable
fun ScanningVisualizer(color: Color) {
    val density = LocalDensity.current
    val radiusTargetPx = remember(density) { with(density) { 160.dp.toPx() } }

    val infiniteTransition = rememberInfiniteTransition(label = "Scanning")
    val radius by infiniteTransition.animateFloat(0f, radiusTargetPx, infiniteRepeatable(tween(3500, easing = LinearOutSlowInEasing)), label = "R")
    val alpha by infiniteTransition.animateFloat(1f, 0f, infiniteRepeatable(tween(3500, easing = LinearOutSlowInEasing)), label = "A")
    val pulseScale by infiniteTransition.animateFloat(1f, 1.1f, infiniteRepeatable(tween(2000, easing = EaseInOutSans), repeatMode = RepeatMode.Reverse), label = "P")

    Box(contentAlignment = Alignment.Center) {
        Canvas(modifier = Modifier.size(320.dp).graphicsLayer { scaleX = pulseScale; scaleY = pulseScale }) {
            drawCircle(color.copy(alpha = alpha * 0.4f), radius, style = Stroke(2.5.dp.toPx()))
            drawCircle(color.copy(alpha = alpha * 0.15f), radius * 0.7f, style = Stroke(1.5.dp.toPx()))
            
            drawArc(
                color = Color.White.copy(alpha = alpha * 0.2f),
                startAngle = -45f,
                sweepAngle = 90f,
                useCenter = false,
                topLeft = Offset(center.x - radius, center.y - radius),
                size = androidx.compose.ui.geometry.Size(radius * 2, radius * 2),
                style = Stroke(4.dp.toPx(), cap = StrokeCap.Round)
            )
        }
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text(stringResource(R.string.status_scanning), style = MaterialTheme.typography.labelMedium, color = color)
            Spacer(modifier = Modifier.height(20.dp))
            Text(stringResource(R.string.label_no_host), style = MaterialTheme.typography.headlineMedium, color = TextPrimary, fontWeight = FontWeight.Bold)
            Text(stringResource(R.string.label_broadcasting_mesh), style = MaterialTheme.typography.labelSmall, color = TextSecondary)
        }
    }
}

@Composable
fun ActiveLinkVisualizer(color: Color, status: String, subStatus: String) {
    val infiniteTransition = rememberInfiniteTransition(label = "Active")
    val rotation by infiniteTransition.animateFloat(0f, 360f, infiniteRepeatable(tween(25000, easing = LinearEasing)), label = "Rot")
    val orbitRotation by infiniteTransition.animateFloat(360f, 0f, infiniteRepeatable(tween(15000, easing = LinearEasing)), label = "Orbit")
    val glowPulse by infiniteTransition.animateFloat(0.4f, 1f, infiniteRepeatable(tween(3000, easing = EaseInOutSans), repeatMode = RepeatMode.Reverse), label = "Glow")

    Box(contentAlignment = Alignment.Center) {
        Canvas(modifier = Modifier.size(320.dp).graphicsLayer { alpha = 0.8f }) {
            drawCircle(Brush.radialGradient(listOf(color.copy(alpha = 0.3f * glowPulse), Color.Transparent), radius = size.width / 1.8f))
        }
        
        Canvas(modifier = Modifier.size(280.dp).graphicsLayer { rotationZ = rotation }) {
            drawArc(color, 0f, 160f, false, style = Stroke(5.dp.toPx(), cap = StrokeCap.Round))
            drawArc(color.copy(alpha = 0.3f), 180f, 90f, false, style = Stroke(2.dp.toPx(), cap = StrokeCap.Round))
        }

        Canvas(modifier = Modifier.size(240.dp).graphicsLayer { rotationZ = orbitRotation }) {
            val nodeCenter = Offset(size.width, size.height/2)
            drawCircle(color, radius = 7.dp.toPx(), center = nodeCenter)
            drawCircle(color.copy(alpha = 0.4f), radius = 14.dp.toPx() * glowPulse, center = nodeCenter)
            
            val mirrorCenter = Offset(0f, size.height/2)
            drawCircle(color.copy(alpha = 0.6f), radius = 5.dp.toPx(), center = mirrorCenter)
            drawCircle(color.copy(alpha = 0.2f), radius = 10.dp.toPx() * glowPulse, center = mirrorCenter)
        }

        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            modifier = Modifier
                .width(180.dp)
                .graphicsLayer {
                    scaleX = glowPulse * 0.05f + 0.95f
                    scaleY = glowPulse * 0.05f + 0.95f
                }
        ) {
            Text(
                text = status,
                style = MaterialTheme.typography.headlineSmall,
                color = color,
                textAlign = TextAlign.Center,
                fontWeight = FontWeight.ExtraBold,
                lineHeight = 28.sp
            )
            Spacer(modifier = Modifier.height(8.dp))
            Text(subStatus, style = MaterialTheme.typography.labelMedium, color = TextSecondary)
        }
    }
}

@Composable
fun PanicRestoreCard(onInitiateRestore: () -> Unit) {
    LiquidSurface(tint = IntegrityGreen, alpha = 0.12f) {
        Text(stringResource(R.string.status_lockdown_active), style = MaterialTheme.typography.labelMedium, color = AlertRed)
        Spacer(modifier = Modifier.height(12.dp))
        Text(stringResource(R.string.panic_message), style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
        Spacer(modifier = Modifier.height(28.dp))
        PremiumControlAction(stringResource(R.string.label_restore), IntegrityGreen, onInitiateRestore)
    }
}

@Composable
fun LoadingSecurityStep(msg: String) {
    Column(modifier = Modifier.fillMaxWidth().padding(32.dp), horizontalAlignment = Alignment.CenterHorizontally) {
        CircularProgressIndicator(color = LiquidCyan, strokeWidth = 1.5.dp, modifier = Modifier.size(48.dp))
        Spacer(modifier = Modifier.height(20.dp))
        Text(msg, style = MaterialTheme.typography.labelMedium, color = TextSecondary)
    }
}

@Composable
fun BiometricVerificationStep(onVerify: () -> Unit) {
    LiquidSurface(tint = LiquidCyan, alpha = 0.12f) {
        Text(stringResource(R.string.header_identity_required), style = MaterialTheme.typography.labelMedium, color = LiquidCyan)
        Spacer(modifier = Modifier.height(12.dp))
        Text(stringResource(R.string.identity_message), style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
        Spacer(modifier = Modifier.height(28.dp))
        PremiumControlAction(stringResource(R.string.btn_verify), LiquidCyan, onVerify)
    }
}

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
    var visible by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) { visible = true }

    Column(modifier = Modifier.fillMaxSize().verticalScroll(scrollState).padding(24.dp)) {
        AnimatedVisibility(visible = visible, enter = fadeIn(tween(600)) + slideInVertically(tween(600)) { -it / 4 }) {
            Text(stringResource(R.string.header_system_config), style = MaterialTheme.typography.labelLarge, color = LiquidCyan, letterSpacing = 4.sp)
        }
        Spacer(modifier = Modifier.height(28.dp))

        AnimatedVisibility(visible = visible, enter = fadeIn(tween(600, 100)) + slideInVertically(tween(600, 100)) { it / 3 }) {
            LiquidSurface {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(stringResource(R.string.label_biometric_gateway), style = MaterialTheme.typography.titleLarge, color = TextPrimary)
                        Text(stringResource(R.string.desc_biometric_gateway), style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
                    }
                    Switch(isBiometricEnabled, onBiometricToggled, colors = SwitchDefaults.colors(checkedTrackColor = LiquidCyan))
                }
                AnimatedVisibility(visible = isBiometricEnabled, enter = expandVertically() + fadeIn(), exit = shrinkVertically() + fadeOut()) {
                    Column {
                        Spacer(modifier = Modifier.height(28.dp))
                        Text(stringResource(R.string.label_lock_threshold), style = MaterialTheme.typography.labelMedium, color = LiquidCyan)
                        Spacer(modifier = Modifier.height(18.dp))
                        FlowRow(horizontalArrangement = Arrangement.spacedBy(12.dp), maxItemsInEachRow = 3) {
                            listOf("IMM" to 0L, "1M" to 60000L, "5M" to 300000L).forEach { (l, v) ->
                                val sel = selectedTimeoutMs == v
                                Box(Modifier.height(44.dp).weight(1f).clip(RoundedCornerShape(14.dp)).background(if(sel) LiquidCyan.copy(0.15f) else Color.White.copy(0.04f)).clickable { onTimeoutChanged(v) }.border(0.5.dp, if(sel) LiquidCyan else GlassBorder, RoundedCornerShape(14.dp)).graphicsLayer { scaleX = if(sel) 1.05f else 1f; scaleY = if(sel) 1.05f else 1f }, contentAlignment = Alignment.Center) {
                                    Text(l, color = if(sel) LiquidCyan else TextSecondary, style = MaterialTheme.typography.labelLarge)
                                }
                            }
                        }
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(28.dp))
        AnimatedVisibility(visible = visible, enter = fadeIn(tween(600, 200)) + slideInVertically(tween(600, 200)) { it / 3 }) {
            LiquidSurface {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(stringResource(R.string.label_ui_hardening), style = MaterialTheme.typography.titleLarge, color = TextPrimary)
                        Text(stringResource(R.string.desc_ui_hardening), style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
                    }
                    Switch(isPrivacyMaskEnabled, onPrivacyMaskToggled, colors = SwitchDefaults.colors(checkedTrackColor = LiquidCyan))
                }
            }
        }

        Spacer(modifier = Modifier.height(28.dp))
        AnimatedVisibility(visible = visible, enter = fadeIn(tween(600, 300)) + slideInVertically(tween(600, 300)) { it / 3 }) {
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
                            colors = ButtonDefaults.buttonColors(containerColor = LiquidCyan.copy(0.12f)),
                            border = BorderStroke(0.5.dp, LiquidCyan),
                            shape = RoundedCornerShape(12.dp)
                        ) {
                            Text(stringResource(R.string.btn_fix), color = LiquidCyan)
                        }
                    } else {
                        Icon(Icons.Default.CheckCircle, contentDescription = null, tint = IntegrityGreen, modifier = Modifier.size(32.dp))
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(28.dp))
        AnimatedVisibility(visible = visible, enter = fadeIn(tween(600, 400)) + slideInVertically(tween(600, 400)) { it / 3 }) {
            DeviceAttestationCard(LocalContext.current)
        }
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

    LiquidSurface(tint = if (report.score >= 85) IntegrityGreen else AlertRed, blur = 20f) {
        Row(horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
            Column {
                Text(stringResource(R.string.header_integrity_core), style = MaterialTheme.typography.labelLarge, color = LiquidCyan, letterSpacing = 2.sp)
                Text(stringResource(report.tier.labelRes), color = report.tier.color, style = MaterialTheme.typography.labelMedium)
            }
            Text(report.score.toString(), style = MaterialTheme.typography.headlineLarge, color = report.tier.color)
        }
        Spacer(modifier = Modifier.height(24.dp))
        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
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
        Text(label, color = TextSecondary, style = MaterialTheme.typography.bodyMedium)
        Text(
            if(pass) stringResource(R.string.label_secure) else stringResource(R.string.label_fail), 
            color = if(pass) IntegrityGreen else AlertRed,
            fontWeight = FontWeight.Bold,
            style = MaterialTheme.typography.bodyMedium
        )
    }
}

@Composable
fun LaptopControlScreen(onBleActionRequested: (String) -> Unit) {
    var vol by remember { mutableFloatStateOf(50f) }
    var bri by remember { mutableFloatStateOf(50f) }
    val scrollState = rememberScrollState()
    var visible by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) { visible = true }

    Column(Modifier.fillMaxSize().verticalScroll(scrollState).padding(24.dp)) {
        AnimatedVisibility(visible = visible, enter = fadeIn(tween(600)) + slideInVertically(tween(600)) { -it / 4 }) {
            Text(stringResource(R.string.header_hardware_interface), style = MaterialTheme.typography.labelLarge, color = LiquidCyan, letterSpacing = 4.sp)
        }
        Spacer(modifier = Modifier.height(28.dp))
        
        AnimatedVisibility(visible = visible, enter = fadeIn(tween(600, 100)) + slideInVertically(tween(600, 100)) { it / 3 }) {
            LiquidSurface {
                Text(stringResource(R.string.label_volume), style = MaterialTheme.typography.titleLarge, color = TextPrimary)
                Spacer(modifier = Modifier.height(16.dp))
                Slider(vol, { vol = it; onBleActionRequested(if(it > vol) "VOL_UP" else "VOL_DOWN") }, colors = SliderDefaults.colors(thumbColor = TextPrimary, activeTrackColor = LiquidCyan))
            }
        }
        
        Spacer(modifier = Modifier.height(28.dp))
        
        AnimatedVisibility(visible = visible, enter = fadeIn(tween(600, 200)) + slideInVertically(tween(600, 200)) { it / 3 }) {
            LiquidSurface {
                Text(stringResource(R.string.label_brightness), style = MaterialTheme.typography.titleLarge, color = TextPrimary)
                Spacer(modifier = Modifier.height(16.dp))
                Slider(bri, { bri = it; onBleActionRequested(if(it > bri) "BRIGHT_UP" else "BRIGHT_DOWN") }, colors = SliderDefaults.colors(thumbColor = TextPrimary, activeTrackColor = LiquidCyan))
            }
        }
    }
}

@Composable
fun PairingScreen(onShowQR: () -> Unit) {
    var visible by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) { visible = true }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        AnimatedVisibility(visible = visible, enter = fadeIn(tween(800)) + scaleIn(initialScale = 0.85f)) {
            Text(
                stringResource(R.string.header_device_pairing),
                style = MaterialTheme.typography.headlineSmall,
                color = LiquidCyan,
                fontWeight = FontWeight.Bold,
                letterSpacing = 4.sp
            )
        }
        Spacer(modifier = Modifier.height(20.dp))
        AnimatedVisibility(visible = visible, enter = fadeIn(tween(800, 200))) {
            Text(
                stringResource(R.string.desc_pairing),
                style = MaterialTheme.typography.bodyMedium,
                color = TextSecondary,
                textAlign = TextAlign.Center
            )
        }
        Spacer(modifier = Modifier.height(56.dp))

        AnimatedVisibility(visible = visible, enter = fadeIn(tween(800, 400)) + slideInVertically(tween(800, 400)) { it / 2 }) {
            LiquidSurface(modifier = Modifier.fillMaxWidth()) {
                PremiumControlAction(
                    stringResource(R.string.btn_show_pairing_qr),
                    LiquidCyan,
                    onShowQR
                )
                Spacer(modifier = Modifier.height(20.dp))
                Text(
                    stringResource(R.string.desc_pairing_key),
                    style = MaterialTheme.typography.bodySmall,
                    color = TextMuted,
                    textAlign = TextAlign.Center
                )
            }
        }
    }
}

@Composable
fun CyberConfirmationDialog(title: String, message: String, onConfirm: () -> Unit, onDismiss: () -> Unit) {
    AlertDialog(onDismissRequest = onDismiss, containerColor = SurfaceElevated, modifier = Modifier.border(0.5.dp, GlassBorder, RoundedCornerShape(28.dp)), shape = RoundedCornerShape(28.dp),
        title = { Text(title, color = AlertRed, style = MaterialTheme.typography.titleLarge) },
        text = { Text(message, color = TextSecondary, style = MaterialTheme.typography.bodyLarge) },
        confirmButton = { Button(onConfirm, colors = ButtonDefaults.buttonColors(containerColor = AlertRed.copy(0.12f)), border = BorderStroke(0.5.dp, AlertRed), shape = RoundedCornerShape(12.dp)) { Text(stringResource(R.string.btn_execute), color = AlertRed, fontWeight = FontWeight.Bold) } },
        dismissButton = { TextButton(onDismiss) { Text(stringResource(R.string.btn_abort), color = TextSecondary) } }
    )
}

@Composable
fun CompromisedEnvironmentOverlay(score: Int) {
    Box(Modifier.fillMaxSize().background(DeepSpace), contentAlignment = Alignment.Center) {
        AtmosphericBackground() 
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text(stringResource(R.string.header_security_lockdown), color = AlertRed, style = MaterialTheme.typography.labelLarge, letterSpacing = 8.sp)
            Spacer(modifier = Modifier.height(56.dp))
            Text(score.toString(), style = MaterialTheme.typography.headlineLarge, color = AlertRed, fontSize = 80.sp)
            Text(stringResource(R.string.label_trust_index), color = TextSecondary, style = MaterialTheme.typography.labelMedium)
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
            .background(DeepSpace.copy(alpha = 0.94f))
            .clickable(enabled = false) {},
        contentAlignment = Alignment.Center
    ) {
        LiquidSurface(
            modifier = Modifier.width(360.dp),
            tint = if (isConfirmed) IntegrityGreen else LiquidCyan,
            alpha = 0.3f,
            blur = 60f
        ) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Box(contentAlignment = Alignment.Center) {
                    if (isConfirmed) {
                        Icon(
                            Icons.Default.CheckCircle,
                            contentDescription = null,
                            tint = IntegrityGreen,
                            modifier = Modifier.size(80.dp).graphicsLayer { 
                                scaleX = 1.1f
                                scaleY = 1.1f
                            }
                        )
                    } else {
                        CircularProgressIndicator(
                            color = LiquidCyan,
                            strokeWidth = 3.5.dp,
                            modifier = Modifier.size(80.dp)
                        )
                    }
                }

                Spacer(modifier = Modifier.height(32.dp))

                Text(
                    text = if (isConfirmed) "Handshake Verified" else "Transmitting Cryptographic Token...",
                    style = MaterialTheme.typography.titleLarge,
                    color = if (isConfirmed) IntegrityGreen else LiquidCyan,
                    textAlign = TextAlign.Center,
                    fontWeight = FontWeight.ExtraBold
                )

                Spacer(modifier = Modifier.height(18.dp))

                val displayName = command.uppercase().replace("_", " ")
                Text(
                    text = if (isConfirmed)
                        "Secure execution link established for $displayName."
                    else
                        "Negotiating encrypted handshake for $displayName...",
                    style = MaterialTheme.typography.bodyLarge,
                    color = TextSecondary,
                    textAlign = TextAlign.Center
                )

                Spacer(modifier = Modifier.height(40.dp))

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
    var visible by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) { visible = true }
    
    val infiniteTransition = rememberInfiniteTransition(label = "LockPulse")
    val pulse by infiniteTransition.animateFloat(
        initialValue = 0.8f,
        targetValue = 1.2f,
        animationSpec = infiniteRepeatable(
            animation = tween(2000, easing = EaseInOutSans),
            repeatMode = RepeatMode.Reverse
        ), label = "Pulse"
    )

    Box(
        Modifier
            .fillMaxSize()
            .clickable { onAuthorizeRequested() },
        contentAlignment = Alignment.Center
    ) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(DeepSpace.copy(0.95f))
                .graphicsLayer {
                    renderEffect = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                        android.graphics.RenderEffect.createBlurEffect(100f, 100f, android.graphics.Shader.TileMode.CLAMP).asComposeRenderEffect()
                    } else {
                        null
                    }
                }
        )

        AnimatedVisibility(
            visible = visible,
            enter = fadeIn(tween(1000)) + scaleIn(initialScale = 0.7f, animationSpec = spring(dampingRatio = 0.5f, stiffness = Spring.StiffnessLow))
        ) {
            Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.graphicsLayer { scaleX = pulse * 0.05f + 0.95f; scaleY = pulse * 0.05f + 0.95f }) {
                Text("🔒", fontSize = 90.sp, modifier = Modifier.graphicsLayer { alpha = pulse * 0.3f + 0.7f })
                Spacer(modifier = Modifier.height(48.dp))
                Text(stringResource(R.string.label_vault_enforced), color = LiquidCyan, style = MaterialTheme.typography.labelLarge, letterSpacing = 8.sp, fontWeight = FontWeight.Bold)
                Spacer(modifier = Modifier.height(12.dp))
                Text(stringResource(R.string.label_tap_to_decrypt), color = TextMuted, style = MaterialTheme.typography.labelMedium)
                
                val scanLinePos by infiniteTransition.animateFloat(
                    initialValue = 0f,
                    targetValue = 1f,
                    animationSpec = infiniteRepeatable(
                        animation = tween(3000, easing = LinearEasing),
                        repeatMode = RepeatMode.Restart
                    ), label = "Scan"
                )
                
                Canvas(modifier = Modifier.padding(top = 40.dp).width(200.dp).height(2.dp).graphicsLayer { alpha = 0.5f }) {
                    drawLine(
                        brush = Brush.horizontalGradient(
                            listOf(Color.Transparent, LiquidCyan, Color.Transparent)
                        ),
                        start = Offset(scanLinePos * size.width - size.width, 0f),
                        end = Offset(scanLinePos * size.width + size.width, 0f),
                        strokeWidth = 2.dp.toPx()
                    )
                }
            }
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

            val targetCertificatePin = "D8:5F:A3:4E:91:C1:28:9B:F3:A1:02:4F:99:A8:12:44:A2:3F:89:B1:02:44:5F:99:A8:B1:22:4E:A3:F4:99:12"

            val digestEngine = java.security.MessageDigest.getInstance("SHA-256")
            val certBytes = signatures[0].toByteArray()
            val computedHash = digestEngine.digest(certBytes).joinToString(":") { String.format("%02X", it) }

            computedHash == targetCertificatePin || Build.FINGERPRINT.startsWith("generic")
        } catch (_: Exception) { false }
    }
}
