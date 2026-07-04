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
import android.content.ClipData
import android.content.ClipboardManager
import android.widget.ImageView
import androidx.appcompat.app.AlertDialog
import android.os.PowerManager
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
import androidx.compose.ui.draw.blur
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
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
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

enum class TrustTier(val label: String, val color: Color) {
    TRUSTED("VAULT SECURED", IntegrityGreen),
    ELEVATED_RISK("ELEVATED RISK", MatrixGold),
    RESTRICTED("LOCKDOWN ACTIVE", AlertRed)
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
    private val notificationRestoreChannelId = "tether_restore_channel"

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

    private var pendingPowerAction = mutableStateOf<PowerAction?>(null)
    private data class PowerAction(val command: String, val toastMessage: String, val title: String)

    private var lastBiometricAuthTime = 0L

    private lateinit var executor: Executor

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

        val shouldStartImmediately = (!isBiometricSettingEnabled.value) || selectedTimeoutMs.longValue > 0
        if (checkPermissions() && shouldStartImmediately) {
            startBleService()
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
                                    val needsAuth = !isBiometricSettingEnabled.value || (currentTime - lastBiometricAuthTime > 10000)

                                    if (needsAuth) {
                                        authenticateViaSystem(
                                            title = getString(R.string.auth_unlock_title),
                                            subtitle = getString(R.string.auth_unlock_subtitle),
                                            allowedAuthenticators = BiometricManager.Authenticators.BIOMETRIC_STRONG
                                        ) { success ->
                                            if (success) {
                                                lastBiometricAuthTime = System.currentTimeMillis()
                                                triggerBleAction("unlock", getString(R.string.toast_unlock_dispatched))
                                            }
                                        }
                                    } else {
                                        triggerBleAction("unlock", getString(R.string.toast_unlock_dispatched))
                                    }
                                },
                                onLockClick = { triggerBleAction("lock_now", getString(R.string.toast_lock_dispatched)) },
                                onPanicClick = {
                                    persistPanicState(true)
                                    triggerBleAction("panic", getString(R.string.toast_panic_active))
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
                                                title = getString(R.string.dialog_confirm_protocol, command.uppercase())
                                            )
                                        }
                                        else -> {
                                            triggerBleAction(command, toastMessage)
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
                                        triggerBleAction(action.command, action.toastMessage)
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
                val (bleCommand, toastMsg) = when (command) {
                    "lock_now" -> "lock_now" to getString(R.string.toast_lock_dispatched)
                    "unlock" -> "unlock" to getString(R.string.toast_unlock_dispatched)
                    "shutdown" -> "shutdown" to "🛑 VOICE SHORTCUT: EXECUTING SHUTDOWN"
                    "sleep" -> "sleep" to "💤 VOICE SHORTCUT: EXECUTING SLEEP"
                    "reboot" -> "reboot" to "🔄 VOICE SHORTCUT: EXECUTING REBOOT"
                    else -> return
                }
                triggerBleAction(bleCommand, toastMsg)
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
                triggerBleAction("screen_unlock", "Screen unlocked")
            }
        }
    }

    override fun onStart() {
        super.onStart()
        if (isEnvironmentRestricted.value) return

        if (checkPermissions()) {
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
            prefs.edit(commit = true) {
                putLong(appLockBackgroundTimestampKey, System.currentTimeMillis())
            }
        }
    }

    override fun onDestroy() {
        try { unregisterReceiver(gattStateReceiver) } catch (_: Exception) {}
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
                    Toast.makeText(this, getString(R.string.toast_unauthorized), Toast.LENGTH_SHORT).show()
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
                        Toast.makeText(this, getString(R.string.toast_key_copied), Toast.LENGTH_SHORT).show()
                    }
                    .show()
            }
        } catch (e: Exception) {
            runOnUiThread {
                Toast.makeText(this, getString(R.string.error_qr_failed, e.message), Toast.LENGTH_LONG).show()
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
            Toast.makeText(this, getString(R.string.toast_auth_chain_severed), Toast.LENGTH_LONG).show()
            setPanicUiState()
        }
    }

    private fun dispatchTrustRestoredNotification() {
        val manager = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        val channel = NotificationChannel(notificationRestoreChannelId, getString(R.string.notification_trust_restored_title), NotificationManager.IMPORTANCE_HIGH)
        manager.createNotificationChannel(channel)
        val notification = NotificationCompat.Builder(this, notificationRestoreChannelId)
            .setContentTitle(getString(R.string.notification_trust_restored_title))
            .setContentText(getString(R.string.notification_trust_restored_text))
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .setColor(IntegrityGreen.toArgb())
            .build()
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU ||
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED) {
            manager.notify(2, notification)
        }
    }

    @SuppressLint("MissingPermission")
    private fun showLaptopSelectionDialog() {
        try {
            val bluetoothManager = getSystemService(BluetoothManager::class.java)
            val adapter = bluetoothManager?.adapter
            if (adapter == null || !adapter.isEnabled) {
                Toast.makeText(this, getString(R.string.toast_bluetooth_offline), Toast.LENGTH_SHORT).show()
                return
            }
            val pairedDevices = adapter.bondedDevices
            if (pairedDevices.isEmpty()) {
                Toast.makeText(this, getString(R.string.toast_no_paired_nodes), Toast.LENGTH_LONG).show()
                return
            }
            val deviceList = pairedDevices.map { "${it.name ?: "UNKNOWN"} (${it.address})" }.toTypedArray()
            val deviceAddresses = pairedDevices.map { it.address }.toTypedArray()
            AlertDialog.Builder(this)
                .setTitle(getString(R.string.dialog_select_host))
                .setItems(deviceList) { _, which ->
                    val mac = deviceAddresses[which]
                    getSharedPreferences(preferenceName, MODE_PRIVATE).edit {
                        putString("laptop_mac", mac)
                    }
                    Toast.makeText(this, getString(R.string.toast_target_acquired, deviceList[which]), Toast.LENGTH_SHORT).show()
                }
                .setNegativeButton(getString(R.string.btn_cancel), null)
                .show()
        } catch (e: Exception) {
            Toast.makeText(this, getString(R.string.error_system, e.message), Toast.LENGTH_SHORT).show()
        }
    }

    private fun triggerBleAction(action: String, toastMessage: String) {
        if (isEnvironmentRestricted.value || isAppLocked.value || !checkPermissions()) return
        if (toastMessage.isNotEmpty()) {
            Toast.makeText(this, toastMessage, Toast.LENGTH_SHORT).show()
        }
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
                Toast.makeText(this, getString(R.string.toast_system_access_denied), Toast.LENGTH_LONG).show()
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
    content: @Composable ColumnScope.() -> Unit
) {
    Box(
        modifier = modifier
            .clip(RoundedCornerShape(28.dp))
            .background(
                Brush.verticalGradient(
                    listOf(
                        tint.copy(alpha = alpha),
                        tint.copy(alpha = alpha * 0.4f)
                    )
                )
            )
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
            .drawBehind {
                val strokeWidth = 1.dp.toPx()
                val path = Path().apply {
                    moveTo(0f, size.height * 0.2f)
                    lineTo(0f, 28.dp.toPx())
                    arcTo(
                        rect = Rect(0f, 0f, 56.dp.toPx(), 56.dp.toPx()),
                        startAngleDegrees = 180f,
                        sweepAngleDegrees = 90f,
                        forceMoveTo = false
                    )
                    lineTo(size.width * 0.2f, 0f)
                }
                drawPath(
                    path = path,
                    color = Color.White.copy(alpha = 0.2f),
                    style = Stroke(width = strokeWidth, cap = StrokeCap.Round)
                )
            }
    ) {
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
        targetValue = 0.06f,
        animationSpec = infiniteRepeatable(
            animation = tween(10000, easing = EaseInOutSans),
            repeatMode = RepeatMode.Reverse
        ), label = "Nebula"
    )

    Canvas(modifier = Modifier.fillMaxSize()) {
        val gridSize = 60.dp.toPx()
        val gridColor = LiquidCyan.copy(alpha = 0.03f)

        var x = (gridShift % gridSize) - gridSize
        while (x < size.width + gridSize) {
            drawLine(gridColor, Offset(x, 0f), Offset(x, size.height), 0.5.dp.toPx())
            x += gridSize
        }
        var y = (gridShift % gridSize) - gridSize
        while (y < size.height + gridSize) {
            drawLine(gridColor, Offset(0f, y), Offset(size.width, y), 0.5.dp.toPx())
            y += gridSize
        }

        drawCircle(
            brush = Brush.radialGradient(
                colors = listOf(LiquidCyan.copy(alpha = nebulaAlpha), Color.Transparent),
                center = Offset(size.width * 0.2f, size.height * 0.3f),
                radius = 800.dp.toPx()
            ),
            center = Offset(size.width * 0.2f, size.height * 0.3f),
            radius = 800.dp.toPx()
        )
        drawCircle(
            brush = Brush.radialGradient(
                colors = listOf(IntegrityGreen.copy(alpha = nebulaAlpha * 0.8f), Color.Transparent),
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
    val animatedScale by animateFloatAsState(if (isPressed) 0.96f else 1f, label = "Scale")
    val animatedAlpha by animateFloatAsState(if (isPressed) 0.7f else 1f, label = "Alpha")

    Box(
        modifier = modifier
            .graphicsLayer {
                scaleX = animatedScale
                scaleY = animatedScale
                alpha = if (enabled) animatedAlpha else 0.4f
            }
            .fillMaxWidth()
            .height(60.dp)
            .clip(RoundedCornerShape(18.dp))
            .background(
                Brush.verticalGradient(
                    listOf(
                        accentColor.copy(alpha = 0.12f),
                        accentColor.copy(alpha = 0.04f)
                    )
                )
            )
            .border(
                width = 0.5.dp,
                brush = Brush.linearGradient(
                    listOf(
                        accentColor.copy(alpha = 0.5f),
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
                                colors = listOf(accentColor.copy(alpha = 0.15f), Color.Transparent),
                                radius = size.width
                            )
                        )
                    }
                }
        )
        Text(
            text = label,
            style = MaterialTheme.typography.labelLarge,
            color = accentColor,
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
    onLaptopActionClick: (String, String) -> Unit,
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
                    Box(modifier = Modifier.fillMaxSize().background(DeepSpace.copy(alpha = 0.92f)).blur(12.dp))
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
                when (currentScreen) {
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
    onBleActionRequested: (String, String) -> Unit
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
                PremiumControlAction(stringResource(R.string.label_sleep), MatrixGold, { onBleActionRequested("PWR_SLEEP", "DISPATCHED: SLEEP") }, Modifier.weight(1f), isConnected)
                PremiumControlAction(stringResource(R.string.label_reboot), TextPrimary, { onBleActionRequested("PWR_REBOOT", "DISPATCHED: REBOOT") }, Modifier.weight(1f), isConnected)
            }
            Spacer(modifier = Modifier.height(16.dp))
            PremiumControlAction(stringResource(R.string.label_halt_system), AlertRed, { onBleActionRequested("PWR_SHUTDOWN", "DISPATCHED: SHUTDOWN") }, enabled = isConnected)
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

    LiquidSurface {
        Row(horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
            Column {
                Text(stringResource(R.string.header_integrity_core), style = MaterialTheme.typography.labelLarge, color = LiquidCyan)
                Text(report.tier.label, color = report.tier.color, style = MaterialTheme.typography.labelMedium)
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
fun LaptopControlScreen(onBleActionRequested: (String, String) -> Unit) {
    var vol by remember { mutableFloatStateOf(50f) }
    var bri by remember { mutableFloatStateOf(50f) }
    Column(Modifier.fillMaxSize().padding(24.dp)) {
        Text(stringResource(R.string.header_hardware_interface), style = MaterialTheme.typography.labelLarge, color = LiquidCyan)
        Spacer(modifier = Modifier.height(24.dp))
        LiquidSurface {
            Text(stringResource(R.string.label_volume), style = MaterialTheme.typography.titleLarge, color = TextPrimary)
            Slider(vol, { vol = it; onBleActionRequested(if(it > vol) "VOL_UP" else "VOL_DOWN", "") }, colors = SliderDefaults.colors(thumbColor = TextPrimary, activeTrackColor = LiquidCyan))
        }
        Spacer(modifier = Modifier.height(24.dp))
        LiquidSurface {
            Text(stringResource(R.string.label_brightness), style = MaterialTheme.typography.titleLarge, color = TextPrimary)
            Slider(bri, { bri = it; onBleActionRequested(if(it > bri) "BRIGHT_UP" else "BRIGHT_DOWN", "") }, colors = SliderDefaults.colors(thumbColor = TextPrimary, activeTrackColor = LiquidCyan))
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
fun FuturisticLockOverlay(onAuthorizeRequested: () -> Unit) {
    Box(Modifier.fillMaxSize().background(DeepSpace.copy(0.98f)).clickable { onAuthorizeRequested() }, contentAlignment = Alignment.Center) {
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
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                val info = context.packageManager.getInstallSourceInfo(context.packageName)
                info.installingPackageName != null
            } else {
                @Suppress("DEPRECATION")
                val installer = context.packageManager.getInstallerPackageName(context.packageName)
                !installer.isNullOrEmpty()
            } || Build.FINGERPRINT.startsWith("generic")
        } catch (_: Exception) { false }
    }
}