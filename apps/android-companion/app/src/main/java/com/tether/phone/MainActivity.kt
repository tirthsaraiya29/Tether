package com.tether.phone

import android.Manifest
import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import android.util.Log
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asComposeRenderEffect
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.core.content.edit
import androidx.core.net.toUri
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import com.tether.phone.ui.components.*
import com.tether.phone.ui.screens.*
import com.tether.phone.ui.theme.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

class MainActivity : FragmentActivity() {
    private val requestPermissionsCode = 101
    private val preferenceName = "tether_secure_prefs"
    private val panicStateKey = "is_panic_active"

    private val appLockTimeoutKey = "app_lock_timeout_ms"
    private val appLockBackgroundTimestampKey = "app_lock_bg_timestamp"

    private var uiStatusText = mutableStateOf("")
    private var uiStatusColor = mutableStateOf(TextSecondary)
    private var uiConnectionStatusText = mutableStateOf("")

    private var isConnected = mutableStateOf(value = false)
    private var isPanicActive = mutableStateOf(value = false)
    private var currentVerificationStep = mutableStateOf(value = TrustVerificationStep.NOT_IN_PANIC)

    private var isAppLocked = mutableStateOf(value = false)
    // Mandatory Security Features
    private var isBiometricSettingEnabled = mutableStateOf(value = true)
    private var selectedTimeoutMs = mutableLongStateOf(value = 0L)

    private var isPrivacyMaskEnabled = mutableStateOf(value = true)
    private var isBlockScreenReadingEnabled = mutableStateOf(value = true)
    private var isHideInRecentsEnabled = mutableStateOf(value = true)

    private var isEnvironmentRestricted = mutableStateOf(value = false)
    private var currentIntegrityScore = mutableIntStateOf(value = 100)
    private var isLoading = mutableStateOf(value = true)

    private var activePendingCommand = mutableStateOf<String?>(null)
    private var isCommandConfirmed = mutableStateOf(value = false)
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
                Log.d("TetherActivity", "GATT state changed. Connection count: $count")
                runOnUiThread {
                    isConnected.value = count > 0
                    Log.d("TetherActivity", "isConnected set to: ${isConnected.value}")
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
                runOnUiThread {
                    isCommandConfirmed.value = true
                    dismissalJob?.cancel()
                    dismissalJob = lifecycleScope.launch {
                        kotlinx.coroutines.delay(kotlin.time.Duration.parse("2s"))
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
        // Force security settings to true regardless of saved state
        isBiometricSettingEnabled.value = true
        isPrivacyMaskEnabled.value = true
        isBlockScreenReadingEnabled.value = true
        isHideInRecentsEnabled.value = true
        
        selectedTimeoutMs.longValue = prefs.getLong(appLockTimeoutKey, 0L)

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
            // PRODUCTION FIX: Removed erroneous remember wrappers that insulate states from background receiver updates.
            // Reading class-level MutableState handles directly guarantees immediate recomposition tracking.
            TetherTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background,
                ) {
                    Box(modifier = Modifier.fillMaxSize()) {
                        DeepSpaceCanvasVisualizer()
                        if (isLoading.value) {
                            Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                                CircularProgressIndicator(color = LiquidCyan, strokeWidth = 1.dp)
                                Text(
                                    getString(R.string.status_verifying_environment),
                                    color = TextSecondary,
                                    style = MaterialTheme.typography.labelMedium,
                                    modifier = Modifier.padding(top = 48.dp),
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
                                selectedTimeoutMs = selectedTimeoutMs.longValue,
                                onUnlockClick = {
                                    val currentTime = System.currentTimeMillis()
                                    val needsAuth = ((currentTime - lastBiometricAuthTime) > 10000)

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
                                    persistPanicState(active = true)
                                    triggerBleAction("panic")
                                },
                                onSideRestore = {
                                    executeVerificationPipeline(TrustVerificationStep.DEVICE_CREDENTIAL)
                                },
                                onSelectLaptop = { showLaptopSelectionDialog() },
                                onTriggerStepVerification = { step ->
                                    triggerSystemBiometricPrompt(step)
                                },
                                onTimeoutChanged = { timeout ->
                                    selectedTimeoutMs.longValue = timeout
                                    prefs.edit { putLong(appLockTimeoutKey, timeout) }
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
                                    getSharedPreferences(preferenceName, MODE_PRIVATE).edit {
                                        putLong("pairing_window_start_time", System.currentTimeMillis())
                                    }
                                    showPairingQRCode()
                                }
                            )

                            pendingPowerAction.value?.let { action: PowerAction ->
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
                                enter = fadeIn(animationSpec = tween(800, easing = TetherEase)),
                                exit = fadeOut(animationSpec = tween(800, easing = TetherEase))
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
                                exit = fadeOut(tween(400)) + scaleOut(targetScale = 0.5f, animationSpec = tween(400, easing = TetherEase))
                            ) {
                                activePendingCommand.value?.let { command: String ->
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

        if (commandType != null || (action == "com.tether.phone.ACTION_VOICE_COMMAND")) {
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
        if (isHideInRecentsEnabled.value) {
            window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
        if (isBiometricSettingEnabled.value) {
            getSharedPreferences(preferenceName, MODE_PRIVATE).edit {
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
                    syncBleState()
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
                    data = "package:$packageName".toUri()
                }
                batteryOptimizationLauncher.launch(intent)
            } catch (_: Exception) {
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
                val imageView = android.widget.ImageView(this).apply {
                    setImageBitmap(qrBitmap)
                    setPadding(40, 40, 40, 40)
                }

                androidx.appcompat.app.AlertDialog.Builder(this)
                    .setTitle(getString(R.string.dialog_pairing_title))
                    .setMessage(getString(R.string.dialog_pairing_message))
                    .setView(imageView)
                    .setPositiveButton(getString(R.string.btn_done)) { _, _ -> 
                        getSharedPreferences(preferenceName, MODE_PRIVATE).edit {
                            putLong("pairing_window_start_time", 0L)
                        }
                    }
                    .setNegativeButton(getString(R.string.btn_copy_key)) { _, _ ->
                        val clipboard = getSystemService(CLIPBOARD_SERVICE) as android.content.ClipboardManager
                        clipboard.setPrimaryClip(android.content.ClipData.newPlainText("TetherPublicKey", base64Key))
                    }
                    .setOnDismissListener {
                        getSharedPreferences(preferenceName, MODE_PRIVATE).edit {
                            putLong("pairing_window_start_time", 0L)
                        }
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
            androidx.appcompat.app.AlertDialog.Builder(this)
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
                Manifest.permission.ACCESS_FINE_LOCATION,
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
                Manifest.permission.ACCESS_FINE_LOCATION,
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
        val bleIntent = Intent(this, BleGattServerService::class.java).apply {
            action = "ACTION_GET_STATUS"
        }
        try {
            startForegroundService(bleIntent)
        } catch (e: Exception) {
            Log.e("TetherActivity", "Failed to start BLE service", e)
        }
    }

    private fun syncBleState() {
        if (isEnvironmentRestricted.value || isAppLocked.value || !checkPermissions()) return
        val serviceIntent = Intent(this, BleGattServerService::class.java).apply {
            action = "ACTION_GET_STATUS"
        }
        try {
            startForegroundService(serviceIntent)
        } catch (e: Exception) {
            Log.e("TetherActivity", "Failed to sync BLE state", e)
        }
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
    selectedTimeoutMs: Long,
    onUnlockClick: () -> Unit,
    onLockClick: () -> Unit,
    onPanicClick: () -> Unit,
    onSideRestore: () -> Unit,
    onSelectLaptop: () -> Unit,
    onTriggerStepVerification: (TrustVerificationStep) -> Unit,
    onTimeoutChanged: (Long) -> Unit,
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
                                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                                    renderEffect = android.graphics.RenderEffect
                                        .createBlurEffect(40f, 40f, android.graphics.Shader.TileMode.CLAMP)
                                        .asComposeRenderEffect()
                                }
                            }
                    )
                    Column(modifier = Modifier.fillMaxSize().padding(32.dp)) {
                        Spacer(modifier = Modifier.height(64.dp))
                        Text(
                            text = stringResource(R.string.nav_command_interface),
                            style = MaterialTheme.typography.labelMedium,
                            color = LiquidCyan
                        )
                        Spacer(modifier = Modifier.height(48.dp))

                        val navItems = listOf(
                            Triple(stringResource(R.string.nav_dashboard), Icons.Default.Home, AppScreen.TELEMETRY_DASHBOARD),
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
                        Text(
                            text = stringResource(R.string.app_title),
                            style = MaterialTheme.typography.headlineSmall,
                            color = TextPrimary
                        )
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
                            onUnlockClick, onLockClick, onPanicClick, onSideRestore, onSelectLaptop,
                            onTriggerStepVerification, onBleActionRequested = onLaptopActionClick
                        )
                        AppScreen.SECURITY_SETTINGS -> SettingsScreen(
                            selectedTimeoutMs = selectedTimeoutMs,
                            onTimeoutChanged = onTimeoutChanged
                        )
                        AppScreen.LAPTOP_CONTROL -> Box(Modifier.fillMaxSize()) // Removed
                        AppScreen.PAIRING -> PairingScreen(onShowQR = onShowQR)
                    }
                }
            }
        }
    }
}
