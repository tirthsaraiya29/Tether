package com.tether.phone

import android.Manifest
import android.annotation.SuppressLint
import android.content.BroadcastReceiver
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import android.text.InputType
import android.util.Base64
import android.util.Log
import android.view.WindowManager
import android.widget.EditText
import android.widget.ImageView
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
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
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import kotlin.time.Duration

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
    private var dismissalJob: Job? = null

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

    private val lanStateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == TetherLanService.ACTION_LAN_STATE_CHANGED) {
                val count = intent.getIntExtra(TetherLanService.EXTRA_CONNECTION_COUNT, 0)
                val stateName = intent.getStringExtra(TetherLanService.EXTRA_TRANSPORT_STATE) ?: "DISCONNECTED"
                Log.d("TetherActivity", "LAN transport state changed: $stateName ($count)")
                runOnUiThread {
                    isConnected.value = count > 0
                    if (count > 0) {
                        uiStatusText.value = getString(R.string.status_link_active)
                        uiStatusColor.value = IntegrityGreen
                        uiConnectionStatusText.value = getString(R.string.status_secure_nodes, count)
                    } else if (stateName == "HOTSPOT_UNSUPPORTED") {
                        uiStatusText.value = "HOTSPOT UNSUPPORTED"
                        uiStatusColor.value = AlertRed
                        uiConnectionStatusText.value = "CONNECT PHONE & WINDOWS TO SAME WI-FI"
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
            if (intent?.action == TetherLanService.ACTION_COMMAND_CONFIRMED) {
                runOnUiThread {
                    isCommandConfirmed.value = true
                    dismissalJob?.cancel()
                    dismissalJob = lifecycleScope.launch {
                        delay(Duration.parse("2s"))
                        activePendingCommand.value = null
                        isCommandConfirmed.value = false
                    }
                }
            }
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
                startLanService()
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
                    stopService(Intent(this@MainActivity, TetherLanService::class.java))
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
                                            allowedAuthenticators = BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL,
                                        ) { success ->
                                            if (success) {
                                                runOnUiThread {
                                                    lastBiometricAuthTime = System.currentTimeMillis()
                                                    triggerLanAction("unlock")
                                                }
                                            }
                                        }
                                    } else {
                                        triggerLanAction("unlock")
                                    }
                                },
                                onLockClick = { triggerLanAction("lock_now") },
                                onPanicClick = {
                                    persistPanicState(active = true)
                                    triggerLanAction("panic")
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
                                                title = getString(R.string.dialog_confirm_protocol, command.uppercase()),
                                            )
                                        }
                                        else -> {
                                            triggerLanAction(command)
                                        }
                                    }
                                },
                                onShowQR = {
                                    getSharedPreferences(preferenceName, MODE_PRIVATE).edit {
                                        putLong("pairing_window_start_time", System.currentTimeMillis())
                                    }
                                    showPairingQRCode()
                                },
                                onRestartServer = ::restartLanServer,
                            )

                            pendingPowerAction.value?.let { action: PowerAction ->
                                CyberConfirmationDialog(
                                    title = action.title,
                                    message = getString(R.string.dialog_confirm_message, action.command),
                                    onConfirm = {
                                        triggerLanAction(action.command)
                                        pendingPowerAction.value = null
                                    },
                                    onDismiss = { pendingPowerAction.value = null },
                                )
                            }

                            AnimatedVisibility(
                                visible = isAppLocked.value,
                                enter = fadeIn(animationSpec = tween(800, easing = TetherEase)),
                                exit = fadeOut(animationSpec = tween(800, easing = TetherEase)),
                            ) {
                                FuturisticLockOverlay(
                                    onAuthorizeRequested = {
                                        authenticateForAppUnlock()
                                    },
                                )
                            }

                            AnimatedVisibility(
                                visible = activePendingCommand.value != null,
                                enter = fadeIn(tween(400)),
                                exit = fadeOut(tween(400)) + scaleOut(targetScale = 0.5f, animationSpec = tween(400, easing = TetherEase)),
                            ) {
                                activePendingCommand.value?.let { command: String ->
                                    CommandConfirmationDialog(
                                        command = command,
                                        isConfirmed = isCommandConfirmed.value,
                                        onDismiss = { activePendingCommand.value = null },
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }

        val filter = IntentFilter(Intent.ACTION_USER_PRESENT)
        ContextCompat.registerReceiver(this, screenUnlockReceiver, filter, ContextCompat.RECEIVER_EXPORTED)
        ContextCompat.registerReceiver(
            this,
            lanStateReceiver,
            IntentFilter(TetherLanService.ACTION_LAN_STATE_CHANGED),
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
        ContextCompat.registerReceiver(
            this,
            commandConfirmedReceiver,
            IntentFilter(TetherLanService.ACTION_COMMAND_CONFIRMED),
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )

        val statusIntent = Intent(this, TetherLanService::class.java).apply {
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

        if ((commandType != null) || (action == "com.tether.phone.ACTION_VOICE_COMMAND")) {
            val command = commandType ?: "unknown"
            if (!isEnvironmentRestricted.value && !isAppLocked.value) {
                val lanCommand = when (command) {
                    "lock_now" -> "lock_now"
                    "unlock" -> "unlock"
                    "shutdown" -> "shutdown"
                    "sleep" -> "sleep"
                    "reboot" -> "reboot"
                    else -> return
                }
                triggerLanAction(lanCommand)
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
                triggerLanAction("screen_unlock")
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
        try { unregisterReceiver(lanStateReceiver) } catch (_: Exception) {}
        try { unregisterReceiver(commandConfirmedReceiver) } catch (_: Exception) {}
        try { unregisterReceiver(screenUnlockReceiver) } catch (_: Exception) {}

        executor.shutdown()
        super.onDestroy()
    }

    private fun authenticateForAppUnlock() {
        authenticateViaSystem(
            title = getString(R.string.auth_title),
            subtitle = getString(R.string.auth_subtitle),
            allowedAuthenticators = BiometricManager.Authenticators.BIOMETRIC_STRONG,
        ) { success ->
            if (success) {
                runOnUiThread {
                    lastBiometricAuthTime = System.currentTimeMillis()
                    isAppLocked.value = false
                    getSharedPreferences(preferenceName, MODE_PRIVATE).edit {
                        putLong(appLockBackgroundTimestampKey, 0L)
                    }
                    if (checkPermissions()) {
                        startLanService()
                    } else {
                        requestPermissions()
                    }
                    syncLanState()
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
                startLanService()
            }
        }
    }

    @SuppressLint("BatteryLife")
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
            val base64Key = Base64.encodeToString(publicKeyBytes, Base64.NO_WRAP)

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
                        getSharedPreferences(preferenceName, MODE_PRIVATE).edit {
                            putLong("pairing_window_start_time", 0L)
                        }
                    }
                    .setNegativeButton(getString(R.string.btn_copy_key)) { _, _ ->
                        val clipboard = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
                        clipboard.setPrimaryClip(ClipData.newPlainText("TetherPublicKey", base64Key))
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
                    allowedAuthenticators = BiometricManager.Authenticators.DEVICE_CREDENTIAL,
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
                    allowedAuthenticators = BiometricManager.Authenticators.BIOMETRIC_STRONG,
                ) { success ->
                    if (success) {
                        lastBiometricAuthTime = System.currentTimeMillis()
                        persistPanicState(active = false)
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

    private fun showLaptopSelectionDialog() {
        runOnUiThread {
            val prefs = getSharedPreferences(preferenceName, MODE_PRIVATE)
            val currentSavedIp = prefs.getString("saved_host_ip", "") ?: ""

            val input = EditText(this).apply {
                hint = "e.g. 192.168.1.100"
                setText(currentSavedIp)
                inputType = InputType.TYPE_CLASS_TEXT
                setPadding(50, 30, 50, 30)
            }

            AlertDialog.Builder(this)
                .setTitle("Wi-Fi / LAN Target Host")
                .setMessage("Tether auto-discovers Windows hosts on local Wi-Fi.\n\nIf auto-discovery is blocked by router or firewall, enter your Windows PC IP address below:")
                .setView(input)
                .setPositiveButton("CONNECT TO IP") { _, _ ->
                    val enteredIp = input.text.toString().trim()
                    if (enteredIp.isNotEmpty()) {
                        prefs.edit { putString("saved_host_ip", enteredIp) }
                        val intent = Intent(this, TetherLanService::class.java).apply {
                            action = TetherLanService.ACTION_CONNECT_DIRECT
                            putExtra("target_ip", enteredIp)
                        }
                        startForegroundService(intent)
                    }
                }
                .setNeutralButton("AUTO-DISCOVER") { _, _ ->
                    prefs.edit { remove("saved_host_ip") }
                    restartLanServer()
                }
                .setNegativeButton(getString(R.string.btn_cancel), null)
                .show()
        }
    }

    private fun triggerLanAction(action: String) {
        if (isEnvironmentRestricted.value || isAppLocked.value || !checkPermissions()) return

        Log.d("TetherActivity", "Triggering LAN action: $action")
        dismissalJob?.cancel()
        activePendingCommand.value = action
        isCommandConfirmed.value = false

        val serviceIntent = Intent(this, TetherLanService::class.java).apply {
            this.action = action
        }
        try {
            startForegroundService(serviceIntent)
        } catch (e: Exception) {
            Log.e("TetherActivity", "Failed to start LAN service for action: $action", e)
        }
    }

    private fun checkPermissions(): Boolean {
        val required = mutableListOf<String>()
        required.add(Manifest.permission.ACCESS_FINE_LOCATION)

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
                    startLanService()
                }
            } else {
                uiStatusText.value = getString(R.string.status_permissions_required)
                uiStatusColor.value = AlertRed
            }
        }
    }

    private fun requestPermissions() {
        val required = mutableListOf<String>()
        required.add(Manifest.permission.ACCESS_FINE_LOCATION)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            required.add(Manifest.permission.POST_NOTIFICATIONS)
        }
        ActivityCompat.requestPermissions(this, required.toTypedArray(), requestPermissionsCode)
    }

    private fun startLanService() {
        if (isPanicActive.value || isEnvironmentRestricted.value) return
        val lanIntent = Intent(this, TetherLanService::class.java).apply {
            action = "ACTION_GET_STATUS"
        }
        try {
            startForegroundService(lanIntent)
        } catch (e: Exception) {
            Log.e("TetherActivity", "Failed to start LAN service", e)
        }
    }

    private fun restartLanServer() {
        val intent = Intent(this, TetherLanService::class.java).apply {
            action = TetherLanService.ACTION_RESTART_SERVER
        }
        try {
            startForegroundService(intent)
            uiConnectionStatusText.value = getString(R.string.status_restarting_stack)
        } catch (e: Exception) {
            Log.e("TetherActivity", "Failed to restart LAN transport", e)
        }
    }

    private fun syncLanState() {
        if (isEnvironmentRestricted.value || isAppLocked.value || !checkPermissions()) return
        val serviceIntent = Intent(this, TetherLanService::class.java).apply {
            action = "ACTION_GET_STATUS"
        }
        try {
            startForegroundService(serviceIntent)
        } catch (e: Exception) {
            Log.e("TetherActivity", "Failed to sync LAN state", e)
        }
    }
}
