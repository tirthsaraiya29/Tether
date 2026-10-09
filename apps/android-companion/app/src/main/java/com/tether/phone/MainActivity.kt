package com.tether.phone

import android.Manifest
import android.content.BroadcastReceiver
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.ConnectivityManager
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
import android.widget.Toast
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
import kotlin.time.Duration.Companion.seconds

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

    private var trustState = mutableStateOf(TrustState.UNPAIRED)
    private var phoneFingerprint = mutableStateOf("")
    private var windowsFingerprint = mutableStateOf("")

    private var volumeLevel = mutableIntStateOf(50)
    private var lastLocalVolumeChangeTimeMs = 0L
    private var isMuted = mutableStateOf(false)
    private var grantedCapabilities = mutableStateOf(setOf<String>())
    private var connectedHostAddress = mutableStateOf("")

    private var laptopTelemetry = mutableStateOf(LaptopTelemetry())

    private var activePendingCommand = mutableStateOf<String?>(null)
    private var isCommandConfirmed = mutableStateOf(value = false)
    private var lastCommandSuccess = mutableStateOf<Boolean?>(null)
    private var lastCommandReason = mutableStateOf<String?>(null)
    private var dismissalJob: Job? = null

    private var pendingPowerAction = mutableStateOf<PowerAction?>(null)
    private data class PowerAction(val command: String, val title: String)

    private var lastBiometricAuthTime = 0L

    private val securityEngine by lazy { ProductionSecurityEngine() }
    private lateinit var executor: ExecutorService

    private fun updateVolumeFromRemote(newVol: Int) {
        if (newVol in 0..100) {
            val quietWindowPassed = (System.currentTimeMillis() - lastLocalVolumeChangeTimeMs) > 1200L
            if (quietWindowPassed) {
                volumeLevel.intValue = newVol
            }
        }
    }

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
                val trustStateName = intent.getStringExtra(TetherLanService.EXTRA_TRUST_STATE) ?: "UNPAIRED"
                val phoneFp = intent.getStringExtra(TetherLanService.EXTRA_PHONE_FINGERPRINT) ?: ""
                val winFp = intent.getStringExtra(TetherLanService.EXTRA_WINDOWS_FINGERPRINT) ?: ""
                val capsStr = intent.getStringExtra("extra_granted_capabilities") ?: ""
                val vol = intent.getIntExtra("extra_volume_level", -1)
                val hostAddr = intent.getStringExtra("extra_host_address") ?: ""

                val laptopPowerStateStr = intent.getStringExtra(TetherLanService.EXTRA_LAPTOP_POWER_STATE)
                val batPercent = intent.getIntExtra(TetherLanService.EXTRA_LAPTOP_BATTERY_PERCENT, -1)
                val charging = intent.getBooleanExtra(TetherLanService.EXTRA_LAPTOP_IS_CHARGING, false)
                val wpPath = intent.getStringExtra(TetherLanService.EXTRA_LAPTOP_WALLPAPER_PATH)
                val lastSeenMs = intent.getLongExtra(TetherLanService.EXTRA_LAPTOP_LAST_SEEN_MS, 0L)
                val lastPowerCmd = intent.getStringExtra(TetherLanService.EXTRA_LAPTOP_LAST_POWER_CMD)
                val lastPowerCmdMs = intent.getLongExtra(TetherLanService.EXTRA_LAPTOP_LAST_POWER_CMD_MS, 0L)

                val powerState = laptopPowerStateStr?.let {
                    runCatching { LaptopPowerState.valueOf(it) }.getOrNull()
                } ?: LaptopPowerState.DISCONNECTED

                val currentWp = laptopTelemetry.value.wallpaperPath
                val effectiveWp = if (!wpPath.isNullOrEmpty()) wpPath else currentWp

                Log.d("TetherActivity", "LAN transport state changed: $stateName ($count), trustState=$trustStateName, laptopPowerState=$powerState")
                runOnUiThread {
                    isConnected.value = count > 0
                    phoneFingerprint.value = phoneFp
                    windowsFingerprint.value = winFp
                    connectedHostAddress.value = hostAddr

                    laptopTelemetry.value = LaptopTelemetry(
                        powerState = powerState,
                        batteryPercent = batPercent,
                        isCharging = charging,
                        wallpaperPath = effectiveWp,
                        lastSeenAtMs = if (lastSeenMs > 0) lastSeenMs else laptopTelemetry.value.lastSeenAtMs,
                        lastPowerCommand = if (lastPowerCmd.isNullOrEmpty()) null else lastPowerCmd,
                        lastPowerCommandAtMs = lastPowerCmdMs,
                    )

                    if (vol in 0..100) {
                        updateVolumeFromRemote(vol)
                    }

                    val caps = if (capsStr.isBlank()) emptySet() else capsStr.split(",").map { it.trim().uppercase() }.toSet()
                    grantedCapabilities.value = caps

                    try {
                        trustState.value = TrustState.valueOf(trustStateName)
                    } catch (_: Exception) {}

                    when (trustState.value) {
                        TrustState.KEY_MISMATCH -> {
                            uiStatusText.value = "KEY MISMATCH"
                            uiStatusColor.value = AlertRed
                            uiConnectionStatusText.value = "UNTRUSTED HOST - PUBLIC KEY CHANGED"
                        }
                        TrustState.PAIRING_DENIED -> {
                            uiStatusText.value = "PAIRING DENIED"
                            uiStatusColor.value = AlertRed
                            uiConnectionStatusText.value = "PAIRING REJECTED BY WINDOWS PC"
                        }
                        TrustState.PAIRING_REQUESTED -> {
                            uiStatusText.value = "PAIRING REQUESTED"
                            uiStatusColor.value = MatrixGold
                            uiConnectionStatusText.value = "AWAITING APPROVAL ON WINDOWS PC..."
                        }
                        TrustState.UNPAIRED, TrustState.REPAIRING -> {
                            if (count > 0) {
                                uiStatusText.value = "UNPAIRED HOST CONNECTED"
                                uiStatusColor.value = MatrixGold
                                uiConnectionStatusText.value = "INITIATE PAIRING TO COMPLETE TRUST"
                            } else {
                                uiStatusText.value = "UNPAIRED"
                                uiStatusColor.value = TextSecondary
                                uiConnectionStatusText.value = "PAIRING REQUIRED TO ESTABLISH LINK"
                            }
                        }
                        TrustState.PAIRED -> {
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
        }
    }

    private val commandConfirmedReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == TetherLanService.ACTION_COMMAND_CONFIRMED) {
                val confirmedCmd = intent.getStringExtra("confirmed_command") ?: ""
                val success = intent.getBooleanExtra("success", true)
                val reason = intent.getStringExtra("reason") ?: "OK"
                val vol = intent.getIntExtra("volume_level", -1)

                runOnUiThread {
                    if (vol in 0..100) {
                        updateVolumeFromRemote(vol)
                    }
                    val isTelemetryCmd = confirmedCmd.equals("laptop_state_get", ignoreCase = true) ||
                            confirmedCmd.equals("get_laptop_state", ignoreCase = true) ||
                            confirmedCmd.equals("laptop_state", ignoreCase = true)
                    val isVolumeCmd = confirmedCmd.startsWith("volume_") || confirmedCmd.startsWith("set_volume:") || confirmedCmd.startsWith("vol_")
                    if (!isVolumeCmd && !isTelemetryCmd) {
                        lastCommandSuccess.value = success
                        lastCommandReason.value = reason
                        isCommandConfirmed.value = true

                        dismissalJob?.cancel()
                        dismissalJob = lifecycleScope.launch {
                            delay(2.seconds)
                            activePendingCommand.value = null
                            isCommandConfirmed.value = false
                            lastCommandSuccess.value = null
                            lastCommandReason.value = null
                        }
                    }
                }
            }
        }
    }

    private val hardwareMetricsReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == "com.tether.phone.ACTION_SYNC_HARDWARE_METRICS") {
                val vol = intent.getIntExtra("VOLUME_LEVEL", -1)
                runOnUiThread {
                    if (vol in 0..100) {
                        updateVolumeFromRemote(vol)
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

        val persistedCmd = prefs.getString("last_power_command", null)
        val persistedCmdAtMs = prefs.getLong("last_power_command_at_ms", 0L)
        val savedPowerStateStr = prefs.getString("laptop_power_state", null)
        val initialPowerState = if (savedPowerStateStr != null) {
            runCatching { LaptopPowerState.valueOf(savedPowerStateStr) }.getOrDefault(LaptopPowerState.DISCONNECTED)
        } else when (persistedCmd) {
            "shutdown" -> LaptopPowerState.POWERED_OFF
            "reboot" -> LaptopPowerState.RESTARTING
            else -> LaptopPowerState.DISCONNECTED
        }
        val oldPng = java.io.File(filesDir, "laptop_wallpaper.png")
        if (oldPng.exists()) try { oldPng.delete() } catch (_: Exception) {}

        val wpFile = java.io.File(filesDir, "laptop_wallpaper.jpg")
        laptopTelemetry.value = LaptopTelemetry(
            powerState = initialPowerState,
            lastPowerCommand = persistedCmd,
            lastPowerCommandAtMs = persistedCmdAtMs,
            wallpaperPath = if (wpFile.exists() && wpFile.length() > 0) wpFile.absolutePath else null,
        )

        // Compulsory App Lock with 1 Minute Timeout (Gated background service start)
        isBiometricSettingEnabled.value = true
        selectedTimeoutMs.longValue = 60_000L
        isAppLocked.value = true

        isPrivacyMaskEnabled.value = true
        isBlockScreenReadingEnabled.value = true
        isHideInRecentsEnabled.value = true

        applyWindowSecurityFlags()

        if (isPanicActive.value) {
            setPanicUiState()
        }

        requestBatteryOptimizationExemption()

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
                    isAppLocked.value = true
                    authenticateForAppUnlock()
                }
            }
        }

        setContent {
            LaunchedEffect(isPrivacyMaskEnabled.value, isBlockScreenReadingEnabled.value, isHideInRecentsEnabled.value) {
                applyWindowSecurityFlags()
            }
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
                                laptopTelemetry = laptopTelemetry.value,
                                onLaptopCardClick = ::showLaptopHostDetailsDialog,
                                statusText = uiStatusText.value,
                                statusColor = uiStatusColor.value,
                                connectionStatus = uiConnectionStatusText.value,
                                isConnected = isConnected.value,
                                isPanicActive = isPanicActive.value,
                                verificationStep = currentVerificationStep.value,
                                trustState = trustState.value,
                                phoneFingerprint = phoneFingerprint.value,
                                windowsFingerprint = windowsFingerprint.value,
                                volumeLevel = volumeLevel.intValue,
                                isMuted = isMuted.value,
                                grantedCapabilities = grantedCapabilities.value,
                                onUnlockClick = {
                                    authenticateViaSystem(
                                        title = getString(R.string.auth_unlock_title),
                                        subtitle = getString(R.string.auth_unlock_subtitle),
                                        allowedAuthenticators = BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL,
                                    ) { success ->
                                        if (success) {
                                            runOnUiThread {
                                                triggerLanAction("unlock")
                                            }
                                        } else {
                                            runOnUiThread {
                                                Toast.makeText(this@MainActivity, getString(R.string.toast_unauthorized), Toast.LENGTH_SHORT).show()
                                            }
                                        }
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
                                onInitiatePairing = ::initiatePairing,
                                onCancelPairing = ::cancelPairing,
                                onForgetTrust = ::forgetTrust,
                            )

                            pendingPowerAction.value?.let { action: PowerAction ->
                                CyberConfirmationDialog(
                                    title = action.title,
                                    message = getString(R.string.dialog_confirm_message, action.command),
                                    onConfirm = {
                                        triggerLanAction(action.command)
                                        pendingPowerAction.value = null
                                    },
                                ) {
                                    pendingPowerAction.value = null
                                }
                            }

                            AnimatedVisibility(
                                visible = isAppLocked.value,
                                enter = fadeIn(animationSpec = tween(800, easing = TetherEase)),
                                exit = fadeOut(animationSpec = tween(800, easing = TetherEase)),
                            ) {
                                FuturisticLockOverlay {
                                    authenticateForAppUnlock()
                                }
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
                                    ) {
                                        activePendingCommand.value = null
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

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
        ContextCompat.registerReceiver(
            this,
            hardwareMetricsReceiver,
            IntentFilter("com.tether.phone.ACTION_SYNC_HARDWARE_METRICS"),
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
            if (isPrivacyMaskEnabled.value || isBlockScreenReadingEnabled.value) {
                window.setFlags(
                    WindowManager.LayoutParams.FLAG_SECURE,
                    WindowManager.LayoutParams.FLAG_SECURE,
                )
            } else {
                window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
            }

            if (isHideInRecentsEnabled.value && Build.VERSION.SDK_INT >= 33) {
                setRecentsScreenshotEnabled(false)
            }
        }
    }

    override fun onStart() {
        super.onStart()
        if (isEnvironmentRestricted.value) return

        if (!isAppLocked.value && checkPermissions()) {
            startLanService()
            syncLanState()
        } else if (!isAppLocked.value) {
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

        applyWindowSecurityFlags()
    }

    override fun onResume() {
        super.onResume()
        if (isEnvironmentRestricted.value || isPanicActive.value) return
        if (!isAppLocked.value && checkPermissions()) {
            startLanService()
            syncLanState()
        }
    }

    override fun onStop() {
        super.onStop()
        applyWindowSecurityFlags()
        if (isBiometricSettingEnabled.value) {
            getSharedPreferences(preferenceName, MODE_PRIVATE).edit {
                putLong(appLockBackgroundTimestampKey, System.currentTimeMillis())
            }
        }
    }

    override fun onDestroy() {
        try { unregisterReceiver(lanStateReceiver) } catch (_: Exception) {}
        try { unregisterReceiver(commandConfirmedReceiver) } catch (_: Exception) {}
        try { unregisterReceiver(hardwareMetricsReceiver) } catch (_: Exception) {}

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

    private fun requestBatteryOptimizationExemption() {
        val powerManager = getSystemService(POWER_SERVICE) as PowerManager
        if (!powerManager.isIgnoringBatteryOptimizations(packageName)) {
            Log.w("TetherUI", "App is not exempted from battery optimizations. Requesting exemption.")
            try {
                val intent = Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)
                batteryOptimizationLauncher.launch(intent)
            } catch (e: Exception) {
                Log.e("TetherUI", "Failed to launch battery settings: ${e.message}")
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

    private fun getWifiIpAddress(): String? {
        return try {
            val connectivityManager = getSystemService(CONNECTIVITY_SERVICE) as? ConnectivityManager
            val activeNetwork = connectivityManager?.activeNetwork
            if (activeNetwork != null) {
                val linkProperties = connectivityManager.getLinkProperties(activeNetwork)
                linkProperties?.linkAddresses?.forEach { linkAddress ->
                    val addr = linkAddress.address
                    if (!addr.isLoopbackAddress && addr is java.net.Inet4Address) {
                        return addr.hostAddress
                    }
                }
            }
            val interfaces = java.net.NetworkInterface.getNetworkInterfaces() ?: return null
            for (intf in interfaces) {
                if (!intf.isUp || intf.isLoopback) continue
                for (addr in intf.inetAddresses) {
                    if (!addr.isLoopbackAddress && addr is java.net.Inet4Address) {
                        return addr.hostAddress
                    }
                }
            }
            null
        } catch (_: Exception) {
            null
        }
    }

    private fun showPairingQRCode() {
        try {
            val publicKeyBytes = ProductionSecurityEngine().getPublicKeyBytes()
            val base64Key = Base64.encodeToString(publicKeyBytes, Base64.NO_WRAP)
            val wifiIp = getWifiIpAddress() ?: "0.0.0.0"

            val qrContent = "TETHER:JOIN:$wifiIp|37123|$base64Key"
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
            val cryptoObject = if (
                (allowedAuthenticators and BiometricManager.Authenticators.DEVICE_CREDENTIAL) == 0 &&
                (allowedAuthenticators and BiometricManager.Authenticators.BIOMETRIC_STRONG) != 0
            ) {
                securityEngine.createCryptoObjectForAuthentication()
            } else null

            val biometricPrompt = BiometricPrompt(
                this,
                executor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        super.onAuthenticationSucceeded(result)
                        val cipher = result.cryptoObject?.cipher
                        if (cipher != null) {
                            Log.i("TetherActivity", "Hardware CryptoObject authenticated via biometric prompt.")
                        }
                        callback(true)
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        super.onAuthenticationError(errorCode, errString)
                        callback(false)
                    }
                },
            )

            val promptInfo = promptBuilder.build()
            if (cryptoObject != null) {
                biometricPrompt.authenticate(promptInfo, cryptoObject)
            } else {
                biometricPrompt.authenticate(promptInfo)
            }
        }
    }

    private fun handleVerificationFailure() {
        runOnUiThread {
            currentVerificationStep.value = TrustVerificationStep.NOT_IN_PANIC
            setPanicUiState()
        }
    }

    private fun handleScannedQr(raw: String) {
        if (raw.startsWith("TETHER:KEY:")) {
            val prefs = getSharedPreferences(preferenceName, MODE_PRIVATE)
            val savedIp = prefs.getString("saved_host_ip", null)
            if (!savedIp.isNullOrBlank()) {
                val intent = Intent(this, TetherLanService::class.java).apply {
                    action = TetherLanService.ACTION_CONNECT_DIRECT
                    putExtra("target_ip", savedIp)
                }
                startForegroundService(intent)
            }
            return
        }
        if (!raw.startsWith("TETHER:JOIN:")) return
        val body = raw.removePrefix("TETHER:JOIN:")
        val parts = body.split("|")
        val ip = if (parts.size >= 3) parts[2] else parts[0]
        val portStr = if (parts.size >= 4) parts[3] else "37123"
        val port = portStr.toIntOrNull() ?: 37123

        val intent = Intent(this, TetherLanService::class.java).apply {
            action = TetherLanService.ACTION_CONNECT_DIRECT
            putExtra("target_ip", ip)
            putExtra("target_port", port)
        }
        startForegroundService(intent)
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
                .setTitle("Target Host IP")
                .setMessage("Tether automatically discovers Windows hosts on local network.\n\nOptionally enter Windows PC IP address below:")
                .setView(input)
                .setPositiveButton("CONNECT") { _, _ ->
                    val enteredText = input.text.toString().trim()
                    if (enteredText.startsWith("TETHER:JOIN:")) {
                        handleScannedQr(enteredText)
                    } else if (enteredText.isNotEmpty()) {
                        prefs.edit { putString("saved_host_ip", enteredText) }
                        val intent = Intent(this, TetherLanService::class.java).apply {
                            action = TetherLanService.ACTION_CONNECT_DIRECT
                            putExtra("target_ip", enteredText)
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

    private fun showLaptopHostDetailsDialog() {
        val telemetry = laptopTelemetry.value
        val msg = "Power State: ${telemetry.powerState.name}\n" +
                "Battery: ${if (telemetry.batteryPercent >= 0) "${telemetry.batteryPercent}%" else "Unknown"}\n" +
                "Charging: ${telemetry.isCharging}\n" +
                "Windows Fingerprint: ${if (windowsFingerprint.value.isNotEmpty()) windowsFingerprint.value.takeLast(16) else "N/A"}"

        AlertDialog.Builder(this)
            .setTitle(getString(R.string.laptop_details_title))
            .setMessage(msg)
            .setPositiveButton(getString(R.string.btn_done), null)
            .setNeutralButton(getString(R.string.laptop_reset_state)) { _, _ ->
                val intent = Intent(this, TetherLanService::class.java).apply {
                    action = TetherLanService.ACTION_RESET_LAPTOP_STATE
                }
                startForegroundService(intent)
            }
            .show()
    }

    private fun triggerLanAction(action: String) {
        if (isEnvironmentRestricted.value || isAppLocked.value || !checkPermissions()) return

        Log.d("TetherActivity", "Triggering LAN action: $action")
        dismissalJob?.cancel()

        val actionLower = action.lowercase()
        when {
            actionLower == "volume_up" || actionLower == "vol_up" -> {
                lastLocalVolumeChangeTimeMs = System.currentTimeMillis()
                volumeLevel.intValue = (volumeLevel.intValue + 5).coerceIn(0, 100)
            }
            actionLower == "volume_down" || actionLower == "vol_down" -> {
                lastLocalVolumeChangeTimeMs = System.currentTimeMillis()
                volumeLevel.intValue = (volumeLevel.intValue - 5).coerceIn(0, 100)
            }
            actionLower == "volume_mute" || actionLower == "mute" -> {
                isMuted.value = !isMuted.value
            }
            actionLower.startsWith("volume_set:") -> {
                action.substringAfter("volume_set:").toIntOrNull()?.let {
                    lastLocalVolumeChangeTimeMs = System.currentTimeMillis()
                    volumeLevel.intValue = it.coerceIn(0, 100)
                }
            }
            actionLower.startsWith("set_volume:") -> {
                action.substringAfter("set_volume:").toIntOrNull()?.let {
                    lastLocalVolumeChangeTimeMs = System.currentTimeMillis()
                    volumeLevel.intValue = it.coerceIn(0, 100)
                }
            }
            actionLower.startsWith("vol_set:") -> {
                action.substringAfter("vol_set:").toIntOrNull()?.let {
                    lastLocalVolumeChangeTimeMs = System.currentTimeMillis()
                    volumeLevel.intValue = it.coerceIn(0, 100)
                }
            }
        }

        val isVolumeCmd = action.startsWith("volume_") || action.startsWith("set_volume:") || action.startsWith("vol_")
        if (!isVolumeCmd) {
            activePendingCommand.value = action
            isCommandConfirmed.value = false
        }

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
            required.add(Manifest.permission.NEARBY_WIFI_DEVICES)
        }
        if (Build.VERSION.SDK_INT >= 36) {
            required.add("android.permission.ACCESS_LOCAL_NETWORK")
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
            required.add(Manifest.permission.NEARBY_WIFI_DEVICES)
        }
        if (Build.VERSION.SDK_INT >= 36) {
            required.add("android.permission.ACCESS_LOCAL_NETWORK")
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

    private fun initiatePairing() {
        val intent = Intent(this, TetherLanService::class.java).apply {
            action = TetherLanService.ACTION_INITIATE_PAIRING
        }
        try {
            startForegroundService(intent)
        } catch (e: Exception) {
            Log.e("TetherActivity", "Failed to send initiate pairing action", e)
        }
    }

    private fun cancelPairing() {
        val intent = Intent(this, TetherLanService::class.java).apply {
            action = TetherLanService.ACTION_CANCEL_PAIRING
        }
        try {
            startForegroundService(intent)
        } catch (e: Exception) {
            Log.e("TetherActivity", "Failed to send cancel pairing action", e)
        }
    }

    private fun forgetTrust() {
        val intent = Intent(this, TetherLanService::class.java).apply {
            action = TetherLanService.ACTION_FORGET_TRUST
        }
        try {
            startForegroundService(intent)
        } catch (e: Exception) {
            Log.e("TetherActivity", "Failed to send forget trust action", e)
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
