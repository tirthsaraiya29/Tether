package com.tether.phone

import android.Manifest
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.os.PowerManager
import android.provider.Settings
import android.text.InputType
import android.util.Log
import android.view.WindowManager
import android.widget.EditText
import android.widget.Toast
import android.net.Uri
import java.io.File
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
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
import androidx.lifecycle.compose.collectAsStateWithLifecycle
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

    private val updateViewModel: UpdateViewModel by viewModels()

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

    private var isPrivacyMaskEnabled = mutableStateOf(value = false)
    private var isBlockScreenReadingEnabled = mutableStateOf(value = false)
    private var isHideInRecentsEnabled = mutableStateOf(value = false)

    private var isEnvironmentRestricted = mutableStateOf(value = false)
    private var currentIntegrityScore = mutableIntStateOf(value = 100)
    private var isLoading = mutableStateOf(value = true)

    private var trustState = mutableStateOf(TrustState.UNPAIRED)
    private var phoneFingerprint = mutableStateOf("")
    private var windowsFingerprint = mutableStateOf("")

    private var volumeLevel = mutableIntStateOf(50)
    private var lastLocalVolumeChangeTimeMs = 0L
    private var brightnessLevel = mutableIntStateOf(50)
    private var lastLocalBrightnessChangeTimeMs = 0L
    private var isMuted = mutableStateOf(value = false)
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
    private var isPermissionsBannerDismissed = mutableStateOf(false)
    private var permissionStates = mutableStateOf<List<PermissionItemState>>(emptyList())

    private val securityEngine by lazy { ProductionSecurityEngine() }
    private lateinit var executor: ExecutorService

    private fun updateVolumeFromRemote(newVol: Int) {
        if (newVol in 0..100) {
            val quietWindowPassed = (System.currentTimeMillis() - lastLocalVolumeChangeTimeMs) > 2000L
            if (quietWindowPassed) {
                volumeLevel.intValue = newVol
            }
        }
    }

    private fun updateBrightnessFromRemote(newBri: Int) {
        if (newBri in 0..100) {
            val quietWindowPassed = (System.currentTimeMillis() - lastLocalBrightnessChangeTimeMs) > 2000L
            if (quietWindowPassed) {
                brightnessLevel.intValue = newBri
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
                val bri = intent.getIntExtra("extra_brightness_level", -1)
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
                    if (bri in 0..100) {
                        updateBrightnessFromRemote(bri)
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
                val bri = intent.getIntExtra("brightness_level", -1)

                runOnUiThread {
                    if (vol in 0..100) {
                        updateVolumeFromRemote(vol)
                    }
                    if (bri in 0..100) {
                        updateBrightnessFromRemote(bri)
                    }
                    val isTelemetryCmd = confirmedCmd.equals("laptop_state_get", ignoreCase = true) ||
                            confirmedCmd.equals("get_laptop_state", ignoreCase = true) ||
                            confirmedCmd.equals("laptop_state", ignoreCase = true)
                    val isVolumeOrBrightnessCmd = confirmedCmd.startsWith("volume_") || confirmedCmd.startsWith("set_volume:") || confirmedCmd.startsWith("vol_") ||
                            confirmedCmd.startsWith("brightness_") || confirmedCmd.startsWith("set_brightness:") || confirmedCmd.startsWith("bright_")
                    if (!isVolumeOrBrightnessCmd && !isTelemetryCmd) {
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
                val bri = intent.getIntExtra("BRIGHTNESS_LEVEL", -1)
                runOnUiThread {
                    if (vol in 0..100) {
                        updateVolumeFromRemote(vol)
                    }
                    if (bri in 0..100) {
                        updateBrightnessFromRemote(bri)
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

        lifecycleScope.launch(Dispatchers.IO) {
            val oldPng = java.io.File(filesDir, "laptop_wallpaper.png")
            if (oldPng.exists()) try { oldPng.delete() } catch (_: Exception) {}

            val wpFile = java.io.File(filesDir, "laptop_wallpaper.jpg")
            val wpPath = if (wpFile.exists() && wpFile.length() > 0) wpFile.absolutePath else null
            
            withContext(Dispatchers.Main) {
                laptopTelemetry.value = LaptopTelemetry(
                    powerState = initialPowerState,
                    lastPowerCommand = persistedCmd,
                    lastPowerCommandAtMs = persistedCmdAtMs,
                    wallpaperPath = wpPath,
                )
            }
        }

        isBiometricSettingEnabled.value = true
        selectedTimeoutMs.longValue = 60_000L
        isAppLocked.value = true

        isPrivacyMaskEnabled.value = false
        isBlockScreenReadingEnabled.value = false
        isHideInRecentsEnabled.value = false

        if (isPanicActive.value) {
            setPanicUiState()
        }

        updatePermissionStates()

        // Show biometric authentication prompt IMMEDIATELY on app launch
        isLoading.value = false
        authenticateForAppUnlock()

        lifecycleScope.launch(Dispatchers.IO) {
            val powerManager = getSystemService(POWER_SERVICE) as PowerManager
            if (!powerManager.isIgnoringBatteryOptimizations(packageName)) {
                withContext(Dispatchers.Main) {
                    requestBatteryOptimizationExemption()
                }
            }
        }

        setContent {
            LaunchedEffect(isPrivacyMaskEnabled.value, isBlockScreenReadingEnabled.value, isHideInRecentsEnabled.value) {
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
                        } else if (isAppLocked.value) {
                            Box(Modifier.fillMaxSize()) { DeepSpaceCanvasVisualizer() }
                            FuturisticLockOverlay {
                                authenticateForAppUnlock()
                            }
                        } else {
                            val ungrantedCritical = permissionStates.value.count { it.level == PermissionLevel.CRITICAL && !it.isGranted }
                            val ungrantedHigh = permissionStates.value.count { it.level == PermissionLevel.HIGH && !it.isGranted }
                            val missingTotal = ungrantedCritical + ungrantedHigh
                            val showBanner = !isPermissionsBannerDismissed.value && missingTotal > 0

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
                                brightnessLevel = brightnessLevel.intValue,
                                isMuted = isMuted.value,
                                grantedCapabilities = grantedCapabilities.value,
                                permissionItems = permissionStates.value,
                                showPermissionsBanner = showBanner,
                                missingPermissionsCount = missingTotal,
                                onOpenAppSettings = ::openAppSettings,
                                onGrantAllMissingPermissions = ::grantAllCriticalPermissions,
                                onDismissPermissionsBanner = { isPermissionsBannerDismissed.value = true },
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
                                onRestartServer = ::restartLanServer,
                                onInitiatePairing = ::initiatePairing,
                                onCancelPairing = ::cancelPairing,
                                onConfirmPairing = ::confirmPairing,
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

                            val dialogVisible by updateViewModel.dialogVisible.collectAsStateWithLifecycle()
                            val updateInfo by updateViewModel.updateInfo.collectAsStateWithLifecycle()

                            val currentUpdateInfo = updateInfo
                            if (dialogVisible && currentUpdateInfo != null) {
                                UpdateDialog(
                                    updateInfo = currentUpdateInfo,
                                    onDismiss = { updateViewModel.dismissDialog() },
                                    onDownload = {
                                        val downloadUrl = currentUpdateInfo.apkDownloadUrl ?: currentUpdateInfo.releaseUrl
                                        if (downloadUrl.isNotBlank()) {
                                            try {
                                                val intent = Intent(Intent.ACTION_VIEW, Uri.parse(downloadUrl))
                                                startActivity(intent)
                                                updateViewModel.dismissDialog()
                                            } catch (e: Exception) {
                                                Log.e("MainActivity", "Failed to open download URL: ${e.message}")
                                            }
                                        }
                                    },
                                )
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

        lifecycleScope.launch(Dispatchers.IO) {
            try {
                securityEngine.getPublicKeyBytes()
            } catch (_: Exception) {}
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
            val permission = "com.tether.phone.permission.VOICE_COMMAND"
            if (checkCallingOrSelfPermission(permission) != PackageManager.PERMISSION_GRANTED) {
                Log.w("TetherActivity", "Caller lacks permission $permission for voice command execution")
                return
            }
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
    }

    override fun onResume() {
        super.onResume()
        updatePermissionStates()
        updateViewModel.checkForUpdate(BuildConfig.VERSION_NAME, this)
        if (isEnvironmentRestricted.value || isPanicActive.value) return
        if (!isAppLocked.value && checkPermissions()) {
            startLanService()
            syncLanState()
        }
    }

    override fun onStop() {
        super.onStop()
        updateViewModel.onAppBackgrounded()
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
                    getSharedPreferences(preferenceName, MODE_PRIVATE).edit(commit = true) {
                        putBoolean("has_unlocked_app_once", true)
                        putLong(appLockBackgroundTimestampKey, 0L)
                    }

                    lifecycleScope.launch(Dispatchers.IO) {
                        val report = DeviceIntegrityRegistry(this@MainActivity).getCachedOrFastReport()
                        withContext(Dispatchers.Main) {
                            currentIntegrityScore.intValue = report.score
                            if (report.score < 70) {
                                isEnvironmentRestricted.value = true
                                stopService(Intent(this@MainActivity, TetherLanService::class.java))
                            } else {
                                isEnvironmentRestricted.value = false
                                if (checkPermissions()) {
                                    startLanService()
                                } else {
                                    requestPermissions()
                                }
                                syncLanState()
                                handleVoiceIntent(intent)
                                
                                // Background evaluation of slow integrity checks
                                lifecycleScope.launch(Dispatchers.IO) {
                                    DeviceIntegrityRegistry(this@MainActivity).runAttestationPipelineAsync()
                                }
                            }
                        }
                    }
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
                val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                    data = Uri.parse("package:$packageName")
                }
                batteryOptimizationLauncher.launch(intent)
            } catch (e: Exception) {
                Log.e("TetherUI", "Direct battery prompt failed, opening app settings: ${e.message}")
                openAppSettings()
            }
        } else {
            Toast.makeText(this, "Battery optimization exemption already active.", Toast.LENGTH_SHORT).show()
        }
    }

    private fun setPanicUiState() {
        uiStatusText.value = getString(R.string.status_lockdown_active)
        uiStatusColor.value = AlertRed
        uiConnectionStatusText.value = getString(R.string.status_trust_revoked)
        isConnected.value = false
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
                .setConfirmationRequired(false) // Accelerate biometric auth
                .setAllowedAuthenticators(allowedAuthenticators)
            if ((allowedAuthenticators and BiometricManager.Authenticators.DEVICE_CREDENTIAL) == 0) {
                promptBuilder.setNegativeButtonText(getString(R.string.btn_abort))
            }

            val biometricPrompt = BiometricPrompt(
                this,
                ContextCompat.getMainExecutor(this),
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        super.onAuthenticationSucceeded(result)
                        Log.i("TetherActivity", "Authenticated via biometric prompt.")
                        callback(true)
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        super.onAuthenticationError(errorCode, errString)
                        callback(false)
                    }
                },
            )

            val promptInfo = promptBuilder.build()
            biometricPrompt.authenticate(promptInfo)
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
                .setTitle("Target Host IP")
                .setMessage("Tether automatically discovers Windows hosts on local network.\n\nOptionally enter Windows PC IP address below:")
                .setView(input)
                .setPositiveButton("CONNECT") { _, _ ->
                    val enteredText = input.text.toString().trim()
                    if (enteredText.isNotEmpty()) {
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
            actionLower == "brightness_up" || actionLower == "bright_up" -> {
                lastLocalBrightnessChangeTimeMs = System.currentTimeMillis()
                brightnessLevel.intValue = (brightnessLevel.intValue + 5).coerceIn(0, 100)
            }
            actionLower == "brightness_down" || actionLower == "bright_down" -> {
                lastLocalBrightnessChangeTimeMs = System.currentTimeMillis()
                brightnessLevel.intValue = (brightnessLevel.intValue - 5).coerceIn(0, 100)
            }
            actionLower.startsWith("brightness_set:") -> {
                action.substringAfter("brightness_set:").toIntOrNull()?.let {
                    lastLocalBrightnessChangeTimeMs = System.currentTimeMillis()
                    brightnessLevel.intValue = it.coerceIn(0, 100)
                }
            }
            actionLower.startsWith("set_brightness:") -> {
                action.substringAfter("set_brightness:").toIntOrNull()?.let {
                    lastLocalBrightnessChangeTimeMs = System.currentTimeMillis()
                    brightnessLevel.intValue = it.coerceIn(0, 100)
                }
            }
            actionLower.startsWith("bright_set:") -> {
                action.substringAfter("bright_set:").toIntOrNull()?.let {
                    lastLocalBrightnessChangeTimeMs = System.currentTimeMillis()
                    brightnessLevel.intValue = it.coerceIn(0, 100)
                }
            }
        }

        val isVolumeOrBrightnessCmd = actionLower.startsWith("volume_") || actionLower.startsWith("set_volume:") || actionLower.startsWith("vol_") ||
                actionLower.startsWith("brightness_") || actionLower.startsWith("set_brightness:") || actionLower.startsWith("bright_")
        if (!isVolumeOrBrightnessCmd) {
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
        updatePermissionStates()
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

    private fun openAppSettings() {
        try {
            val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                data = Uri.parse("package:$packageName")
            }
            startActivity(intent)
        } catch (e: Exception) {
            Log.e("TetherUI", "Failed to open app details settings: ${e.message}")
        }
    }

    private fun grantAllCriticalPermissions() {
        val ungranted = mutableListOf<String>()
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
            ungranted.add(Manifest.permission.ACCESS_FINE_LOCATION)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.NEARBY_WIFI_DEVICES) != PackageManager.PERMISSION_GRANTED) {
                ungranted.add(Manifest.permission.NEARBY_WIFI_DEVICES)
            }
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                ungranted.add(Manifest.permission.POST_NOTIFICATIONS)
            }
        }
        if (Build.VERSION.SDK_INT >= 36) {
            if (ContextCompat.checkSelfPermission(this, "android.permission.ACCESS_LOCAL_NETWORK") != PackageManager.PERMISSION_GRANTED) {
                ungranted.add("android.permission.ACCESS_LOCAL_NETWORK")
            }
        }

        if (ungranted.isNotEmpty()) {
            ActivityCompat.requestPermissions(this, ungranted.toTypedArray(), requestPermissionsCode)
        } else {
            val powerManager = getSystemService(POWER_SERVICE) as PowerManager
            if (!powerManager.isIgnoringBatteryOptimizations(packageName)) {
                requestBatteryOptimizationExemption()
            }
        }
    }

    private fun updatePermissionStates() {
        val context = this
        val powerManager = getSystemService(POWER_SERVICE) as PowerManager
        val nm = getSystemService(android.app.NotificationManager::class.java)

        val list = mutableListOf<PermissionItemState>()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val isGranted = ContextCompat.checkSelfPermission(context, Manifest.permission.NEARBY_WIFI_DEVICES) == PackageManager.PERMISSION_GRANTED
            list.add(
                PermissionItemState(
                    id = Manifest.permission.NEARBY_WIFI_DEVICES,
                    title = "Nearby Wi-Fi / Local Network",
                    description = "Required for Wi-Fi Direct and local P2P socket communication with host PC.",
                    level = PermissionLevel.CRITICAL,
                    isGranted = isGranted,
                    actionText = "GRANT",
                    onClick = {
                        if (!isGranted) {
                            ActivityCompat.requestPermissions(context, arrayOf(Manifest.permission.NEARBY_WIFI_DEVICES), requestPermissionsCode)
                        }
                    }
                )
            )
        }

        val isLocGranted = ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED
        list.add(
            PermissionItemState(
                id = Manifest.permission.ACCESS_FINE_LOCATION,
                title = "Local Network Discovery (Location)",
                description = "Required by Android OS to scan Wi-Fi LAN interfaces and discover host PC.",
                level = PermissionLevel.CRITICAL,
                isGranted = isLocGranted,
                actionText = "GRANT",
                onClick = {
                    if (!isLocGranted) {
                        ActivityCompat.requestPermissions(context, arrayOf(Manifest.permission.ACCESS_FINE_LOCATION), requestPermissionsCode)
                    }
                }
            )
        )

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val isNotifGranted = ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED
            list.add(
                PermissionItemState(
                    id = Manifest.permission.POST_NOTIFICATIONS,
                    title = "System Notifications",
                    description = "Shows real-time connection status, background link activity, and file progress.",
                    level = PermissionLevel.HIGH,
                    isGranted = isNotifGranted,
                    actionText = "ALLOW",
                    onClick = {
                        if (!isNotifGranted) {
                            ActivityCompat.requestPermissions(context, arrayOf(Manifest.permission.POST_NOTIFICATIONS), requestPermissionsCode)
                        }
                    }
                )
            )
        }

        /* Discarded/Excluded: File transfer feature disabled, storage access permission not required
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val isAllFilesGranted = Environment.isExternalStorageManager()
            list.add(
                PermissionItemState(
                    id = "all_files_storage_access",
                    title = "All Files Storage Access",
                    description = "Required to browse, read, and save files across all internal and SD card storage folders.",
                    level = PermissionLevel.HIGH,
                    isGranted = isAllFilesGranted,
                    actionText = "GRANT",
                    onClick = {
                        try {
                            val intent = Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION, Uri.parse("package:$packageName"))
                            startActivity(intent)
                        } catch (_: Exception) {
                            try {
                                val intent = Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION)
                                startActivity(intent)
                            } catch (_: Exception) {
                                openAppSettings()
                            }
                        }
                    }
                )
            )
        }
        */

        val isBatteryIgnored = powerManager.isIgnoringBatteryOptimizations(packageName)
        list.add(
            PermissionItemState(
                id = "battery_optimization",
                title = "Manage Battery Usage",
                description = "Exempts Tether from Android Doze mode so background LAN communication stays active.",
                level = PermissionLevel.HIGH,
                isGranted = isBatteryIgnored,
                actionText = "EXEMPT",
                onClick = {
                    requestBatteryOptimizationExemption()
                }
            )
        )

        val canOverlay = Settings.canDrawOverlays(context)
        list.add(
            PermissionItemState(
                id = "system_overlay",
                title = "Display Over Other Apps",
                description = "Enables floating quick controls and overlay alerts when working in other apps.",
                level = PermissionLevel.OPTIONAL,
                isGranted = canOverlay,
                actionText = "CONFIGURE",
                onClick = {
                    try {
                        val intent = Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION, Uri.parse("package:$packageName"))
                        startActivity(intent)
                    } catch (_: Exception) {
                        openAppSettings()
                    }
                }
            )
        )

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            val canFullScreen = nm?.canUseFullScreenIntent() ?: true
            list.add(
                PermissionItemState(
                    id = "full_screen_intent",
                    title = "Full Screen Emergency Alerts",
                    description = "Allows immediate full-screen notifications for emergency panic disconnect or unlock prompts.",
                    level = PermissionLevel.OPTIONAL,
                    isGranted = canFullScreen,
                    actionText = "CONFIGURE",
                    onClick = {
                        try {
                            val intent = Intent(Settings.ACTION_MANAGE_APP_USE_FULL_SCREEN_INTENT, Uri.parse("package:$packageName"))
                            startActivity(intent)
                        } catch (_: Exception) {
                            openAppSettings()
                        }
                    }
                )
            )
        }

        permissionStates.value = list
    }

    private fun startLanService() {
        if (isPanicActive.value || isEnvironmentRestricted.value) return
        getSharedPreferences(preferenceName, MODE_PRIVATE).edit(commit = true) {
            putBoolean("has_unlocked_app_once", true)
        }
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

    private fun confirmPairing(pin: String) {
        val intent = Intent(this, TetherLanService::class.java).apply {
            action = TetherLanService.ACTION_CONFIRM_PAIRING
            putExtra(TetherLanService.EXTRA_PAIRING_PIN, pin)
        }
        try {
            startForegroundService(intent)
        } catch (e: Exception) {
            Log.e("TetherActivity", "Failed to send confirm pairing action", e)
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