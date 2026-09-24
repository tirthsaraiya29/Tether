package com.tether.phone

import android.Manifest
import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.content.BroadcastReceiver
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.RenderEffect
import android.graphics.Shader
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import android.view.WindowManager
import android.widget.Toast
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.scaleIn
import androidx.compose.animation.scaleOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Menu
import androidx.compose.material.icons.filled.QrCode
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Tune
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CenterAlignedTopAppBar
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DrawerValue
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalDrawerSheet
import androidx.compose.material3.ModalNavigationDrawer
import androidx.compose.material3.NavigationDrawerItem
import androidx.compose.material3.NavigationDrawerItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.rememberDrawerState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asComposeRenderEffect
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.core.content.edit
import androidx.core.net.toUri
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import com.tether.phone.ui.components.CommandConfirmationDialog
import com.tether.phone.ui.components.CompromisedEnvironmentOverlay
import com.tether.phone.ui.components.CyberConfirmationDialog
import com.tether.phone.ui.components.DeepSpaceCanvasVisualizer
import com.tether.phone.ui.components.FuturisticLockOverlay
import com.tether.phone.ui.screens.PairingScreen
import com.tether.phone.ui.screens.RemoteControlScreen
import com.tether.phone.ui.screens.SettingsScreen
import com.tether.phone.ui.screens.TetherAppScreen
import com.tether.phone.ui.theme.AlertRed
import com.tether.phone.ui.theme.DeepSpace
import com.tether.phone.ui.theme.IntegrityGreen
import com.tether.phone.ui.theme.LiquidCyan
import com.tether.phone.ui.theme.TextPrimary
import com.tether.phone.ui.theme.TextSecondary
import com.tether.phone.ui.theme.TetherEase
import com.tether.phone.ui.theme.TetherTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Arrays
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import kotlin.math.roundToInt
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

    private var masterVolumeLevel = mutableFloatStateOf(value = 50f)
    private var isMasterMuted = mutableStateOf(value = false)
    private var brightnessLevel = mutableFloatStateOf(value = 50f)
    private var mediaState = mutableStateOf(value = MediaState())
    private var applicationsList = mutableStateOf(value = defaultWindowsApplications)
    private var powerPlansList = mutableStateOf<List<PowerPlanInfo>>(value = emptyList())
    private var batteryState = mutableStateOf(value = BatteryState())

    private var activePendingCommand = mutableStateOf<String?>(null)
    private var isCommandConfirmed = mutableStateOf(value = false)
    private var dismissalJob: Job? = null

    private var pendingPowerAction = mutableStateOf<PowerAction?>(null)
    private data class PowerAction(val command: String, val title: String)

    private var lastBiometricAuthTime = 0L
    private var isQrDialogVisible = mutableStateOf(value = false)
    private var qrBitmap: MutableState<Bitmap?> = mutableStateOf(null)
    private var qrBase64Key = mutableStateOf("")

    private lateinit var executor: ExecutorService

    companion object {
        private const val BIOMETRIC_KEY_ALIAS = "TetherBiometricAuthKey_v1"
    }

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
                    if (count > 0) {
                        uiStatusText.value = getString(R.string.status_link_active)
                        uiStatusColor.value = IntegrityGreen
                        uiConnectionStatusText.value = getString(R.string.status_secure_nodes, count)
                        refreshAllHostState()
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
                        delay(Duration.parse("2s"))
                        activePendingCommand.value = null
                        isCommandConfirmed.value = false
                    }
                }
            }
        }
    }

    private val hardwareMetricsReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == "com.tether.phone.ACTION_SYNC_HARDWARE_METRICS") {
                val vol = intent.getIntExtra("VOLUME_LEVEL", -1)
                val bright = intent.getIntExtra("BRIGHTNESS_LEVEL", -1)
                runOnUiThread {
                    if (vol != -1) {
                        masterVolumeLevel.floatValue = vol.toFloat().coerceIn(0f, 100f)
                    }
                    if (bright != -1) {
                        brightnessLevel.floatValue = bright.toFloat().coerceIn(0f, 100f)
                    }
                    if (intent.hasExtra("IS_MUTED")) {
                        isMasterMuted.value = intent.getBooleanExtra("IS_MUTED", false)
                    }
                }
            }
        }
    }

    private val mediaStateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == "com.tether.phone.ACTION_SYNC_MEDIA_STATE") {
                val jsonStr = intent.getStringExtra("MEDIA_JSON")
                if (!jsonStr.isNullOrEmpty()) {
                    try {
                        val jsonObj = JSONObject(jsonStr)
                        val title = jsonObj.optString("title", "No Active Session")
                        val artist = jsonObj.optString("artist", "Windows Media Engine")
                        val album = jsonObj.optString("album", "")
                        val isPlaying = jsonObj.optBoolean("isPlaying", jsonObj.optBoolean("is_playing", false))
                        val durationMs = jsonObj.optLong("durationMs", jsonObj.optLong("duration_ms", 0L))
                        val positionMs = jsonObj.optLong("positionMs", jsonObj.optLong("position_ms", 0L))
                        val artStr = if (jsonObj.has("artworkBase64")) jsonObj.optString("artworkBase64", "") else jsonObj.optString("artwork_base64", "")
                        val artworkBase64 = if ((artStr.isEmpty()) || (artStr == "null")) null else artStr
                        runOnUiThread {
                            mediaState.value = MediaState(
                                title = title,
                                artist = artist,
                                album = album,
                                isPlaying = isPlaying,
                                durationMs = durationMs,
                                positionMs = positionMs,
                                artworkBase64 = artworkBase64,
                            )
                        }
                    } catch (e: Exception) {
                        Log.e("TetherActivity", "Failed to parse media state JSON: ${e.message}")
                    }
                } else {
                    val title = intent.getStringExtra("MEDIA_TITLE") ?: "No Active Session"
                    val artist = intent.getStringExtra("MEDIA_ARTIST") ?: "Windows Media Engine"
                    val album = intent.getStringExtra("MEDIA_ALBUM") ?: ""
                    val isPlaying = intent.getBooleanExtra("IS_PLAYING", false)
                    val durationMs = intent.getLongExtra("DURATION_MS", 0L)
                    val positionMs = intent.getLongExtra("POSITION_MS", 0L)
                    val artworkBase64 = intent.getStringExtra("ARTWORK_BASE64")
                    runOnUiThread {
                        mediaState.value = MediaState(
                            title = title,
                            artist = artist,
                            album = album,
                            isPlaying = isPlaying,
                            durationMs = durationMs,
                            positionMs = positionMs,
                            artworkBase64 = artworkBase64,
                        )
                    }
                }
            }
        }
    }

    private val appListReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == "com.tether.phone.ACTION_SYNC_APP_LIST") {
                val jsonStr = intent.getStringExtra("APP_LIST_JSON")
                if (!jsonStr.isNullOrEmpty()) {
                    try {
                        val jsonArray = JSONArray(jsonStr)
                        val newList = mutableListOf<AppInfo>()
                        for (i in 0 until jsonArray.length()) {
                            val obj = jsonArray.getJSONObject(i)
                            val id = obj.optString("id", obj.optString("app_id", ""))
                            val name = obj.optString("name", obj.optString("app_name", "App $i"))
                            val category = obj.optString("category", "Windows App")
                            val iconName = obj.optString("iconName", obj.optString("icon_name", "default"))
                            if (id.isNotEmpty()) {
                                newList.add(AppInfo(id, name, category, iconName))
                            }
                        }
                        if (newList.isNotEmpty()) {
                            runOnUiThread {
                                applicationsList.value = newList
                            }
                        }
                    } catch (e: Exception) {
                        Log.e("TetherActivity", "Failed to parse app list JSON: ${e.message}")
                    }
                }
            }
        }
    }

    private val powerPlansReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == "com.tether.phone.ACTION_SYNC_POWER_PLANS") {
                val jsonStr = intent.getStringExtra("POWER_PLANS_JSON")
                if (!jsonStr.isNullOrEmpty()) {
                    try {
                        val jsonArray = JSONArray(jsonStr)
                        val newList = mutableListOf<PowerPlanInfo>()
                        for (i in 0 until jsonArray.length()) {
                            val obj = jsonArray.getJSONObject(i)
                            val id = obj.optString("id", obj.optString("plan_id", ""))
                            val name = obj.optString("name", obj.optString("plan_name", "Power Plan $i"))
                            val isActive = obj.optBoolean("isActive", obj.optBoolean("is_active", false))
                            if (id.isNotEmpty()) {
                                newList.add(PowerPlanInfo(id, name, isActive))
                            }
                        }
                        if (newList.isNotEmpty()) {
                            runOnUiThread {
                                powerPlansList.value = newList
                            }
                        }
                    } catch (e: Exception) {
                        Log.e("TetherActivity", "Failed to parse power plans JSON: ${e.message}")
                    }
                }
            }
        }
    }

    private val batteryStateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == "com.tether.phone.ACTION_SYNC_BATTERY_STATE") {
                val jsonStr = intent.getStringExtra("BATTERY_JSON")
                if (!jsonStr.isNullOrEmpty()) {
                    try {
                        val jsonObj = JSONObject(jsonStr)
                        val pct = jsonObj.optInt("percentage", jsonObj.optInt("level", 100))
                        val isCharging = jsonObj.optBoolean("isCharging", jsonObj.optBoolean("charging", false))
                        val health = jsonObj.optString("health", "Good")
                        runOnUiThread {
                            batteryState.value = BatteryState(
                                percentage = pct.coerceIn(0, 100),
                                isCharging = isCharging,
                                health = health,
                            )
                        }
                    } catch (e: Exception) {
                        Log.e("TetherActivity", "Failed to parse battery state JSON: ${e.message}")
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
                                volumeLevel = masterVolumeLevel.floatValue,
                                isMuted = isMasterMuted.value,
                                brightnessLevel = brightnessLevel.floatValue,
                                mediaState = mediaState.value,
                                applications = applicationsList.value,
                                powerPlans = powerPlansList.value,
                                batteryState = batteryState.value,
                                onUnlockClick = {
                                    val currentTime = System.currentTimeMillis()
                                    val needsAuth = (currentTime - lastBiometricAuthTime) > 10000

                                    if (needsAuth) {
                                        authenticateViaSystem(
                                            title = getString(R.string.auth_unlock_title),
                                            subtitle = getString(R.string.auth_unlock_subtitle),
                                            allowedAuthenticators = BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL,
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
                                                title = getString(R.string.dialog_confirm_protocol, command.uppercase()),
                                            )
                                        }
                                        else -> {
                                            triggerBleAction(command)
                                        }
                                    }
                                },
                                onShowQR = {
                                    showPairingQRCode()
                                },
                                onUnpinHostKey = {
                                    ProductionSecurityEngine().clearPinnedKey(this@MainActivity)
                                    Toast.makeText(this@MainActivity, "Pinned host key reset. Ready for new pairing.", Toast.LENGTH_SHORT).show()
                                },
                                onPairingTabEntered = {
                                    getSharedPreferences(preferenceName, MODE_PRIVATE).edit {
                                        putLong("pairing_window_start_time", System.currentTimeMillis())
                                    }
                                    Log.i("TetherActivity", "Pairing window OPENED (entered Pair tab)")
                                },
                                onPairingTabExited = {
                                    getSharedPreferences(preferenceName, MODE_PRIVATE).edit {
                                        putLong("pairing_window_start_time", 0L)
                                    }
                                    Log.i("TetherActivity", "Pairing window CLOSED (left Pair tab)")
                                },
                                onRestartServer = { restartBleServer() },
                                onRefreshState = { refreshAllHostState() },
                            )

                            pendingPowerAction.value?.let { action: PowerAction ->
                                CyberConfirmationDialog(
                                    title = action.title,
                                    message = getString(R.string.dialog_confirm_message, action.command),
                                    onConfirm = {
                                        triggerBleAction(action.command)
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

                            if (isQrDialogVisible.value) {
                                val currentBitmap = qrBitmap.value
                                AlertDialog(
                                    onDismissRequest = { isQrDialogVisible.value = false },
                                    title = { Text(getString(R.string.dialog_pairing_title)) },
                                    text = {
                                        Column(
                                            horizontalAlignment = Alignment.CenterHorizontally,
                                            modifier = Modifier.fillMaxWidth(),
                                        ) {
                                            Text(
                                                text = getString(R.string.dialog_pairing_message),
                                                style = MaterialTheme.typography.bodyMedium,
                                            )
                                            Spacer(modifier = Modifier.height(16.dp))
                                            if (currentBitmap != null) {
                                                Image(
                                                    bitmap = currentBitmap.asImageBitmap(),
                                                    contentDescription = "Pairing QR Code",
                                                    modifier = Modifier
                                                        .size(280.dp)
                                                        .padding(4.dp),
                                                )
                                            } else {
                                                CircularProgressIndicator(color = LiquidCyan)
                                            }
                                        }
                                    },
                                    confirmButton = {
                                        TextButton(
                                            onClick = { isQrDialogVisible.value = false },
                                        ) {
                                            Text(getString(R.string.btn_done))
                                        }
                                    },
                                    dismissButton = {
                                        TextButton(
                                            onClick = {
                                                val clipboard = getSystemService(CLIPBOARD_SERVICE)
                                                        as ClipboardManager
                                                clipboard.setPrimaryClip(
                                                    ClipData.newPlainText(
                                                        "TetherPublicKey",
                                                        qrBase64Key.value,
                                                    ),
                                                )
                                                isQrDialogVisible.value = false
                                            },
                                        ) {
                                            Text(getString(R.string.btn_copy_key))
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
            bluetoothStateReceiver,
            IntentFilter(BluetoothAdapter.ACTION_STATE_CHANGED),
            ContextCompat.RECEIVER_EXPORTED,
        )
        val filter = IntentFilter(Intent.ACTION_USER_PRESENT)
        ContextCompat.registerReceiver(this, screenUnlockReceiver, filter, ContextCompat.RECEIVER_EXPORTED)
        ContextCompat.registerReceiver(
            this,
            gattStateReceiver,
            IntentFilter(BleGattServerService.ACTION_GATT_STATE_CHANGED),
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
        ContextCompat.registerReceiver(
            this,
            commandConfirmedReceiver,
            IntentFilter("com.tether.phone.ACTION_COMMAND_CONFIRMED"),
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
        ContextCompat.registerReceiver(
            this,
            hardwareMetricsReceiver,
            IntentFilter("com.tether.phone.ACTION_SYNC_HARDWARE_METRICS"),
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
        ContextCompat.registerReceiver(
            this,
            mediaStateReceiver,
            IntentFilter("com.tether.phone.ACTION_SYNC_MEDIA_STATE"),
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
        ContextCompat.registerReceiver(
            this,
            appListReceiver,
            IntentFilter("com.tether.phone.ACTION_SYNC_APP_LIST"),
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
        ContextCompat.registerReceiver(
            this,
            powerPlansReceiver,
            IntentFilter("com.tether.phone.ACTION_SYNC_POWER_PLANS"),
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
        ContextCompat.registerReceiver(
            this,
            batteryStateReceiver,
            IntentFilter("com.tether.phone.ACTION_SYNC_BATTERY_STATE"),
            ContextCompat.RECEIVER_NOT_EXPORTED,
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

        if ((commandType != null) || (action == "com.tether.phone.ACTION_VOICE_COMMAND")) {
            val command = commandType ?: "unknown"

            val callingPkg = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                callingPackage ?: launchedFromPackage
            } else {
                callingPackage ?: callingActivity?.packageName
            }
            val hasInternalPermission = checkCallingOrSelfPermission("com.tether.phone.permission.INTERNAL_VOICE_TRIGGER") == PackageManager.PERMISSION_GRANTED
            val isSelfCall = (callingPkg == packageName)

            if (!isSelfCall && !hasInternalPermission) {
                Log.w("TetherActivity", "Rejected unauthorized external voice command from: $callingPkg")
                return
            }

            if (!isEnvironmentRestricted.value && !isAppLocked.value) {
                val bleCommand = when (command) {
                    "lock_now" -> "lock_now"
                    "unlock" -> "unlock"
                    "shutdown" -> "shutdown"
                    "sleep" -> "sleep"
                    "reboot" -> "reboot"
                    else -> return
                }

                if (bleCommand == "lock_now") {
                    triggerBleAction(bleCommand)
                    finish()
                } else {
                    authenticateViaSystem(
                        title = getString(R.string.auth_title),
                        subtitle = getString(R.string.auth_subtitle),
                        allowedAuthenticators = BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL,
                    ) { success ->
                        if (success) {
                            runOnUiThread {
                                lastBiometricAuthTime = System.currentTimeMillis()
                                triggerBleAction(bleCommand)
                                finish()
                            }
                        } else {
                            Log.w("TetherActivity", "Shortcut/Voice action $bleCommand rejected: Authentication failed")
                        }
                    }
                }
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
        try { unregisterReceiver(hardwareMetricsReceiver) } catch (_: Exception) {}
        try { unregisterReceiver(mediaStateReceiver) } catch (_: Exception) {}
        try { unregisterReceiver(appListReceiver) } catch (_: Exception) {}
        try { unregisterReceiver(powerPlansReceiver) } catch (_: Exception) {}
        try { unregisterReceiver(batteryStateReceiver) } catch (_: Exception) {}
        try { unregisterReceiver(screenUnlockReceiver) } catch (_: Exception) {}
        try { unregisterReceiver(bluetoothStateReceiver) } catch (_: Exception) {}

        executor.shutdown()
        super.onDestroy()
    }

    private fun refreshAllHostState() {
        if (!isConnected.value) return
        triggerBleAction("get_apps")
        triggerBleAction("get_power_plans")
        triggerBleAction("get_battery")
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
        if (powerManager.isIgnoringBatteryOptimizations(packageName)) {
            Log.i("TetherUI", "App is already exempted from battery optimizations.")
            return
        }

        Log.w("TetherUI", "App is not exempted from battery optimizations. Opening settings for user opt-in.")

        try {
            val intent = Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)
            batteryOptimizationLauncher.launch(intent)
            return
        } catch (e: Exception) {
            Log.w("TetherUI", "Could not open ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS: ${e.message}")
        }

        try {
            val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                data = "package:$packageName".toUri()
            }
            batteryOptimizationLauncher.launch(intent)
        } catch (e: Exception) {
            Log.e("TetherUI", "Could not open app details settings: ${e.message}")
        }
    }

    private fun setPanicUiState() {
        uiStatusText.value = getString(R.string.status_lockdown_active)
        uiStatusColor.value = AlertRed
        uiConnectionStatusText.value = getString(R.string.status_trust_revoked)
        isConnected.value = false
    }

    private fun showPairingQRCode() {
        executor.execute {
            try {
                val publicKeyBytes = ProductionSecurityEngine().getPublicKeyBytes()
                val base64Key = Base64.encodeToString(
                    publicKeyBytes,
                    Base64.NO_WRAP,
                )

                val qrContent = "TETHER:KEY:$base64Key"
                val bitmap = QRCodeGenerator.generateQRCode(qrContent)

                runOnUiThread {
                    qrBitmap.value = bitmap
                    qrBase64Key.value = base64Key
                    isQrDialogVisible.value = true
                }
            } catch (e: Exception) {
                Log.e("TetherActivity", "QR generation failed: ${e.message}", e)
                runOnUiThread {
                    Toast.makeText(
                        this@MainActivity,
                        "Failed to generate QR: ${e.message}",
                        Toast.LENGTH_LONG,
                    ).show()
                }
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

    private fun authenticateViaSystem(
        title: String,
        subtitle: String,
        allowedAuthenticators: Int,
        callback: (Boolean) -> Unit,
    ) {
        val keyStore: KeyStore = try {
            KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        } catch (e: Exception) {
            Log.e("TetherActivity", "AndroidKeyStore unavailable: ${e.message}")
            callback(false)
            return
        }

        if (!keyStore.containsAlias(BIOMETRIC_KEY_ALIAS)) {
            try {
                val kpg = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC,
                    "AndroidKeyStore",
                )
                val specBuilder = KeyGenParameterSpec.Builder(
                    BIOMETRIC_KEY_ALIAS,
                    KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
                )
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setUserAuthenticationRequired(true)

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    specBuilder.setUserAuthenticationParameters(
                        0,
                        KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
                    )
                } else {
                    @Suppress("DEPRECATION")
                    specBuilder.setUserAuthenticationValidityDurationSeconds(-1)
                }

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    try {
                        specBuilder.setIsStrongBoxBacked(true)
                        kpg.initialize(specBuilder.build())
                        kpg.generateKeyPair()
                        Log.i("TetherActivity", "Biometric Keystore key created (StrongBox backed).")
                    } catch (e: Exception) {
                        Log.w("TetherActivity", "StrongBox unavailable, falling back to TEE: ${e.message}")
                        specBuilder.setIsStrongBoxBacked(false)
                        kpg.initialize(specBuilder.build())
                        kpg.generateKeyPair()
                        Log.i("TetherActivity", "Biometric Keystore key created (TEE backed).")
                    }
                } else {
                    kpg.initialize(specBuilder.build())
                    kpg.generateKeyPair()
                    Log.i("TetherActivity", "Biometric Keystore key created.")
                }
            } catch (e: Exception) {
                Log.e("TetherActivity", "Failed to create biometric Keystore key: ${e.message}")
                callback(false)
                return
            }
        }

        val requiresCrypto = (allowedAuthenticators and BiometricManager.Authenticators.DEVICE_CREDENTIAL) == 0

        val cryptoObject: BiometricPrompt.CryptoObject? = if (requiresCrypto) {
            try {
                val privateKey = keyStore.getKey(BIOMETRIC_KEY_ALIAS, null) as? PrivateKey
                if (privateKey == null) {
                    Log.e("TetherActivity", "Biometric private key missing from Keystore")
                    callback(false)
                    return
                }
                val signature = Signature.getInstance("SHA256withECDSA")
                signature.initSign(privateKey)
                BiometricPrompt.CryptoObject(signature)
            } catch (e: Exception) {
                Log.e("TetherActivity", "Signature.initSign failed: ${e.message}")
                callback(false)
                return
            }
        } else {
            null
        }

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
                    override fun onAuthenticationSucceeded(
                        result: BiometricPrompt.AuthenticationResult,
                    ) {
                        super.onAuthenticationSucceeded(result)
                        try {
                            val authSignature = result.cryptoObject?.signature
                            if (authSignature != null) {
                                val challenge = ByteArray(32)
                                SecureRandom().nextBytes(challenge)
                                try {
                                    authSignature.update(challenge)
                                    val proof = authSignature.sign()
                                    Arrays.fill(proof, 0)
                                    Arrays.fill(challenge, 0)
                                    Log.i("TetherActivity", "Keystore-backed biometric proof succeeded")
                                    callback(true)
                                } catch (e: Exception) {
                                    Log.e("TetherActivity", "Keystore signature failed after auth: ${e.message}")
                                    Arrays.fill(challenge, 0)
                                    callback(false)
                                }
                            } else {
                                Log.i("TetherActivity", "Authentication succeeded via system credential")
                                callback(true)
                            }
                        } catch (e: Exception) {
                            Log.e("TetherActivity", "Unexpected error in auth success handler: ${e.message}")
                            callback(false)
                        }
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        super.onAuthenticationError(errorCode, errString)
                        callback(false)
                    }
                },
            )

            try {
                if (requiresCrypto && (cryptoObject != null)) {
                    biometricPrompt.authenticate(promptBuilder.build(), cryptoObject)
                } else {
                    biometricPrompt.authenticate(promptBuilder.build())
                }
            } catch (e: Exception) {
                Log.e("TetherActivity", "BiometricPrompt.authenticate threw: ${e.message}")
                callback(false)
            }
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
            if ((adapter == null) || !adapter.isEnabled) {
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
            required.addAll(
                listOf(
                    Manifest.permission.BLUETOOTH_SCAN,
                    Manifest.permission.BLUETOOTH_CONNECT,
                    Manifest.permission.BLUETOOTH_ADVERTISE,
                    Manifest.permission.ACCESS_FINE_LOCATION,
                ),
            )
        } else {
            required.addAll(
                listOf(
                    Manifest.permission.ACCESS_FINE_LOCATION,
                    Manifest.permission.BLUETOOTH,
                    Manifest.permission.BLUETOOTH_ADMIN,
                ),
            )
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
            required.addAll(
                listOf(
                    Manifest.permission.BLUETOOTH_SCAN,
                    Manifest.permission.BLUETOOTH_CONNECT,
                    Manifest.permission.BLUETOOTH_ADVERTISE,
                    Manifest.permission.ACCESS_FINE_LOCATION,
                ),
            )
        } else {
            required.addAll(
                listOf(
                    Manifest.permission.ACCESS_FINE_LOCATION,
                    Manifest.permission.BLUETOOTH,
                    Manifest.permission.BLUETOOTH_ADMIN,
                ),
            )
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

    private fun restartBleServer() {
        val intent = Intent(this, BleGattServerService::class.java).apply {
            action = BleGattServerService.ACTION_RESTART_SERVER
        }
        try {
            startForegroundService(intent)
            uiConnectionStatusText.value = getString(R.string.status_restarting_stack)
        } catch (e: Exception) {
            Log.e("TetherActivity", "Failed to restart server", e)
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
    volumeLevel: Float = 50f,
    isMuted: Boolean = false,
    brightnessLevel: Float = 50f,
    mediaState: MediaState = MediaState(),
    applications: List<AppInfo> = defaultWindowsApplications,
    powerPlans: List<PowerPlanInfo> = emptyList(),
    batteryState: BatteryState = BatteryState(),
    onUnlockClick: () -> Unit,
    onLockClick: () -> Unit,
    onPanicClick: () -> Unit,
    onSideRestore: () -> Unit,
    onSelectLaptop: () -> Unit,
    onTriggerStepVerification: (TrustVerificationStep) -> Unit,
    onTimeoutChanged: (Long) -> Unit,
    onLaptopActionClick: (String) -> Unit,
    onShowQR: () -> Unit,
    onUnpinHostKey: () -> Unit,
    onRestartServer: () -> Unit,
    onRefreshState: () -> Unit,
    onPairingTabEntered: () -> Unit,
    onPairingTabExited: () -> Unit,
) {
    val drawerState = rememberDrawerState(initialValue = DrawerValue.Closed)
    val scope = rememberCoroutineScope()
    var currentScreen by remember { mutableStateOf(AppScreen.TELEMETRY_DASHBOARD) }

    DisposableEffect(currentScreen) {
        if (currentScreen == AppScreen.PAIRING) {
            onPairingTabEntered()
        } else if (currentScreen == AppScreen.LAPTOP_CONTROL) {
            onRefreshState()
        }
        onDispose {
            if (currentScreen == AppScreen.PAIRING) {
                onPairingTabExited()
            }
        }
    }

    ModalNavigationDrawer(
        drawerState = drawerState,
        drawerContent = {
            ModalDrawerSheet(
                drawerContainerColor = Color.Transparent,
                drawerContentColor = TextSecondary,
                modifier = Modifier.width(320.dp).fillMaxHeight(),
            ) {
                Box(modifier = Modifier.fillMaxSize()) {
                    Box(
                        modifier = Modifier
                            .fillMaxSize()
                            .background(DeepSpace.copy(alpha = 0.85f))
                            .graphicsLayer {
                                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                                    renderEffect = RenderEffect
                                        .createBlurEffect(40f, 40f, Shader.TileMode.CLAMP)
                                        .asComposeRenderEffect()
                                }
                            },
                    )
                    Column(modifier = Modifier.fillMaxSize().padding(32.dp)) {
                        Spacer(modifier = Modifier.height(64.dp))
                        Text(
                            text = stringResource(R.string.nav_command_interface),
                            style = MaterialTheme.typography.labelMedium,
                            color = LiquidCyan,
                        )
                        Spacer(modifier = Modifier.height(48.dp))

                        val navItems = listOf(
                            Triple(stringResource(R.string.nav_dashboard), Icons.Default.Home, AppScreen.TELEMETRY_DASHBOARD),
                            Triple("PC Remote Control", Icons.Default.Tune, AppScreen.LAPTOP_CONTROL),
                            Triple(stringResource(R.string.nav_security), Icons.Default.Settings, AppScreen.SECURITY_SETTINGS),
                            Triple(stringResource(R.string.nav_pair), Icons.Default.QrCode, AppScreen.PAIRING),
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
                                    unselectedTextColor = TextSecondary,
                                ),
                                shape = RoundedCornerShape(20.dp),
                                onClick = {
                                    currentScreen = screen
                                    scope.launch { drawerState.close() }
                                },
                            )
                            Spacer(modifier = Modifier.height(8.dp))
                        }
                    }
                }
            }
        },
    ) {
        Scaffold(
            topBar = {
                CenterAlignedTopAppBar(
                    title = {
                        Text(
                            text = stringResource(R.string.app_title),
                            style = MaterialTheme.typography.headlineSmall,
                            color = TextPrimary,
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
                    colors = TopAppBarDefaults.topAppBarColors(containerColor = Color.Transparent),
                )
            },
            containerColor = Color.Transparent,
        ) { paddingValues ->
            Box(modifier = Modifier.fillMaxSize().padding(paddingValues)) {
                AnimatedContent(
                    targetState = currentScreen,
                    transitionSpec = {
                        val enterSpec = fadeIn(animationSpec = spring(stiffness = Spring.StiffnessLow)) +
                                scaleIn(initialScale = 0.96f, animationSpec = spring(stiffness = Spring.StiffnessLow))
                        val exitSpec = fadeOut(animationSpec = spring(stiffness = Spring.StiffnessLow)) +
                                scaleOut(targetScale = 1.04f, animationSpec = spring(stiffness = Spring.StiffnessLow))
                        enterSpec.togetherWith(exitSpec)
                    },
                    label = "ScreenTransition",
                ) { screen ->
                    when (screen) {
                        AppScreen.TELEMETRY_DASHBOARD -> TetherAppScreen(
                            statusText = statusText,
                            statusColor = statusColor,
                            connectionStatus = connectionStatus,
                            isConnected = isConnected,
                            isPanicActive = isPanicActive,
                            verificationStep = verificationStep,
                            volumeLevel = volumeLevel,
                            isMuted = isMuted,
                            mediaState = mediaState,
                            onUnlockClick = onUnlockClick,
                            onLockClick = onLockClick,
                            onPanicClick = onPanicClick,
                            onSideRestore = onSideRestore,
                            onSelectLaptop = onSelectLaptop,
                            onTriggerStepVerification = onTriggerStepVerification,
                            onBleActionRequested = onLaptopActionClick,
                            onVolumeChanged = { newVol -> onLaptopActionClick("volume:${newVol.roundToInt()}") },
                            onMuteToggled = { onLaptopActionClick("mute_toggle") },
                            onMediaPlayPause = { onLaptopActionClick("media:play_pause") },
                            onMediaPrevious = { onLaptopActionClick("media:prev") },
                        ) {
                            onLaptopActionClick("media:next")
                        }
                        AppScreen.SECURITY_SETTINGS -> SettingsScreen(
                            selectedTimeoutMs = selectedTimeoutMs,
                            onTimeoutChanged = onTimeoutChanged,
                            onRestartServer = onRestartServer,
                        )
                        AppScreen.LAPTOP_CONTROL -> RemoteControlScreen(
                            volumeLevel = volumeLevel,
                            isMuted = isMuted,
                            brightnessLevel = brightnessLevel,
                            mediaState = mediaState,
                            applications = applications,
                            powerPlans = powerPlans,
                            batteryState = batteryState,
                            isConnected = isConnected,
                            onVolumeChanged = { newVol -> onLaptopActionClick("volume:${newVol.roundToInt()}") },
                            onMuteToggled = { onLaptopActionClick("mute_toggle") },
                            onBrightnessChanged = { newBright -> onLaptopActionClick("brightness:${newBright.roundToInt()}") },
                            onSelectPowerPlan = { planId -> onLaptopActionClick("power_plan:$planId") },
                            onMediaPlayPause = { onLaptopActionClick("media:play_pause") },
                            onMediaPrevious = { onLaptopActionClick("media:prev") },
                            onMediaNext = { onLaptopActionClick("media:next") },
                            onLaunchApp = { appId -> onLaptopActionClick("app_launch:$appId") },
                            onRefreshApps = { onLaptopActionClick("get_apps") },
                            onRefreshState = onRefreshState,
                        )
                        AppScreen.PAIRING -> PairingScreen(
                            onShowQR = onShowQR,
                            onUnpinHostKey = onUnpinHostKey,
                        )
                    }
                }
            }
        }
    }
}
