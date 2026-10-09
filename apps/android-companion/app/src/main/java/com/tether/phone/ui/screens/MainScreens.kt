package com.tether.phone.ui.screens

import android.content.Context
import android.content.Intent
import android.graphics.RenderEffect
import android.graphics.Shader
import android.os.Build
import android.os.PowerManager
import android.provider.Settings
import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Menu
import androidx.compose.material.icons.filled.QrCode
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.asComposeRenderEffect
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.graphicsLayer
import kotlinx.coroutines.launch
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.tether.phone.R
import com.tether.phone.*
import com.tether.phone.ui.components.*
import com.tether.phone.ui.theme.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

@Composable
fun TetherAppScreen(
    laptopTelemetry: LaptopTelemetry = LaptopTelemetry(),
    windowsFingerprint: String = "",
    statusText: String,
    statusColor: Color,
    connectionStatus: String,
    isConnected: Boolean,
    isPanicActive: Boolean,
    verificationStep: TrustVerificationStep,
    volumeLevel: Int = 50,
    isMuted: Boolean = false,
    grantedCapabilities: Set<String> = emptySet(),
    onUnlockClick: () -> Unit,
    onLockClick: () -> Unit,
    onPanicClick: () -> Unit,
    onSideRestore: () -> Unit,
    onSelectLaptop: () -> Unit,
    onLaptopCardClick: () -> Unit = {},
    onTriggerStepVerification: (TrustVerificationStep) -> Unit,
    onLanActionRequested: (String) -> Unit,
) {
    val scrollState = rememberScrollState()
    var visible by remember { mutableStateOf(value = false) }
    LaunchedEffect(Unit) { visible = true }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(scrollState)
            .padding(horizontal = 24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        // --- Hero Component: LaptopScreenCard ---
        AnimatedVisibility(
            visible = visible,
            enter = fadeIn(animationSpec = tween(durationMillis = 1000)) + 
                    expandVertically(animationSpec = tween(durationMillis = 800, easing = TetherEase)),
        ) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 12.dp)
                    .graphicsLayer { translationY = -scrollState.value * 0.15f },
                contentAlignment = Alignment.Center,
            ) {
                LaptopScreenCard(
                    telemetry = laptopTelemetry,
                    windowsFingerprint = windowsFingerprint,
                    onClick = onLaptopCardClick,
                )
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // --- Tactical Action Chips ---
        AnimatedContent(
            targetState = verificationStep,
            label = "SecurityActions",
        ) { step ->
            Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
                when (step) {
                    TrustVerificationStep.NOT_IN_PANIC -> {
                        if (isPanicActive) {
                            AnimatedVisibility(
                                visible = visible,
                                enter = fadeIn(animationSpec = tween(durationMillis = 800)) + scaleIn(initialScale = 0.9f),
                            ) {
                                PanicRestoreCard(onSideRestore = onSideRestore)
                            }
                        } else {
                            AnimatedVisibility(
                                visible = visible,
                                enter = fadeIn(animationSpec = tween(durationMillis = 800, delayMillis = 200)) + 
                                        slideInVertically(animationSpec = tween(durationMillis = 800, delayMillis = 200)) { it / 2 },
                            ) {
                                Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.spacedBy(16.dp),
                                    ) {
                                        TacticalAction(
                                            label = stringResource(R.string.label_unlock),
                                            accentColor = IntegrityGreen,
                                            onClick = onUnlockClick,
                                            modifier = Modifier.weight(1f),
                                            enabled = isConnected,
                                        )
                                        TacticalAction(
                                            label = stringResource(R.string.label_lock),
                                            accentColor = LiquidCyan,
                                            onClick = onLockClick,
                                            modifier = Modifier.weight(1f),
                                            enabled = isConnected,
                                        )
                                    }
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.spacedBy(16.dp),
                                    ) {
                                        TacticalAction(
                                            label = stringResource(R.string.label_target),
                                            accentColor = TextSecondary,
                                            onClick = onSelectLaptop,
                                            modifier = Modifier.weight(1f),
                                        )
                                        TacticalAction(
                                            label = stringResource(R.string.label_panic),
                                            accentColor = AlertRed,
                                            onClick = onPanicClick,
                                            modifier = Modifier.weight(1f),
                                        )
                                    }
                                }
                            }
                        }
                    }
                    TrustVerificationStep.DEVICE_CREDENTIAL -> LoadingSecurityStep(msg = stringResource(R.string.status_verifying_security))
                    TrustVerificationStep.BIOMETRIC_FINGERPRINT -> BiometricVerificationStep { onTriggerStepVerification(step) }
                }
            }
        }

        Spacer(modifier = Modifier.height(20.dp))

        // --- Controls & Telemetry Surfaces ---
        AnimatedVisibility(
            visible = visible,
            enter = fadeIn(animationSpec = tween(durationMillis = 800, delayMillis = 300)) + 
                    slideInVertically(animationSpec = tween(durationMillis = 800, delayMillis = 300)) { it / 2 },
        ) {
            Column(verticalArrangement = Arrangement.spacedBy(20.dp)) {
                LiquidGlassVolumeControl(
                    volumeLevel = volumeLevel,
                    isMuted = isMuted,
                    onVolumeChange = { level -> onLanActionRequested("volume_set:$level") },
                    onVolumeUp = { onLanActionRequested("VOL_UP") },
                    onVolumeDown = { onLanActionRequested("VOL_DOWN") },
                    onToggleMute = { onLanActionRequested("volume_mute") },
                    enabled = isConnected,
                )

                ProfessionalGlassSurface(modifier = Modifier.fillMaxWidth()) {
                    Text(
                        text = stringResource(R.string.header_hardware_directives),
                        style = MaterialTheme.typography.labelMedium,
                        color = LiquidCyan,
                    )
                    Spacer(modifier = Modifier.height(20.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(16.dp),
                    ) {
                        TacticalAction(
                            label = stringResource(R.string.label_sleep),
                            accentColor = MatrixGold,
                            onClick = { onLanActionRequested("PWR_SLEEP") },
                            modifier = Modifier.weight(1f),
                            enabled = isConnected,
                        )
                        TacticalAction(
                            label = stringResource(R.string.label_reboot),
                            accentColor = TextPrimary,
                            onClick = { onLanActionRequested("PWR_REBOOT") },
                            modifier = Modifier.weight(1f),
                            enabled = isConnected,
                        )
                    }
                    Spacer(modifier = Modifier.height(16.dp))
                    TacticalAction(
                        label = stringResource(R.string.label_halt_system),
                        accentColor = AlertRed,
                        onClick = { onLanActionRequested("PWR_SHUTDOWN") },
                        enabled = isConnected,
                    )
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
    val radius by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = radiusTargetPx,
        animationSpec = infiniteRepeatable(animation = tween(durationMillis = 3500, easing = LinearOutSlowInEasing)),
        label = "R",
    )
    val alpha by infiniteTransition.animateFloat(
        initialValue = 1f,
        targetValue = 0f,
        animationSpec = infiniteRepeatable(animation = tween(durationMillis = 3500, easing = LinearOutSlowInEasing)),
        label = "A",
    )
    val pulseScale by infiniteTransition.animateFloat(
        initialValue = 1f,
        targetValue = 1.1f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 2000, easing = TetherEase),
            repeatMode = RepeatMode.Reverse,
        ),
        label = "P",
    )

    Box(contentAlignment = Alignment.Center) {
        Canvas(
            modifier = Modifier
                .size(320.dp)
                .graphicsLayer {
                    scaleX = pulseScale
                    scaleY = pulseScale
                },
        ) {
            drawCircle(
                color = color.copy(alpha = alpha * 0.4f),
                radius = radius,
                style = Stroke(width = 2.5.dp.toPx()),
            )
            drawCircle(
                color = color.copy(alpha = alpha * 0.15f),
                radius = radius * 0.7f,
                style = Stroke(width = 1.5.dp.toPx()),
            )

            drawArc(
                color = Color.White.copy(alpha = alpha * 0.2f),
                startAngle = -45f,
                sweepAngle = 90f,
                useCenter = false,
                topLeft = Offset(x = center.x - radius, y = center.y - radius),
                size = androidx.compose.ui.geometry.Size(width = radius * 2, height = radius * 2),
                style = Stroke(width = 4.dp.toPx(), cap = StrokeCap.Round),
            )
        }
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text(
                text = stringResource(R.string.status_scanning),
                style = MaterialTheme.typography.labelMedium,
                color = color,
            )
            Spacer(modifier = Modifier.height(20.dp))
            Text(
                text = stringResource(R.string.label_no_host),
                style = MaterialTheme.typography.headlineMedium,
                color = TextPrimary,
                fontWeight = FontWeight.Bold,
            )
            Text(
                text = stringResource(R.string.label_broadcasting_mesh),
                style = MaterialTheme.typography.labelSmall,
                color = TextSecondary,
            )
        }
    }
}

@Composable
fun ActiveLinkVisualizer(color: Color, status: String, subStatus: String) {
    val infiniteTransition = rememberInfiniteTransition(label = "Active")
    val rotation by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(animation = tween(durationMillis = 25000, easing = LinearEasing)),
        label = "Rot",
    )
    val orbitRotation by infiniteTransition.animateFloat(
        initialValue = 360f,
        targetValue = 0f,
        animationSpec = infiniteRepeatable(animation = tween(durationMillis = 15000, easing = LinearEasing)),
        label = "Orbit",
    )
    val glowPulse by infiniteTransition.animateFloat(
        initialValue = 0.4f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 3000, easing = TetherEase),
            repeatMode = RepeatMode.Reverse,
        ),
        label = "Glow",
    )

    Box(contentAlignment = Alignment.Center) {
        Canvas(
            modifier = Modifier
                .size(320.dp)
                .graphicsLayer { alpha = 0.8f },
        ) {
            drawCircle(
                brush = Brush.radialGradient(
                    colors = listOf(color.copy(alpha = 0.3f * glowPulse), Color.Transparent),
                    radius = size.width / 1.8f,
                ),
            )
        }

        Canvas(
            modifier = Modifier
                .size(280.dp)
                .graphicsLayer { rotationZ = rotation },
        ) {
            drawArc(
                color = color,
                startAngle = 0f,
                sweepAngle = 160f,
                useCenter = false,
                style = Stroke(width = 5.dp.toPx(), cap = StrokeCap.Round),
            )
            drawArc(
                color = color.copy(alpha = 0.3f),
                startAngle = 180f,
                sweepAngle = 90f,
                useCenter = false,
                style = Stroke(width = 2.dp.toPx(), cap = StrokeCap.Round),
            )
        }

        Canvas(
            modifier = Modifier
                .size(240.dp)
                .graphicsLayer { rotationZ = orbitRotation },
        ) {
            val nodeCenter = Offset(x = size.width, y = size.height / 2)
            drawCircle(
                color = color,
                radius = 7.dp.toPx(),
                center = nodeCenter,
            )
            drawCircle(
                color = color.copy(alpha = 0.4f),
                radius = 14.dp.toPx() * glowPulse,
                center = nodeCenter,
            )

            val mirrorCenter = Offset(x = 0f, y = size.height / 2)
            drawCircle(
                color = color.copy(alpha = 0.6f),
                radius = 5.dp.toPx(),
                center = mirrorCenter,
            )
            drawCircle(
                color = color.copy(alpha = 0.2f),
                radius = 10.dp.toPx() * glowPulse,
                center = mirrorCenter,
            )
        }

        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            modifier = Modifier
                .width(180.dp)
                .graphicsLayer {
                    scaleX = (glowPulse * 0.05f) + 0.95f
                    scaleY = (glowPulse * 0.05f) + 0.95f
                },
        ) {
            Text(
                text = status,
                style = MaterialTheme.typography.headlineSmall,
                color = color,
                textAlign = TextAlign.Center,
                fontWeight = FontWeight.ExtraBold,
                lineHeight = 28.sp,
            )
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = subStatus,
                style = MaterialTheme.typography.labelMedium,
                color = TextSecondary,
            )
        }
    }
}

@Composable
fun PanicRestoreCard(onSideRestore: () -> Unit) {
    ProfessionalGlassSurface(tint = IntegrityGreen, alpha = 0.12f) {
        Text(
            text = stringResource(R.string.status_lockdown_active),
            style = MaterialTheme.typography.labelMedium,
            color = AlertRed,
        )
        Spacer(modifier = Modifier.height(12.dp))
        Text(
            text = stringResource(R.string.panic_message),
            style = MaterialTheme.typography.bodyMedium,
            color = TextSecondary,
        )
        Spacer(modifier = Modifier.height(28.dp))
        TacticalAction(
            label = stringResource(R.string.label_restore),
            accentColor = IntegrityGreen,
            onClick = onSideRestore,
        )
    }
}

@Composable
fun LoadingSecurityStep(msg: String) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        CircularProgressIndicator(
            color = LiquidCyan,
            strokeWidth = 1.5.dp,
            modifier = Modifier.size(48.dp),
        )
        Spacer(modifier = Modifier.height(20.dp))
        Text(
            text = msg,
            style = MaterialTheme.typography.labelMedium,
            color = TextSecondary,
        )
    }
}

@Composable
fun BiometricVerificationStep(onVerify: () -> Unit) {
    ProfessionalGlassSurface(tint = LiquidCyan, alpha = 0.12f) {
        Text(
            text = stringResource(R.string.header_identity_required),
            style = MaterialTheme.typography.labelMedium,
            color = LiquidCyan
        )
        Spacer(modifier = Modifier.height(12.dp))
        Text(
            text = stringResource(R.string.identity_message),
            style = MaterialTheme.typography.bodyMedium,
            color = TextSecondary
        )
        Spacer(modifier = Modifier.height(28.dp))
        TacticalAction(
            label = stringResource(R.string.btn_verify),
            accentColor = LiquidCyan,
            onClick = onVerify
        )
    }
}

@Composable
fun SettingsScreen(
    trustState: TrustState = TrustState.UNPAIRED,
    phoneFingerprint: String = "",
    windowsFingerprint: String = "",
    onRestartServer: () -> Unit,
    onForgetTrust: () -> Unit = {}
) {
    val context = LocalContext.current
    val powerManager = remember { context.getSystemService(Context.POWER_SERVICE) as PowerManager }
    var isBatteryOptimized by remember { mutableStateOf(value = !powerManager.isIgnoringBatteryOptimizations(context.packageName)) }

    val scrollState = rememberScrollState()
    var visible by remember { mutableStateOf(value = false) }
    LaunchedEffect(Unit) { visible = true }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(scrollState)
            .padding(24.dp)
    ) {
        AnimatedVisibility(
            visible = visible,
            enter = fadeIn(animationSpec = tween(durationMillis = 600)) + 
                    slideInVertically(animationSpec = tween(durationMillis = 600)) { -it / 4 }
        ) {
            Text(
                text = stringResource(R.string.header_system_config),
                style = MaterialTheme.typography.labelLarge,
                color = LiquidCyan,
                letterSpacing = 4.sp
            )
        }
        Spacer(modifier = Modifier.height(28.dp))

        AnimatedVisibility(
            visible = visible,
            enter = fadeIn(animationSpec = tween(durationMillis = 600, delayMillis = 150)) + 
                    slideInVertically(animationSpec = tween(durationMillis = 600, delayMillis = 150)) { it / 3 }
        ) {
            ProfessionalGlassSurface {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text(
                        text = "TRUST & CRYPTOGRAPHIC IDENTITY",
                        style = MaterialTheme.typography.titleLarge,
                        color = TextPrimary
                    )
                    Text(
                        text = stringResource(R.string.label_phone_fingerprint),
                        style = MaterialTheme.typography.labelSmall,
                        color = LiquidCyan
                    )
                    Text(
                        text = phoneFingerprint.ifBlank { "COMPUTING..." },
                        style = MaterialTheme.typography.bodySmall,
                        color = TextPrimary,
                        fontSize = 11.sp
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = stringResource(R.string.label_windows_fingerprint),
                        style = MaterialTheme.typography.labelSmall,
                        color = LiquidCyan
                    )

                    val (fpText, fpColor) = when {
                        trustState == TrustState.PAIRED && windowsFingerprint.isNotBlank() && windowsFingerprint != "NONE" ->
                            windowsFingerprint to IntegrityGreen
                        trustState == TrustState.PAIRED ->
                            "PAIRED & PINNED" to IntegrityGreen
                        else ->
                            "NOT PINNED" to AlertRed
                    }
                    Text(
                        text = fpText,
                        style = MaterialTheme.typography.bodySmall,
                        color = fpColor,
                        fontSize = 11.sp
                    )

                    if (trustState == TrustState.PAIRED) {
                        Spacer(modifier = Modifier.height(8.dp))
                        TacticalAction(
                            label = stringResource(R.string.label_forget_trust),
                            accentColor = AlertRed,
                            onClick = onForgetTrust
                        )
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(28.dp))
        AnimatedVisibility(
            visible = visible,
            enter = fadeIn(animationSpec = tween(durationMillis = 600, delayMillis = 200)) + 
                    slideInVertically(animationSpec = tween(durationMillis = 600, delayMillis = 200)) { it / 3 }
        ) {
            ProfessionalGlassSurface {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(
                            text = "Security Hardening",
                            style = MaterialTheme.typography.titleLarge,
                            color = TextPrimary
                        )
                        Text(
                            text = "Biometric Gateway and UI Privacy Mask are active and enforced by system policy.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = IntegrityGreen
                        )
                    }
                    Icon(
                        imageVector = Icons.Default.CheckCircle,
                        contentDescription = null,
                        tint = IntegrityGreen,
                        modifier = Modifier.size(24.dp)
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(28.dp))
        AnimatedVisibility(
            visible = visible,
            enter = fadeIn(animationSpec = tween(durationMillis = 600, delayMillis = 300)) + 
                    slideInVertically(animationSpec = tween(durationMillis = 600, delayMillis = 300)) { it / 3 }
        ) {
            ProfessionalGlassSurface {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(
                            text = stringResource(R.string.label_battery_persistence),
                            style = MaterialTheme.typography.titleLarge,
                            color = TextPrimary
                        )
                        Text(
                            text = if (isBatteryOptimized) stringResource(R.string.desc_battery_optimized) else stringResource(R.string.desc_battery_unrestricted),
                            style = MaterialTheme.typography.bodyMedium,
                            color = if (isBatteryOptimized) MatrixGold else IntegrityGreen
                        )
                    }
                    if (isBatteryOptimized) {
                        Button(
                            onClick = {
                                val intent = Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)
                                context.startActivity(intent)
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = LiquidCyan.copy(alpha = 0.12f)),
                            border = BorderStroke(width = 0.5.dp, color = LiquidCyan),
                            shape = RoundedCornerShape(12.dp)
                        ) {
                            Text(text = stringResource(R.string.btn_fix), color = LiquidCyan)
                        }
                    } else {
                        Icon(
                            imageVector = Icons.Default.CheckCircle,
                            contentDescription = null,
                            tint = IntegrityGreen,
                            modifier = Modifier.size(32.dp)
                        )
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(28.dp))
        AnimatedVisibility(
            visible = visible,
            enter = fadeIn(animationSpec = tween(durationMillis = 600, delayMillis = 400)) + 
                    slideInVertically(animationSpec = tween(durationMillis = 600, delayMillis = 400)) { it / 3 }
        ) {
            ProfessionalGlassSurface {
                Column(
                    modifier = Modifier.fillMaxWidth(),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Text(
                        text = stringResource(R.string.label_service_control),
                        style = MaterialTheme.typography.titleLarge,
                        color = TextPrimary
                    )
                    Text(
                        text = stringResource(R.string.desc_restart_server),
                        style = MaterialTheme.typography.bodyMedium,
                        color = TextSecondary
                    )
                    Button(
                        onClick = onRestartServer,
                        modifier = Modifier.fillMaxWidth().height(48.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = LiquidCyan.copy(alpha = 0.12f)),
                        border = BorderStroke(width = 0.5.dp, color = LiquidCyan),
                        shape = RoundedCornerShape(14.dp)
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Icon(imageVector = Icons.Default.Refresh, contentDescription = null, modifier = Modifier.size(18.dp), tint = LiquidCyan)
                            Text(text = stringResource(R.string.label_restart_server), color = LiquidCyan, style = MaterialTheme.typography.labelLarge)
                        }
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(28.dp))
        AnimatedVisibility(
            visible = visible,
            enter = fadeIn(animationSpec = tween(durationMillis = 600, delayMillis = 500)) + 
                    slideInVertically(animationSpec = tween(durationMillis = 600, delayMillis = 500)) { it / 3 }
        ) {
            DeviceAttestationCard(context = LocalContext.current)
        }
    }
}

@Composable
fun DeviceAttestationCard(context: Context) {
    val evaluator = remember { DeviceIntegrityRegistry(context = context) }
    val report by produceState(
        initialValue = IntegrityReport(
            score = 100,
            tier = TrustTier.TRUSTED,
            isBootloaderLocked = true,
            isNotRooted = true,
            isDevOptionsDisabled = true,
            isUsbDebuggingDisabled = true,
            isAppIntegrityValid = true,
            isSecureLockscreenEnabled = true,
        ),
    ) {
        withContext(Dispatchers.IO) { value = evaluator.runAttestationPipeline() }
    }

    ProfessionalGlassSurface(tint = if (report.score >= 85) IntegrityGreen else AlertRed, blur = 20f) {
        Row(
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.fillMaxWidth()
        ) {
            Column {
                Text(
                    text = stringResource(R.string.header_integrity_core),
                    style = MaterialTheme.typography.labelLarge,
                    color = LiquidCyan,
                    letterSpacing = 2.sp
                )
                Text(
                    text = stringResource(report.tier.labelRes),
                    color = report.tier.color,
                    style = MaterialTheme.typography.labelMedium
                )
            }
            Text(
                text = report.score.toString(),
                style = MaterialTheme.typography.headlineLarge,
                color = report.tier.color
            )
        }
        Spacer(modifier = Modifier.height(24.dp))
        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            MetricRow(label = stringResource(R.string.label_bootloader), pass = report.isBootloaderLocked)
            MetricRow(label = stringResource(R.string.label_root), pass = report.isNotRooted)
            MetricRow(label = stringResource(R.string.label_dev_module), pass = report.isDevOptionsDisabled)
            MetricRow(label = stringResource(R.string.label_adb), pass = report.isUsbDebuggingDisabled)
        }
    }
}

@Composable
fun MetricRow(label: String, pass: Boolean) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(
            text = label,
            color = TextSecondary,
            style = MaterialTheme.typography.bodyMedium
        )
        Text(
            text = if (pass) stringResource(R.string.label_secure) else stringResource(R.string.label_fail),
            color = if (pass) IntegrityGreen else AlertRed,
            fontWeight = FontWeight.Bold,
            style = MaterialTheme.typography.bodyMedium
        )
    }
}

@Composable
fun PairingScreen(
    trustState: TrustState = TrustState.UNPAIRED,
    phoneFingerprint: String = "",
    windowsFingerprint: String = "",
    onInitiatePairing: () -> Unit = {},
    onCancelPairing: () -> Unit = {},
    onForgetTrust: () -> Unit = {},
    onShowQR: () -> Unit
) {
    var visible by remember { mutableStateOf(value = false) }
    LaunchedEffect(Unit) { visible = true }

    val scrollState = rememberScrollState()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(scrollState)
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        AnimatedVisibility(
            visible = visible,
            enter = fadeIn(animationSpec = tween(durationMillis = 800)) + 
                    scaleIn(initialScale = 0.85f)
        ) {
            Text(
                text = stringResource(R.string.header_device_pairing),
                style = MaterialTheme.typography.headlineSmall,
                color = LiquidCyan,
                fontWeight = FontWeight.Bold,
                letterSpacing = 4.sp
            )
        }
        Spacer(modifier = Modifier.height(20.dp))

        AnimatedVisibility(
            visible = visible,
            enter = fadeIn(animationSpec = tween(durationMillis = 800, delayMillis = 200))
        ) {
            ProfessionalGlassSurface(modifier = Modifier.fillMaxWidth()) {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text(
                        text = "PAIRING STATUS",
                        style = MaterialTheme.typography.labelSmall,
                        color = LiquidCyan
                    )
                    val (statusMsg, statusColor) = when (trustState) {
                        TrustState.UNPAIRED, TrustState.REPAIRING -> stringResource(R.string.desc_unpaired_status) to TextSecondary
                        TrustState.PAIRING_REQUESTED -> stringResource(R.string.desc_pairing_requested_status) to MatrixGold
                        TrustState.PAIRED -> stringResource(R.string.desc_paired_status) to IntegrityGreen
                        TrustState.PAIRING_DENIED -> stringResource(R.string.desc_pairing_denied_status) to AlertRed
                        TrustState.KEY_MISMATCH -> stringResource(R.string.desc_key_mismatch_status) to AlertRed
                    }
                    Text(
                        text = statusMsg,
                        style = MaterialTheme.typography.bodyMedium,
                        color = statusColor,
                        fontWeight = FontWeight.Bold
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(24.dp))

        AnimatedVisibility(
            visible = visible,
            enter = fadeIn(animationSpec = tween(durationMillis = 800, delayMillis = 300))
        ) {
            ProfessionalGlassSurface(modifier = Modifier.fillMaxWidth()) {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text(
                        text = "CRYPTOGRAPHIC IDENTITY",
                        style = MaterialTheme.typography.labelSmall,
                        color = LiquidCyan
                    )
                    Text(
                        text = stringResource(R.string.label_phone_fingerprint),
                        style = MaterialTheme.typography.labelSmall,
                        color = TextSecondary
                    )
                    Text(
                        text = phoneFingerprint.ifBlank { "COMPUTING..." },
                        style = MaterialTheme.typography.bodySmall,
                        color = TextPrimary,
                        fontSize = 11.sp
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = stringResource(R.string.label_windows_fingerprint),
                        style = MaterialTheme.typography.labelSmall,
                        color = TextSecondary
                    )
                    val (fpText, fpColor) = when {
                        trustState == TrustState.PAIRED && windowsFingerprint.isNotBlank() && windowsFingerprint != "NONE" ->
                            windowsFingerprint to IntegrityGreen
                        trustState == TrustState.PAIRED ->
                            "PAIRED & PINNED" to IntegrityGreen
                        else ->
                            "NOT PINNED" to AlertRed
                    }
                    Text(
                        text = fpText,
                        style = MaterialTheme.typography.bodySmall,
                        color = fpColor,
                        fontSize = 11.sp
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(32.dp))

        AnimatedVisibility(
            visible = visible,
            enter = fadeIn(animationSpec = tween(durationMillis = 800, delayMillis = 400)) + 
                    slideInVertically(animationSpec = tween(durationMillis = 800, delayMillis = 400)) { it / 2 }
        ) {
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                when (trustState) {
                    TrustState.UNPAIRED, TrustState.REPAIRING, TrustState.PAIRING_DENIED -> {
                        TacticalAction(
                            label = stringResource(R.string.label_initiate_pairing),
                            accentColor = LiquidCyan,
                            onClick = onInitiatePairing
                        )
                    }
                    TrustState.PAIRING_REQUESTED -> {
                        TacticalAction(
                            label = stringResource(R.string.label_cancel_pairing),
                            accentColor = AlertRed,
                            onClick = onCancelPairing
                        )
                    }
                    TrustState.PAIRED -> {
                        TacticalAction(
                            label = stringResource(R.string.label_forget_trust),
                            accentColor = AlertRed,
                            onClick = onForgetTrust
                        )
                    }
                    TrustState.KEY_MISMATCH -> {
                        TacticalAction(
                            label = stringResource(R.string.label_forget_trust),
                            accentColor = AlertRed,
                            onClick = onForgetTrust
                        )
                    }
                }

                TacticalAction(
                    label = stringResource(R.string.btn_show_pairing_qr),
                    accentColor = TextSecondary,
                    onClick = onShowQR
                )
            }
        }
    }
}

@Composable
fun LaptopControlScreen(
    isConnected: Boolean,
    volumeLevel: Int = 50,
    isMuted: Boolean = false,
    onLanActionRequested: (String) -> Unit
) {
    val scrollState = rememberScrollState()
    var visible by remember { mutableStateOf(value = false) }
    LaunchedEffect(Unit) { visible = true }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(scrollState)
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(24.dp)
    ) {
        AnimatedVisibility(
            visible = visible,
            enter = fadeIn(animationSpec = tween(600)) + slideInVertically(animationSpec = tween(600)) { -it / 4 }
        ) {
            Text(
                text = "WINDOWS REMOTE CONTROL",
                style = MaterialTheme.typography.labelLarge,
                color = LiquidCyan,
                letterSpacing = 4.sp
            )
        }

        AnimatedVisibility(
            visible = visible,
            enter = fadeIn(animationSpec = tween(600, delayMillis = 100)) + slideInVertically(animationSpec = tween(600, delayMillis = 100)) { it / 3 }
        ) {
            LiquidGlassVolumeControl(
                volumeLevel = volumeLevel,
                isMuted = isMuted,
                onVolumeChange = { level -> onLanActionRequested("volume_set:$level") },
                onVolumeUp = { onLanActionRequested("VOL_UP") },
                onVolumeDown = { onLanActionRequested("VOL_DOWN") },
                onToggleMute = { onLanActionRequested("volume_mute") },
                enabled = isConnected
            )
        }
    }
}

@Composable
fun SystemAppsScreen(
    isConnected: Boolean,
    onLanActionRequested: (String) -> Unit
) {
    val scrollState = rememberScrollState()
    var visible by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) { visible = true }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(scrollState)
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(24.dp)
    ) {
        AnimatedVisibility(
            visible = visible,
            enter = fadeIn(animationSpec = tween(600)) + slideInVertically(animationSpec = tween(600)) { -it / 4 }
        ) {
            Text(
                text = stringResource(R.string.nav_apps),
                style = MaterialTheme.typography.labelLarge,
                color = LiquidCyan,
                letterSpacing = 4.sp
            )
        }

        AnimatedVisibility(
            visible = visible,
            enter = fadeIn(animationSpec = tween(600, delayMillis = 100)) + slideInVertically(animationSpec = tween(600, delayMillis = 100)) { it / 3 }
        ) {
            LiquidGlassAppLauncher(
                onLaunchApp = onLanActionRequested,
                enabled = isConnected
            )
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TetherNavigationShell(
    laptopTelemetry: LaptopTelemetry = LaptopTelemetry(),
    onLaptopCardClick: () -> Unit = {},
    statusText: String,
    statusColor: Color,
    connectionStatus: String,
    isConnected: Boolean,
    isPanicActive: Boolean,
    verificationStep: TrustVerificationStep,
    trustState: TrustState = TrustState.UNPAIRED,
    phoneFingerprint: String = "",
    windowsFingerprint: String = "",
    volumeLevel: Int = 50,
    isMuted: Boolean = false,
    grantedCapabilities: Set<String> = emptySet(),
    onUnlockClick: () -> Unit,
    onLockClick: () -> Unit,
    onPanicClick: () -> Unit,
    onSideRestore: () -> Unit,
    onSelectLaptop: () -> Unit,
    onTriggerStepVerification: (TrustVerificationStep) -> Unit,
    onLaptopActionClick: (String) -> Unit,
    onShowQR: () -> Unit,
    onRestartServer: () -> Unit,
    onInitiatePairing: () -> Unit = {},
    onCancelPairing: () -> Unit = {},
    onForgetTrust: () -> Unit = {}
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
                                    renderEffect = RenderEffect
                                        .createBlurEffect(40f, 40f, Shader.TileMode.CLAMP)
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
                            Triple(stringResource(R.string.nav_hardware), Icons.Default.Menu, AppScreen.LAPTOP_CONTROL),
                            Triple(stringResource(R.string.nav_apps), Icons.Default.Refresh, AppScreen.SYSTEM_APPS),
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
                            .togetherWith(
                                fadeOut(animationSpec = spring(stiffness = Spring.StiffnessLow)) + 
                                scaleOut(targetScale = 1.04f, animationSpec = spring(stiffness = Spring.StiffnessLow)),
                            )
                    },
                    label = "ScreenTransition"
                ) { screen ->
                    when (screen) {
                        AppScreen.TELEMETRY_DASHBOARD -> TetherAppScreen(
                            laptopTelemetry = laptopTelemetry,
                            windowsFingerprint = windowsFingerprint,
                            onLaptopCardClick = onLaptopCardClick,
                            statusText = statusText,
                            statusColor = statusColor,
                            connectionStatus = connectionStatus,
                            isConnected = isConnected,
                            isPanicActive = isPanicActive,
                            verificationStep = verificationStep,
                            volumeLevel = volumeLevel,
                            isMuted = isMuted,
                            grantedCapabilities = grantedCapabilities,
                            onUnlockClick = onUnlockClick,
                            onLockClick = onLockClick,
                            onPanicClick = onPanicClick,
                            onSideRestore = onSideRestore,
                            onSelectLaptop = onSelectLaptop,
                            onTriggerStepVerification = onTriggerStepVerification,
                            onLanActionRequested = onLaptopActionClick
                        )
                        AppScreen.SECURITY_SETTINGS -> SettingsScreen(
                            trustState = trustState,
                            phoneFingerprint = phoneFingerprint,
                            windowsFingerprint = windowsFingerprint,
                            onRestartServer = onRestartServer,
                            onForgetTrust = onForgetTrust
                        )
                        AppScreen.LAPTOP_CONTROL -> LaptopControlScreen(
                            isConnected = isConnected,
                            volumeLevel = volumeLevel,
                            isMuted = isMuted,
                            onLanActionRequested = onLaptopActionClick
                        )
                        AppScreen.SYSTEM_APPS -> SystemAppsScreen(
                            isConnected = isConnected,
                            onLanActionRequested = onLaptopActionClick
                        )
                        AppScreen.PAIRING -> PairingScreen(
                            trustState = trustState,
                            phoneFingerprint = phoneFingerprint,
                            windowsFingerprint = windowsFingerprint,
                            onInitiatePairing = onInitiatePairing,
                            onCancelPairing = onCancelPairing,
                            onForgetTrust = onForgetTrust,
                            onShowQR = onShowQR
                        )
                    }
                }
            }
        }
    }
}

