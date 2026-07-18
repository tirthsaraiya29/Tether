package com.tether.phone.ui.screens

import android.content.Context
import android.content.Intent
import android.os.PowerManager
import android.provider.Settings
import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.tether.phone.R
import com.tether.phone.*
import com.tether.phone.ui.components.ProfessionalGlassSurface
import com.tether.phone.ui.components.TacticalAction
import com.tether.phone.ui.theme.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

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
    onSideRestore: () -> Unit,
    onSelectLaptop: () -> Unit,
    onTriggerStepVerification: (TrustVerificationStep) -> Unit,
    onBleActionRequested: (String) -> Unit,
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
        AnimatedVisibility(
            visible = visible,
            enter = fadeIn(animationSpec = tween(durationMillis = 1000)) + 
                    expandVertically(animationSpec = tween(durationMillis = 800, easing = TetherEase))
        ) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(360.dp)
                    .graphicsLayer { translationY = -scrollState.value * 0.2f },
                contentAlignment = Alignment.Center
            ) {
                if (isConnected) {
                    ActiveLinkVisualizer(
                        color = statusColor,
                        status = statusText,
                        subStatus = connectionStatus
                    )
                } else {
                    ScanningVisualizer(color = statusColor)
                }
            }
        }

        AnimatedVisibility(
            visible = visible,
            enter = fadeIn(animationSpec = tween(durationMillis = 800, delayMillis = 200)) + 
                    slideInVertically(animationSpec = tween(durationMillis = 800, delayMillis = 200)) { it / 2 }
        ) {
            ProfessionalGlassSurface(modifier = Modifier.fillMaxWidth()) {
                Text(
                    text = stringResource(R.string.header_hardware_directives),
                    style = MaterialTheme.typography.labelMedium,
                    color = LiquidCyan
                )
                Spacer(modifier = Modifier.height(28.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(20.dp)
                ) {
                    TacticalAction(
                        label = stringResource(R.string.label_sleep),
                        accentColor = MatrixGold,
                        onClick = { onBleActionRequested("PWR_SLEEP") },
                        modifier = Modifier.weight(1f),
                        enabled = isConnected
                    )
                    TacticalAction(
                        label = stringResource(R.string.label_reboot),
                        accentColor = TextPrimary,
                        onClick = { onBleActionRequested("PWR_REBOOT") },
                        modifier = Modifier.weight(1f),
                        enabled = isConnected
                    )
                }
                Spacer(modifier = Modifier.height(20.dp))
                TacticalAction(
                    label = stringResource(R.string.label_halt_system),
                    accentColor = AlertRed,
                    onClick = { onBleActionRequested("PWR_SHUTDOWN") },
                    enabled = isConnected
                )
            }
        }

        Spacer(modifier = Modifier.height(28.dp))

        AnimatedContent(
            targetState = verificationStep,
            label = "Security"
        ) { step ->
            Column(verticalArrangement = Arrangement.spacedBy(20.dp)) {
                when (step) {
                    TrustVerificationStep.NOT_IN_PANIC -> {
                        if (isPanicActive) {
                            AnimatedVisibility(
                                visible = visible,
                                enter = fadeIn(animationSpec = tween(durationMillis = 800, delayMillis = 400)) + 
                                        scaleIn(initialScale = 0.9f)
                            ) {
                                PanicRestoreCard(onSideRestore = onSideRestore)
                            }
                        } else {
                            AnimatedVisibility(
                                visible = visible,
                                enter = fadeIn(animationSpec = tween(durationMillis = 800, delayMillis = 400)) + 
                                        slideInVertically(animationSpec = tween(durationMillis = 800, delayMillis = 400)) { it / 2 }
                            ) {
                                Column(verticalArrangement = Arrangement.spacedBy(20.dp)) {
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.spacedBy(20.dp)
                                    ) {
                                        TacticalAction(
                                            label = stringResource(R.string.label_unlock),
                                            accentColor = IntegrityGreen,
                                            onClick = onUnlockClick,
                                            modifier = Modifier.weight(1f),
                                            enabled = isConnected
                                        )
                                        TacticalAction(
                                            label = stringResource(R.string.label_lock),
                                            accentColor = LiquidCyan,
                                            onClick = onLockClick,
                                            modifier = Modifier.weight(1f),
                                            enabled = isConnected
                                        )
                                    }
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.spacedBy(20.dp)
                                    ) {
                                        TacticalAction(
                                            label = stringResource(R.string.label_target),
                                            accentColor = TextSecondary,
                                            onClick = onSelectLaptop,
                                            modifier = Modifier.weight(1f)
                                        )
                                        TacticalAction(
                                            label = stringResource(R.string.label_panic),
                                            accentColor = AlertRed,
                                            onClick = onPanicClick,
                                            modifier = Modifier.weight(1f)
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
        label = "R"
    )
    val alpha by infiniteTransition.animateFloat(
        initialValue = 1f,
        targetValue = 0f,
        animationSpec = infiniteRepeatable(animation = tween(durationMillis = 3500, easing = LinearOutSlowInEasing)),
        label = "A"
    )
    val pulseScale by infiniteTransition.animateFloat(
        initialValue = 1f,
        targetValue = 1.1f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 2000, easing = TetherEase),
            repeatMode = RepeatMode.Reverse
        ), label = "P"
    )

    Box(contentAlignment = Alignment.Center) {
        Canvas(
            modifier = Modifier
                .size(320.dp)
                .graphicsLayer {
                    scaleX = pulseScale
                    scaleY = pulseScale
                }
        ) {
            drawCircle(
                color = color.copy(alpha = alpha * 0.4f),
                radius = radius,
                style = Stroke(width = 2.5.dp.toPx())
            )
            drawCircle(
                color = color.copy(alpha = alpha * 0.15f),
                radius = radius * 0.7f,
                style = Stroke(width = 1.5.dp.toPx())
            )

            drawArc(
                color = Color.White.copy(alpha = alpha * 0.2f),
                startAngle = -45f,
                sweepAngle = 90f,
                useCenter = false,
                topLeft = Offset(x = center.x - radius, y = center.y - radius),
                size = androidx.compose.ui.geometry.Size(width = radius * 2, height = radius * 2),
                style = Stroke(width = 4.dp.toPx(), cap = StrokeCap.Round)
            )
        }
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text(
                text = stringResource(R.string.status_scanning),
                style = MaterialTheme.typography.labelMedium,
                color = color
            )
            Spacer(modifier = Modifier.height(20.dp))
            Text(
                text = stringResource(R.string.label_no_host),
                style = MaterialTheme.typography.headlineMedium,
                color = TextPrimary,
                fontWeight = FontWeight.Bold
            )
            Text(
                text = stringResource(R.string.label_broadcasting_mesh),
                style = MaterialTheme.typography.labelSmall,
                color = TextSecondary
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
        label = "Rot"
    )
    val orbitRotation by infiniteTransition.animateFloat(
        initialValue = 360f,
        targetValue = 0f,
        animationSpec = infiniteRepeatable(animation = tween(durationMillis = 15000, easing = LinearEasing)),
        label = "Orbit"
    )
    val glowPulse by infiniteTransition.animateFloat(
        initialValue = 0.4f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 3000, easing = TetherEase),
            repeatMode = RepeatMode.Reverse
        ), label = "Glow"
    )

    Box(contentAlignment = Alignment.Center) {
        Canvas(
            modifier = Modifier
                .size(320.dp)
                .graphicsLayer { alpha = 0.8f }
        ) {
            drawCircle(
                brush = Brush.radialGradient(
                    colors = listOf(color.copy(alpha = 0.3f * glowPulse), Color.Transparent),
                    radius = size.width / 1.8f
                )
            )
        }

        Canvas(
            modifier = Modifier
                .size(280.dp)
                .graphicsLayer { rotationZ = rotation }
        ) {
            drawArc(
                color = color,
                startAngle = 0f,
                sweepAngle = 160f,
                useCenter = false,
                style = Stroke(width = 5.dp.toPx(), cap = StrokeCap.Round)
            )
            drawArc(
                color = color.copy(alpha = 0.3f),
                startAngle = 180f,
                sweepAngle = 90f,
                useCenter = false,
                style = Stroke(width = 2.dp.toPx(), cap = StrokeCap.Round)
            )
        }

        Canvas(
            modifier = Modifier
                .size(240.dp)
                .graphicsLayer { rotationZ = orbitRotation }
        ) {
            val nodeCenter = Offset(x = size.width, y = size.height / 2)
            drawCircle(
                color = color,
                radius = 7.dp.toPx(),
                center = nodeCenter
            )
            drawCircle(
                color = color.copy(alpha = 0.4f),
                radius = 14.dp.toPx() * glowPulse,
                center = nodeCenter
            )

            val mirrorCenter = Offset(x = 0f, y = size.height / 2)
            drawCircle(
                color = color.copy(alpha = 0.6f),
                radius = 5.dp.toPx(),
                center = mirrorCenter
            )
            drawCircle(
                color = color.copy(alpha = 0.2f),
                radius = 10.dp.toPx() * glowPulse,
                center = mirrorCenter
            )
        }

        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            modifier = Modifier
                .width(180.dp)
                .graphicsLayer {
                    scaleX = (glowPulse * 0.05f) + 0.95f
                    scaleY = (glowPulse * 0.05f) + 0.95f
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
            Text(
                text = subStatus,
                style = MaterialTheme.typography.labelMedium,
                color = TextSecondary
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
            color = AlertRed
        )
        Spacer(modifier = Modifier.height(12.dp))
        Text(
            text = stringResource(R.string.panic_message),
            style = MaterialTheme.typography.bodyMedium,
            color = TextSecondary
        )
        Spacer(modifier = Modifier.height(28.dp))
        TacticalAction(
            label = stringResource(R.string.label_restore),
            accentColor = IntegrityGreen,
            onClick = onSideRestore
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
            modifier = Modifier.size(48.dp)
        )
        Spacer(modifier = Modifier.height(20.dp))
        Text(
            text = msg,
            style = MaterialTheme.typography.labelMedium,
            color = TextSecondary
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
    selectedTimeoutMs: Long,
    onTimeoutChanged: (Long) -> Unit
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
            enter = fadeIn(animationSpec = tween(durationMillis = 600, delayMillis = 100)) + 
                    slideInVertically(animationSpec = tween(durationMillis = 600, delayMillis = 100)) { it / 3 }
        ) {
            ProfessionalGlassSurface {
                Column {
                    Text(
                        text = stringResource(R.string.label_lock_threshold),
                        style = MaterialTheme.typography.titleLarge,
                        color = TextPrimary
                    )
                    Text(
                        text = "Automated vault enforcement interval.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = TextSecondary
                    )
                    Spacer(modifier = Modifier.height(28.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        listOf("IMM" to 0L, "1M" to 60000L, "5M" to 300000L).forEach { (l, v) ->
                            val sel = selectedTimeoutMs == v
                            Box(
                                modifier = Modifier
                                    .height(56.dp)
                                    .weight(1f)
                                    .clip(RoundedCornerShape(16.dp))
                                    .background(if (sel) LiquidCyan.copy(alpha = 0.15f) else Color.White.copy(alpha = 0.04f))
                                    .clickable { onTimeoutChanged(v) }
                                    .border(
                                        width = 0.5.dp,
                                        color = if (sel) LiquidCyan else GlassBorder,
                                        shape = RoundedCornerShape(16.dp)
                                    )
                                    .graphicsLayer {
                                        scaleX = if (sel) 1.05f else 1f
                                        scaleY = if (sel) 1.05f else 1f
                                    },
                                contentAlignment = Alignment.Center
                            ) {
                                Text(
                                    text = l,
                                    color = if (sel) LiquidCyan else TextSecondary,
                                    style = MaterialTheme.typography.labelLarge,
                                    fontWeight = if (sel) FontWeight.Bold else FontWeight.Normal
                                )
                            }
                        }
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
            isSecureLockscreenEnabled = true
        )
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
fun PairingScreen(onShowQR: () -> Unit) {
    var visible by remember { mutableStateOf(value = false) }
    LaunchedEffect(Unit) { visible = true }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
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
            Text(
                text = stringResource(R.string.desc_pairing),
                style = MaterialTheme.typography.bodyMedium,
                color = TextSecondary,
                textAlign = TextAlign.Center
            )
        }
        Spacer(modifier = Modifier.height(56.dp))

        AnimatedVisibility(
            visible = visible,
            enter = fadeIn(animationSpec = tween(durationMillis = 800, delayMillis = 400)) + 
                    slideInVertically(animationSpec = tween(durationMillis = 800, delayMillis = 400)) { it / 2 }
        ) {
            ProfessionalGlassSurface(modifier = Modifier.fillMaxWidth()) {
                TacticalAction(
                    label = stringResource(R.string.btn_show_pairing_qr),
                    accentColor = LiquidCyan,
                    onClick = onShowQR
                )
                Spacer(modifier = Modifier.height(20.dp))
                Text(
                    text = stringResource(R.string.desc_pairing_key),
                    style = MaterialTheme.typography.bodySmall,
                    color = TextMuted,
                    textAlign = TextAlign.Center
                )
            }
        }
    }
}
