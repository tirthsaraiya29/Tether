package com.tether.phone.ui.components

import android.graphics.RenderEffect
import android.graphics.Shader
import android.os.Build
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.LinearOutSlowInEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.scaleIn
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Slider
import androidx.compose.material3.SliderDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
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
import androidx.compose.ui.graphics.asComposeRenderEffect
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.tether.phone.R
import com.tether.phone.ui.theme.AlertRed
import com.tether.phone.ui.theme.DeepSpace
import com.tether.phone.ui.theme.GlassBorder
import com.tether.phone.ui.theme.IntegrityGreen
import com.tether.phone.ui.theme.LiquidCyan
import com.tether.phone.ui.theme.MatrixGold
import com.tether.phone.ui.theme.SurfaceElevated
import com.tether.phone.ui.theme.TetherEase
import com.tether.phone.ui.theme.TextMuted
import com.tether.phone.ui.theme.TextPrimary
import com.tether.phone.ui.theme.TextSecondary

@Composable
fun ProfessionalGlassSurface(
    modifier: Modifier = Modifier,
    alpha: Float = 0.12f,
    tint: Color = Color.White,
    blur: Float = 32f,
    content: @Composable ColumnScope.() -> Unit,
) {
    val infiniteTransition = rememberInfiniteTransition(label = "GlassRefraction")
    val tiltX by infiniteTransition.animateFloat(
        initialValue = -1.2f,
        targetValue = 1.2f,
        animationSpec = infiniteRepeatable(
            animation = tween(8000, easing = TetherEase),
            repeatMode = RepeatMode.Reverse,
        ),
        label = "TiltX",
    )
    val tiltY by infiniteTransition.animateFloat(
        initialValue = -1.2f,
        targetValue = 1.2f,
        animationSpec = infiniteRepeatable(
            animation = tween(6500, easing = TetherEase),
            repeatMode = RepeatMode.Reverse,
        ),
        label = "TiltY",
    )

    Box(
        modifier = modifier
            .graphicsLayer {
                rotationX = tiltX * 1.5f
                rotationY = tiltY * 1.5f
                cameraDistance = 12f * density
            }
            .clip(RoundedCornerShape(28.dp))
            .drawBehind {
                drawCircle(
                    brush = Brush.radialGradient(
                        0.0f to Color.Black.copy(alpha = 0.4f),
                        1.0f to Color.Transparent,
                        center = Offset(
                            (size.width / 2) + (tiltX * 5.dp.toPx()),
                            (size.height / 2) + (tiltY * 5.dp.toPx()),
                        ),
                        radius = size.width.coerceAtLeast(size.height),
                    ),
                    radius = size.width.coerceAtLeast(size.height),
                    center = Offset(
                        (size.width / 2) + (tiltX * 5.dp.toPx()),
                        (size.height / 2) + (tiltY * 5.dp.toPx()),
                    ),
                )
            }
            .border(
                width = 0.5.dp,
                brush = Brush.linearGradient(
                    listOf(
                        Color.White.copy(alpha = 0.35f),
                        Color.White.copy(alpha = 0.05f),
                        Color.White.copy(alpha = 0.25f),
                    ),
                    start = Offset(0f, 0f),
                    end = Offset(1000f, 1000f),
                ),
                shape = RoundedCornerShape(28.dp),
            ),
    ) {
        Box(
            modifier = Modifier
                .matchParentSize()
                .background(
                    Brush.verticalGradient(
                        listOf(
                            tint.copy(alpha = alpha * 1.4f),
                            tint.copy(alpha = alpha * 0.5f),
                        ),
                    ),
                )
                .graphicsLayer {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                        renderEffect = RenderEffect
                            .createBlurEffect(blur, blur, Shader.TileMode.CLAMP)
                            .asComposeRenderEffect()
                    }
                }
                .drawBehind {
                    val strokeWidth = 1.2.dp.toPx()
                    val highlightPath = Path().apply {
                        moveTo(0f, size.height * 0.3f)
                        lineTo(0f, 28.dp.toPx())
                        arcTo(
                            rect = Rect(0f, 0f, 56.dp.toPx(), 56.dp.toPx()),
                            startAngleDegrees = 180f,
                            sweepAngleDegrees = 90f,
                            forceMoveTo = false,
                        )
                        lineTo(size.width * 0.3f, 0f)
                    }
                    drawPath(
                        path = highlightPath,
                        brush = Brush.linearGradient(
                            colors = listOf(Color.White.copy(alpha = 0.5f), Color.Transparent),
                            start = Offset(tiltX * 30f, tiltY * 30f),
                            end = Offset(size.width * 0.4f, size.height * 0.4f),
                        ),
                        style = Stroke(width = strokeWidth, cap = StrokeCap.Round),
                    )

                    drawArc(
                        color = Color.White.copy(alpha = 0.08f),
                        startAngle = 0f,
                        sweepAngle = 360f,
                        useCenter = false,
                        topLeft = Offset(8.dp.toPx(), 8.dp.toPx()),
                        size = size.copy(width = size.width - 16.dp.toPx(), height = size.height - 16.dp.toPx()),
                        style = Stroke(width = 0.5.dp.toPx()),
                    )

                    val noiseStep = 3f
                    for (x in 0 until size.width.toInt() step (noiseStep.toInt() * 4)) {
                        for (y in 0 until size.height.toInt() step (noiseStep.toInt() * 4)) {
                            if (((x + y) % 17) == 0) {
                                drawCircle(
                                    color = Color.White.copy(alpha = 0.015f),
                                    radius = 0.4f,
                                    center = Offset(x.toFloat(), y.toFloat()),
                                )
                            }
                        }
                    }
                },
        )
        Column(
            modifier = Modifier.padding(24.dp),
            content = content,
        )
    }
}

@Composable
fun LiquidGlassVolumeControl(
    volumeLevel: Int,
    isMuted: Boolean,
    onVolumeChange: (Int) -> Unit = {},
    onVolumeUp: () -> Unit,
    onVolumeDown: () -> Unit,
    onToggleMute: () -> Unit,
    enabled: Boolean = true,
) {
    var isDragging by remember { mutableStateOf(false) }
    var localVolume by remember(volumeLevel) { mutableIntStateOf(volumeLevel) }

    LaunchedEffect(volumeLevel) {
        if (!isDragging) {
            localVolume = volumeLevel
        }
    }

    ProfessionalGlassSurface(
        tint = LiquidCyan,
        alpha = 0.15f,
        blur = 40f,
    ) {
        Column {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column {
                    Text(
                        text = stringResource(R.string.label_volume),
                        style = MaterialTheme.typography.labelSmall,
                        color = LiquidCyan,
                        letterSpacing = 2.sp,
                    )
                    Text(
                        text = if (isMuted) "MUTED" else "$localVolume%",
                        style = MaterialTheme.typography.headlineMedium,
                        color = if (isMuted) AlertRed else TextPrimary,
                        fontWeight = FontWeight.Bold,
                    )
                }

                Box(
                    modifier = Modifier
                        .size(48.dp)
                        .clip(RoundedCornerShape(16.dp))
                        .background(if (isMuted) AlertRed.copy(alpha = 0.2f) else LiquidCyan.copy(alpha = 0.15f))
                        .border(
                            width = 0.5.dp,
                            color = if (isMuted) AlertRed else LiquidCyan,
                            shape = RoundedCornerShape(16.dp),
                        )
                        .clickable(enabled = enabled, onClick = onToggleMute),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        text = if (isMuted) "🔇" else "🔊",
                        fontSize = 20.sp,
                    )
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            Slider(
                value = localVolume.toFloat(),
                onValueChange = { newValue ->
                    isDragging = true
                    localVolume = newValue.toInt()
                },
                onValueChangeFinished = {
                    isDragging = false
                    onVolumeChange(localVolume)
                },
                valueRange = 0f..100f,
                enabled = enabled,
                colors = SliderDefaults.colors(
                    thumbColor = LiquidCyan,
                    activeTrackColor = LiquidCyan,
                    inactiveTrackColor = LiquidCyan.copy(alpha = 0.2f)
                ),
                modifier = Modifier.fillMaxWidth()
            )

            Spacer(modifier = Modifier.height(12.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                TacticalAction(
                    label = "VOL -",
                    accentColor = TextSecondary,
                    onClick = {
                        val newVol = (localVolume - 5).coerceIn(0, 100)
                        localVolume = newVol
                        onVolumeDown()
                    },
                    enabled = enabled,
                    modifier = Modifier.weight(1f),
                )
                TacticalAction(
                    label = "VOL +",
                    accentColor = LiquidCyan,
                    onClick = {
                        val newVol = (localVolume + 5).coerceIn(0, 100)
                        localVolume = newVol
                        onVolumeUp()
                    },
                    enabled = enabled,
                    modifier = Modifier.weight(1f),
                )
            }
        }
    }
}

@Composable
fun LiquidGlassAppLauncher(
    onLaunchApp: (String) -> Unit,
    enabled: Boolean = true,
) {
    val apps = listOf(
        Triple("Browser", "🌐", "launch_browser"),
        Triple("Terminal", "💻", "powershell"),
        Triple("Task Manager", "📊", "launch_task_manager"),
        Triple("Explorer", "📁", "launch_explorer"),
        Triple("Settings", "⚙️", "launch_settings"),
        Triple("Lock PC", "🔒", "lock_now"),
    )

    ProfessionalGlassSurface(
        tint = TextPrimary,
        alpha = 0.12f,
        blur = 36f,
    ) {
        Column {
            Text(
                text = "SYSTEM APPLICATIONS",
                style = MaterialTheme.typography.labelSmall,
                color = LiquidCyan,
                letterSpacing = 2.sp,
            )
            Spacer(modifier = Modifier.height(16.dp))

            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                apps.chunked(2).forEach { rowApps ->
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        rowApps.forEach { (name, icon, cmd) ->
                            Box(
                                modifier = Modifier
                                    .weight(1f)
                                    .height(56.dp)
                                    .clip(RoundedCornerShape(16.dp))
                                    .background(Color.White.copy(alpha = 0.05f))
                                    .border(
                                        width = 0.5.dp,
                                        brush = Brush.linearGradient(
                                            listOf(Color.White.copy(alpha = 0.25f), Color.White.copy(alpha = 0.05f)),
                                        ),
                                        shape = RoundedCornerShape(16.dp),
                                    )
                                    .clickable(enabled = enabled) { onLaunchApp(cmd) },
                                contentAlignment = Alignment.Center,
                            ) {
                                Row(
                                    modifier = Modifier.padding(horizontal = 8.dp),
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                                ) {
                                    Text(text = icon, fontSize = 16.sp)
                                    Text(
                                        text = name,
                                        style = MaterialTheme.typography.labelMedium,
                                        color = TextPrimary,
                                        fontWeight = FontWeight.SemiBold,
                                        fontSize = 12.sp,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis,
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun TacticalAction(
    label: String,
    accentColor: Color,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    subLabel: String? = null,
) {
    val interactionSource = remember { MutableInteractionSource() }
    val isPressed by interactionSource.collectIsPressedAsState()
    val haptic = LocalHapticFeedback.current

    LaunchedEffect(isPressed) {
        if (isPressed) haptic.performHapticFeedback(HapticFeedbackType.LongPress)
    }

    val scale by animateFloatAsState(
        targetValue = if (isPressed) 0.94f else 1f,
        animationSpec = spring(dampingRatio = 0.5f, stiffness = 500f),
        label = "Scale",
    )
    val glow by animateFloatAsState(
        targetValue = if (isPressed) 0.45f else 0.16f,
        animationSpec = tween(300, easing = LinearOutSlowInEasing),
        label = "Glow",
    )
    val tilt by animateFloatAsState(
        targetValue = if (isPressed) 4f else 0f,
        animationSpec = spring(dampingRatio = 0.6f, stiffness = 300f),
        label = "Tilt",
    )

    Box(
        modifier = modifier
            .graphicsLayer {
                scaleX = scale
                scaleY = scale
                rotationX = tilt
                cameraDistance = 12f * density
                alpha = if (enabled) 1f else 0.45f
            }
            .fillMaxWidth()
            .height(72.dp)
            .clip(RoundedCornerShape(22.dp))
            .background(
                Brush.verticalGradient(
                    listOf(
                        accentColor.copy(alpha = glow),
                        accentColor.copy(alpha = glow * 0.6f),
                        accentColor.copy(alpha = glow * 0.2f),
                    ),
                ),
            )
            .border(
                width = 0.5.dp,
                brush = Brush.linearGradient(
                    listOf(
                        accentColor.copy(alpha = if (isPressed) 0.9f else 0.5f),
                        accentColor.copy(alpha = 0.05f),
                    ),
                ),
                shape = RoundedCornerShape(22.dp),
            )
            .drawBehind {
                if (isPressed) {
                    drawCircle(
                        brush = Brush.radialGradient(
                            colors = listOf(accentColor.copy(alpha = 0.15f), Color.Transparent),
                            center = center,
                            radius = size.width,
                        ),
                    )
                }
            }
            .clickable(
                interactionSource = interactionSource,
                indication = null,
                enabled = enabled,
                onClick = onClick,
            ),
        contentAlignment = Alignment.Center,
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text(
                text = label.uppercase(),
                style = MaterialTheme.typography.labelLarge,
                color = if (enabled) accentColor else TextMuted,
                fontWeight = FontWeight.ExtraBold,
                letterSpacing = 4.sp,
                modifier = Modifier.graphicsLayer {
                    translationY = if (isPressed) 1.dp.toPx() else 0f
                },
            )
            subLabel?.let {
                Text(
                    text = it.uppercase(),
                    style = MaterialTheme.typography.labelSmall,
                    color = (if (enabled) accentColor else TextMuted).copy(alpha = 0.7f),
                    letterSpacing = 2.sp,
                )
            }
        }
    }
}

@Composable
fun CyberConfirmationDialog(
    title: String,
    message: String,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = SurfaceElevated,
        modifier = Modifier.border(
            width = 0.5.dp,
            color = GlassBorder,
            shape = RoundedCornerShape(28.dp),
        ),
        shape = RoundedCornerShape(28.dp),
        title = {
            Text(
                text = title,
                color = AlertRed,
                style = MaterialTheme.typography.titleLarge,
            )
        },
        text = {
            Text(
                text = message,
                color = TextSecondary,
                style = MaterialTheme.typography.bodyLarge,
            )
        },
        confirmButton = {
            Button(
                onClick = onConfirm,
                colors = ButtonDefaults.buttonColors(containerColor = AlertRed.copy(alpha = 0.12f)),
                border = BorderStroke(width = 0.5.dp, color = AlertRed),
                shape = RoundedCornerShape(12.dp),
            ) {
                Text(
                    text = stringResource(R.string.btn_execute),
                    color = AlertRed,
                    fontWeight = FontWeight.Bold,
                )
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(
                    text = stringResource(R.string.btn_abort),
                    color = TextSecondary,
                )
            }
        },
    )
}

@Composable
fun LinkServiceDialog(
    onRestartService: () -> Unit,
    onConfigureHost: () -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = SurfaceElevated,
        modifier = Modifier.border(
            width = 1.dp,
            brush = Brush.linearGradient(
                listOf(
                    LiquidCyan.copy(alpha = 0.5f),
                    LiquidCyan.copy(alpha = 0.15f),
                ),
            ),
            shape = RoundedCornerShape(24.dp),
        ),
        shape = RoundedCornerShape(24.dp),
        title = {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Box(
                    modifier = Modifier
                        .size(10.dp)
                        .clip(CircleShape)
                        .background(LiquidCyan),
                )
                Text(
                    text = stringResource(R.string.dialog_link_control_title),
                    color = TextPrimary,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                )
            }
        },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
                Text(
                    text = stringResource(R.string.dialog_link_control_desc),
                    color = TextSecondary,
                    style = MaterialTheme.typography.bodyMedium,
                )

                Surface(
                    color = DeepSpace.copy(alpha = 0.6f),
                    shape = RoundedCornerShape(16.dp),
                    border = BorderStroke(0.5.dp, GlassBorder),
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(12.dp),
                        verticalArrangement = Arrangement.spacedBy(10.dp),
                    ) {
                        Button(
                            onClick = {
                                onRestartService()
                                onDismiss()
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = LiquidCyan.copy(alpha = 0.15f)),
                            border = BorderStroke(1.dp, LiquidCyan),
                            shape = RoundedCornerShape(12.dp),
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(8.dp),
                            ) {
                                Icon(
                                    imageVector = Icons.Default.Refresh,
                                    contentDescription = null,
                                    tint = LiquidCyan,
                                    modifier = Modifier.size(18.dp),
                                )
                                Text(
                                    text = stringResource(R.string.btn_reinitialize_link),
                                    color = LiquidCyan,
                                    fontWeight = FontWeight.Bold,
                                    style = MaterialTheme.typography.labelLarge,
                                )
                            }
                        }

                        OutlinedButton(
                            onClick = {
                                onConfigureHost()
                                onDismiss()
                            },
                            colors = ButtonDefaults.outlinedButtonColors(contentColor = TextPrimary),
                            border = BorderStroke(0.5.dp, GlassBorder),
                            shape = RoundedCornerShape(12.dp),
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(8.dp),
                            ) {
                                Icon(
                                    imageVector = Icons.Default.Settings,
                                    contentDescription = null,
                                    tint = TextSecondary,
                                    modifier = Modifier.size(18.dp),
                                )
                                Text(
                                    text = stringResource(R.string.btn_configure_host_ip),
                                    color = TextSecondary,
                                    style = MaterialTheme.typography.labelLarge,
                                )
                            }
                        }
                    }
                }
            }
        },
        confirmButton = {},
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(
                    text = stringResource(R.string.btn_done),
                    color = TextMuted,
                )
            }
        },
    )
}

@Composable
fun CompromisedEnvironmentOverlay(score: Int) {
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(DeepSpace),
        contentAlignment = Alignment.Center,
    ) {
        DeepSpaceCanvasVisualizer()
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text(
                text = stringResource(R.string.header_security_lockdown),
                color = AlertRed,
                style = MaterialTheme.typography.labelLarge,
                letterSpacing = 8.sp,
            )
            Spacer(modifier = Modifier.height(56.dp))
            Text(
                text = score.toString(),
                style = MaterialTheme.typography.headlineLarge,
                color = AlertRed,
                fontSize = 80.sp,
            )
            Text(
                text = stringResource(R.string.label_trust_index),
                color = TextSecondary,
                style = MaterialTheme.typography.labelMedium,
            )
        }
    }
}

@Composable
fun CommandConfirmationDialog(
    command: String,
    isConfirmed: Boolean,
    onDismiss: () -> Unit,
) {
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(DeepSpace.copy(alpha = 0.94f))
            .clickable(enabled = false) {},
        contentAlignment = Alignment.Center,
    ) {
        ProfessionalGlassSurface(
            modifier = Modifier.width(360.dp),
            tint = if (isConfirmed) IntegrityGreen else LiquidCyan,
            alpha = 0.3f,
            blur = 60f,
        ) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Box(contentAlignment = Alignment.Center) {
                    if (isConfirmed) {
                        Icon(
                            imageVector = Icons.Default.CheckCircle,
                            contentDescription = null,
                            tint = IntegrityGreen,
                            modifier = Modifier
                                .size(80.dp)
                                .graphicsLayer {
                                    scaleX = 1.1f
                                    scaleY = 1.1f
                                },
                        )
                    } else {
                        CircularProgressIndicator(
                            color = LiquidCyan,
                            strokeWidth = 3.5.dp,
                            modifier = Modifier.size(80.dp),
                        )
                    }
                }

                Spacer(modifier = Modifier.height(32.dp))

                Text(
                    text = if (isConfirmed) "Handshake Verified" else "Transmitting Cryptographic Token...",
                    style = MaterialTheme.typography.titleLarge,
                    color = if (isConfirmed) IntegrityGreen else LiquidCyan,
                    textAlign = TextAlign.Center,
                    fontWeight = FontWeight.ExtraBold,
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
                    textAlign = TextAlign.Center,
                )

                Spacer(modifier = Modifier.height(40.dp))

                TacticalAction(
                    label = "Dismiss",
                    accentColor = TextSecondary,
                    onClick = onDismiss,
                )
            }
        }
    }
}

@Composable
fun FuturisticLockOverlay(onAuthorizeRequested: () -> Unit) {
    var visible by remember { mutableStateOf(value = false) }
    LaunchedEffect(Unit) { visible = true }

    val infiniteTransition = rememberInfiniteTransition(label = "LockPulse")
    val pulse by infiniteTransition.animateFloat(
        initialValue = 0.8f,
        targetValue = 1.2f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 2000, easing = TetherEase),
            repeatMode = RepeatMode.Reverse,
        ),
        label = "Pulse",
    )

    Box(
        modifier = Modifier
            .fillMaxSize()
            .clickable { onAuthorizeRequested() },
        contentAlignment = Alignment.Center,
    ) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(DeepSpace.copy(alpha = 0.95f))
                .graphicsLayer {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                        renderEffect = RenderEffect
                            .createBlurEffect(100f, 100f, Shader.TileMode.CLAMP)
                            .asComposeRenderEffect()
                    }
                },
        )

        AnimatedVisibility(
            visible = visible,
            enter = fadeIn(animationSpec = tween(durationMillis = 1000)) +
                    scaleIn(
                        initialScale = 0.7f,
                        animationSpec = spring(dampingRatio = 0.5f, stiffness = Spring.StiffnessLow),
                    ),
        ) {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                modifier = Modifier.graphicsLayer {
                    scaleX = (pulse * 0.05f) + 0.95f
                    scaleY = (pulse * 0.05f) + 0.95f
                },
            ) {
                Text(
                    text = "🔒",
                    fontSize = 90.sp,
                    modifier = Modifier.graphicsLayer { alpha = (pulse * 0.3f) + 0.7f },
                )
                Spacer(modifier = Modifier.height(48.dp))
                Text(
                    text = stringResource(R.string.label_vault_enforced),
                    color = LiquidCyan,
                    style = MaterialTheme.typography.labelLarge,
                    letterSpacing = 8.sp,
                    fontWeight = FontWeight.Bold,
                )
                Spacer(modifier = Modifier.height(12.dp))
                Text(
                    text = stringResource(R.string.label_tap_to_decrypt),
                    color = TextMuted,
                    style = MaterialTheme.typography.labelMedium,
                )

                val scanLinePos by infiniteTransition.animateFloat(
                    initialValue = 0f,
                    targetValue = 1f,
                    animationSpec = infiniteRepeatable(
                        animation = tween(durationMillis = 3000, easing = LinearEasing),
                        repeatMode = RepeatMode.Restart,
                    ),
                    label = "Scan",
                )

                Canvas(
                    modifier = Modifier
                        .padding(top = 40.dp)
                        .width(200.dp)
                        .height(2.dp)
                        .graphicsLayer { alpha = 0.5f },
                ) {
                    drawLine(
                        brush = Brush.horizontalGradient(
                            listOf(Color.Transparent, LiquidCyan, Color.Transparent),
                        ),
                        start = Offset(x = (scanLinePos * size.width) - size.width, y = 0f),
                        end = Offset(x = (scanLinePos * size.width) + size.width, y = 0f),
                        strokeWidth = 2.dp.toPx(),
                    )
                }
            }
        }
    }
}