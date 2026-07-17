package com.tether.phone.ui.components

import android.os.Build
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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.graphics.*
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.tether.phone.*
import com.tether.phone.R
import com.tether.phone.ui.theme.*

/**
 * High-End Professional Glass Surface
 * Features multi-layered refractive properties, dynamic highlights, and realistic depth.
 */
@Composable
fun ProfessionalGlassSurface(
    modifier: Modifier = Modifier,
    alpha: Float = 0.12f,
    tint: Color = Color.White,
    blur: Float = 32f,
    content: @Composable ColumnScope.() -> Unit
) {
    val infiniteTransition = rememberInfiniteTransition(label = "GlassRefraction")
    val tiltX by infiniteTransition.animateFloat(
        initialValue = -1.2f,
        targetValue = 1.2f,
        animationSpec = infiniteRepeatable(
            animation = tween(8000, easing = TetherEase),
            repeatMode = RepeatMode.Reverse
        ), label = "TiltX"
    )
    val tiltY by infiniteTransition.animateFloat(
        initialValue = -1.2f,
        targetValue = 1.2f,
        animationSpec = infiniteRepeatable(
            animation = tween(6500, easing = TetherEase),
            repeatMode = RepeatMode.Reverse
        ), label = "TiltY"
    )

    Box(
        modifier = modifier
            .graphicsLayer {
                rotationX = tiltX * 1.5f
                rotationY = tiltY * 1.5f
                cameraDistance = 12f * density
            }
            .clip(RoundedCornerShape(28.dp))
            .border(
                width = 0.5.dp,
                brush = Brush.linearGradient(
                    listOf(
                        Color.White.copy(alpha = 0.35f),
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
                            tint.copy(alpha = alpha * 1.4f),
                            tint.copy(alpha = alpha * 0.5f)
                        )
                    )
                )
                .graphicsLayer {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                        renderEffect = android.graphics.RenderEffect
                            .createBlurEffect(blur, blur, android.graphics.Shader.TileMode.CLAMP)
                            .asComposeRenderEffect()
                    }
                }
                .drawBehind {
                    // Specular highlight path (Fresnel-like effect)
                    val strokeWidth = 1.6.dp.toPx()
                    val highlightPath = Path().apply {
                        moveTo(0f, size.height * 0.4f)
                        lineTo(0f, 28.dp.toPx())
                        arcTo(
                            rect = Rect(0f, 0f, 56.dp.toPx(), 56.dp.toPx()),
                            startAngleDegrees = 180f,
                            sweepAngleDegrees = 90f,
                            forceMoveTo = false
                        )
                        lineTo(size.width * 0.4f, 0f)
                    }
                    drawPath(
                        path = highlightPath,
                        brush = Brush.linearGradient(
                            colors = listOf(Color.White.copy(alpha = 0.6f), Color.Transparent),
                            start = Offset(tiltX * 40f, tiltY * 40f),
                            end = Offset(size.width * 0.5f, size.height * 0.5f)
                        ),
                        style = Stroke(width = strokeWidth, cap = StrokeCap.Round)
                    )

                    // Grain/Noise texture overlay for tactile depth
                    val noiseStep = 4f
                    for (x in 0 until size.width.toInt() step (noiseStep.toInt() * 3)) {
                        for (y in 0 until size.height.toInt() step (noiseStep.toInt() * 3)) {
                            if ((x * y) % 13 == 0) {
                                drawCircle(
                                    color = Color.White.copy(alpha = 0.02f),
                                    radius = 0.5f,
                                    center = Offset(x.toFloat(), y.toFloat())
                                )
                            }
                        }
                    }
                }
        )
        Column(
            modifier = Modifier.padding(24.dp),
            content = content
        )
    }
}

/**
 * Tactile Tactical Action - Interactive Control
 */
@Composable
fun TacticalAction(
    label: String,
    accentColor: Color,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    subLabel: String? = null
) {
    val interactionSource = remember { MutableInteractionSource() }
    val isPressed by interactionSource.collectIsPressedAsState()

    val scale by animateFloatAsState(
        targetValue = if (isPressed) 0.94f else 1f,
        animationSpec = spring(dampingRatio = 0.5f, stiffness = 500f),
        label = "Scale"
    )
    val glow by animateFloatAsState(
        targetValue = if (isPressed) 0.45f else 0.16f,
        animationSpec = tween(300, easing = LinearOutSlowInEasing),
        label = "Glow"
    )
    val tilt by animateFloatAsState(
        targetValue = if (isPressed) 4f else 0f,
        animationSpec = spring(dampingRatio = 0.6f, stiffness = 300f),
        label = "Tilt"
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
                        accentColor.copy(alpha = glow * 0.4f)
                    )
                )
            )
            .border(
                width = 0.5.dp,
                brush = Brush.linearGradient(
                    listOf(
                        accentColor.copy(alpha = if (isPressed) 0.8f else 0.4f),
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
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text(
                text = label.uppercase(),
                style = MaterialTheme.typography.labelLarge,
                color = if (enabled) accentColor else TextMuted,
                fontWeight = FontWeight.ExtraBold,
                letterSpacing = 4.sp,
                modifier = Modifier.graphicsLayer {
                    translationY = if (isPressed) 1.dp.toPx() else 0f
                }
            )
            if (subLabel != null) {
                Text(
                    text = subLabel.uppercase(),
                    style = MaterialTheme.typography.labelSmall,
                    color = (if (enabled) accentColor else TextMuted).copy(alpha = 0.7f),
                    letterSpacing = 2.sp
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
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = SurfaceElevated,
        modifier = Modifier.border(
            width = 0.5.dp,
            color = GlassBorder,
            shape = RoundedCornerShape(28.dp)
        ),
        shape = RoundedCornerShape(28.dp),
        title = {
            Text(
                text = title,
                color = AlertRed,
                style = MaterialTheme.typography.titleLarge
            )
        },
        text = {
            Text(
                text = message,
                color = TextSecondary,
                style = MaterialTheme.typography.bodyLarge
            )
        },
        confirmButton = {
            Button(
                onClick = onConfirm,
                colors = ButtonDefaults.buttonColors(containerColor = AlertRed.copy(alpha = 0.12f)),
                border = BorderStroke(width = 0.5.dp, color = AlertRed),
                shape = RoundedCornerShape(12.dp)
            ) {
                Text(
                    text = stringResource(R.string.btn_execute),
                    color = AlertRed,
                    fontWeight = FontWeight.Bold
                )
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(
                    text = stringResource(R.string.btn_abort),
                    color = TextSecondary
                )
            }
        }
    )
}

@Composable
fun CompromisedEnvironmentOverlay(score: Int) {
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(DeepSpace),
        contentAlignment = Alignment.Center
    ) {
        DeepSpaceCanvasVisualizer()
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text(
                text = stringResource(R.string.header_security_lockdown),
                color = AlertRed,
                style = MaterialTheme.typography.labelLarge,
                letterSpacing = 8.sp
            )
            Spacer(modifier = Modifier.height(56.dp))
            Text(
                text = score.toString(),
                style = MaterialTheme.typography.headlineLarge,
                color = AlertRed,
                fontSize = 80.sp
            )
            Text(
                text = stringResource(R.string.label_trust_index),
                color = TextSecondary,
                style = MaterialTheme.typography.labelMedium
            )
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
        ProfessionalGlassSurface(
            modifier = Modifier.width(360.dp),
            tint = if (isConfirmed) IntegrityGreen else LiquidCyan,
            alpha = 0.3f,
            blur = 60f
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

                TacticalAction(
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
            animation = tween(durationMillis = 2000, easing = TetherEase),
            repeatMode = RepeatMode.Reverse
        ), label = "Pulse"
    )

    Box(
        modifier = Modifier
            .fillMaxSize()
            .clickable { onAuthorizeRequested() },
        contentAlignment = Alignment.Center
    ) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(DeepSpace.copy(alpha = 0.95f))
                .graphicsLayer {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                        renderEffect = android.graphics.RenderEffect
                            .createBlurEffect(100f, 100f, android.graphics.Shader.TileMode.CLAMP)
                            .asComposeRenderEffect()
                    }
                }
        )

        AnimatedVisibility(
            visible = visible,
            enter = fadeIn(animationSpec = tween(durationMillis = 1000)) + 
                    scaleIn(
                        initialScale = 0.7f, 
                        animationSpec = spring(dampingRatio = 0.5f, stiffness = Spring.StiffnessLow)
                    )
        ) {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                modifier = Modifier.graphicsLayer {
                    scaleX = pulse * 0.05f + 0.95f
                    scaleY = pulse * 0.05f + 0.95f
                }
            ) {
                Text(
                    text = "🔒",
                    fontSize = 90.sp,
                    modifier = Modifier.graphicsLayer { alpha = pulse * 0.3f + 0.7f }
                )
                Spacer(modifier = Modifier.height(48.dp))
                Text(
                    text = stringResource(R.string.label_vault_enforced),
                    color = LiquidCyan,
                    style = MaterialTheme.typography.labelLarge,
                    letterSpacing = 8.sp,
                    fontWeight = FontWeight.Bold
                )
                Spacer(modifier = Modifier.height(12.dp))
                Text(
                    text = stringResource(R.string.label_tap_to_decrypt),
                    color = TextMuted,
                    style = MaterialTheme.typography.labelMedium
                )

                val scanLinePos by infiniteTransition.animateFloat(
                    initialValue = 0f,
                    targetValue = 1f,
                    animationSpec = infiniteRepeatable(
                        animation = tween(durationMillis = 3000, easing = LinearEasing),
                        repeatMode = RepeatMode.Restart
                    ), label = "Scan"
                )

                Canvas(
                    modifier = Modifier
                        .padding(top = 40.dp)
                        .width(200.dp)
                        .height(2.dp)
                        .graphicsLayer { alpha = 0.5f }
                ) {
                    drawLine(
                        brush = Brush.horizontalGradient(
                            listOf(Color.Transparent, LiquidCyan, Color.Transparent)
                        ),
                        start = Offset(x = scanLinePos * size.width - size.width, y = 0f),
                        end = Offset(x = scanLinePos * size.width + size.width, y = 0f),
                        strokeWidth = 2.dp.toPx()
                    )
                }
            }
        }
    }
}
