package com.tether.phone.ui.components

import android.graphics.BitmapFactory
import androidx.compose.animation.core.*
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.BatteryChargingFull
import androidx.compose.material.icons.filled.BatteryFull
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.tether.phone.LaptopPowerState
import com.tether.phone.LaptopTelemetry
import com.tether.phone.R
import com.tether.phone.ui.theme.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

@Composable
fun LaptopScreenCard(
    telemetry: LaptopTelemetry,
    windowsFingerprint: String = "",
    onClick: () -> Unit = {},
    modifier: Modifier = Modifier,
) {
    val wallpaperBitmap = rememberWallpaperBitmap(telemetry.wallpaperPath)

    Box(
        modifier = modifier
            .fillMaxWidth()
            .aspectRatio(16f / 10f)
            .shadow(
                elevation = 16.dp,
                shape = RoundedCornerShape(24.dp),
                ambientColor = LiquidCyan.copy(alpha = 0.2f),
                spotColor = LiquidCyan.copy(alpha = 0.4f),
            )
            .clip(RoundedCornerShape(24.dp))
            .background(
                Brush.radialGradient(
                    colors = listOf(
                        SurfaceElevated,
                        Obsidian,
                        DeepSpace,
                    ),
                    radius = 800f,
                ),
            )
            .border(
                width = 1.dp,
                brush = Brush.linearGradient(
                    listOf(
                        LiquidCyan.copy(alpha = 0.6f),
                        LiquidCyan.copy(alpha = 0.15f),
                        LiquidCyan.copy(alpha = 0.4f),
                    ),
                ),
                shape = RoundedCornerShape(24.dp),
            )
            .clickable(onClick = onClick),
    ) {
        // --- Layer 1: Background Wallpaper / Fallback ---
        if (telemetry.powerState != LaptopPowerState.POWERED_OFF) {
            if (wallpaperBitmap != null) {
                Image(
                    bitmap = wallpaperBitmap,
                    contentDescription = null,
                    modifier = Modifier.fillMaxSize(),
                    contentScale = ContentScale.Crop,
                )
            } else {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .background(
                            Brush.verticalGradient(
                                listOf(
                                    DeepSpace,
                                    SurfaceVeneer,
                                    DeepSpace,
                                ),
                            ),
                        ),
                    contentAlignment = Alignment.Center,
                ) {
                    WindowsLogoSilhouette(
                        modifier = Modifier.size(96.dp),
                        alpha = 0.08f,
                    )
                }
            }
        }

        // --- Layer 2: Animated Scan Line (Only when CONNECTED_UNLOCKED) ---
        if (telemetry.powerState == LaptopPowerState.CONNECTED_UNLOCKED) {
            ScanLineOverlay(modifier = Modifier.fillMaxSize())
        }

        // --- Layer 3: Power State Overlays ---
        when (telemetry.powerState) {
            LaptopPowerState.POWERED_OFF -> {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .background(Color.Black.copy(alpha = 0.88f)),
                    contentAlignment = Alignment.Center,
                ) {
                    Column(
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        Icon(
                            imageVector = Icons.Default.PowerSettingsNew,
                            contentDescription = null,
                            tint = TextSecondary.copy(alpha = 0.6f),
                            modifier = Modifier.size(48.dp),
                        )
                        Text(
                            text = stringResource(R.string.laptop_state_powered_off),
                            style = MaterialTheme.typography.labelLarge,
                            color = TextSecondary.copy(alpha = 0.8f),
                            letterSpacing = 2.sp,
                        )
                    }
                }
            }
            LaptopPowerState.RESTARTING, LaptopPowerState.SHUTTING_DOWN -> {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .background(Color.Black.copy(alpha = 0.60f)),
                    contentAlignment = Alignment.Center,
                ) {
                    Column(
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(16.dp),
                    ) {
                        CircularProgressIndicator(
                            color = LiquidCyan,
                            strokeWidth = 2.dp,
                            modifier = Modifier.size(36.dp),
                        )
                        Text(
                            text = if (telemetry.powerState == LaptopPowerState.RESTARTING) {
                                stringResource(R.string.laptop_state_restarting)
                            } else {
                                stringResource(R.string.laptop_state_shutting_down)
                            },
                            style = MaterialTheme.typography.bodyMedium,
                            color = TextPrimary,
                        )
                    }
                }
            }
            else -> {}
        }

        // --- Layer 4: HUD Elements Overlay (Top & Bottom bars) ---
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp),
            verticalArrangement = Arrangement.SpaceBetween,
        ) {
            // Top Row: Status Badge (Left) & Battery Chip (Right)
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                // Connection State Pill
                Surface(
                    color = DeepSpace.copy(alpha = 0.75f),
                    shape = CircleShape,
                    border = androidx.compose.foundation.BorderStroke(0.5.dp, GlassBorder),
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        val (dotColor, stateText) = when (telemetry.powerState) {
                            LaptopPowerState.CONNECTED_UNLOCKED -> IntegrityGreen to stringResource(R.string.laptop_state_unlocked)
                            LaptopPowerState.CONNECTED_LOCKED -> MatrixGold to stringResource(R.string.laptop_state_locked)
                            LaptopPowerState.DISCONNECTED -> AlertRed to stringResource(R.string.laptop_state_disconnected)
                            LaptopPowerState.RESTARTING -> TextSecondary.copy(alpha = 0.6f) to "RESTARTING"
                            LaptopPowerState.SHUTTING_DOWN -> TextSecondary.copy(alpha = 0.6f) to "SHUTTING DOWN"
                            LaptopPowerState.POWERED_OFF -> TextSecondary.copy(alpha = 0.6f) to stringResource(R.string.laptop_state_powered_off)
                            LaptopPowerState.UNKNOWN -> TextMuted to stringResource(R.string.label_unknown)
                        }

                        Box(
                            modifier = Modifier
                                .size(8.dp)
                                .clip(CircleShape)
                                .background(dotColor),
                        )
                        Text(
                            text = stateText,
                            style = MaterialTheme.typography.labelSmall,
                            color = TextPrimary,
                            fontWeight = FontWeight.Bold,
                        )
                    }
                }

                // Battery Chip (Hidden if batteryPercent < 0)
                if (telemetry.batteryPercent >= 0) {
                    Surface(
                        color = DeepSpace.copy(alpha = 0.75f),
                        shape = CircleShape,
                        border = androidx.compose.foundation.BorderStroke(0.5.dp, GlassBorder),
                    ) {
                        Row(
                            modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(6.dp),
                        ) {
                            val batIcon = if (telemetry.isCharging) Icons.Default.BatteryChargingFull else Icons.Default.BatteryFull
                            val batColor = when {
                                telemetry.batteryPercent <= 20 -> AlertRed
                                telemetry.batteryPercent <= 50 -> MatrixGold
                                else -> IntegrityGreen
                            }

                            Icon(
                                imageVector = batIcon,
                                contentDescription = null,
                                tint = batColor,
                                modifier = Modifier.size(16.dp),
                            )
                            Text(
                                text = "${telemetry.batteryPercent}%",
                                style = MaterialTheme.typography.labelSmall,
                                color = TextPrimary,
                                fontWeight = FontWeight.Bold,
                            )
                            if (telemetry.isCharging) {
                                Icon(
                                    imageVector = Icons.Default.Bolt,
                                    contentDescription = null,
                                    tint = MatrixGold,
                                    modifier = Modifier.size(14.dp),
                                )
                            }
                        }
                    }
                }
            }

            // Bottom Bar: Monospace fingerprint & relative time
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(12.dp))
                    .background(DeepSpace.copy(alpha = 0.65f))
                    .padding(horizontal = 12.dp, vertical = 6.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                val fpSnippet = if (windowsFingerprint.length >= 8) windowsFingerprint.takeLast(8) else "HOST-LINK"
                Text(
                    text = "WIN: $fpSnippet",
                    style = MaterialTheme.typography.labelSmall,
                    color = TextSecondary,
                    fontFamily = FontFamily.Monospace,
                )
                Text(
                    text = formatRelativeTime(telemetry.lastSeenAtMs),
                    style = MaterialTheme.typography.labelSmall,
                    color = TextMuted,
                    fontFamily = FontFamily.Monospace,
                )
            }
        }
    }
}

@Composable
private fun rememberWallpaperBitmap(wallpaperPath: String?): ImageBitmap? {
    var bitmap by remember(wallpaperPath) { mutableStateOf<ImageBitmap?>(null) }
    LaunchedEffect(wallpaperPath) {
        if (wallpaperPath.isNullOrEmpty()) {
            bitmap = null
            return@LaunchedEffect
        }
        withContext(Dispatchers.IO) {
            try {
                val file = File(wallpaperPath)
                if (!file.exists() || file.length() == 0L) {
                    bitmap = null
                    return@withContext
                }
                val options = BitmapFactory.Options().apply {
                    inJustDecodeBounds = true
                }
                BitmapFactory.decodeFile(file.absolutePath, options)

                var sampleSize = 1
                val targetW = 1080
                val targetH = 720
                if (options.outWidth > targetW || options.outHeight > targetH) {
                    val halfW = options.outWidth / 2
                    val halfH = options.outHeight / 2
                    while ((halfW / sampleSize) >= targetW && (halfH / sampleSize) >= targetH) {
                        sampleSize *= 2
                    }
                }

                val decodeOptions = BitmapFactory.Options().apply {
                    inSampleSize = sampleSize
                }
                val decoded = BitmapFactory.decodeFile(file.absolutePath, decodeOptions)
                bitmap = decoded?.asImageBitmap()
            } catch (_: Exception) {
                bitmap = null
            }
        }
    }
    return bitmap
}

@Composable
private fun WindowsLogoSilhouette(modifier: Modifier = Modifier, alpha: Float = 0.08f) {
    Canvas(modifier = modifier) {
        val gap = 4.dp.toPx()
        val halfW = (size.width - gap) / 2f
        val halfH = (size.height - gap) / 2f
        val color = Color.White.copy(alpha = alpha)

        drawRect(color = color, topLeft = Offset(0f, 0f), size = Size(halfW, halfH))
        drawRect(color = color, topLeft = Offset(halfW + gap, 0f), size = Size(halfW, halfH))
        drawRect(color = color, topLeft = Offset(0f, halfH + gap), size = Size(halfW, halfH))
        drawRect(color = color, topLeft = Offset(halfW + gap, halfH + gap), size = Size(halfW, halfH))
    }
}

@Composable
private fun ScanLineOverlay(modifier: Modifier = Modifier) {
    val infiniteTransition = rememberInfiniteTransition(label = "ScanLine")
    val progress by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(3500, easing = LinearEasing),
            repeatMode = RepeatMode.Restart,
        ),
        label = "ScanY",
    )

    Canvas(modifier = modifier) {
        val y = size.height * progress
        drawRect(
            brush = Brush.verticalGradient(
                colors = listOf(
                    Color.Transparent,
                    LiquidCyan.copy(alpha = 0.35f),
                    LiquidCyan.copy(alpha = 0.10f),
                    Color.Transparent,
                ),
                startY = (y - 12.dp.toPx()).coerceAtLeast(0f),
                endY = (y + 12.dp.toPx()).coerceAtMost(size.height),
            ),
            topLeft = Offset(0f, (y - 12.dp.toPx()).coerceAtLeast(0f)),
            size = Size(size.width, 24.dp.toPx()),
        )
    }
}

private fun formatRelativeTime(lastSeenAtMs: Long): String {
    if (lastSeenAtMs <= 0L) return "Never"
    val diffSec = ((System.currentTimeMillis() - lastSeenAtMs) / 1000L).coerceAtLeast(0L)
    return when {
        diffSec < 5 -> "just now"
        diffSec < 60 -> "${diffSec}s ago"
        diffSec < 3600 -> "${diffSec / 60}m ago"
        diffSec < 86400 -> "${diffSec / 3600}h ago"
        else -> "${diffSec / 86400}d ago"
    }
}
