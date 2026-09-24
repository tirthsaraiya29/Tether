package com.tether.phone.ui.components

import android.graphics.BitmapFactory
import android.graphics.RenderEffect
import android.graphics.Shader
import android.os.Build
import android.util.Base64
import androidx.compose.animation.core.*
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectDragGestures
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.VolumeDown
import androidx.compose.material.icons.automirrored.filled.VolumeOff
import androidx.compose.material.icons.automirrored.filled.VolumeUp
import androidx.compose.material.icons.filled.*
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
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.tether.phone.AppInfo
import com.tether.phone.BatteryState
import com.tether.phone.MediaState
import com.tether.phone.PowerPlanInfo
import com.tether.phone.ui.theme.*
import java.util.Locale
import kotlin.math.roundToInt

/**
 * True Liquid Glass Container
 * Implements a multi-layered glass substrate inspired by Echo Music & refractive optics.
 * Combines GPU blur, specular corner reflections, dual-stroke highlights, and tactile noise depth.
 */
@Composable
fun LiquidGlassSurface(
    modifier: Modifier = Modifier,
    cornerRadius: Dp = 28.dp,
    alpha: Float = 0.16f,
    tint: Color = LiquidCyan,
    blur: Float = 36f,
    content: @Composable ColumnScope.() -> Unit,
) {
    val infiniteTransition = rememberInfiniteTransition(label = "LiquidGlassRefraction")
    val tiltX by infiniteTransition.animateFloat(
        initialValue = -1.0f,
        targetValue = 1.0f,
        animationSpec = infiniteRepeatable(
            animation = tween(9000, easing = TetherEase),
            repeatMode = RepeatMode.Reverse,
        ),
        label = "TiltX",
    )
    val tiltY by infiniteTransition.animateFloat(
        initialValue = -1.0f,
        targetValue = 1.0f,
        animationSpec = infiniteRepeatable(
            animation = tween(7200, easing = TetherEase),
            repeatMode = RepeatMode.Reverse,
        ),
        label = "TiltY",
    )

    Box(
        modifier = modifier
            .graphicsLayer {
                rotationX = tiltX * 1.2f
                rotationY = tiltY * 1.2f
                cameraDistance = 14f * density
            }
            .clip(RoundedCornerShape(cornerRadius))
            .drawBehind {
                // Ambient 3D depth shadow
                drawCircle(
                    brush = Brush.radialGradient(
                        0.0f to Color.Black.copy(alpha = 0.45f),
                        1.0f to Color.Transparent,
                        center = Offset(
                            (size.width / 2) + (tiltX * 6.dp.toPx()),
                            (size.height / 2) + (tiltY * 6.dp.toPx()),
                        ),
                        radius = size.width.coerceAtLeast(size.height),
                    ),
                    radius = size.width.coerceAtLeast(size.height),
                    center = Offset(
                        (size.width / 2) + (tiltX * 6.dp.toPx()),
                        (size.height / 2) + (tiltY * 6.dp.toPx()),
                    ),
                )
            }
            .border(
                width = 0.75.dp,
                brush = Brush.linearGradient(
                    colors = listOf(
                        Color.White.copy(alpha = 0.40f),
                        tint.copy(alpha = 0.25f),
                        Color.White.copy(alpha = 0.08f),
                    ),
                    start = Offset(0f, 0f),
                    end = Offset(1000f, 1000f),
                ),
                shape = RoundedCornerShape(cornerRadius),
            ),
    ) {
        Box(
            modifier = Modifier
                .matchParentSize()
                .background(
                    Brush.verticalGradient(
                        colors = listOf(
                            tint.copy(alpha = alpha * 1.5f),
                            SurfaceVeneer.copy(alpha = alpha * 1.2f),
                            DeepSpace.copy(alpha = alpha * 0.8f),
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
                    // Specular highlight path
                    val strokeWidth = 1.2.dp.toPx()
                    val highlightPath = Path().apply {
                        moveTo(0f, size.height * 0.25f)
                        lineTo(0f, cornerRadius.toPx())
                        arcTo(
                            rect = Rect(0f, 0f, cornerRadius.toPx() * 2, cornerRadius.toPx() * 2),
                            startAngleDegrees = 180f,
                            sweepAngleDegrees = 90f,
                            forceMoveTo = false,
                        )
                        lineTo(size.width * 0.35f, 0f)
                    }
                    drawPath(
                        path = highlightPath,
                        brush = Brush.linearGradient(
                            colors = listOf(Color.White.copy(alpha = 0.50f), Color.Transparent),
                            start = Offset(tiltX * 20f, tiltY * 20f),
                            end = Offset(size.width * 0.4f, size.height * 0.4f),
                        ),
                        style = Stroke(width = strokeWidth, cap = StrokeCap.Round),
                    )

                    // Secondary refractive inner ring
                    drawArc(
                        color = Color.White.copy(alpha = 0.06f),
                        startAngle = 0f,
                        sweepAngle = 360f,
                        useCenter = false,
                        topLeft = Offset(6.dp.toPx(), 6.dp.toPx()),
                        size = size.copy(
                            width = (size.width - 12.dp.toPx()).coerceAtLeast(1f),
                            height = (size.height - 12.dp.toPx()).coerceAtLeast(1f),
                        ),
                        style = Stroke(width = 0.5.dp.toPx()),
                    )
                },
        )
        Column(
            modifier = Modifier.padding(20.dp),
            content = content,
        )
    }
}

/**
 * Liquid Glass Master Volume Slider
 * Responsive, immediate visual update on Android with debounced/throttled BLE network delivery.
 */
@Composable
fun LiquidGlassVolumeSlider(
    value: Float, // 0f..100f
    onValueChange: (Float) -> Unit,
    onValueChangeFinished: (Float) -> Unit,
    modifier: Modifier = Modifier,
    isMuted: Boolean = false,
    enabled: Boolean = true,
) {
    val haptic = LocalHapticFeedback.current
    var isDragging by remember { mutableStateOf(value = false) }
    var dragProgress by remember(value) { mutableFloatStateOf(value.coerceIn(0f, 100f)) }

    // Synchronize local drag progress when value updates externally and user is not dragging
    LaunchedEffect(value) {
        if (!isDragging) {
            dragProgress = value.coerceIn(0f, 100f)
        }
    }

    val activeColor = if (isMuted) TextMuted else LiquidCyan
    val levelPercentage = dragProgress.roundToInt()

    Column(modifier = modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Icon(
                    imageVector = when {
                        ((isMuted) || (levelPercentage == 0)) -> Icons.AutoMirrored.Filled.VolumeOff
                        levelPercentage < 40 -> Icons.AutoMirrored.Filled.VolumeDown
                        else -> Icons.AutoMirrored.Filled.VolumeUp
                    },
                    contentDescription = "Volume Icon",
                    tint = if (isMuted) AlertRed else LiquidCyan,
                    modifier = Modifier.size(20.dp),
                )
                Text(
                    text = if (isMuted) "MUTED" else "MASTER VOLUME",
                    style = MaterialTheme.typography.labelSmall,
                    color = if (isMuted) AlertRed else TextSecondary,
                    fontWeight = FontWeight.Bold,
                    letterSpacing = 1.2.sp,
                )
            }
            Box(
                modifier = Modifier
                    .clip(RoundedCornerShape(10.dp))
                    .background(activeColor.copy(alpha = 0.15f))
                    .border(0.5.dp, activeColor.copy(alpha = 0.3f), RoundedCornerShape(10.dp))
                    .padding(horizontal = 10.dp, vertical = 4.dp),
            ) {
                Text(
                    text = "$levelPercentage%",
                    style = MaterialTheme.typography.labelMedium,
                    color = if (isMuted) AlertRed else TextPrimary,
                    fontWeight = FontWeight.ExtraBold,
                )
            }
        }

        Spacer(modifier = Modifier.height(14.dp))

        // Custom Glass Track + Thumb
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(44.dp)
                .clip(RoundedCornerShape(22.dp))
                .background(SurfaceElevated.copy(alpha = 0.6f))
                .border(
                    width = 0.75.dp,
                    brush = Brush.linearGradient(
                        listOf(Color.White.copy(alpha = 0.25f), activeColor.copy(alpha = 0.1f)),
                    ),
                    shape = RoundedCornerShape(22.dp),
                )
                .pointerInput(enabled) {
                    if (!enabled) return@pointerInput
                    detectTapGestures { offset ->
                        val newPct = (offset.x / size.width.toFloat()).coerceIn(0f, 1f) * 100f
                        dragProgress = newPct
                        haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                        onValueChange(newPct)
                        onValueChangeFinished(newPct)
                    }
                }
                .pointerInput(enabled) {
                    if (!enabled) return@pointerInput
                    detectDragGestures(
                        onDragStart = { offset ->
                            isDragging = true
                            haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                            val newPct = (offset.x / size.width.toFloat()).coerceIn(0f, 1f) * 100f
                            dragProgress = newPct
                            onValueChange(newPct)
                        },
                        onDragEnd = {
                            isDragging = false
                            onValueChangeFinished(dragProgress)
                        },
                        onDragCancel = {
                            isDragging = false
                            onValueChangeFinished(dragProgress)
                        },
                    ) { change, _ ->
                        change.consume()
                        val newPct = (change.position.x / size.width.toFloat()).coerceIn(0f, 1f) * 100f
                        dragProgress = newPct
                        onValueChange(newPct)
                    }
                },
            contentAlignment = Alignment.CenterStart,
        ) {
            val fraction = (dragProgress / 100f).coerceIn(0f, 1f)

            // Track Fill
            Box(
                modifier = Modifier
                    .fillMaxHeight()
                    .fillMaxWidth(fraction.coerceAtLeast(0.02f))
                    .clip(RoundedCornerShape(22.dp))
                    .background(
                        Brush.horizontalGradient(
                            colors = if (isMuted) listOf(AlertRed.copy(alpha = 0.6f), AlertRedMuted)
                            else listOf(LiquidCyanMuted, LiquidCyan, IntegrityGreen),
                        ),
                    ),
            )

            // Refractive Specular Track Reflection
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(18.dp)
                    .align(Alignment.TopCenter)
                    .background(
                        Brush.verticalGradient(
                            colors = listOf(Color.White.copy(alpha = 0.18f), Color.Transparent),
                        ),
                    ),
            )

            // Glass Handle / Thumb Marker
            Box(
                modifier = Modifier
                    .fillMaxHeight()
                    .align(Alignment.CenterStart)
                    .padding(start = ((fraction * 0.90f) * 100).coerceAtLeast(0f).dp)
                    .width(36.dp)
                    .clip(CircleShape)
                    .background(
                        Brush.verticalGradient(
                            listOf(Color.White.copy(alpha = 0.95f), activeColor.copy(alpha = 0.8f)),
                        ),
                    )
                    .border(1.dp, Color.White, CircleShape),
                contentAlignment = Alignment.Center,
            ) {
                Box(
                    modifier = Modifier
                        .size(8.dp)
                        .clip(CircleShape)
                        .background(DeepSpace),
                )
            }
        }
    }
}

/**
 * Liquid Glass Action Button / Icon Control
 */
@Composable
fun LiquidGlassButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    icon: ImageVector? = null,
    accentColor: Color = LiquidCyan,
    enabled: Boolean = true,
    isHighlighted: Boolean = false,
) {
    val interactionSource = remember { MutableInteractionSource() }
    val isPressed by interactionSource.collectIsPressedAsState()
    val haptic = LocalHapticFeedback.current

    val scale by animateFloatAsState(
        targetValue = if (isPressed) 0.93f else 1f,
        animationSpec = spring(dampingRatio = 0.5f, stiffness = 600f),
        label = "BtnScale",
    )

    Box(
        modifier = modifier
            .graphicsLayer {
                scaleX = scale
                scaleY = scale
                alpha = if (enabled) 1f else 0.45f
            }
            .fillMaxWidth()
            .height(52.dp)
            .clip(RoundedCornerShape(18.dp))
            .background(
                Brush.verticalGradient(
                    colors = if (isHighlighted) listOf(
                        accentColor.copy(alpha = 0.35f),
                        accentColor.copy(alpha = 0.15f),
                    ) else listOf(
                        SurfaceElevated.copy(alpha = 0.50f),
                        SurfaceVeneer.copy(alpha = 0.30f),
                    ),
                ),
            )
            .border(
                width = 0.75.dp,
                brush = Brush.linearGradient(
                    colors = listOf(
                        accentColor.copy(alpha = if (isHighlighted) 0.8f else 0.4f),
                        Color.White.copy(alpha = 0.05f),
                    ),
                ),
                shape = RoundedCornerShape(18.dp),
            )
            .clickable(
                enabled = enabled,
                interactionSource = interactionSource,
                indication = null,
            ) {
                haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                onClick()
            },
        contentAlignment = Alignment.Center,
    ) {
        Row(
            horizontalArrangement = Arrangement.Center,
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.padding(horizontal = 16.dp),
        ) {
            if (icon != null) {
                Icon(
                    imageVector = icon,
                    contentDescription = text,
                    tint = accentColor,
                    modifier = Modifier.size(18.dp),
                )
                Spacer(modifier = Modifier.width(8.dp))
            }
            Text(
                text = text,
                style = MaterialTheme.typography.labelMedium,
                color = TextPrimary,
                fontWeight = FontWeight.Bold,
                textAlign = TextAlign.Center,
            )
        }
    }
}

/**
 * Glass Media Session Card with Artwork, Playback Info, and Controls
 */
@Composable
fun LiquidGlassMediaCard(
    mediaState: MediaState,
    onPlayPause: () -> Unit,
    onPrev: () -> Unit,
    onNext: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
) {
    LiquidGlassSurface(
        modifier = modifier,
        tint = LiquidCyan,
        alpha = 0.18f,
    ) {
        Text(
            text = "MEDIA CONTROLS",
            style = MaterialTheme.typography.labelSmall,
            color = LiquidCyan,
            fontWeight = FontWeight.Bold,
            letterSpacing = 1.2.sp,
        )
        Spacer(modifier = Modifier.height(16.dp))

        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            // Album Artwork Container
            Box(
                modifier = Modifier
                    .size(72.dp)
                    .clip(RoundedCornerShape(16.dp))
                    .background(Obsidian)
                    .border(1.dp, GlassBorderBright, RoundedCornerShape(16.dp)),
                contentAlignment = Alignment.Center,
            ) {
                val artworkBitmap = remember(mediaState.artworkBase64) {
                    try {
                        if (!mediaState.artworkBase64.isNullOrEmpty()) {
                            val decodedBytes = Base64.decode(mediaState.artworkBase64, Base64.DEFAULT)
                            BitmapFactory.decodeByteArray(decodedBytes, 0, decodedBytes.size)?.asImageBitmap()
                        } else null
                    } catch (_: Exception) {
                        null
                    }
                }

                if (artworkBitmap != null) {
                    Image(
                        bitmap = artworkBitmap,
                        contentDescription = "Album Art",
                        modifier = Modifier.fillMaxSize(),
                        contentScale = ContentScale.Crop,
                    )
                } else {
                    Box(
                        modifier = Modifier
                            .fillMaxSize()
                            .background(
                                Brush.radialGradient(
                                    listOf(LiquidCyan.copy(alpha = 0.3f), Obsidian),
                                ),
                            ),
                        contentAlignment = Alignment.Center,
                    ) {
                        Icon(
                            imageVector = Icons.Default.MusicNote,
                            contentDescription = "Media Artwork",
                            tint = LiquidCyan,
                            modifier = Modifier.size(32.dp),
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.width(16.dp))

            // Title & Artist Metadata
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = mediaState.title,
                    style = MaterialTheme.typography.titleMedium,
                    color = TextPrimary,
                    fontWeight = FontWeight.Bold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = if (mediaState.album.isNotEmpty()) "${mediaState.artist} • ${mediaState.album}" else mediaState.artist,
                    style = MaterialTheme.typography.bodySmall,
                    color = TextSecondary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Spacer(modifier = Modifier.height(8.dp))

                // Status Badge
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier
                            .size(8.dp)
                            .clip(CircleShape)
                            .background(if (mediaState.isPlaying) IntegrityGreen else TextMuted),
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = if (mediaState.isPlaying) "PLAYING" else "PAUSED",
                        style = MaterialTheme.typography.labelSmall,
                        color = if (mediaState.isPlaying) IntegrityGreen else TextMuted,
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold,
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(20.dp))

        // Playback Progress Bar (if duration is available)
        if (mediaState.durationMs > 0) {
            val progressFraction = (mediaState.positionMs.toFloat() / mediaState.durationMs.toFloat()).coerceIn(0f, 1f)
            Column(modifier = Modifier.fillMaxWidth()) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(6.dp)
                        .clip(CircleShape)
                        .background(SurfaceElevated),
                ) {
                    Box(
                        modifier = Modifier
                            .fillMaxHeight()
                            .fillMaxWidth(progressFraction)
                            .clip(CircleShape)
                            .background(LiquidCyan),
                    )
                }
                Spacer(modifier = Modifier.height(4.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Text(
                        text = formatMillis(mediaState.positionMs),
                        style = MaterialTheme.typography.labelSmall,
                        color = TextMuted,
                        fontSize = 10.sp,
                    )
                    Text(
                        text = formatMillis(mediaState.durationMs),
                        style = MaterialTheme.typography.labelSmall,
                        color = TextMuted,
                        fontSize = 10.sp,
                    )
                }
            }
            Spacer(modifier = Modifier.height(16.dp))
        }

        // Media Action Controls (Prev, Play/Pause, Next)
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceEvenly,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            IconButton(
                onClick = onPrev,
                enabled = enabled,
                modifier = Modifier
                    .size(48.dp)
                    .clip(CircleShape)
                    .background(SurfaceElevated.copy(alpha = 0.5f))
                    .border(0.5.dp, GlassBorderBright, CircleShape),
            ) {
                Icon(
                    imageVector = Icons.Default.SkipPrevious,
                    contentDescription = "Previous Track",
                    tint = TextPrimary,
                )
            }

            IconButton(
                onClick = onPlayPause,
                enabled = enabled,
                modifier = Modifier
                    .size(60.dp)
                    .clip(CircleShape)
                    .background(
                        Brush.radialGradient(
                            listOf(LiquidCyan, LiquidCyanMuted),
                        ),
                    )
                    .border(1.dp, Color.White, CircleShape),
            ) {
                Icon(
                    imageVector = if (mediaState.isPlaying) Icons.Default.Pause else Icons.Default.PlayArrow,
                    contentDescription = "Play / Pause",
                    tint = DeepSpace,
                    modifier = Modifier.size(32.dp),
                )
            }

            IconButton(
                onClick = onNext,
                enabled = enabled,
                modifier = Modifier
                    .size(48.dp)
                    .clip(CircleShape)
                    .background(SurfaceElevated.copy(alpha = 0.5f))
                    .border(0.5.dp, GlassBorderBright, CircleShape),
            ) {
                Icon(
                    imageVector = Icons.Default.SkipNext,
                    contentDescription = "Next Track",
                    tint = TextPrimary,
                )
            }
        }
    }
}

/**
 * Glass Application Launcher Card
 */
@Composable
fun LiquidGlassAppCard(
    app: AppInfo,
    onLaunch: (String) -> Unit,
    modifier: Modifier = Modifier,
    isLaunching: Boolean = false,
    enabled: Boolean = true,
) {
    val haptic = LocalHapticFeedback.current

    Box(
        modifier = modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(20.dp))
            .background(
                Brush.verticalGradient(
                    listOf(
                        SurfaceElevated.copy(alpha = 0.5f),
                        SurfaceVeneer.copy(alpha = 0.3f),
                    ),
                ),
            )
            .border(
                width = 0.75.dp,
                brush = Brush.linearGradient(
                    listOf(Color.White.copy(alpha = 0.3f), LiquidCyan.copy(alpha = 0.1f)),
                ),
                shape = RoundedCornerShape(20.dp),
            )
            .clickable(enabled = enabled && !isLaunching) {
                haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                onLaunch(app.id)
            }
            .padding(16.dp),
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Box(
                modifier = Modifier
                    .size(44.dp)
                    .clip(RoundedCornerShape(14.dp))
                    .background(LiquidCyan.copy(alpha = 0.15f))
                    .border(0.5.dp, LiquidCyan.copy(alpha = 0.4f), RoundedCornerShape(14.dp)),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    imageVector = getAppIcon(app.iconName),
                    contentDescription = app.name,
                    tint = LiquidCyan,
                    modifier = Modifier.size(24.dp),
                )
            }

            Spacer(modifier = Modifier.width(14.dp))

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = app.name,
                    style = MaterialTheme.typography.titleSmall,
                    color = TextPrimary,
                    fontWeight = FontWeight.Bold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = app.category,
                    style = MaterialTheme.typography.labelSmall,
                    color = TextMuted,
                    fontSize = 11.sp,
                )
            }

            Spacer(modifier = Modifier.width(8.dp))

            if (isLaunching) {
                CircularProgressIndicator(
                    modifier = Modifier.size(20.dp),
                    color = LiquidCyan,
                    strokeWidth = 2.dp,
                )
            } else {
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(12.dp))
                        .background(LiquidCyan.copy(alpha = 0.12f))
                        .border(0.5.dp, LiquidCyan.copy(alpha = 0.3f), RoundedCornerShape(12.dp))
                        .padding(horizontal = 12.dp, vertical = 6.dp),
                ) {
                    Text(
                        text = "LAUNCH",
                        style = MaterialTheme.typography.labelSmall,
                        color = LiquidCyan,
                        fontWeight = FontWeight.ExtraBold,
                        fontSize = 10.sp,
                    )
                }
            }
        }
    }
}

/**
 * Liquid Glass Search Input Field
 */
@Composable
fun LiquidGlassSearchField(
    query: String,
    onQueryChange: (String) -> Unit,
    modifier: Modifier = Modifier,
    placeholder: String = "Search Windows Apps...",
) {
    val keyboardController = LocalSoftwareKeyboardController.current

    Box(
        modifier = modifier
            .fillMaxWidth()
            .height(48.dp)
            .clip(RoundedCornerShape(16.dp))
            .background(SurfaceElevated.copy(alpha = 0.5f))
            .border(0.5.dp, GlassBorderBright, RoundedCornerShape(16.dp))
            .padding(horizontal = 14.dp),
        contentAlignment = Alignment.CenterStart,
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Icon(
                imageVector = Icons.Default.Search,
                contentDescription = "Search",
                tint = TextSecondary,
                modifier = Modifier.size(20.dp),
            )
            Spacer(modifier = Modifier.width(10.dp))
            Box(modifier = Modifier.weight(1f)) {
                if (query.isEmpty()) {
                    Text(
                        text = placeholder,
                        style = MaterialTheme.typography.bodyMedium,
                        color = TextMuted,
                    )
                }
                TextField(
                    value = query,
                    onValueChange = onQueryChange,
                    colors = TextFieldDefaults.colors(
                        focusedContainerColor = Color.Transparent,
                        unfocusedContainerColor = Color.Transparent,
                        disabledContainerColor = Color.Transparent,
                        focusedIndicatorColor = Color.Transparent,
                        unfocusedIndicatorColor = Color.Transparent,
                        focusedTextColor = TextPrimary,
                        unfocusedTextColor = TextPrimary,
                    ),
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search),
                    keyboardActions = KeyboardActions(onSearch = { keyboardController?.hide() }),
                    modifier = Modifier.fillMaxWidth(),
                )
            }
            if (query.isNotEmpty()) {
                IconButton(
                    onClick = { onQueryChange("") },
                    modifier = Modifier.size(24.dp),
                ) {
                    Icon(
                        imageVector = Icons.Default.Close,
                        contentDescription = "Clear",
                        tint = TextSecondary,
                        modifier = Modifier.size(16.dp),
                    )
                }
            }
        }
    }
}

/**
 * Liquid Glass Brightness Slider
 */
@Composable
fun LiquidGlassBrightnessSlider(
    value: Float, // 0f..100f
    onValueChange: (Float) -> Unit,
    onValueChangeFinished: (Float) -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
) {
    val haptic = LocalHapticFeedback.current
    var isDragging by remember { mutableStateOf(value = false) }
    var dragProgress by remember(value) { mutableFloatStateOf(value.coerceIn(0f, 100f)) }

    LaunchedEffect(value) {
        if (!isDragging) {
            dragProgress = value.coerceIn(0f, 100f)
        }
    }

    val levelPercentage = dragProgress.roundToInt()

    Column(modifier = modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Icon(
                    imageVector = Icons.Default.WbSunny,
                    contentDescription = "Brightness Icon",
                    tint = MatrixGold,
                    modifier = Modifier.size(20.dp),
                )
                Text(
                    text = "DISPLAY BRIGHTNESS",
                    style = MaterialTheme.typography.labelSmall,
                    color = TextSecondary,
                    fontWeight = FontWeight.Bold,
                    letterSpacing = 1.2.sp,
                )
            }
            Box(
                modifier = Modifier
                    .clip(RoundedCornerShape(10.dp))
                    .background(MatrixGold.copy(alpha = 0.15f))
                    .border(0.5.dp, MatrixGold.copy(alpha = 0.3f), RoundedCornerShape(10.dp))
                    .padding(horizontal = 10.dp, vertical = 4.dp),
            ) {
                Text(
                    text = "$levelPercentage%",
                    style = MaterialTheme.typography.labelMedium,
                    color = TextPrimary,
                    fontWeight = FontWeight.ExtraBold,
                )
            }
        }

        Spacer(modifier = Modifier.height(14.dp))

        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(44.dp)
                .clip(RoundedCornerShape(22.dp))
                .background(SurfaceElevated.copy(alpha = 0.6f))
                .border(
                    width = 0.75.dp,
                    brush = Brush.linearGradient(
                        listOf(Color.White.copy(alpha = 0.25f), MatrixGold.copy(alpha = 0.1f)),
                    ),
                    shape = RoundedCornerShape(22.dp),
                )
                .pointerInput(enabled) {
                    if (!enabled) return@pointerInput
                    detectTapGestures { offset ->
                        val newPct = (offset.x / size.width.toFloat()).coerceIn(0f, 1f) * 100f
                        dragProgress = newPct
                        haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                        onValueChange(newPct)
                        onValueChangeFinished(newPct)
                    }
                }
                .pointerInput(enabled) {
                    if (!enabled) return@pointerInput
                    detectDragGestures(
                        onDragStart = { offset ->
                            isDragging = true
                            haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                            val newPct = (offset.x / size.width.toFloat()).coerceIn(0f, 1f) * 100f
                            dragProgress = newPct
                            onValueChange(newPct)
                        },
                        onDragEnd = {
                            isDragging = false
                            onValueChangeFinished(dragProgress)
                        },
                        onDragCancel = {
                            isDragging = false
                            onValueChangeFinished(dragProgress)
                        },
                    ) { change, _ ->
                        change.consume()
                        val newPct = (change.position.x / size.width.toFloat()).coerceIn(0f, 1f) * 100f
                        dragProgress = newPct
                        onValueChange(newPct)
                    }
                },
            contentAlignment = Alignment.CenterStart,
        ) {
            val fraction = (dragProgress / 100f).coerceIn(0f, 1f)

            Box(
                modifier = Modifier
                    .fillMaxHeight()
                    .fillMaxWidth(fraction.coerceAtLeast(0.02f))
                    .clip(RoundedCornerShape(22.dp))
                    .background(
                        Brush.horizontalGradient(
                            colors = listOf(MatrixGold.copy(alpha = 0.6f), MatrixGold, LiquidCyan),
                        ),
                    ),
            )

            Box(
                modifier = Modifier
                    .fillMaxHeight()
                    .align(Alignment.CenterStart)
                    .padding(start = ((fraction * 0.90f) * 100).coerceAtLeast(0f).dp)
                    .width(36.dp)
                    .clip(CircleShape)
                    .background(
                        Brush.verticalGradient(
                            listOf(Color.White.copy(alpha = 0.95f), MatrixGold.copy(alpha = 0.8f)),
                        ),
                    )
                    .border(1.dp, Color.White, CircleShape),
                contentAlignment = Alignment.Center,
            ) {
                Box(
                    modifier = Modifier
                        .size(8.dp)
                        .clip(CircleShape)
                        .background(DeepSpace),
                )
            }
        }
    }
}

/**
 * Liquid Glass Battery Card
 */
@Composable
fun LiquidGlassBatteryCard(
    batteryState: BatteryState,
    onRefresh: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
) {
    LiquidGlassSurface(
        modifier = modifier,
        tint = if (batteryState.percentage < 20) AlertRed else IntegrityGreen,
        alpha = 0.16f,
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column {
                Text(
                    text = "HOST BATTERY STATUS",
                    style = MaterialTheme.typography.labelSmall,
                    color = if (batteryState.percentage < 20) AlertRed else IntegrityGreen,
                    fontWeight = FontWeight.Bold,
                    letterSpacing = 1.2.sp,
                )
                Text(
                    text = if (batteryState.isCharging) "Charging • Health: ${batteryState.health}" else "On Battery • Health: ${batteryState.health}",
                    style = MaterialTheme.typography.labelSmall,
                    color = TextSecondary,
                    fontSize = 11.sp,
                )
            }

            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(10.dp))
                        .background((if (batteryState.percentage < 20) AlertRed else IntegrityGreen).copy(alpha = 0.15f))
                        .border(0.5.dp, (if (batteryState.percentage < 20) AlertRed else IntegrityGreen).copy(alpha = 0.3f), RoundedCornerShape(10.dp))
                        .padding(horizontal = 10.dp, vertical = 4.dp),
                ) {
                    Text(
                        text = "${batteryState.percentage}%",
                        style = MaterialTheme.typography.labelMedium,
                        color = TextPrimary,
                        fontWeight = FontWeight.ExtraBold,
                    )
                }

                IconButton(
                    onClick = onRefresh,
                    enabled = enabled,
                    modifier = Modifier
                        .size(32.dp)
                        .clip(CircleShape)
                        .background(SurfaceElevated.copy(alpha = 0.5f)),
                ) {
                    Icon(
                        imageVector = Icons.Default.Refresh,
                        contentDescription = "Refresh Battery",
                        tint = LiquidCyan,
                        modifier = Modifier.size(16.dp),
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(14.dp))

        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(10.dp)
                .clip(RoundedCornerShape(5.dp))
                .background(SurfaceElevated),
        ) {
            Box(
                modifier = Modifier
                    .fillMaxHeight()
                    .fillMaxWidth((batteryState.percentage / 100f).coerceIn(0f, 1f))
                    .clip(RoundedCornerShape(5.dp))
                    .background(
                        if (batteryState.percentage < 20) AlertRed
                        else if (batteryState.isCharging) LiquidCyan
                        else IntegrityGreen,
                    ),
            )
        }
    }
}

/**
 * Liquid Glass Power Plan Card
 */
@Composable
fun LiquidGlassPowerPlanCard(
    powerPlans: List<PowerPlanInfo>,
    onSelectPlan: (String) -> Unit,
    onRefresh: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
) {
    LiquidGlassSurface(
        modifier = modifier,
        tint = LiquidCyan,
        alpha = 0.14f,
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column {
                Text(
                    text = "POWER PLAN CONFIGURATION",
                    style = MaterialTheme.typography.labelSmall,
                    color = LiquidCyan,
                    fontWeight = FontWeight.Bold,
                    letterSpacing = 1.2.sp,
                )
                Text(
                    text = "Windows Host Power Profiles",
                    style = MaterialTheme.typography.labelSmall,
                    color = TextSecondary,
                    fontSize = 11.sp,
                )
            }

            IconButton(
                onClick = onRefresh,
                enabled = enabled,
                modifier = Modifier
                    .size(32.dp)
                    .clip(CircleShape)
                    .background(SurfaceElevated.copy(alpha = 0.5f)),
            ) {
                Icon(
                    imageVector = Icons.Default.Refresh,
                    contentDescription = "Refresh Power Plans",
                    tint = LiquidCyan,
                    modifier = Modifier.size(16.dp),
                )
            }
        }

        Spacer(modifier = Modifier.height(14.dp))

        val displayPlans = powerPlans.ifEmpty {
            listOf(
                PowerPlanInfo("balanced", "Balanced", isActive = true),
                PowerPlanInfo("high_performance", "High Performance", isActive = false),
                PowerPlanInfo("power_saver", "Power Saver", isActive = false),
            )
        }

        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            displayPlans.forEach { plan ->
                val haptic = LocalHapticFeedback.current
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(16.dp))
                        .background(
                            if (plan.isActive) LiquidCyan.copy(alpha = 0.18f)
                            else SurfaceElevated.copy(alpha = 0.4f),
                        )
                        .border(
                            width = 0.5.dp,
                            color = if (plan.isActive) LiquidCyan else GlassBorder,
                            shape = RoundedCornerShape(16.dp),
                        )
                        .clickable(enabled = enabled && !plan.isActive) {
                            haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                            onSelectPlan(plan.id)
                        }
                        .padding(horizontal = 16.dp, vertical = 12.dp),
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(
                            text = plan.name,
                            style = MaterialTheme.typography.bodyMedium,
                            color = if (plan.isActive) LiquidCyan else TextPrimary,
                            fontWeight = if (plan.isActive) FontWeight.Bold else FontWeight.Normal,
                        )
                        if (plan.isActive) {
                            Box(
                                modifier = Modifier
                                    .clip(RoundedCornerShape(8.dp))
                                    .background(LiquidCyan.copy(alpha = 0.2f))
                                    .padding(horizontal = 8.dp, vertical = 2.dp),
                            ) {
                                Text(
                                    text = "ACTIVE",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = LiquidCyan,
                                    fontSize = 10.sp,
                                    fontWeight = FontWeight.Bold,
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}


// Helpers
private fun formatMillis(ms: Long): String {
    val totalSeconds = (ms / 1000).coerceAtLeast(0)
    val minutes = totalSeconds / 60
    val seconds = totalSeconds % 60
    return String.format(Locale.US, "%d:%02d", minutes, seconds)
}

private fun getAppIcon(name: String): ImageVector {
    return when (name.lowercase()) {
        "calculator" -> Icons.Default.Calculate
        "folder", "explorer" -> Icons.Default.Folder
        "public", "internet", "browser" -> Icons.Default.Public
        "music_note", "spotify", "media" -> Icons.Default.MusicNote
        "terminal", "cmd", "developer" -> Icons.Default.Terminal
        "analytics", "taskmgr" -> Icons.Default.Analytics
        "description", "notepad" -> Icons.Default.Description
        "settings" -> Icons.Default.Settings
        "code", "vscode" -> Icons.Default.Code
        else -> Icons.Default.Apps
    }
}
