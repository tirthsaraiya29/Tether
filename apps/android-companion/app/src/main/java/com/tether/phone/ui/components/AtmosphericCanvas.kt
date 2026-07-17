package com.tether.phone.ui.components

import androidx.compose.animation.core.*
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.dp
import com.tether.phone.ui.theme.*

/**
 * Deep Space Atmospheric Canvas Visualizer
 * Professional grade background with complex refractive layers, nebula glows, and shimmering starfields.
 */
@Composable
fun DeepSpaceCanvasVisualizer() {
    val density = LocalDensity.current
    val gridStep = remember { with(density) { 60.dp.toPx() } }

    val transition = rememberInfiniteTransition(label = "Atmosphere")
    val shift by transition.animateFloat(
        initialValue = 0f,
        targetValue = gridStep,
        animationSpec = infiniteRepeatable(
            animation = tween(25000, easing = LinearEasing)
        ), label = "Shift"
    )
    val nebAlpha by transition.animateFloat(
        initialValue = 0.04f,
        targetValue = 0.18f,
        animationSpec = infiniteRepeatable(
            animation = tween(15000, easing = TetherEase),
            repeatMode = RepeatMode.Reverse
        ), label = "Nebula"
    )
    val starShimmer by transition.animateFloat(
        initialValue = 0.1f,
        targetValue = 0.6f,
        animationSpec = infiniteRepeatable(
            animation = tween(4000, easing = TetherEase),
            repeatMode = RepeatMode.Reverse
        ), label = "Stars"
    )

    Canvas(modifier = Modifier.fillMaxSize()) {
        drawRect(color = DeepSpace)

        // Refractive Mesh Grid with dynamic distortion
        var x = (shift % gridStep) - gridStep
        while (x < (size.width + gridStep)) {
            val distortion = kotlin.math.sin((x + shift) / 150.0).toFloat() * 6f
            drawLine(
                color = LiquidCyan.copy(alpha = 0.04f),
                start = Offset(x + distortion, 0f),
                end = Offset(x + distortion, size.height),
                strokeWidth = 0.5.dp.toPx()
            )
            x += gridStep
        }
        var y = (shift % gridStep) - gridStep
        while (y < (size.height + gridStep)) {
            val distortion = kotlin.math.cos((y + shift) / 150.0).toFloat() * 6f
            drawLine(
                color = LiquidCyan.copy(alpha = 0.04f),
                start = Offset(0f, y + distortion),
                end = Offset(size.width, y + distortion),
                strokeWidth = 0.5.dp.toPx()
            )
            y += gridStep
        }

        // Nebula Plasma Core 1 (Cyan - Top Left)
        drawCircle(
            brush = Brush.radialGradient(
                0.0f to LiquidCyan.copy(alpha = nebAlpha),
                0.6f to LiquidCyan.copy(alpha = nebAlpha * 0.3f),
                1.0f to Color.Transparent,
                center = Offset(size.width * 0.2f, size.height * 0.2f),
                radius = 1200.dp.toPx()
            ),
            center = Offset(size.width * 0.2f, size.height * 0.2f),
            radius = 1200.dp.toPx()
        )

        // Nebula Plasma Core 2 (Green - Bottom Right)
        drawCircle(
            brush = Brush.radialGradient(
                0.0f to IntegrityGreen.copy(alpha = nebAlpha * 0.7f),
                0.7f to IntegrityGreen.copy(alpha = nebAlpha * 0.1f),
                1.0f to Color.Transparent,
                center = Offset(size.width * 0.8f, size.height * 0.8f),
                radius = 1000.dp.toPx()
            ),
            center = Offset(size.width * 0.8f, size.height * 0.8f),
            radius = 1000.dp.toPx()
        )

        // Nebula Plasma Core 3 (Subtle Red - Center Right)
        drawCircle(
            brush = Brush.radialGradient(
                0.0f to AlertRed.copy(alpha = nebAlpha * 0.4f),
                0.8f to Color.Transparent,
                center = Offset(size.width * 0.9f, size.height * 0.4f),
                radius = 800.dp.toPx()
            ),
            center = Offset(size.width * 0.9f, size.height * 0.4f),
            radius = 800.dp.toPx()
        )

        // High-Density Starfield
        val rnd = java.util.Random(42)
        repeat(60) {
            val px = rnd.nextFloat() * size.width
            val py = rnd.nextFloat() * size.height
            val radius = rnd.nextFloat() * 1.8.dp.toPx()
            val individualShimmer = rnd.nextFloat() * starShimmer
            drawCircle(
                color = Color.White.copy(alpha = individualShimmer),
                radius = radius,
                center = Offset(px, py)
            )
        }
    }
}

