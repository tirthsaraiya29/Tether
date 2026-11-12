package com.tether.phone.ui.components

import androidx.compose.animation.core.*
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawWithCache
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.dp
import com.tether.phone.ui.theme.*

@Composable
fun DeepSpaceCanvasVisualizer() {
    val density = LocalDensity.current
    val gridStep = remember(density) { with(density) { 60.dp.toPx() } }

    val transition = rememberInfiniteTransition(label = "Atmosphere")
    val shift by transition.animateFloat(
        initialValue = 0f,
        targetValue = gridStep,
        animationSpec = infiniteRepeatable(
            animation = tween(25000, easing = LinearEasing),
        ),
        label = "Shift",
    )
    val starShimmer by transition.animateFloat(
        initialValue = 0.15f,
        targetValue = 0.55f,
        animationSpec = infiniteRepeatable(
            animation = tween(4000, easing = TetherEase),
            repeatMode = RepeatMode.Reverse,
        ),
        label = "Stars",
    )

    val starSeeds = remember {
        val rnd = java.util.Random(42)
        Array(48) {
            floatArrayOf(rnd.nextFloat(), rnd.nextFloat(), rnd.nextFloat(), rnd.nextFloat())
        }
    }

    Canvas(
        modifier = Modifier
            .fillMaxSize()
            .drawWithCache {
                val strokePx = 0.5.dp.toPx()
                val maxStarRadius = 1.8.dp.toPx()
                val neb1 = Brush.radialGradient(
                    0.0f to LiquidCyan.copy(alpha = 0.11f),
                    0.6f to LiquidCyan.copy(alpha = 0.035f),
                    1.0f to Color.Transparent,
                    center = Offset(size.width * 0.2f, size.height * 0.2f),
                    radius = 1200.dp.toPx(),
                )
                val neb2 = Brush.radialGradient(
                    0.0f to IntegrityGreen.copy(alpha = 0.08f),
                    0.7f to IntegrityGreen.copy(alpha = 0.015f),
                    1.0f to Color.Transparent,
                    center = Offset(size.width * 0.8f, size.height * 0.8f),
                    radius = 1000.dp.toPx(),
                )
                val neb3 = Brush.radialGradient(
                    0.0f to AlertRed.copy(alpha = 0.045f),
                    0.8f to Color.Transparent,
                    center = Offset(size.width * 0.9f, size.height * 0.4f),
                    radius = 800.dp.toPx(),
                )
                val gridColor = LiquidCyan.copy(alpha = 0.04f)
                onDrawBehind {
                    drawRect(color = DeepSpace)
                    drawCircle(brush = neb1, center = Offset(size.width * 0.2f, size.height * 0.2f), radius = 1200.dp.toPx())
                    drawCircle(brush = neb2, center = Offset(size.width * 0.8f, size.height * 0.8f), radius = 1000.dp.toPx())
                    drawCircle(brush = neb3, center = Offset(size.width * 0.9f, size.height * 0.4f), radius = 800.dp.toPx())

                    var x = (shift % gridStep) - gridStep
                    while (x < (size.width + gridStep)) {
                        drawLine(
                            color = gridColor,
                            start = Offset(x, 0f),
                            end = Offset(x, size.height),
                            strokeWidth = strokePx,
                        )
                        x += gridStep
                    }
                    var y = (shift % gridStep) - gridStep
                    while (y < (size.height + gridStep)) {
                        drawLine(
                            color = gridColor,
                            start = Offset(0f, y),
                            end = Offset(size.width, y),
                            strokeWidth = strokePx,
                        )
                        y += gridStep
                    }

                    for (star in starSeeds) {
                        drawCircle(
                            color = Color.White.copy(alpha = star[3] * starShimmer),
                            radius = star[2] * maxStarRadius,
                            center = Offset(star[0] * size.width, star[1] * size.height),
                        )
                    }
                }
            },
    ) {}
}