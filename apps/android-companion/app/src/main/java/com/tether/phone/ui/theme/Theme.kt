package com.tether.phone.ui.theme

import android.app.Activity
import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.animation.core.CubicBezierEasing
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat

val TetherEase = CubicBezierEasing(0.42f, 0f, 0.58f, 1f)

private val LiquidGlassColorScheme = darkColorScheme(
    primary = LiquidCyan,
    onPrimary = DeepSpace,
    primaryContainer = LiquidCyanMuted,
    onPrimaryContainer = TextPrimary,
    secondary = IntegrityGreen,
    onSecondary = DeepSpace,
    error = AlertRed,
    onError = TextPrimary,
    background = DeepSpace,
    onBackground = TextPrimary,
    surface = Obsidian,
    onSurface = TextPrimary,
    surfaceVariant = SurfaceVeneer,
    onSurfaceVariant = TextSecondary,
    outline = GlassBorder,
)

@Composable
fun TetherTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    dynamicColor: Boolean = false,
    content: @Composable () -> Unit,
) {
    val baseColorScheme = when {
        dynamicColor && (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) -> {
            val context = LocalContext.current
            dynamicDarkColorScheme(context)
        }
        darkTheme -> LiquidGlassColorScheme
        else -> LiquidGlassColorScheme
    }

    val colorScheme = baseColorScheme.copy(
        error = ColorPanic,
    )

    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val activity = view.context as Activity
            val window = activity.window

            val insetsController = WindowCompat.getInsetsController(window, view)
            insetsController.isAppearanceLightStatusBars = false
            insetsController.isAppearanceLightNavigationBars = false
            
            WindowCompat.setDecorFitsSystemWindows(window, false)
        }
    }

    MaterialTheme(
        colorScheme = colorScheme,
        typography = Typography,
        content = content,
    )
}