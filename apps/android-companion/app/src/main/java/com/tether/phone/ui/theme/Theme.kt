package com.tether.phone.ui.theme

import android.app.Activity
import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat

/**
 * Tether Liquid Glass Theme
 * Implements a modern dark-mode aesthetic with realistic material behaviors.
 */

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
    outline = GlassBorder
)

@Composable
fun TetherTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    // Dynamic color is available on Android 12+
    dynamicColor: Boolean = false,
    content: @Composable () -> Unit
) {
    val colorScheme = when {
        dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            val context = LocalContext.current
            dynamicDarkColorScheme(context)
        }
        else -> LiquidGlassColorScheme
    }

    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as Activity).window
            window.statusBarColor = colorScheme.background.toArgb()
            window.navigationBarColor = colorScheme.background.toArgb()

            val insetsController = WindowCompat.getInsetsController(window, view)
            insetsController.isAppearanceLightStatusBars = false
            insetsController.isAppearanceLightNavigationBars = false
        }
    }

    MaterialTheme(
        colorScheme = colorScheme,
        typography = Typography,
        content = content
    )
}
