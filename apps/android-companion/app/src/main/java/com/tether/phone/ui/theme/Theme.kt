package com.tether.phone.ui.theme

import android.app.Activity
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat

private val FuturisticDarkScheme = darkColorScheme(
    primary = NeonCyan,
    secondary = NeonRed,
    tertiary = NeonGreen,
    background = SpaceDark,
    surface = SurfaceDark,
    onPrimary = SpaceDark,
    onSecondary = TextPrimary,
    onTertiary = SpaceDark,
    onBackground = TextPrimary,
    onSurface = TextPrimary
)

@Composable
fun TetherTheme(
    content: @Composable () -> Unit
) {
    val colorScheme = FuturisticDarkScheme
    val view = LocalView.current

    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as Activity).window
            // Modern Window Framework implementation ensuring fully adaptive color pass-through
            window.statusBarColor = android.graphics.Color.TRANSPARENT
            window.navigationBarColor = android.graphics.Color.TRANSPARENT

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