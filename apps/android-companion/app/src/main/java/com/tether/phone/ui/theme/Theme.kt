package com.tether.phone.ui.theme

import android.app.Activity
import android.os.Build
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
            window.statusBarColor = SpaceDark.toArgb()
            window.navigationBarColor = SpaceDark.toArgb()
            WindowCompat.getInsetsController(window, view).isAppearanceLightStatusBars = false
        }
    }

    MaterialTheme(
        colorScheme = colorScheme,
        typography = Typography,
        content = content
    )
}