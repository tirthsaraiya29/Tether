package com.tether.phone.ui.screens

import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.VolumeOff
import androidx.compose.material.icons.automirrored.filled.VolumeUp
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.tether.phone.AppInfo
import com.tether.phone.MediaState
import com.tether.phone.R
import com.tether.phone.defaultWindowsApplications
import com.tether.phone.ui.components.*
import com.tether.phone.ui.theme.*
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlin.math.abs

/**
 * Tether PC Control Screen
 * Houses Master Volume, Master Mute, Generic Media Controls, and Windows Application Launcher.
 * Built with the True Liquid Glass Design System.
 */
@Composable
fun RemoteControlScreen(
    volumeLevel: Float, // 0f..100f
    isMuted: Boolean,
    mediaState: MediaState,
    applications: List<AppInfo>,
    isConnected: Boolean,
    onVolumeChanged: (Float) -> Unit,
    onMuteToggled: () -> Unit,
    onMediaPlayPause: () -> Unit,
    onMediaPrevious: () -> Unit,
    onMediaNext: () -> Unit,
    onLaunchApp: (String) -> Unit,
    onRefreshApps: () -> Unit,
    modifier: Modifier = Modifier
) {
    val scrollState = rememberScrollState()
    val scope = rememberCoroutineScope()

    var searchQuery by remember { mutableStateOf("") }
    var launchingAppId by remember { mutableStateOf<String?>(null) }
    var launchFeedbackJob by remember { mutableStateOf<Job?>(null) }

    val filteredApps = remember(searchQuery, applications) {
        val list = applications.ifEmpty { defaultWindowsApplications }
        if (searchQuery.isBlank()) {
            list
        } else {
            list.filter {
                it.name.contains(searchQuery, ignoreCase = true) ||
                        it.category.contains(searchQuery, ignoreCase = true)
            }
        }
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(scrollState)
            .padding(horizontal = 20.dp, vertical = 12.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        // Status Bar Card
        LiquidGlassSurface(
            modifier = Modifier.fillMaxWidth(),
            tint = if (isConnected) LiquidCyan else AlertRed,
            alpha = 0.12f
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Box(
                        modifier = Modifier
                            .size(10.dp)
                            .clip(CircleShape)
                            .background(if (isConnected) IntegrityGreen else AlertRed)
                    )
                    Column {
                        Text(
                            text = if (isConnected) "ENCRYPTED PC LINK ACTIVE" else "PC OFFLINE / RECONNECTING",
                            style = MaterialTheme.typography.labelMedium,
                            color = if (isConnected) TextPrimary else AlertRed,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = if (isConnected) "Authenticated BLE Transport" else "Commands disabled while offline",
                            style = MaterialTheme.typography.labelSmall,
                            color = TextSecondary,
                            fontSize = 11.sp
                        )
                    }
                }

                IconButton(
                    onClick = onRefreshApps,
                    enabled = isConnected,
                    modifier = Modifier
                        .size(36.dp)
                        .clip(CircleShape)
                        .background(SurfaceElevated.copy(alpha = 0.5f))
                        .border(0.5.dp, GlassBorderBright, CircleShape)
                ) {
                    Icon(
                        imageVector = Icons.Default.Refresh,
                        contentDescription = "Sync State",
                        tint = LiquidCyan,
                        modifier = Modifier.size(18.dp)
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(20.dp))

        // 1. MASTER VOLUME & MUTE CONTROL CARD
        LiquidGlassSurface(
            modifier = Modifier.fillMaxWidth(),
            tint = LiquidCyan,
            alpha = 0.16f
        ) {
            LiquidGlassVolumeSlider(
                value = volumeLevel,
                onValueChange = { localVal ->
                    // Throttled local callback
                    onVolumeChanged(localVal)
                },
                onValueChangeFinished = { finalVal ->
                    onVolumeChanged(finalVal)
                },
                isMuted = isMuted,
                enabled = isConnected
            )

            Spacer(modifier = Modifier.height(20.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                // Mute / Unmute Button
                LiquidGlassButton(
                    text = if (isMuted) "UNMUTE" else "MUTE AUDIO",
                    icon = if (isMuted) Icons.AutoMirrored.Filled.VolumeUp else Icons.AutoMirrored.Filled.VolumeOff,
                    accentColor = if (isMuted) AlertRed else LiquidCyan,
                    isHighlighted = isMuted,
                    enabled = isConnected,
                    onClick = onMuteToggled,
                    modifier = Modifier.weight(1.2f)
                )

                // Quick Presets
                Row(
                    modifier = Modifier.weight(1.8f),
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    listOf(25f, 50f, 75f, 100f).forEach { preset ->
                        Box(
                            modifier = Modifier
                                .weight(1f)
                                .height(52.dp)
                                .clip(RoundedCornerShape(18.dp))
                                .background(SurfaceElevated.copy(alpha = 0.5f))
                                .border(0.5.dp, GlassBorderBright, RoundedCornerShape(18.dp))
                                .border(
                                    width = if (!isMuted && (volumeLevel - preset).let { abs(it) < 5f }) 1.dp else 0.dp,
                                    color = LiquidCyan,
                                    shape = RoundedCornerShape(18.dp)
                                )
                                .padding(vertical = 12.dp),
                            contentAlignment = Alignment.Center
                        ) {
                            Text(
                                text = "${preset.toInt()}%",
                                style = MaterialTheme.typography.labelSmall,
                                color = if (!isMuted && (volumeLevel - preset).let { abs(it) < 5f }) LiquidCyan else TextSecondary,
                                fontWeight = FontWeight.Bold,
                                fontSize = 11.sp,
                                modifier = Modifier.clickable(enabled = isConnected) {
                                    onVolumeChanged(preset)
                                }
                            )
                        }
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(20.dp))

        // 2. GENERIC MEDIA CONTROLS CARD
        LiquidGlassMediaCard(
            mediaState = mediaState,
            onPlayPause = onMediaPlayPause,
            onPrev = onMediaPrevious,
            onNext = onMediaNext,
            enabled = isConnected,
            modifier = Modifier.fillMaxWidth()
        )

        Spacer(modifier = Modifier.height(20.dp))

        // 3. APPLICATION LAUNCHER SECTION
        LiquidGlassSurface(
            modifier = Modifier.fillMaxWidth(),
            tint = IntegrityGreen,
            alpha = 0.14f
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text(
                        text = "WINDOWS APPLICATION LAUNCHER",
                        style = MaterialTheme.typography.labelSmall,
                        color = IntegrityGreen,
                        fontWeight = FontWeight.Bold,
                        letterSpacing = 1.2.sp
                    )
                    Text(
                        text = "Trusted Host Execution",
                        style = MaterialTheme.typography.labelSmall,
                        color = TextSecondary,
                        fontSize = 11.sp
                    )
                }

                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(12.dp))
                        .background(IntegrityGreen.copy(alpha = 0.15f))
                        .border(0.5.dp, IntegrityGreen.copy(alpha = 0.3f), RoundedCornerShape(12.dp))
                        .padding(horizontal = 10.dp, vertical = 4.dp)
                ) {
                    Text(
                        text = "${filteredApps.size} APPS",
                        style = MaterialTheme.typography.labelSmall,
                        color = IntegrityGreen,
                        fontWeight = FontWeight.Bold
                    )
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Search Bar
            LiquidGlassSearchField(
                query = searchQuery,
                onQueryChange = { searchQuery = it },
                placeholder = "Search Windows Applications..."
            )

            Spacer(modifier = Modifier.height(16.dp))

            // Applications List
            if (filteredApps.isEmpty()) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 32.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = "No applications matching search query",
                        style = MaterialTheme.typography.bodyMedium,
                        color = TextMuted
                    )
                }
            } else {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    filteredApps.forEach { app ->
                        LiquidGlassAppCard(
                            app = app,
                            isLaunching = launchingAppId == app.id,
                            enabled = isConnected,
                            onLaunch = { appId ->
                                launchingAppId = appId
                                onLaunchApp(appId)
                                launchFeedbackJob?.cancel()
                                launchFeedbackJob = scope.launch {
                                    delay(2000L)
                                    if (launchingAppId == appId) {
                                        launchingAppId = null
                                    }
                                }
                            }
                        )
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(64.dp))
    }
}
