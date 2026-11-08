package com.tether.phone.ui.screens

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.graphics.BitmapFactory
import android.util.Base64
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import com.tether.phone.*
import com.tether.phone.ui.components.DeepSpaceCanvasVisualizer
import com.tether.phone.ui.components.ProfessionalGlassSurface
import com.tether.phone.ui.theme.*
import org.json.JSONArray

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AdvancedAudioScreen(
    onBack: () -> Unit
) {
    val context = LocalContext.current
    val service = TetherLanService.instance

    var mediaTitle by remember { mutableStateOf("") }
    var mediaArtist by remember { mutableStateOf("") }
    var mediaAlbum by remember { mutableStateOf("") }
    var isPlaying by remember { mutableStateOf(false) }
    var mediaPosition by remember { mutableLongStateOf(0L) }
    var mediaDuration by remember { mutableLongStateOf(0L) }
    var mediaThumbnailB64 by remember { mutableStateOf("") }

    // Instant initialisation from persistent cache
    var appSessions by remember { mutableStateOf(LaptopStateCache.getAudioSessions(context)) }
    var audioDevices by remember { mutableStateOf(LaptopStateCache.getAudioDevices(context)) }
    var isMasterMuted by remember { mutableStateOf(false) }
    var isMicMuted by remember { mutableStateOf(false) }
    var micGain by remember { mutableIntStateOf(50) }
    var masterVolume by remember { mutableIntStateOf(50) }

    var showDeviceDialog by remember { mutableStateOf(false) }

    DisposableEffect(context) {
        service?.currentActiveScreen = "AdvancedAudio"

        val receiver = object : BroadcastReceiver() {
            override fun onReceive(ctx: Context?, intent: Intent?) {
                when (intent?.action) {
                    TetherLanService.ACTION_MEDIA_UPDATE -> {
                        mediaTitle = intent.getStringExtra("title") ?: ""
                        mediaArtist = intent.getStringExtra("artist") ?: ""
                        mediaAlbum = intent.getStringExtra("album") ?: ""
                        isPlaying = intent.getBooleanExtra("isPlaying", false)
                        mediaPosition = intent.getLongExtra("position", 0L)
                        mediaDuration = intent.getLongExtra("duration", 0L)
                        mediaThumbnailB64 = intent.getStringExtra("thumbnail") ?: ""
                    }
                    TetherLanService.ACTION_AUDIO_SESSIONS_UPDATE -> {
                        isMasterMuted = intent.getBooleanExtra("masterMuted", false)
                        isMicMuted = intent.getBooleanExtra("micMuted", false)
                        micGain = intent.getIntExtra("micGain", 50)

                        val sessionsJson = intent.getStringExtra("sessionsJson")
                        if (!sessionsJson.isNullOrBlank() && sessionsJson != "[]") {
                            try {
                                val arr = JSONArray(sessionsJson)
                                val list = mutableListOf<AppAudioSessionItem>()
                                for (i in 0 until arr.length()) {
                                    val obj = arr.getJSONObject(i)
                                    list.add(
                                        AppAudioSessionItem(
                                            pid = obj.optInt("pid", 0),
                                            processName = obj.optString("processName", "Application"),
                                            volumePercent = obj.optInt("volumePercent", 50),
                                            isMuted = obj.optBoolean("isMuted", false)
                                        )
                                    )
                                }
                                appSessions = list
                                LaptopStateCache.saveAudioSessions(context, list)
                            } catch (_: Exception) {}
                        }

                        val devicesJson = intent.getStringExtra("devicesJson")
                        if (!devicesJson.isNullOrBlank() && devicesJson != "[]") {
                            try {
                                val arr = JSONArray(devicesJson)
                                val list = mutableListOf<AudioDeviceItem>()
                                for (i in 0 until arr.length()) {
                                    val obj = arr.getJSONObject(i)
                                    list.add(
                                        AudioDeviceItem(
                                            id = obj.optString("id", ""),
                                            name = obj.optString("name", "Audio Device"),
                                            isDefault = obj.optBoolean("isDefault", false),
                                            isInput = obj.optBoolean("isInput", false)
                                        )
                                    )
                                }
                                audioDevices = list
                                LaptopStateCache.saveAudioDevices(context, list)
                            } catch (_: Exception) {}
                        }
                    }
                }
            }
        }

        val filter = IntentFilter().apply {
            addAction(TetherLanService.ACTION_MEDIA_UPDATE)
            addAction(TetherLanService.ACTION_AUDIO_SESSIONS_UPDATE)
        }
        ContextCompat.registerReceiver(context, receiver, filter, ContextCompat.RECEIVER_NOT_EXPORTED)

        // Request initial audio refresh
        service?.sendMediaControl("GET_METADATA")
        service?.requestAudioSessions()
        service?.requestAudioDevices()
        service?.requestMicState()

        onDispose {
            service?.currentActiveScreen = null
            try { context.unregisterReceiver(receiver) } catch (_: Exception) {}
        }
    }

    Box(modifier = Modifier.fillMaxSize()) {
        DeepSpaceCanvasVisualizer()

        Scaffold(
            topBar = {
                TopAppBar(
                    title = { Text("Audio & Media Deck", color = TextPrimary, fontWeight = FontWeight.SemiBold) },
                    navigationIcon = {
                        IconButton(onClick = onBack) {
                            Icon(Icons.Default.ArrowBack, contentDescription = "Back", tint = TextPrimary)
                        }
                    },
                    actions = {
                        IconButton(onClick = {
                            service?.requestAudioSessions()
                            service?.requestAudioDevices()
                            service?.sendMediaControl("GET_METADATA")
                        }) {
                            Icon(Icons.Default.Refresh, contentDescription = "Refresh", tint = LiquidCyan)
                        }
                        IconButton(onClick = { showDeviceDialog = true }) {
                            Icon(Icons.Default.Speaker, contentDescription = "Audio Devices", tint = LiquidCyan)
                        }
                    },
                    colors = TopAppBarDefaults.topAppBarColors(containerColor = Color.Transparent)
                )
            },
            containerColor = Color.Transparent
        ) { padding ->
            LazyColumn(
                modifier = Modifier
                    .padding(padding)
                    .fillMaxSize()
                    .padding(horizontal = 20.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                // Now Playing Media Card
                item {
                    ProfessionalGlassSurface(
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(modifier = Modifier.padding(20.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                // Thumbnail Art
                                val thumbBitmap = remember(mediaThumbnailB64) {
                                    if (mediaThumbnailB64.isNotEmpty()) {
                                        try {
                                            val bytes = Base64.decode(mediaThumbnailB64, Base64.DEFAULT)
                                            BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
                                        } catch (_: Exception) {
                                            null
                                        }
                                    } else null
                                }

                                if (thumbBitmap != null) {
                                    Image(
                                        bitmap = thumbBitmap.asImageBitmap(),
                                        contentDescription = "Media Artwork",
                                        modifier = Modifier
                                            .size(72.dp)
                                            .clip(RoundedCornerShape(12.dp))
                                            .border(1.dp, GlassBorder, RoundedCornerShape(12.dp))
                                    )
                                } else {
                                    Box(
                                        modifier = Modifier
                                            .size(72.dp)
                                            .clip(RoundedCornerShape(12.dp))
                                            .background(SurfaceElevated),
                                        contentAlignment = Alignment.Center
                                    ) {
                                        Icon(
                                            Icons.Default.MusicNote,
                                            contentDescription = null,
                                            tint = LiquidCyan,
                                            modifier = Modifier.size(36.dp)
                                        )
                                    }
                                }

                                Spacer(modifier = Modifier.width(16.dp))

                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        if (mediaTitle.isNotEmpty()) mediaTitle else "No Active Media",
                                        color = TextPrimary,
                                        fontWeight = FontWeight.Bold,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis,
                                        style = MaterialTheme.typography.titleMedium
                                    )
                                    Spacer(modifier = Modifier.height(4.dp))
                                    Text(
                                        if (mediaArtist.isNotEmpty()) mediaArtist else "Windows Media Session",
                                        color = LiquidCyan,
                                        style = MaterialTheme.typography.bodySmall,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis
                                    )
                                    if (mediaAlbum.isNotEmpty()) {
                                        Text(
                                            mediaAlbum,
                                            color = TextMuted,
                                            style = MaterialTheme.typography.labelSmall,
                                            maxLines = 1,
                                            overflow = TextOverflow.Ellipsis
                                        )
                                    }
                                }
                            }

                            Spacer(modifier = Modifier.height(16.dp))

                            // Playback Progress Bar
                            if (mediaDuration > 0) {
                                LinearProgressIndicator(
                                    progress = { (mediaPosition.toFloat() / mediaDuration.toFloat()).coerceIn(0f, 1f) },
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .height(4.dp)
                                        .clip(CircleShape),
                                    color = LiquidCyan,
                                    trackColor = SurfaceElevated
                                )
                                Spacer(modifier = Modifier.height(12.dp))
                            }

                            // Media Transport Controls
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceEvenly,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                IconButton(onClick = { service?.sendMediaControl("PREVIOUS") }) {
                                    Icon(Icons.Default.SkipPrevious, contentDescription = "Previous", tint = TextPrimary)
                                }
                                IconButton(
                                    onClick = { service?.sendMediaControl("PLAY_PAUSE") },
                                    modifier = Modifier
                                        .size(48.dp)
                                        .background(LiquidCyan, CircleShape)
                                ) {
                                    Icon(
                                        if (isPlaying) Icons.Default.Pause else Icons.Default.PlayArrow,
                                        contentDescription = "Play/Pause",
                                        tint = DeepSpace
                                    )
                                }
                                IconButton(onClick = { service?.sendMediaControl("NEXT") }) {
                                    Icon(Icons.Default.SkipNext, contentDescription = "Next", tint = TextPrimary)
                                }
                            }
                        }
                    }
                }

                // Audio Endpoint Hardware Devices Card
                item {
                    val defaultDevice = audioDevices.find { it.isDefault && !it.isInput } ?: audioDevices.firstOrNull { !it.isInput }
                    ProfessionalGlassSurface(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { showDeviceDialog = true }
                    ) {
                        Row(
                            modifier = Modifier.padding(16.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(Icons.Default.SpeakerGroup, contentDescription = null, tint = LiquidCyan)
                            Spacer(modifier = Modifier.width(12.dp))
                            Column(modifier = Modifier.weight(1f)) {
                                Text("Active Audio Output Device", color = TextMuted, style = MaterialTheme.typography.labelSmall)
                                Text(
                                    defaultDevice?.name ?: if (audioDevices.isNotEmpty()) "${audioDevices.size} Endpoints Available" else "Scanning Audio Endpoints...",
                                    color = if (defaultDevice != null) IntegrityGreen else TextPrimary,
                                    fontWeight = FontWeight.SemiBold,
                                    maxLines = 1
                                )
                            }
                            TextButton(onClick = { showDeviceDialog = true }) {
                                Text("Switch (${audioDevices.size})", color = LiquidCyan, fontSize = 12.sp)
                            }
                        }
                    }
                }

                // Master & Mic Quick Controls
                item {
                    ProfessionalGlassSurface(modifier = Modifier.fillMaxWidth()) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(16.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            // Master Volume Mute Toggle
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                IconButton(onClick = {
                                    isMasterMuted = !isMasterMuted
                                    service?.sendSetMasterMute(isMasterMuted)
                                }) {
                                    Icon(
                                        if (isMasterMuted) Icons.Default.VolumeOff else Icons.Default.VolumeUp,
                                        contentDescription = "Master Mute",
                                        tint = if (isMasterMuted) AlertRed else LiquidCyan
                                    )
                                }
                                Spacer(modifier = Modifier.width(8.dp))
                                Column {
                                    Text("Master Audio", color = TextPrimary, fontWeight = FontWeight.SemiBold)
                                    Text(if (isMasterMuted) "MUTED" else "UNMUTED", color = if (isMasterMuted) AlertRed else IntegrityGreen, style = MaterialTheme.typography.labelSmall)
                                }
                            }

                            // Microphone Mute Toggle
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                IconButton(onClick = {
                                    isMicMuted = !isMicMuted
                                    service?.sendSetMicMute(isMicMuted)
                                }) {
                                    Icon(
                                        if (isMicMuted) Icons.Default.MicOff else Icons.Default.Mic,
                                        contentDescription = "Microphone Mute",
                                        tint = if (isMicMuted) AlertRed else IntegrityGreen
                                    )
                                }
                                Spacer(modifier = Modifier.width(8.dp))
                                Column {
                                    Text("Microphone", color = TextPrimary, fontWeight = FontWeight.SemiBold)
                                    Text(if (isMicMuted) "MUTED" else "ACTIVE", color = if (isMicMuted) AlertRed else IntegrityGreen, style = MaterialTheme.typography.labelSmall)
                                }
                            }
                        }
                    }
                }

                // Per-Application Audio Sessions Header
                item {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            "Per-Application Audio Mixer",
                            color = TextPrimary,
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            "${appSessions.size} Active",
                            color = LiquidCyan,
                            style = MaterialTheme.typography.labelSmall
                        )
                    }
                }

                if (appSessions.isEmpty()) {
                    item {
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 24.dp),
                            contentAlignment = Alignment.Center
                        ) {
                            Text("No active per-application audio streams detected.", color = TextMuted, style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }

                // Per-Application Items
                items(appSessions) { app ->
                    var vol by remember(app.volumePercent) { mutableIntStateOf(app.volumePercent) }
                    var muted by remember(app.isMuted) { mutableStateOf(app.isMuted) }
                    var lastSentMs by remember { mutableLongStateOf(0L) }

                    ProfessionalGlassSurface(modifier = Modifier.fillMaxWidth()) {
                        Row(
                            modifier = Modifier.padding(16.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(Icons.Default.VolumeUp, contentDescription = null, tint = LiquidCyan)
                            Spacer(modifier = Modifier.width(12.dp))
                            Column(modifier = Modifier.weight(1f)) {
                                Text(app.processName, color = TextPrimary, fontWeight = FontWeight.SemiBold, maxLines = 1)
                                Text("${vol}%", color = TextSecondary, style = MaterialTheme.typography.labelSmall)
                                Slider(
                                    value = vol.toFloat(),
                                    onValueChange = {
                                        val newVol = it.toInt()
                                        vol = newVol
                                        val now = System.currentTimeMillis()
                                        if (now - lastSentMs > 30L) {
                                            lastSentMs = now
                                            service?.sendSetAppVolume(app.pid, newVol)
                                        }
                                    },
                                    onValueChangeFinished = {
                                        service?.sendSetAppVolume(app.pid, vol)
                                    },
                                    valueRange = 0f..100f,
                                    colors = SliderDefaults.colors(
                                        thumbColor = LiquidCyan,
                                        activeTrackColor = LiquidCyan,
                                        inactiveTrackColor = SurfaceElevated
                                    )
                                )
                            }
                            IconButton(
                                onClick = {
                                    muted = !muted
                                    service?.sendSetAppMute(app.pid, muted)
                                }
                            ) {
                                Icon(
                                    if (muted) Icons.Default.VolumeOff else Icons.Default.VolumeUp,
                                    contentDescription = "Mute App",
                                    tint = if (muted) AlertRed else TextSecondary
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    // Audio Devices Selector Dialog
    if (showDeviceDialog) {
        AlertDialog(
            onDismissRequest = { showDeviceDialog = false },
            title = { Text("Audio Endpoint Devices (${audioDevices.size})", color = TextPrimary) },
            text = {
                LazyColumn(modifier = Modifier.fillMaxWidth().heightIn(max = 350.dp)) {
                    if (audioDevices.isEmpty()) {
                        item {
                            Text("No audio devices reported.", color = TextMuted)
                        }
                    }
                    items(audioDevices) { device ->
                        Surface(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable {
                                    service?.sendSetAudioDevice(device.id, device.isInput)
                                    showDeviceDialog = false
                                }
                                .padding(vertical = 8.dp),
                            color = Color.Transparent
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(
                                    if (device.isInput) Icons.Default.Mic else Icons.Default.Speaker,
                                    contentDescription = null,
                                    tint = if (device.isDefault) IntegrityGreen else TextSecondary
                                )
                                Spacer(modifier = Modifier.width(12.dp))
                                Column {
                                    Text(
                                        device.name,
                                        color = if (device.isDefault) IntegrityGreen else TextPrimary,
                                        fontWeight = if (device.isDefault) FontWeight.Bold else FontWeight.Normal
                                    )
                                    Text(
                                        if (device.isDefault) "Default Device" else if (device.isInput) "Recording Input" else "Playback Output",
                                        color = TextMuted,
                                        style = MaterialTheme.typography.bodySmall
                                    )
                                }
                            }
                        }
                        Divider(color = GlassBorder)
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = { showDeviceDialog = false }) {
                    Text("Close", color = LiquidCyan)
                }
            },
            containerColor = SurfaceElevated
        )
    }
}
