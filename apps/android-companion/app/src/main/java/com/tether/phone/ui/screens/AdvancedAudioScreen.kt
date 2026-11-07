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

    var appSessions by remember { mutableStateOf<List<AppAudioSessionItem>>(emptyList()) }
    var audioDevices by remember { mutableStateOf<List<AudioDeviceItem>>(emptyList()) }
    var isMasterMuted by remember { mutableStateOf(false) }
    var isMicMuted by remember { mutableStateOf(false) }
    var micGain by remember { mutableIntStateOf(50) }
    var masterVolume by remember { mutableIntStateOf(50) }

    var showDeviceDialog by remember { mutableStateOf(false) }

    DisposableEffect(context) {
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

                        val sessionsJson = intent.getStringExtra("sessionsJson") ?: "[]"
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
                        } catch (_: Exception) {}

                        val devicesJson = intent.getStringExtra("devicesJson") ?: "[]"
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
                        } catch (_: Exception) {}
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

        onDispose {
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
                                            val b = Base64.decode(mediaThumbnailB64, Base64.DEFAULT)
                                            BitmapFactory.decodeByteArray(b, 0, b.size)
                                        } catch (_: Exception) { null }
                                    } else null
                                }

                                if (thumbBitmap != null) {
                                    Image(
                                        bitmap = thumbBitmap.asImageBitmap(),
                                        contentDescription = "Album Art",
                                        modifier = Modifier
                                            .size(72.dp)
                                            .clip(RoundedCornerShape(14.dp))
                                    )
                                } else {
                                    Box(
                                        modifier = Modifier
                                            .size(72.dp)
                                            .clip(RoundedCornerShape(14.dp))
                                            .background(SurfaceElevated),
                                        contentAlignment = Alignment.Center
                                    ) {
                                        Icon(Icons.Default.MusicNote, contentDescription = null, tint = LiquidCyan, modifier = Modifier.size(36.dp))
                                    }
                                }

                                Spacer(modifier = Modifier.width(16.dp))

                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        if (mediaTitle.isNotEmpty()) mediaTitle else "No Media Active",
                                        color = TextPrimary,
                                        fontWeight = FontWeight.Bold,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis,
                                        style = MaterialTheme.typography.titleMedium
                                    )
                                    Spacer(modifier = Modifier.height(4.dp))
                                    Text(
                                        if (mediaArtist.isNotEmpty()) mediaArtist else "Windows Media Session",
                                        color = TextSecondary,
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

                            // Playback timeline slider
                            if (mediaDuration > 0L) {
                                Slider(
                                    value = mediaPosition.toFloat(),
                                    onValueChange = { mediaPosition = it.toLong() },
                                    onValueChangeFinished = {
                                        service?.sendMediaControl("SEEK", mediaPosition)
                                    },
                                    valueRange = 0f..mediaDuration.toFloat(),
                                    colors = SliderDefaults.colors(
                                        thumbColor = LiquidCyan,
                                        activeTrackColor = LiquidCyan,
                                        inactiveTrackColor = SurfaceElevated
                                    )
                                )
                            }

                            // Controls Row
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceEvenly,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                IconButton(onClick = { service?.sendMediaControl("PREVIOUS") }) {
                                    Icon(Icons.Default.SkipPrevious, contentDescription = "Previous Track", tint = TextPrimary)
                                }
                                Box(
                                    modifier = Modifier
                                        .size(52.dp)
                                        .clip(CircleShape)
                                        .background(LiquidCyan)
                                        .clickable {
                                            service?.sendMediaControl(if (isPlaying) "PAUSE" else "PLAY")
                                            isPlaying = !isPlaying
                                        },
                                    contentAlignment = Alignment.Center
                                ) {
                                    Icon(
                                        if (isPlaying) Icons.Default.Pause else Icons.Default.PlayArrow,
                                        contentDescription = "Play / Pause",
                                        tint = DeepSpace,
                                        modifier = Modifier.size(30.dp)
                                    )
                                }
                                IconButton(onClick = { service?.sendMediaControl("NEXT") }) {
                                    Icon(Icons.Default.SkipNext, contentDescription = "Next Track", tint = TextPrimary)
                                }
                            }
                        }
                    }
                }

                // Microphone Control Card
                item {
                    ProfessionalGlassSurface(modifier = Modifier.fillMaxWidth()) {
                        Column(modifier = Modifier.padding(18.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Icon(Icons.Default.Mic, contentDescription = null, tint = LiquidCyan)
                                    Spacer(modifier = Modifier.width(10.dp))
                                    Text("Microphone Input", color = TextPrimary, fontWeight = FontWeight.SemiBold)
                                }
                                IconButton(
                                    onClick = {
                                        isMicMuted = !isMicMuted
                                        service?.sendSetMicMute(isMicMuted)
                                    }
                                ) {
                                    Icon(
                                        if (isMicMuted) Icons.Default.MicOff else Icons.Default.Mic,
                                        contentDescription = "Mic Mute",
                                        tint = if (isMicMuted) AlertRed else IntegrityGreen
                                    )
                                }
                            }
                            Spacer(modifier = Modifier.height(8.dp))
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text("Gain: ${micGain}%", color = TextSecondary, style = MaterialTheme.typography.bodySmall)
                                Spacer(modifier = Modifier.width(12.dp))
                                Slider(
                                    value = micGain.toFloat(),
                                    onValueChange = { micGain = it.toInt() },
                                    onValueChangeFinished = { service?.sendSetMicGain(micGain) },
                                    valueRange = 0f..100f,
                                    modifier = Modifier.weight(1f),
                                    colors = SliderDefaults.colors(
                                        thumbColor = LiquidCyan,
                                        activeTrackColor = LiquidCyan,
                                        inactiveTrackColor = SurfaceElevated
                                    )
                                )
                            }
                        }
                    }
                }

                // Per-Application Volume Header
                item {
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text(
                            "Per-App Audio Sessions",
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
                                    onValueChange = { vol = it.toInt() },
                                    onValueChangeFinished = { service?.sendSetAppVolume(app.pid, vol) },
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
            title = { Text("Audio Endpoint Devices", color = TextPrimary) },
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
