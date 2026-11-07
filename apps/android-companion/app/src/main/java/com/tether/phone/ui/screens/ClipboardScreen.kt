package com.tether.phone.ui.screens

import android.content.BroadcastReceiver
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import com.tether.phone.TetherLanService
import com.tether.phone.ui.components.DeepSpaceCanvasVisualizer
import com.tether.phone.ui.components.ProfessionalGlassSurface
import com.tether.phone.ui.theme.*
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

data class ClipboardHistoryItem(
    val content: String,
    val source: String, // "WINDOWS" or "PHONE"
    val timestamp: Long
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ClipboardScreen(
    onBack: () -> Unit
) {
    val context = LocalContext.current
    val service = TetherLanService.instance
    val clipboardManager = LocalClipboardManager.current

    val prefs = remember { context.getSharedPreferences("tether_clipboard_prefs", Context.MODE_PRIVATE) }
    var isLiveSyncEnabled by remember { mutableStateOf(prefs.getBoolean("live_sync_enabled", true)) }

    var latestWindowsClipboard by remember { mutableStateOf("") }
    var historyItems by remember { mutableStateOf<List<ClipboardHistoryItem>>(emptyList()) }
    var phoneClipboardText by remember { mutableStateOf("") }

    // Read phone clipboard initially
    LaunchedEffect(Unit) {
        val sysCb = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
        val clip = sysCb?.primaryClip
        if (clip != null && clip.itemCount > 0) {
            phoneClipboardText = clip.getItemAt(0).text?.toString() ?: ""
        }
    }

    DisposableEffect(context) {
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(ctx: Context?, intent: Intent?) {
                if (intent?.action == TetherLanService.ACTION_CLIPBOARD_SYNC) {
                    val content = intent.getStringExtra("content") ?: ""
                    val time = intent.getLongExtra("timestamp", System.currentTimeMillis())
                    if (content.isNotEmpty()) {
                        latestWindowsClipboard = content
                        historyItems = listOf(ClipboardHistoryItem(content, "WINDOWS", time)) + historyItems.take(49)
                    }
                }
            }
        }

        val filter = IntentFilter(TetherLanService.ACTION_CLIPBOARD_SYNC)
        ContextCompat.registerReceiver(context, receiver, filter, ContextCompat.RECEIVER_NOT_EXPORTED)

        onDispose {
            try { context.unregisterReceiver(receiver) } catch (_: Exception) {}
        }
    }

    Box(modifier = Modifier.fillMaxSize()) {
        DeepSpaceCanvasVisualizer()

        Scaffold(
            topBar = {
                TopAppBar(
                    title = { Text("Clipboard Sync", color = TextPrimary, fontWeight = FontWeight.SemiBold) },
                    navigationIcon = {
                        IconButton(onClick = onBack) {
                            Icon(Icons.Default.ArrowBack, contentDescription = "Back", tint = TextPrimary)
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
                // Live Sync Switch Card
                item {
                    ProfessionalGlassSurface(modifier = Modifier.fillMaxWidth()) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(18.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text("Live Synchronization", color = TextPrimary, fontWeight = FontWeight.Bold)
                                Spacer(modifier = Modifier.height(2.dp))
                                Text("Bidirectional real-time clipboard sharing", color = TextSecondary, style = MaterialTheme.typography.bodySmall)
                            }
                            Switch(
                                checked = isLiveSyncEnabled,
                                onCheckedChange = { checked ->
                                    isLiveSyncEnabled = checked
                                    prefs.edit().putBoolean("live_sync_enabled", checked).apply()
                                },
                                colors = SwitchDefaults.colors(
                                    checkedThumbColor = LiquidCyan,
                                    checkedTrackColor = LiquidCyanMuted,
                                    uncheckedThumbColor = TextMuted,
                                    uncheckedTrackColor = SurfaceElevated
                                )
                            )
                        }
                    }
                }

                // Remote Command Shortcuts
                item {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Button(
                            onClick = { service?.sendRemoteCopy() },
                            modifier = Modifier.weight(1f),
                            colors = ButtonDefaults.buttonColors(containerColor = SurfaceElevated),
                            shape = RoundedCornerShape(14.dp),
                            border = androidx.compose.foundation.BorderStroke(1.dp, GlassBorder)
                        ) {
                            Icon(Icons.Default.ContentCopy, contentDescription = null, tint = LiquidCyan, modifier = Modifier.size(18.dp))
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Remote Copy", color = TextPrimary, fontSize = 12.sp)
                        }

                        Button(
                            onClick = { service?.sendRemotePaste() },
                            modifier = Modifier.weight(1f),
                            colors = ButtonDefaults.buttonColors(containerColor = SurfaceElevated),
                            shape = RoundedCornerShape(14.dp),
                            border = androidx.compose.foundation.BorderStroke(1.dp, GlassBorder)
                        ) {
                            Icon(Icons.Default.ContentPaste, contentDescription = null, tint = IntegrityGreen, modifier = Modifier.size(18.dp))
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Remote Paste", color = TextPrimary, fontSize = 12.sp)
                        }
                    }
                }

                // Phone Clipboard Preview Card
                item {
                    ProfessionalGlassSurface(modifier = Modifier.fillMaxWidth()) {
                        Column(modifier = Modifier.padding(18.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Icon(Icons.Default.PhoneAndroid, contentDescription = null, tint = LiquidCyan)
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Text("Phone Clipboard", color = TextPrimary, fontWeight = FontWeight.SemiBold)
                                }
                                TextButton(onClick = {
                                    if (phoneClipboardText.isNotEmpty()) {
                                        service?.sendClipboardSyncFrame(phoneClipboardText)
                                        historyItems = listOf(
                                            ClipboardHistoryItem(phoneClipboardText, "PHONE", System.currentTimeMillis())
                                        ) + historyItems.take(49)
                                    }
                                }) {
                                    Icon(Icons.Default.Upload, contentDescription = null, tint = LiquidCyan, modifier = Modifier.size(16.dp))
                                    Spacer(modifier = Modifier.width(4.dp))
                                    Text("Push to PC", color = LiquidCyan, fontSize = 12.sp)
                                }
                            }
                            Spacer(modifier = Modifier.height(8.dp))
                            Text(
                                if (phoneClipboardText.isNotEmpty()) phoneClipboardText else "No text currently on phone clipboard",
                                color = if (phoneClipboardText.isNotEmpty()) TextPrimary else TextMuted,
                                style = MaterialTheme.typography.bodyMedium,
                                maxLines = 4,
                                overflow = TextOverflow.Ellipsis
                            )
                        }
                    }
                }

                // Windows Host Clipboard Preview Card
                item {
                    ProfessionalGlassSurface(modifier = Modifier.fillMaxWidth()) {
                        Column(modifier = Modifier.padding(18.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Icon(Icons.Default.Laptop, contentDescription = null, tint = IntegrityGreen)
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Text("Windows Host Clipboard", color = TextPrimary, fontWeight = FontWeight.SemiBold)
                                }
                                TextButton(onClick = {
                                    if (latestWindowsClipboard.isNotEmpty()) {
                                        clipboardManager.setText(AnnotatedString(latestWindowsClipboard))
                                        phoneClipboardText = latestWindowsClipboard
                                    }
                                }) {
                                    Icon(Icons.Default.Download, contentDescription = null, tint = IntegrityGreen, modifier = Modifier.size(16.dp))
                                    Spacer(modifier = Modifier.width(4.dp))
                                    Text("Copy to Phone", color = IntegrityGreen, fontSize = 12.sp)
                                }
                            }
                            Spacer(modifier = Modifier.height(8.dp))
                            Text(
                                if (latestWindowsClipboard.isNotEmpty()) latestWindowsClipboard else "Awaiting clipboard content from Windows...",
                                color = if (latestWindowsClipboard.isNotEmpty()) TextPrimary else TextMuted,
                                style = MaterialTheme.typography.bodyMedium,
                                maxLines = 4,
                                overflow = TextOverflow.Ellipsis
                            )
                        }
                    }
                }

                // History Header
                item {
                    Text(
                        "Recent Clipboard History",
                        color = TextPrimary,
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.padding(top = 8.dp)
                    )
                }

                if (historyItems.isEmpty()) {
                    item {
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 20.dp),
                            contentAlignment = Alignment.Center
                        ) {
                            Text("No recent synchronized items.", color = TextMuted, style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }

                items(historyItems) { item ->
                    val dateStr = remember(item.timestamp) {
                        SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date(item.timestamp))
                    }
                    ProfessionalGlassSurface(modifier = Modifier.fillMaxWidth()) {
                        Row(
                            modifier = Modifier.padding(14.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(
                                if (item.source == "WINDOWS") Icons.Default.Laptop else Icons.Default.PhoneAndroid,
                                contentDescription = null,
                                tint = if (item.source == "WINDOWS") IntegrityGreen else LiquidCyan,
                                modifier = Modifier.size(20.dp)
                            )
                            Spacer(modifier = Modifier.width(12.dp))
                            Column(modifier = Modifier.weight(1f)) {
                                Text(item.content, color = TextPrimary, maxLines = 2, overflow = TextOverflow.Ellipsis, style = MaterialTheme.typography.bodySmall)
                                Spacer(modifier = Modifier.height(2.dp))
                                Text("${item.source} • $dateStr", color = TextMuted, style = MaterialTheme.typography.labelSmall)
                            }
                            IconButton(onClick = {
                                clipboardManager.setText(AnnotatedString(item.content))
                            }) {
                                Icon(Icons.Default.ContentCopy, contentDescription = "Copy Item", tint = TextSecondary, modifier = Modifier.size(18.dp))
                            }
                        }
                    }
                }
            }
        }
    }
}
