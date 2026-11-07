package com.tether.phone.ui.screens

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.provider.Settings
import androidx.compose.foundation.background
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import com.tether.phone.SyncedNotification
import com.tether.phone.TetherLanService
import com.tether.phone.ui.components.DeepSpaceCanvasVisualizer
import com.tether.phone.ui.components.ProfessionalGlassSurface
import com.tether.phone.ui.theme.*
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NotificationSyncScreen(
    onBack: () -> Unit
) {
    val context = LocalContext.current
    val service = TetherLanService.instance

    val prefs = remember { context.getSharedPreferences("tether_notif_prefs", Context.MODE_PRIVATE) }
    var mirrorPhoneToPc by remember { mutableStateOf(prefs.getBoolean("mirror_phone_to_pc", true)) }

    var notifications by remember { mutableStateOf<List<SyncedNotification>>(emptyList()) }

    var isListenerGranted by remember {
        mutableStateOf(
            NotificationManagerCompat.getEnabledListenerPackages(context).contains(context.packageName)
        )
    }

    DisposableEffect(context) {
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(ctx: Context?, intent: Intent?) {
                if (intent?.action == TetherLanService.ACTION_NOTIFICATION_SYNC) {
                    val action = intent.getStringExtra("action") ?: "POSTED"
                    val id = intent.getLongExtra("id", 0L)
                    val app = intent.getStringExtra("app") ?: "Windows"
                    val title = intent.getStringExtra("title") ?: ""
                    val body = intent.getStringExtra("body") ?: ""
                    val time = intent.getLongExtra("timestamp", System.currentTimeMillis())

                    if (action == "POSTED") {
                        val item = SyncedNotification(
                            id = id,
                            app = app,
                            title = title,
                            body = body,
                            timestamp = time,
                            source = "WINDOWS"
                        )
                        notifications = listOf(item) + notifications.filter { it.id != id }
                    } else if (action == "REMOVED") {
                        notifications = notifications.filter { it.id != id }
                    }
                }
            }
        }

        val filter = IntentFilter(TetherLanService.ACTION_NOTIFICATION_SYNC)
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
                    title = { Text("Notification Bridge", color = TextPrimary, fontWeight = FontWeight.SemiBold) },
                    navigationIcon = {
                        IconButton(onClick = onBack) {
                            Icon(Icons.Default.ArrowBack, contentDescription = "Back", tint = TextPrimary)
                        }
                    },
                    actions = {
                        if (notifications.isNotEmpty()) {
                            IconButton(onClick = { notifications = emptyList() }) {
                                Icon(Icons.Default.ClearAll, contentDescription = "Clear All", tint = TextSecondary)
                            }
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
                // Permission Warning Banner if Listener not active
                if (!isListenerGranted) {
                    item {
                        ProfessionalGlassSurface(
                            modifier = Modifier.fillMaxWidth(),
                            tint = MatrixGold
                        ) {
                            Column(modifier = Modifier.padding(18.dp)) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Icon(Icons.Default.NotificationImportant, contentDescription = null, tint = MatrixGold)
                                    Spacer(modifier = Modifier.width(10.dp))
                                    Text("Notification Access Required", color = TextPrimary, fontWeight = FontWeight.Bold)
                                }
                                Spacer(modifier = Modifier.height(8.dp))
                                Text(
                                    "Android requires explicit permission for Tether to forward incoming phone notifications to your Windows PC.",
                                    color = TextSecondary,
                                    style = MaterialTheme.typography.bodySmall
                                )
                                Spacer(modifier = Modifier.height(12.dp))
                                Button(
                                    onClick = {
                                        context.startActivity(Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS))
                                    },
                                    colors = ButtonDefaults.buttonColors(containerColor = MatrixGold)
                                ) {
                                    Text("Grant Notification Access", color = DeepSpace, fontWeight = FontWeight.Bold)
                                }
                            }
                        }
                    }
                }

                // Settings Switch Card
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
                                Text("Mirror Phone Notifications", color = TextPrimary, fontWeight = FontWeight.SemiBold)
                                Spacer(modifier = Modifier.height(2.dp))
                                Text("Forward phone alerts to Windows desktop toasts", color = TextSecondary, style = MaterialTheme.typography.bodySmall)
                            }
                            Switch(
                                checked = mirrorPhoneToPc,
                                onCheckedChange = { checked ->
                                    mirrorPhoneToPc = checked
                                    prefs.edit().putBoolean("mirror_phone_to_pc", checked).apply()
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

                // Feed Header
                item {
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text(
                            "Synced Notifications",
                            color = TextPrimary,
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            "${notifications.size} Received",
                            color = LiquidCyan,
                            style = MaterialTheme.typography.labelSmall
                        )
                    }
                }

                if (notifications.isEmpty()) {
                    item {
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 32.dp),
                            contentAlignment = Alignment.Center
                        ) {
                            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                Icon(Icons.Default.NotificationsNone, contentDescription = null, tint = TextMuted, modifier = Modifier.size(40.dp))
                                Spacer(modifier = Modifier.height(10.dp))
                                Text("No active synced notifications.", color = TextMuted, style = MaterialTheme.typography.bodySmall)
                            }
                        }
                    }
                }

                items(notifications) { notif ->
                    val dateStr = remember(notif.timestamp) {
                        SimpleDateFormat("HH:mm", Locale.getDefault()).format(Date(notif.timestamp))
                    }

                    ProfessionalGlassSurface(modifier = Modifier.fillMaxWidth()) {
                        Row(
                            modifier = Modifier.padding(16.dp),
                            verticalAlignment = Alignment.Top
                        ) {
                            Box(
                                modifier = Modifier
                                    .size(40.dp)
                                    .clip(RoundedCornerShape(10.dp))
                                    .background(SurfaceElevated),
                                contentAlignment = Alignment.Center
                            ) {
                                Icon(Icons.Default.Notifications, contentDescription = null, tint = LiquidCyan)
                            }
                            Spacer(modifier = Modifier.width(14.dp))
                            Column(modifier = Modifier.weight(1f)) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween
                                ) {
                                    Text(
                                        notif.app,
                                        color = LiquidCyan,
                                        style = MaterialTheme.typography.labelSmall,
                                        fontWeight = FontWeight.Bold
                                    )
                                    Text(
                                        dateStr,
                                        color = TextMuted,
                                        style = MaterialTheme.typography.labelSmall
                                    )
                                }
                                Spacer(modifier = Modifier.height(2.dp))
                                if (notif.title.isNotEmpty()) {
                                    Text(
                                        notif.title,
                                        color = TextPrimary,
                                        fontWeight = FontWeight.SemiBold,
                                        style = MaterialTheme.typography.bodyMedium
                                    )
                                    Spacer(modifier = Modifier.height(2.dp))
                                }
                                if (notif.body.isNotEmpty()) {
                                    Text(
                                        notif.body,
                                        color = TextSecondary,
                                        style = MaterialTheme.typography.bodySmall,
                                        maxLines = 3,
                                        overflow = TextOverflow.Ellipsis
                                    )
                                }
                            }
                            IconButton(
                                onClick = {
                                    service?.sendNotificationDismiss(notif.id)
                                    notifications = notifications.filter { it.id != notif.id }
                                }
                            ) {
                                Icon(Icons.Default.Close, contentDescription = "Dismiss", tint = TextMuted, modifier = Modifier.size(18.dp))
                            }
                        }
                    }
                }
            }
        }
    }
}
