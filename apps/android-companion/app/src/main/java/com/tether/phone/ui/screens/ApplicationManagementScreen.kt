package com.tether.phone.ui.screens

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
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
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import com.tether.phone.*
import com.tether.phone.ui.components.DeepSpaceCanvasVisualizer
import com.tether.phone.ui.components.ProfessionalGlassSurface
import com.tether.phone.ui.theme.*
import kotlinx.coroutines.launch
import org.json.JSONArray

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ApplicationManagementScreen(
    onBack: () -> Unit
) {
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()
    val service = TetherLanService.instance
    val hostIp = service?.connectedHostAddress

    var selectedTab by remember { mutableIntStateOf(0) }
    val tabs = listOf("Running Windows", "Installed Apps")

    var runningWindows by remember { mutableStateOf<List<DesktopWindow>>(emptyList()) }
    var installedApps by remember { mutableStateOf<List<InstalledAppItem>>(emptyList()) }
    var appFilter by remember { mutableStateOf("") }
    var token by remember { mutableStateOf<String?>(null) }
    var isLoading by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) {
        if (service != null && hostIp != null) {
            try {
                token = service.requestFileTransferToken()
                // Initial loads
                isLoading = true
                runningWindows = FileTransferClient.fetchDesktopWindows(hostIp, token!!, context)
                installedApps = FileTransferClient.fetchInstalledApps(hostIp, token!!, context)
            } catch (_: Exception) {
            } finally {
                isLoading = false
            }
        }
    }

    DisposableEffect(context) {
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(ctx: Context?, intent: Intent?) {
                if (intent?.action == TetherLanService.ACTION_WINDOWS_LIST) {
                    val jsonStr = intent.getStringExtra("windowsJson") ?: "[]"
                    try {
                        val arr = JSONArray(jsonStr)
                        val list = mutableListOf<DesktopWindow>()
                        for (i in 0 until arr.length()) {
                            val obj = arr.getJSONObject(i)
                            list.add(
                                DesktopWindow(
                                    hwnd = obj.optLong("hwnd", obj.optLong("id", 0L)),
                                    title = obj.optString("title", ""),
                                    processName = obj.optString("processName", ""),
                                    processId = obj.optInt("processId", obj.optInt("pid", 0)),
                                    width = obj.optInt("width", 0),
                                    height = obj.optInt("height", 0)
                                )
                            )
                        }
                        runningWindows = list
                    } catch (_: Exception) {}
                }
            }
        }

        val filter = IntentFilter(TetherLanService.ACTION_WINDOWS_LIST)
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
                    title = { Text("Application Management", color = TextPrimary, fontWeight = FontWeight.SemiBold) },
                    navigationIcon = {
                        IconButton(onClick = onBack) {
                            Icon(Icons.Default.ArrowBack, contentDescription = "Back", tint = TextPrimary)
                        }
                    },
                    actions = {
                        IconButton(onClick = {
                            coroutineScope.launch {
                                if (hostIp != null && token != null) {
                                    isLoading = true
                                    try {
                                        if (selectedTab == 0) {
                                            runningWindows = FileTransferClient.fetchDesktopWindows(hostIp, token!!, context)
                                        } else {
                                            installedApps = FileTransferClient.fetchInstalledApps(hostIp, token!!, context)
                                        }
                                    } catch (_: Exception) {}
                                    isLoading = false
                                }
                            }
                        }) {
                            Icon(Icons.Default.Refresh, contentDescription = "Refresh", tint = LiquidCyan)
                        }
                    },
                    colors = TopAppBarDefaults.topAppBarColors(containerColor = Color.Transparent)
                )
            },
            containerColor = Color.Transparent
        ) { padding ->
            Column(
                modifier = Modifier
                    .padding(padding)
                    .fillMaxSize()
            ) {
                TabRow(
                    selectedTabIndex = selectedTab,
                    containerColor = SurfaceElevated.copy(alpha = 0.5f),
                    contentColor = LiquidCyan,
                    divider = {}
                ) {
                    tabs.forEachIndexed { idx, title ->
                        Tab(
                            selected = selectedTab == idx,
                            onClick = { selectedTab = idx },
                            text = {
                                Text(
                                    title,
                                    color = if (selectedTab == idx) LiquidCyan else TextSecondary,
                                    fontWeight = if (selectedTab == idx) FontWeight.Bold else FontWeight.Normal
                                )
                            }
                        )
                    }
                }

                if (isLoading) {
                    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                        CircularProgressIndicator(color = LiquidCyan)
                    }
                } else if (selectedTab == 0) {
                    // Running Windows
                    LazyColumn(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(14.dp)
                    ) {
                        item {
                            Text(
                                "${runningWindows.size} Active Desktop Windows",
                                color = TextPrimary,
                                fontWeight = FontWeight.Bold,
                                style = MaterialTheme.typography.titleSmall
                            )
                        }

                        if (runningWindows.isEmpty()) {
                            item {
                                Box(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(vertical = 30.dp),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Text("No interactive desktop windows enumerated.", color = TextMuted)
                                }
                            }
                        }

                        items(runningWindows) { win ->
                            ProfessionalGlassSurface(modifier = Modifier.fillMaxWidth()) {
                                Column(modifier = Modifier.padding(16.dp)) {
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        verticalAlignment = Alignment.CenterVertically,
                                        horizontalArrangement = Arrangement.SpaceBetween
                                    ) {
                                        Column(modifier = Modifier.weight(1f)) {
                                            Text(
                                                win.title,
                                                color = TextPrimary,
                                                fontWeight = FontWeight.SemiBold,
                                                maxLines = 1
                                            )
                                            Spacer(modifier = Modifier.height(2.dp))
                                            Text(
                                                "${win.processName} • PID: ${win.processId}",
                                                color = TextMuted,
                                                style = MaterialTheme.typography.bodySmall
                                            )
                                        }

                                        IconButton(
                                            onClick = {
                                                service?.sendWindowClose(win.hwnd, false)
                                                runningWindows = runningWindows.filter { it.hwnd != win.hwnd }
                                            }
                                        ) {
                                            Icon(Icons.Default.Close, contentDescription = "Close Window", tint = AlertRed)
                                        }
                                    }

                                    Spacer(modifier = Modifier.height(10.dp))

                                    // Window Control Buttons
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                                    ) {
                                        OutlinedButton(
                                            onClick = { service?.sendWindowFocus(win.hwnd) },
                                            modifier = Modifier.weight(1f),
                                            contentPadding = PaddingValues(horizontal = 4.dp, vertical = 2.dp),
                                            colors = ButtonDefaults.outlinedButtonColors(contentColor = LiquidCyan)
                                        ) {
                                            Text("Focus", fontSize = 11.sp)
                                        }
                                        OutlinedButton(
                                            onClick = { service?.sendWindowSnap(win.hwnd, "LEFT") },
                                            modifier = Modifier.weight(1f),
                                            contentPadding = PaddingValues(horizontal = 4.dp, vertical = 2.dp),
                                            colors = ButtonDefaults.outlinedButtonColors(contentColor = TextPrimary)
                                        ) {
                                            Text("Snap L", fontSize = 11.sp)
                                        }
                                        OutlinedButton(
                                            onClick = { service?.sendWindowSnap(win.hwnd, "RIGHT") },
                                            modifier = Modifier.weight(1f),
                                            contentPadding = PaddingValues(horizontal = 4.dp, vertical = 2.dp),
                                            colors = ButtonDefaults.outlinedButtonColors(contentColor = TextPrimary)
                                        ) {
                                            Text("Snap R", fontSize = 11.sp)
                                        }
                                        OutlinedButton(
                                            onClick = { service?.sendWindowState(win.hwnd, "MINIMIZE") },
                                            modifier = Modifier.weight(1f),
                                            contentPadding = PaddingValues(horizontal = 4.dp, vertical = 2.dp),
                                            colors = ButtonDefaults.outlinedButtonColors(contentColor = TextSecondary)
                                        ) {
                                            Text("Min", fontSize = 11.sp)
                                        }
                                        OutlinedButton(
                                            onClick = { service?.sendWindowState(win.hwnd, "MAXIMIZE") },
                                            modifier = Modifier.weight(1f),
                                            contentPadding = PaddingValues(horizontal = 4.dp, vertical = 2.dp),
                                            colors = ButtonDefaults.outlinedButtonColors(contentColor = IntegrityGreen)
                                        ) {
                                            Text("Max", fontSize = 11.sp)
                                        }
                                    }
                                }
                            }
                        }
                    }
                } else {
                    // Installed Apps Catalog
                    val filteredApps = remember(installedApps, appFilter) {
                        if (appFilter.isBlank()) installedApps
                        else installedApps.filter { it.name.contains(appFilter, ignoreCase = true) }
                    }

                    LazyColumn(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        item {
                            TextField(
                                value = appFilter,
                                onValueChange = { appFilter = it },
                                modifier = Modifier.fillMaxWidth(),
                                placeholder = { Text("Search installed applications...", color = TextMuted) },
                                singleLine = true,
                                colors = TextFieldDefaults.colors(
                                    focusedContainerColor = SurfaceElevated,
                                    unfocusedContainerColor = SurfaceElevated,
                                    focusedTextColor = TextPrimary,
                                    unfocusedTextColor = TextPrimary,
                                    focusedIndicatorColor = LiquidCyan,
                                    unfocusedIndicatorColor = GlassBorder
                                ),
                                shape = RoundedCornerShape(12.dp)
                            )
                        }

                        item {
                            Text(
                                "${filteredApps.size} Applications Available",
                                color = TextPrimary,
                                fontWeight = FontWeight.Bold,
                                style = MaterialTheme.typography.titleSmall
                            )
                        }

                        items(filteredApps) { app ->
                            ProfessionalGlassSurface(modifier = Modifier.fillMaxWidth()) {
                                Row(
                                    modifier = Modifier.padding(16.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Icon(Icons.Default.Apps, contentDescription = null, tint = LiquidCyan)
                                    Spacer(modifier = Modifier.width(14.dp))
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(app.name, color = TextPrimary, fontWeight = FontWeight.SemiBold, maxLines = 1)
                                        Text(app.path, color = TextMuted, style = MaterialTheme.typography.bodySmall, maxLines = 1)
                                    }
                                    Button(
                                        onClick = { service?.sendLaunchApp(app.path) },
                                        colors = ButtonDefaults.buttonColors(containerColor = LiquidCyan),
                                        contentPadding = PaddingValues(horizontal = 14.dp, vertical = 6.dp)
                                    ) {
                                        Text("Launch", color = DeepSpace, fontWeight = FontWeight.Bold, fontSize = 12.sp)
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
