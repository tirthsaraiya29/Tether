package com.tether.phone.ui.screens

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.graphics.BitmapFactory
import androidx.compose.foundation.Image
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
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.layout.ContentScale
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

@Composable
fun AppThumbnailIcon(
    iconB64: String?,
    fallbackIcon: ImageVector,
    modifier: Modifier = Modifier
) {
    val bitmap = remember(iconB64) {
        if (!iconB64.isNullOrBlank()) {
            try {
                val bytes = android.util.Base64.decode(iconB64, android.util.Base64.DEFAULT)
                BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
            } catch (_: Exception) {
                null
            }
        } else null
    }

    if (bitmap != null) {
        Image(
            bitmap = bitmap.asImageBitmap(),
            contentDescription = null,
            modifier = modifier
                .size(38.dp)
                .clip(RoundedCornerShape(8.dp)),
            contentScale = ContentScale.Fit
        )
    } else {
        Icon(
            fallbackIcon,
            contentDescription = null,
            tint = LiquidCyan,
            modifier = modifier.size(36.dp)
        )
    }
}

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

    // Immediately initialize from persistent cache to eliminate loading latency
    var runningWindows by remember { mutableStateOf(LaptopStateCache.getWindows(context)) }
    var installedApps by remember { mutableStateOf(LaptopStateCache.getInstalledApps(context)) }
    var appFilter by remember { mutableStateOf("") }
    var token by remember { mutableStateOf<String?>(null) }
    var isLoading by remember { mutableStateOf(false) }

    DisposableEffect(context) {
        service?.currentActiveScreen = "AppManagement"

        val receiver = object : BroadcastReceiver() {
            override fun onReceive(ctx: Context?, intent: Intent?) {
                when (intent?.action) {
                    TetherLanService.ACTION_WINDOWS_LIST -> {
                        val jsonStr = intent.getStringExtra("windowsJson") ?: "[]"
                        try {
                            val arr = JSONArray(jsonStr)
                            val list = mutableListOf<DesktopWindow>()
                            for (i in 0 until arr.length()) {
                                val obj = arr.getJSONObject(i)
                                val hwnd = obj.optLong("hwnd", obj.optLong("id", obj.optLong("Id", 0L)))
                                val title = obj.optString("title", obj.optString("Title", ""))
                                val procName = obj.optString("processName", obj.optString("ProcessName", obj.optString("appName", "")))
                                val pid = obj.optInt("processId", obj.optInt("ProcessId", obj.optInt("pid", obj.optInt("Pid", 0))))
                                val w = obj.optInt("width", obj.optInt("Width", 0))
                                val h = obj.optInt("height", obj.optInt("Height", 0))
                                val iconB64 = obj.optString("iconB64", obj.optString("IconB64", "")).ifEmpty { null }
                                list.add(
                                    DesktopWindow(
                                        hwnd = hwnd,
                                        title = title,
                                        processName = procName,
                                        processId = pid,
                                        width = w,
                                        height = h,
                                        iconB64 = iconB64
                                    )
                                )
                            }
                            runningWindows = list
                            LaptopStateCache.saveWindows(context, list)
                        } catch (_: Exception) {}
                    }
                    TetherLanService.ACTION_INSTALLED_APPS -> {
                        val jsonStr = intent.getStringExtra("appsJson") ?: "[]"
                        try {
                            val arr = JSONArray(jsonStr)
                            val list = mutableListOf<InstalledAppItem>()
                            for (i in 0 until arr.length()) {
                                val obj = arr.getJSONObject(i)
                                val appName = obj.optString("name", obj.optString("Name", ""))
                                val appPath = obj.optString("path", obj.optString("Path", obj.optString("shortcutPath", "")))
                                val iconB64 = obj.optString("iconB64", obj.optString("IconB64", "")).ifEmpty { null }
                                list.add(
                                    InstalledAppItem(
                                        name = appName,
                                        path = appPath,
                                        iconB64 = iconB64
                                    )
                                )
                            }
                            installedApps = list
                            LaptopStateCache.saveInstalledApps(context, list)
                        } catch (_: Exception) {}
                    }
                }
            }
        }

        val filter = IntentFilter().apply {
            addAction(TetherLanService.ACTION_WINDOWS_LIST)
            addAction(TetherLanService.ACTION_INSTALLED_APPS)
        }
        ContextCompat.registerReceiver(context, receiver, filter, ContextCompat.RECEIVER_NOT_EXPORTED)

        // Request instant fresh snapshot over fast binary IPC
        service?.requestRunningWindows()
        service?.requestInstalledApps()

        onDispose {
            service?.currentActiveScreen = null
            try { context.unregisterReceiver(receiver) } catch (_: Exception) {}
        }
    }

    LaunchedEffect(Unit) {
        if (service != null && hostIp != null) {
            try {
                token = service.requestFileTransferToken()
                if (token != null && (runningWindows.isEmpty() || installedApps.isEmpty())) {
                    isLoading = true
                    val w = FileTransferClient.fetchDesktopWindows(hostIp, token!!, context)
                    if (w.isNotEmpty()) {
                        runningWindows = w
                        LaptopStateCache.saveWindows(context, w)
                    }
                    val a = FileTransferClient.fetchInstalledApps(hostIp, token!!, context)
                    if (a.isNotEmpty()) {
                        installedApps = a
                        LaptopStateCache.saveInstalledApps(context, a)
                    }
                }
            } catch (_: Exception) {
            } finally {
                isLoading = false
            }
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
                            service?.requestRunningWindows()
                            service?.requestInstalledApps()
                            coroutineScope.launch {
                                if (hostIp != null && token != null) {
                                    isLoading = true
                                    try {
                                        if (selectedTab == 0) {
                                            val w = FileTransferClient.fetchDesktopWindows(hostIp, token!!, context)
                                            if (w.isNotEmpty()) {
                                                runningWindows = w
                                                LaptopStateCache.saveWindows(context, w)
                                            }
                                        } else {
                                            val a = FileTransferClient.fetchInstalledApps(hostIp, token!!, context)
                                            if (a.isNotEmpty()) {
                                                installedApps = a
                                                LaptopStateCache.saveInstalledApps(context, a)
                                            }
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

                if (isLoading && runningWindows.isEmpty() && installedApps.isEmpty()) {
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
                                        Row(
                                            modifier = Modifier.weight(1f),
                                            verticalAlignment = Alignment.CenterVertically
                                        ) {
                                            AppThumbnailIcon(iconB64 = win.iconB64, fallbackIcon = Icons.Default.Window)
                                            Spacer(modifier = Modifier.width(12.dp))
                                            Column(modifier = Modifier.weight(1f)) {
                                                val displayTitle = if (win.title.isNotBlank()) win.title else if (win.processName.isNotBlank()) win.processName else "Application Window"
                                                val displayProc = if (win.processName.isNotBlank()) win.processName else "Process"
                                                Text(
                                                    displayTitle,
                                                    color = TextPrimary,
                                                    fontWeight = FontWeight.SemiBold,
                                                    maxLines = 1
                                                )
                                                Spacer(modifier = Modifier.height(2.dp))
                                                Text(
                                                    "$displayProc • PID: ${win.processId}",
                                                    color = TextMuted,
                                                    style = MaterialTheme.typography.bodySmall
                                                )
                                            }
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

                                    // Window Control Action Buttons
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
                                            Text("Focus", fontSize = 10.sp, maxLines = 1)
                                        }
                                        OutlinedButton(
                                            onClick = { service?.sendWindowSnap(win.hwnd, "LEFT") },
                                            modifier = Modifier.weight(1f),
                                            contentPadding = PaddingValues(horizontal = 4.dp, vertical = 2.dp),
                                            colors = ButtonDefaults.outlinedButtonColors(contentColor = TextPrimary)
                                        ) {
                                            Text("Snap L", fontSize = 10.sp, maxLines = 1)
                                        }
                                        OutlinedButton(
                                            onClick = { service?.sendWindowSnap(win.hwnd, "RIGHT") },
                                            modifier = Modifier.weight(1f),
                                            contentPadding = PaddingValues(horizontal = 4.dp, vertical = 2.dp),
                                            colors = ButtonDefaults.outlinedButtonColors(contentColor = TextPrimary)
                                        ) {
                                            Text("Snap R", fontSize = 10.sp, maxLines = 1)
                                        }
                                        OutlinedButton(
                                            onClick = { service?.sendWindowState(win.hwnd, "MINIMIZE") },
                                            modifier = Modifier.weight(1f),
                                            contentPadding = PaddingValues(horizontal = 4.dp, vertical = 2.dp),
                                            colors = ButtonDefaults.outlinedButtonColors(contentColor = TextSecondary)
                                        ) {
                                            Text("Min", fontSize = 10.sp, maxLines = 1)
                                        }
                                        OutlinedButton(
                                            onClick = { service?.sendWindowState(win.hwnd, "MAXIMIZE") },
                                            modifier = Modifier.weight(1f),
                                            contentPadding = PaddingValues(horizontal = 4.dp, vertical = 2.dp),
                                            colors = ButtonDefaults.outlinedButtonColors(contentColor = IntegrityGreen)
                                        ) {
                                            Text("Max", fontSize = 10.sp, maxLines = 1)
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
                                    AppThumbnailIcon(iconB64 = app.iconB64, fallbackIcon = Icons.Default.Apps)
                                    Spacer(modifier = Modifier.width(14.dp))
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(app.name.ifBlank { "Application" }, color = TextPrimary, fontWeight = FontWeight.SemiBold, maxLines = 1)
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
