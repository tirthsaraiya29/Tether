package com.tether.phone.ui.screens

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import androidx.compose.foundation.background
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import com.tether.phone.*
import com.tether.phone.ui.components.DeepSpaceCanvasVisualizer
import com.tether.phone.ui.components.ProfessionalGlassSurface
import com.tether.phone.ui.theme.*
import org.json.JSONArray
import org.json.JSONObject

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun WindowsAdminScreen(
    onBack: () -> Unit
) {
    val context = LocalContext.current
    val service = TetherLanService.instance

    var selectedTab by remember { mutableIntStateOf(0) }
    val tabs = listOf("Telemetry", "Hardware", "Power", "Services & Updates")

    // Telemetry State
    var telemetry by remember { mutableStateOf(AdminTelemetry()) }
    var batteryHealth by remember { mutableStateOf(BatteryHealthState()) }
    var powerPlans by remember { mutableStateOf<List<PowerPlanItem>>(emptyList()) }
    var printers by remember { mutableStateOf<List<PrinterItem>>(emptyList()) }
    var usbDevices by remember { mutableStateOf<List<UsbItem>>(emptyList()) }
    var servicesList by remember { mutableStateOf<List<WindowsServiceItem>>(emptyList()) }
    var updateState by remember { mutableStateOf(WindowsUpdateState()) }
    var serviceFilter by remember { mutableStateOf("") }
    var isCheckingUpdates by remember { mutableStateOf(false) }

    DisposableEffect(context) {
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(ctx: Context?, intent: Intent?) {
                when (intent?.action) {
                    TetherLanService.ACTION_ADMIN_TELEMETRY -> {
                        val cpu = intent.getIntExtra("cpuUsage", 0)
                        val totalRam = intent.getLongExtra("totalRamMb", 0L)
                        val availRam = intent.getLongExtra("availRamMb", 0L)
                        val ramPct = intent.getIntExtra("ramUsagePct", 0)

                        val disksList = mutableListOf<DiskUsageItem>()
                        try {
                            val arr = JSONArray(intent.getStringExtra("disksJson") ?: "[]")
                            for (i in 0 until arr.length()) {
                                val d = arr.getJSONObject(i)
                                disksList.add(
                                    DiskUsageItem(
                                        name = d.optString("name", "C:"),
                                        volumeLabel = d.optString("volumeLabel", ""),
                                        totalGb = d.optDouble("totalGb", 0.0),
                                        freeGb = d.optDouble("freeGb", 0.0),
                                        format = d.optString("format", "NTFS")
                                    )
                                )
                            }
                        } catch (_: Exception) {}

                        val netList = mutableListOf<NetworkAdapterItem>()
                        try {
                            val arr = JSONArray(intent.getStringExtra("networksJson") ?: "[]")
                            for (i in 0 until arr.length()) {
                                val n = arr.getJSONObject(i)
                                netList.add(
                                    NetworkAdapterItem(
                                        name = n.optString("name", "Ethernet"),
                                        description = n.optString("description", ""),
                                        type = n.optString("type", ""),
                                        bytesReceived = n.optLong("bytesReceived", 0L),
                                        bytesSent = n.optLong("bytesSent", 0L),
                                        speedMbps = n.optLong("speedMbps", 0L)
                                    )
                                )
                            }
                        } catch (_: Exception) {}

                        telemetry = AdminTelemetry(cpu, totalRam, availRam, ramPct, disksList, netList)
                    }
                    TetherLanService.ACTION_BATTERY_HEALTH -> {
                        batteryHealth = BatteryHealthState(
                            designCapacityMwh = intent.getDoubleExtra("designCapacityMwh", 0.0),
                            fullChargeCapacityMwh = intent.getDoubleExtra("fullChargeCapacityMwh", 0.0),
                            wearLevelPct = intent.getIntExtra("wearLevelPct", 0),
                            cycleCount = intent.getIntExtra("cycleCount", 0)
                        )
                    }
                    TetherLanService.ACTION_POWER_PLANS -> {
                        try {
                            val arr = JSONArray(intent.getStringExtra("plansJson") ?: "[]")
                            val list = mutableListOf<PowerPlanItem>()
                            for (i in 0 until arr.length()) {
                                val p = arr.getJSONObject(i)
                                list.add(
                                    PowerPlanItem(
                                        guid = p.optString("guid", ""),
                                        name = p.optString("name", "Power Plan"),
                                        isActive = p.optBoolean("isActive", false)
                                    )
                                )
                            }
                            powerPlans = list
                        } catch (_: Exception) {}
                    }
                    TetherLanService.ACTION_PRINTERS -> {
                        try {
                            val arr = JSONArray(intent.getStringExtra("printersJson") ?: "[]")
                            val list = mutableListOf<PrinterItem>()
                            for (i in 0 until arr.length()) {
                                val p = arr.getJSONObject(i)
                                list.add(
                                    PrinterItem(
                                        name = p.optString("name", "Printer"),
                                        port = p.optString("port", ""),
                                        status = p.optString("status", "Ready"),
                                        jobsCount = p.optInt("jobsCount", 0)
                                    )
                                )
                            }
                            printers = list
                        } catch (_: Exception) {}
                    }
                    TetherLanService.ACTION_USB_DEVICES -> {
                        try {
                            val arr = JSONArray(intent.getStringExtra("devicesJson") ?: "[]")
                            val list = mutableListOf<UsbItem>()
                            for (i in 0 until arr.length()) {
                                val u = arr.getJSONObject(i)
                                list.add(
                                    UsbItem(
                                        id = u.optString("id", ""),
                                        name = u.optString("name", "USB Device"),
                                        status = u.optString("status", "OK")
                                    )
                                )
                            }
                            usbDevices = list
                        } catch (_: Exception) {}
                    }
                    TetherLanService.ACTION_SERVICES -> {
                        try {
                            val arr = JSONArray(intent.getStringExtra("servicesJson") ?: "[]")
                            val list = mutableListOf<WindowsServiceItem>()
                            for (i in 0 until arr.length()) {
                                val s = arr.getJSONObject(i)
                                list.add(
                                    WindowsServiceItem(
                                        name = s.optString("name", ""),
                                        displayName = s.optString("displayName", s.optString("name", "")),
                                        status = s.optString("status", "Stopped"),
                                        canStop = s.optBoolean("canStop", true)
                                    )
                                )
                            }
                            servicesList = list
                        } catch (_: Exception) {}
                    }
                    TetherLanService.ACTION_UPDATES -> {
                        isCheckingUpdates = false
                        val count = intent.getIntExtra("pendingCount", 0)
                        val avail = intent.getBooleanExtra("isAvailable", false)
                        val titlesList = mutableListOf<String>()
                        try {
                            val arr = JSONArray(intent.getStringExtra("titlesJson") ?: "[]")
                            for (i in 0 until arr.length()) {
                                titlesList.add(arr.getString(i))
                            }
                        } catch (_: Exception) {}
                        updateState = WindowsUpdateState(count, avail, titlesList)
                    }
                }
            }
        }

        val filter = IntentFilter().apply {
            addAction(TetherLanService.ACTION_ADMIN_TELEMETRY)
            addAction(TetherLanService.ACTION_BATTERY_HEALTH)
            addAction(TetherLanService.ACTION_POWER_PLANS)
            addAction(TetherLanService.ACTION_PRINTERS)
            addAction(TetherLanService.ACTION_USB_DEVICES)
            addAction(TetherLanService.ACTION_SERVICES)
            addAction(TetherLanService.ACTION_UPDATES)
        }
        ContextCompat.registerReceiver(context, receiver, filter, ContextCompat.RECEIVER_NOT_EXPORTED)

        // Request initial data
        service?.requestAdminTelemetry()
        service?.requestBatteryHealth()
        service?.requestPowerPlans()
        service?.requestPrinters()
        service?.requestUsbDevices()
        service?.requestWindowsServices()
        service?.requestWindowsUpdates()

        onDispose {
            try { context.unregisterReceiver(receiver) } catch (_: Exception) {}
        }
    }

    Box(modifier = Modifier.fillMaxSize()) {
        DeepSpaceCanvasVisualizer()

        Scaffold(
            topBar = {
                TopAppBar(
                    title = { Text("Windows Administration", color = TextPrimary, fontWeight = FontWeight.SemiBold) },
                    navigationIcon = {
                        IconButton(onClick = onBack) {
                            Icon(Icons.Default.ArrowBack, contentDescription = "Back", tint = TextPrimary)
                        }
                    },
                    actions = {
                        IconButton(onClick = {
                            service?.requestAdminTelemetry()
                            service?.requestBatteryHealth()
                            service?.requestPowerPlans()
                            service?.requestPrinters()
                            service?.requestUsbDevices()
                            service?.requestWindowsServices(serviceFilter)
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
                // Tab Row
                ScrollableTabRow(
                    selectedTabIndex = selectedTab,
                    containerColor = SurfaceElevated.copy(alpha = 0.5f),
                    contentColor = LiquidCyan,
                    edgePadding = 16.dp,
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

                // Tab Contents
                when (selectedTab) {
                    0 -> TelemetryTabContent(telemetry)
                    1 -> HardwareTabContent(batteryHealth, printers, usbDevices)
                    2 -> PowerTabContent(powerPlans) { guid -> service?.sendSetPowerPlan(guid) }
                    3 -> ServicesAndUpdatesTabContent(
                        servicesList = servicesList,
                        updateState = updateState,
                        filter = serviceFilter,
                        onFilterChange = {
                            serviceFilter = it
                            service?.requestWindowsServices(it)
                        },
                        onServiceAction = { sName, action -> service?.sendControlService(sName, action) },
                        isCheckingUpdates = isCheckingUpdates,
                        onCheckUpdates = {
                            isCheckingUpdates = true
                            service?.requestWindowsUpdates()
                        }
                    )
                }
            }
        }
    }
}

@Composable
fun TelemetryTabContent(telemetry: AdminTelemetry) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // CPU Gauge
        item {
            ProfessionalGlassSurface(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(18.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text("Processor Activity (CPU)", color = TextPrimary, fontWeight = FontWeight.Bold)
                        Text("${telemetry.cpuUsage}%", color = LiquidCyan, fontWeight = FontWeight.Bold, fontSize = 18.sp)
                    }
                    Spacer(modifier = Modifier.height(10.dp))
                    LinearProgressIndicator(
                        progress = { telemetry.cpuUsage / 100f },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(8.dp)
                            .clip(CircleShape),
                        color = if (telemetry.cpuUsage > 85) AlertRed else LiquidCyan,
                        trackColor = SurfaceElevated
                    )
                }
            }
        }

        // RAM Gauge
        item {
            ProfessionalGlassSurface(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(18.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text("Physical Memory (RAM)", color = TextPrimary, fontWeight = FontWeight.Bold)
                        Text("${telemetry.ramUsagePct}%", color = IntegrityGreen, fontWeight = FontWeight.Bold, fontSize = 18.sp)
                    }
                    Spacer(modifier = Modifier.height(6.dp))
                    val usedRamGb = ((telemetry.totalRamMb - telemetry.availRamMb) / 1024.0)
                    val totalRamGb = (telemetry.totalRamMb / 1024.0)
                    Text(
                        String.format("%.1f GB used of %.1f GB", usedRamGb, totalRamGb),
                        color = TextSecondary,
                        style = MaterialTheme.typography.bodySmall
                    )
                    Spacer(modifier = Modifier.height(10.dp))
                    LinearProgressIndicator(
                        progress = { telemetry.ramUsagePct / 100f },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(8.dp)
                            .clip(CircleShape),
                        color = if (telemetry.ramUsagePct > 90) AlertRed else IntegrityGreen,
                        trackColor = SurfaceElevated
                    )
                }
            }
        }

        // Logical Storage Volumes
        item {
            Text("Storage Volumes", color = TextPrimary, fontWeight = FontWeight.Bold, style = MaterialTheme.typography.titleSmall)
        }

        items(telemetry.disks) { disk ->
            val usedGb = (disk.totalGb - disk.freeGb).coerceAtLeast(0.0)
            val usedPct = if (disk.totalGb > 0) ((usedGb / disk.totalGb) * 100).toInt() else 0

            ProfessionalGlassSurface(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.Storage, contentDescription = null, tint = LiquidCyan)
                            Spacer(modifier = Modifier.width(10.dp))
                            Text(
                                "${disk.name} ${if (disk.volumeLabel.isNotEmpty()) "(${disk.volumeLabel})" else ""}",
                                color = TextPrimary,
                                fontWeight = FontWeight.SemiBold
                            )
                        }
                        Text("${disk.format} • ${usedPct}%", color = TextSecondary, style = MaterialTheme.typography.labelSmall)
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        String.format("%.1f GB free of %.1f GB", disk.freeGb, disk.totalGb),
                        color = TextMuted,
                        style = MaterialTheme.typography.bodySmall
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    LinearProgressIndicator(
                        progress = { usedPct / 100f },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(6.dp)
                            .clip(CircleShape),
                        color = if (usedPct > 90) AlertRed else LiquidCyan,
                        trackColor = SurfaceElevated
                    )
                }
            }
        }

        // Network Adapters
        if (telemetry.networks.isNotEmpty()) {
            item {
                Text("Network Interfaces", color = TextPrimary, fontWeight = FontWeight.Bold, style = MaterialTheme.typography.titleSmall)
            }
            items(telemetry.networks) { net ->
                ProfessionalGlassSurface(modifier = Modifier.fillMaxWidth()) {
                    Row(
                        modifier = Modifier.padding(16.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(Icons.Default.NetworkCheck, contentDescription = null, tint = IntegrityGreen)
                        Spacer(modifier = Modifier.width(12.dp))
                        Column(modifier = Modifier.weight(1f)) {
                            Text(net.name, color = TextPrimary, fontWeight = FontWeight.SemiBold)
                            Text(
                                "Speed: ${net.speedMbps} Mbps • Sent: ${net.bytesSent / 1048576L} MB • Recv: ${net.bytesReceived / 1048576L} MB",
                                color = TextMuted,
                                style = MaterialTheme.typography.bodySmall
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun HardwareTabContent(
    batteryHealth: BatteryHealthState,
    printers: List<PrinterItem>,
    usbDevices: List<UsbItem>
) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Battery Health Diagnostics Card
        item {
            ProfessionalGlassSurface(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(18.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.BatteryChargingFull, contentDescription = null, tint = IntegrityGreen)
                        Spacer(modifier = Modifier.width(10.dp))
                        Text("Battery Health & Wear Analytics", color = TextPrimary, fontWeight = FontWeight.Bold)
                    }
                    Spacer(modifier = Modifier.height(14.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Column {
                            Text("Wear Level", color = TextMuted, style = MaterialTheme.typography.labelSmall)
                            Text("${batteryHealth.wearLevelPct}%", color = if (batteryHealth.wearLevelPct > 30) AlertRed else IntegrityGreen, fontWeight = FontWeight.Bold, fontSize = 16.sp)
                        }
                        Column {
                            Text("Cycle Count", color = TextMuted, style = MaterialTheme.typography.labelSmall)
                            Text("${batteryHealth.cycleCount}", color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 16.sp)
                        }
                        Column {
                            Text("Full Charge", color = TextMuted, style = MaterialTheme.typography.labelSmall)
                            Text(String.format("%.0f mWh", batteryHealth.fullChargeCapacityMwh), color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 16.sp)
                        }
                    }
                }
            }
        }

        // USB Devices
        item {
            Text("Connected USB Hardware (${usbDevices.size})", color = TextPrimary, fontWeight = FontWeight.Bold, style = MaterialTheme.typography.titleSmall)
        }
        if (usbDevices.isEmpty()) {
            item {
                Text("No external USB peripherals currently detected.", color = TextMuted, style = MaterialTheme.typography.bodySmall)
            }
        }
        items(usbDevices) { usb ->
            ProfessionalGlassSurface(modifier = Modifier.fillMaxWidth()) {
                Row(
                    modifier = Modifier.padding(14.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(Icons.Default.Usb, contentDescription = null, tint = LiquidCyan)
                    Spacer(modifier = Modifier.width(12.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text(usb.name, color = TextPrimary, fontWeight = FontWeight.Medium, maxLines = 1)
                        Text("Status: ${usb.status}", color = IntegrityGreen, style = MaterialTheme.typography.labelSmall)
                    }
                }
            }
        }

        // Printers
        item {
            Text("Printers & Spooler (${printers.size})", color = TextPrimary, fontWeight = FontWeight.Bold, style = MaterialTheme.typography.titleSmall)
        }
        if (printers.isEmpty()) {
            item {
                Text("No configured printers reported.", color = TextMuted, style = MaterialTheme.typography.bodySmall)
            }
        }
        items(printers) { prn ->
            ProfessionalGlassSurface(modifier = Modifier.fillMaxWidth()) {
                Row(
                    modifier = Modifier.padding(14.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(Icons.Default.Print, contentDescription = null, tint = TextSecondary)
                    Spacer(modifier = Modifier.width(12.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text(prn.name, color = TextPrimary, fontWeight = FontWeight.Medium)
                        Text("Port: ${prn.port} • Status: ${prn.status} • Queue: ${prn.jobsCount}", color = TextMuted, style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }
    }
}

@Composable
fun PowerTabContent(
    powerPlans: List<PowerPlanItem>,
    onSelectPlan: (String) -> Unit
) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        item {
            Text("Windows ACPI Power Schemes", color = TextPrimary, fontWeight = FontWeight.Bold, style = MaterialTheme.typography.titleSmall)
            Spacer(modifier = Modifier.height(4.dp))
            Text("Switch between native Windows power profiles remotely.", color = TextSecondary, style = MaterialTheme.typography.bodySmall)
        }

        if (powerPlans.isEmpty()) {
            item {
                Text("Querying Windows Power Management subsystem...", color = TextMuted)
            }
        }

        items(powerPlans) { plan ->
            ProfessionalGlassSurface(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { onSelectPlan(plan.guid) }
            ) {
                Row(
                    modifier = Modifier.padding(16.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    RadioButton(
                        selected = plan.isActive,
                        onClick = { onSelectPlan(plan.guid) },
                        colors = RadioButtonDefaults.colors(selectedColor = LiquidCyan)
                    )
                    Spacer(modifier = Modifier.width(12.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            plan.name,
                            color = if (plan.isActive) LiquidCyan else TextPrimary,
                            fontWeight = if (plan.isActive) FontWeight.Bold else FontWeight.Normal
                        )
                        if (plan.isActive) {
                            Text("Active Scheme", color = IntegrityGreen, style = MaterialTheme.typography.labelSmall)
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun ServicesAndUpdatesTabContent(
    servicesList: List<WindowsServiceItem>,
    updateState: WindowsUpdateState,
    filter: String,
    onFilterChange: (String) -> Unit,
    onServiceAction: (String, String) -> Unit,
    isCheckingUpdates: Boolean,
    onCheckUpdates: () -> Unit
) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Windows Update Card
        item {
            ProfessionalGlassSurface(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(18.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.SystemUpdate, contentDescription = null, tint = LiquidCyan)
                            Spacer(modifier = Modifier.width(10.dp))
                            Text("Windows Update", color = TextPrimary, fontWeight = FontWeight.Bold)
                        }
                        if (isCheckingUpdates) {
                            CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp, color = LiquidCyan)
                        } else {
                            TextButton(onClick = onCheckUpdates) {
                                Text("Check Now", color = LiquidCyan, fontSize = 12.sp)
                            }
                        }
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        if (updateState.pendingCount > 0)
                            "${updateState.pendingCount} update(s) ready for installation."
                        else
                            "Windows is up to date.",
                        color = if (updateState.pendingCount > 0) MatrixGold else IntegrityGreen,
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.SemiBold
                    )
                    if (updateState.titles.isNotEmpty()) {
                        Spacer(modifier = Modifier.height(6.dp))
                        updateState.titles.forEach { title ->
                            Text("• $title", color = TextSecondary, style = MaterialTheme.typography.bodySmall, maxLines = 1)
                        }
                    }
                }
            }
        }

        // Services Filter Header
        item {
            Text("Windows Services Control", color = TextPrimary, fontWeight = FontWeight.Bold, style = MaterialTheme.typography.titleSmall)
            Spacer(modifier = Modifier.height(6.dp))
            TextField(
                value = filter,
                onValueChange = onFilterChange,
                modifier = Modifier.fillMaxWidth(),
                placeholder = { Text("Filter services by name...", color = TextMuted) },
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

        items(servicesList) { s ->
            val isRunning = s.status.equals("Running", ignoreCase = true)
            ProfessionalGlassSurface(modifier = Modifier.fillMaxWidth()) {
                Row(
                    modifier = Modifier.padding(14.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(s.displayName, color = TextPrimary, fontWeight = FontWeight.SemiBold, maxLines = 1)
                        Text("${s.name} • ${s.status}", color = if (isRunning) IntegrityGreen else AlertRed, style = MaterialTheme.typography.labelSmall)
                    }

                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        if (!isRunning) {
                            IconButton(onClick = { onServiceAction(s.name, "START") }) {
                                Icon(Icons.Default.PlayArrow, contentDescription = "Start Service", tint = IntegrityGreen)
                            }
                        } else {
                            IconButton(onClick = { onServiceAction(s.name, "RESTART") }) {
                                Icon(Icons.Default.Refresh, contentDescription = "Restart Service", tint = LiquidCyan)
                            }
                            if (s.canStop) {
                                IconButton(onClick = { onServiceAction(s.name, "STOP") }) {
                                    Icon(Icons.Default.Stop, contentDescription = "Stop Service", tint = AlertRed)
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
