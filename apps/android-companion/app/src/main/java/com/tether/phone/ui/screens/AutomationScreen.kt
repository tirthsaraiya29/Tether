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
import com.tether.phone.AutomationWorkflowItem
import com.tether.phone.TetherLanService
import com.tether.phone.ui.components.DeepSpaceCanvasVisualizer
import com.tether.phone.ui.components.ProfessionalGlassSurface
import com.tether.phone.ui.theme.*
import org.json.JSONArray
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AutomationScreen(
    onBack: () -> Unit
) {
    val context = LocalContext.current
    val service = TetherLanService.instance

    var workflows by remember { mutableStateOf<List<AutomationWorkflowItem>>(emptyList()) }
    var showCreateDialog by remember { mutableStateOf(false) }

    DisposableEffect(context) {
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(ctx: Context?, intent: Intent?) {
                when (intent?.action) {
                    TetherLanService.ACTION_WORKFLOWS -> {
                        val jsonStr = intent.getStringExtra("workflowsJson") ?: "[]"
                        try {
                            val arr = JSONArray(jsonStr)
                            val list = mutableListOf<AutomationWorkflowItem>()
                            for (i in 0 until arr.length()) {
                                val obj = arr.getJSONObject(i)
                                val actionsArr = obj.optJSONArray("actions")
                                val actList = mutableListOf<String>()
                                if (actionsArr != null) {
                                    for (j in 0 until actionsArr.length()) {
                                        actList.add(actionsArr.getString(j))
                                    }
                                }
                                list.add(
                                    AutomationWorkflowItem(
                                        id = obj.optString("id", UUID.randomUUID().toString()),
                                        name = obj.optString("name", "Workflow"),
                                        isEnabled = obj.optBoolean("isEnabled", true),
                                        scheduleType = obj.optString("scheduleType", "manual"),
                                        scheduleValue = obj.optString("scheduleValue", ""),
                                        conditionType = obj.optString("conditionType", "none"),
                                        conditionValue = obj.optString("conditionValue", ""),
                                        actions = actList,
                                        lastExecutedMs = obj.optLong("lastExecutedMs", 0L),
                                        lastStatus = obj.optString("lastStatus", "NEVER")
                                    )
                                )
                            }
                            workflows = list
                        } catch (_: Exception) {}
                    }
                    TetherLanService.ACTION_WORKFLOW_STATUS -> {
                        val id = intent.getStringExtra("id") ?: ""
                        val status = intent.getStringExtra("status") ?: ""
                        val time = intent.getLongExtra("timestamp", System.currentTimeMillis())
                        if (id.isNotEmpty()) {
                            workflows = workflows.map {
                                if (it.id == id) it.copy(lastStatus = status, lastExecutedMs = time) else it
                            }
                        }
                    }
                }
            }
        }

        val filter = IntentFilter().apply {
            addAction(TetherLanService.ACTION_WORKFLOWS)
            addAction(TetherLanService.ACTION_WORKFLOW_STATUS)
        }
        ContextCompat.registerReceiver(context, receiver, filter, ContextCompat.RECEIVER_NOT_EXPORTED)

        // Request workflows from Windows
        service?.requestWorkflows()

        onDispose {
            try { context.unregisterReceiver(receiver) } catch (_: Exception) {}
        }
    }

    Box(modifier = Modifier.fillMaxSize()) {
        DeepSpaceCanvasVisualizer()

        Scaffold(
            topBar = {
                TopAppBar(
                    title = { Text("Automation Workflows", color = TextPrimary, fontWeight = FontWeight.SemiBold) },
                    navigationIcon = {
                        IconButton(onClick = onBack) {
                            Icon(Icons.Default.ArrowBack, contentDescription = "Back", tint = TextPrimary)
                        }
                    },
                    actions = {
                        IconButton(onClick = { service?.requestWorkflows() }) {
                            Icon(Icons.Default.Refresh, contentDescription = "Refresh Workflows", tint = LiquidCyan)
                        }
                    },
                    colors = TopAppBarDefaults.topAppBarColors(containerColor = Color.Transparent)
                )
            },
            floatingActionButton = {
                FloatingActionButton(
                    onClick = { showCreateDialog = true },
                    containerColor = LiquidCyan,
                    contentColor = DeepSpace
                ) {
                    Icon(Icons.Default.Add, contentDescription = "Create Workflow")
                }
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
                item {
                    Text(
                        "Configured Remote Workflows (${workflows.size})",
                        color = TextPrimary,
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.padding(top = 4.dp)
                    )
                }

                if (workflows.isEmpty()) {
                    item {
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 40.dp),
                            contentAlignment = Alignment.Center
                        ) {
                            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                Icon(Icons.Default.AutoFixHigh, contentDescription = null, tint = TextMuted, modifier = Modifier.size(44.dp))
                                Spacer(modifier = Modifier.height(12.dp))
                                Text("No automated workflows configured.", color = TextMuted)
                                Spacer(modifier = Modifier.height(6.dp))
                                Text("Tap the + button to build scheduled or conditional multi-step routines.", color = TextSecondary, style = MaterialTheme.typography.bodySmall)
                            }
                        }
                    }
                }

                items(workflows) { wf ->
                    val statusColor = when (wf.lastStatus) {
                        "SUCCESS" -> IntegrityGreen
                        "FAILED" -> AlertRed
                        "RUNNING" -> LiquidCyan
                        else -> TextMuted
                    }

                    val dateStr = remember(wf.lastExecutedMs) {
                        if (wf.lastExecutedMs > 0L) {
                            SimpleDateFormat("MMM d, HH:mm", Locale.getDefault()).format(Date(wf.lastExecutedMs))
                        } else "Never"
                    }

                    ProfessionalGlassSurface(modifier = Modifier.fillMaxWidth()) {
                        Column(modifier = Modifier.padding(18.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(wf.name, color = TextPrimary, fontWeight = FontWeight.Bold, style = MaterialTheme.typography.titleMedium)
                                    Spacer(modifier = Modifier.height(2.dp))
                                    Text(
                                        "Trigger: ${wf.scheduleType.uppercase()} • Condition: ${wf.conditionType.uppercase()}",
                                        color = LiquidCyan,
                                        style = MaterialTheme.typography.labelSmall
                                    )
                                }

                                Switch(
                                    checked = wf.isEnabled,
                                    onCheckedChange = { enabled ->
                                        val updated = wf.copy(isEnabled = enabled)
                                        workflows = workflows.map { if (it.id == wf.id) updated else it }
                                        val json = JSONObject().apply {
                                            put("id", updated.id)
                                            put("name", updated.name)
                                            put("isEnabled", updated.isEnabled)
                                            put("scheduleType", updated.scheduleType)
                                            put("scheduleValue", updated.scheduleValue)
                                            put("conditionType", updated.conditionType)
                                            put("conditionValue", updated.conditionValue)
                                            val actArr = JSONArray()
                                            updated.actions.forEach { actArr.put(it) }
                                            put("actions", actArr)
                                        }
                                        service?.sendSaveWorkflow(json)
                                    },
                                    colors = SwitchDefaults.colors(
                                        checkedThumbColor = LiquidCyan,
                                        checkedTrackColor = LiquidCyanMuted,
                                        uncheckedThumbColor = TextMuted,
                                        uncheckedTrackColor = SurfaceElevated
                                    )
                                )
                            }

                            Spacer(modifier = Modifier.height(10.dp))

                            // Action steps pill list
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(6.dp)
                            ) {
                                wf.actions.take(3).forEach { act ->
                                    Box(
                                        modifier = Modifier
                                            .clip(RoundedCornerShape(6.dp))
                                            .background(SurfaceElevated)
                                            .padding(horizontal = 8.dp, vertical = 3.dp)
                                    ) {
                                        Text(act, color = TextSecondary, fontSize = 11.sp, fontWeight = FontWeight.Medium)
                                    }
                                }
                                if (wf.actions.size > 3) {
                                    Text("+${wf.actions.size - 3} more", color = TextMuted, fontSize = 11.sp)
                                }
                            }

                            Spacer(modifier = Modifier.height(12.dp))
                            Divider(color = GlassBorder)
                            Spacer(modifier = Modifier.height(10.dp))

                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Text(
                                    "Status: ${wf.lastStatus} ($dateStr)",
                                    color = statusColor,
                                    style = MaterialTheme.typography.labelSmall,
                                    fontWeight = FontWeight.Bold
                                )

                                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                    TextButton(
                                        onClick = { service?.sendTriggerWorkflow(wf.id) },
                                        contentPadding = PaddingValues(horizontal = 8.dp, vertical = 2.dp)
                                    ) {
                                        Icon(Icons.Default.PlayArrow, contentDescription = null, tint = IntegrityGreen, modifier = Modifier.size(16.dp))
                                        Spacer(modifier = Modifier.width(4.dp))
                                        Text("Run Now", color = IntegrityGreen, fontSize = 12.sp)
                                    }

                                    IconButton(
                                        onClick = {
                                            service?.sendDeleteWorkflow(wf.id)
                                            workflows = workflows.filter { it.id != wf.id }
                                        },
                                        modifier = Modifier.size(28.dp)
                                    ) {
                                        Icon(Icons.Default.Delete, contentDescription = "Delete", tint = AlertRed, modifier = Modifier.size(18.dp))
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // New Workflow Dialog
    if (showCreateDialog) {
        var wfName by remember { mutableStateOf("") }
        var scheduleType by remember { mutableStateOf("manual") }
        var scheduleValue by remember { mutableStateOf("") }
        var conditionType by remember { mutableStateOf("none") }
        var selectedActions by remember { mutableStateOf(listOf("LOCK")) }

        val availableActions = listOf("LOCK", "MUTE", "SLEEP", "HIBERNATE", "UNMUTE", "KILL_APPS")

        AlertDialog(
            onDismissRequest = { showCreateDialog = false },
            title = { Text("Build New Workflow", color = TextPrimary) },
            text = {
                Column(modifier = Modifier.fillMaxWidth()) {
                    TextField(
                        value = wfName,
                        onValueChange = { wfName = it },
                        label = { Text("Workflow Name") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                        colors = TextFieldDefaults.colors(focusedTextColor = TextPrimary, unfocusedTextColor = TextPrimary)
                    )

                    Spacer(modifier = Modifier.height(12.dp))
                    Text("Trigger Schedule:", color = TextSecondary, style = MaterialTheme.typography.labelMedium)
                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        listOf("manual", "interval", "time").forEach { sType ->
                            FilterChip(
                                selected = scheduleType == sType,
                                onClick = { scheduleType = sType },
                                label = { Text(sType.replaceFirstChar { it.uppercase() }, fontSize = 12.sp) }
                            )
                        }
                    }

                    if (scheduleType != "manual") {
                        Spacer(modifier = Modifier.height(6.dp))
                        TextField(
                            value = scheduleValue,
                            onValueChange = { scheduleValue = it },
                            placeholder = { Text(if (scheduleType == "interval") "e.g. 30m or 1h" else "e.g. 23:00") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth()
                        )
                    }

                    Spacer(modifier = Modifier.height(12.dp))
                    Text("Execution Condition:", color = TextSecondary, style = MaterialTheme.typography.labelMedium)
                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        listOf("none", "battery_low", "charging").forEach { cType ->
                            FilterChip(
                                selected = conditionType == cType,
                                onClick = { conditionType = cType },
                                label = { Text(cType.replace("_", " ").replaceFirstChar { it.uppercase() }, fontSize = 12.sp) }
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(12.dp))
                    Text("Action Sequence:", color = TextSecondary, style = MaterialTheme.typography.labelMedium)
                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        availableActions.take(3).forEach { act ->
                            val isSel = selectedActions.contains(act)
                            FilterChip(
                                selected = isSel,
                                onClick = {
                                    selectedActions = if (isSel) selectedActions - act else selectedActions + act
                                },
                                label = { Text(act, fontSize = 11.sp) }
                            )
                        }
                    }
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        if (wfName.isNotBlank() && selectedActions.isNotEmpty()) {
                            val newId = UUID.randomUUID().toString()
                            val json = JSONObject().apply {
                                put("id", newId)
                                put("name", wfName)
                                put("isEnabled", true)
                                put("scheduleType", scheduleType)
                                put("scheduleValue", scheduleValue)
                                put("conditionType", conditionType)
                                put("conditionValue", "")
                                val actArr = JSONArray()
                                selectedActions.forEach { actArr.put(it) }
                                put("actions", actArr)
                            }
                            service?.sendSaveWorkflow(json)
                            showCreateDialog = false
                        }
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = LiquidCyan)
                ) {
                    Text("Save Workflow", color = DeepSpace, fontWeight = FontWeight.Bold)
                }
            },
            dismissButton = {
                TextButton(onClick = { showCreateDialog = false }) {
                    Text("Cancel", color = TextSecondary)
                }
            },
            containerColor = SurfaceElevated
        )
    }
}
