package com.tether.phone.ui.screens

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import com.tether.phone.*
import com.tether.phone.ui.components.DeepSpaceCanvasVisualizer
import com.tether.phone.ui.theme.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RemoteTerminalScreen(
    onBack: () -> Unit
) {
    val context = LocalContext.current
    val service = TetherLanService.instance

    // Session tabs: id -> TerminalTab
    var activeSessions by remember {
        mutableStateOf(
            listOf(TerminalTab(id = "default", shellType = "powershell", workingDir = ""))
        )
    }
    var currentSessionId by remember { mutableStateOf("default") }
    // Session output buffers: id -> String
    val sessionOutputs = remember { mutableStateMapOf<String, StringBuilder>() }
    if (!sessionOutputs.containsKey("default")) {
        sessionOutputs["default"] = StringBuilder("Windows PowerShell Interactive Console\nReady.\n\n")
    }

    var commandInput by remember { mutableStateOf("") }
    var showNewSessionDialog by remember { mutableStateOf(false) }
    val outputScrollState = rememberScrollState()

    DisposableEffect(context) {
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(ctx: Context?, intent: Intent?) {
                when (intent?.action) {
                    TetherLanService.ACTION_TERMINAL_OUTPUT -> {
                        val sessId = intent.getStringExtra("sessionId") ?: "default"
                        val data = intent.getStringExtra("data") ?: ""
                        val sb = sessionOutputs.getOrPut(sessId) { StringBuilder() }
                        sb.append(data)
                        // Trigger recomposition by re-putting
                        sessionOutputs[sessId] = StringBuilder(sb.toString())
                    }
                    TetherLanService.ACTION_TERMINAL_SESSION -> {
                        val type = intent.getStringExtra("type") ?: ""
                        val sessId = intent.getStringExtra("sessionId") ?: ""
                        val shell = intent.getStringExtra("shellType") ?: "powershell"
                        val dir = intent.getStringExtra("workingDir") ?: ""

                        if (type == "TERMINAL_SESSION_STARTED" && sessId.isNotEmpty()) {
                            if (activeSessions.none { it.id == sessId }) {
                                activeSessions = activeSessions + TerminalTab(sessId, shell, dir)
                                currentSessionId = sessId
                                sessionOutputs[sessId] = StringBuilder("Session started: $shell ($sessId)\n\n")
                            }
                        } else if (type == "TERMINAL_SESSION_CLOSED" && sessId.isNotEmpty()) {
                            activeSessions = activeSessions.filter { it.id != sessId }
                            if (currentSessionId == sessId && activeSessions.isNotEmpty()) {
                                currentSessionId = activeSessions.first().id
                            }
                        }
                    }
                }
            }
        }

        val filter = IntentFilter().apply {
            addAction(TetherLanService.ACTION_TERMINAL_OUTPUT)
            addAction(TetherLanService.ACTION_TERMINAL_SESSION)
        }
        ContextCompat.registerReceiver(context, receiver, filter, ContextCompat.RECEIVER_NOT_EXPORTED)

        onDispose {
            try { context.unregisterReceiver(receiver) } catch (_: Exception) {}
        }
    }

    // Auto-scroll output on new lines
    val currentOutputText = sessionOutputs[currentSessionId]?.toString() ?: ""
    LaunchedEffect(currentOutputText) {
        outputScrollState.animateScrollTo(outputScrollState.maxValue)
    }

    Box(modifier = Modifier.fillMaxSize()) {
        DeepSpaceCanvasVisualizer()

        Scaffold(
            topBar = {
                TopAppBar(
                    title = { Text("Remote Terminal", color = TextPrimary, fontWeight = FontWeight.SemiBold) },
                    navigationIcon = {
                        IconButton(onClick = onBack) {
                            Icon(Icons.Default.ArrowBack, contentDescription = "Back", tint = TextPrimary)
                        }
                    },
                    actions = {
                        IconButton(onClick = { showNewSessionDialog = true }) {
                            Icon(Icons.Default.Add, contentDescription = "New Terminal Session", tint = LiquidCyan)
                        }
                        IconButton(onClick = {
                            sessionOutputs[currentSessionId]?.clear()
                            sessionOutputs[currentSessionId] = StringBuilder()
                        }) {
                            Icon(Icons.Default.DeleteSweep, contentDescription = "Clear Terminal", tint = TextSecondary)
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
                // Session Tabs Row
                ScrollableTabRow(
                    selectedTabIndex = activeSessions.indexOfFirst { it.id == currentSessionId }.coerceAtLeast(0),
                    containerColor = SurfaceElevated.copy(alpha = 0.6f),
                    contentColor = LiquidCyan,
                    edgePadding = 16.dp,
                    divider = {}
                ) {
                    activeSessions.forEach { tab ->
                        Tab(
                            selected = tab.id == currentSessionId,
                            onClick = { currentSessionId = tab.id },
                            text = {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Text(
                                        "${tab.shellType.uppercase()} [${tab.id.take(4)}]",
                                        color = if (tab.id == currentSessionId) LiquidCyan else TextSecondary,
                                        style = MaterialTheme.typography.labelSmall
                                    )
                                    if (activeSessions.size > 1) {
                                        Spacer(modifier = Modifier.width(6.dp))
                                        Icon(
                                            Icons.Default.Close,
                                            contentDescription = "Close Tab",
                                            tint = TextMuted,
                                            modifier = Modifier
                                                .size(14.dp)
                                                .clickable {
                                                    service?.sendTerminalClose(tab.id)
                                                    activeSessions = activeSessions.filter { it.id != tab.id }
                                                    if (currentSessionId == tab.id && activeSessions.isNotEmpty()) {
                                                        currentSessionId = activeSessions.first().id
                                                    }
                                                }
                                        )
                                    }
                                }
                            }
                        )
                    }
                }

                // Monospace Terminal Canvas
                Box(
                    modifier = Modifier
                        .weight(1f)
                        .fillMaxWidth()
                        .padding(12.dp)
                        .clip(RoundedCornerShape(12.dp))
                        .background(Color(0xFF0C0E14))
                        .border(1.dp, GlassBorder, RoundedCornerShape(12.dp))
                        .padding(12.dp)
                ) {
                    Text(
                        text = if (currentOutputText.isNotEmpty()) currentOutputText else "No terminal output yet.",
                        color = Color(0xFF4AF626), // Classic Phosphor Terminal Green
                        fontFamily = FontFamily.Monospace,
                        fontSize = 12.sp,
                        lineHeight = 16.sp,
                        modifier = Modifier
                            .fillMaxSize()
                            .verticalScroll(outputScrollState)
                    )
                }

                // Virtual Terminal Shortcut Bar
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 12.dp, vertical = 4.dp)
                        .horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    fun sendKey(k: String) {
                        service?.sendTerminalInput(currentSessionId, k)
                    }

                    OutlinedButton(
                        onClick = { sendKey("\u0003") }, // Ctrl+C
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp),
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = AlertRed)
                    ) {
                        Text("Ctrl+C", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                    }
                    OutlinedButton(
                        onClick = { sendKey("\t") }, // Tab
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp),
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = LiquidCyan)
                    ) {
                        Text("TAB", fontSize = 11.sp)
                    }
                    OutlinedButton(
                        onClick = { sendKey("\u001b") }, // Esc
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp),
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = TextSecondary)
                    ) {
                        Text("ESC", fontSize = 11.sp)
                    }
                    OutlinedButton(
                        onClick = { sendKey("\u001b[A") }, // Up arrow
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp),
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = TextSecondary)
                    ) {
                        Text("↑", fontSize = 11.sp)
                    }
                    OutlinedButton(
                        onClick = { sendKey("\u001b[B") }, // Down arrow
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp),
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = TextSecondary)
                    ) {
                        Text("↓", fontSize = 11.sp)
                    }
                    OutlinedButton(
                        onClick = { sendKey("ipconfig\r\n") },
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp),
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = IntegrityGreen)
                    ) {
                        Text("ipconfig", fontSize = 11.sp)
                    }
                    OutlinedButton(
                        onClick = { sendKey("git status\r\n") },
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp),
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = IntegrityGreen)
                    ) {
                        Text("git status", fontSize = 11.sp)
                    }
                }

                // Command Input Field
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(12.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    TextField(
                        value = commandInput,
                        onValueChange = { commandInput = it },
                        modifier = Modifier.weight(1f),
                        placeholder = { Text("Enter shell command...", color = TextMuted) },
                        singleLine = true,
                        keyboardOptions = KeyboardOptions(imeAction = ImeAction.Send),
                        keyboardActions = KeyboardActions(onSend = {
                            if (commandInput.isNotEmpty()) {
                                service?.sendTerminalInput(currentSessionId, commandInput + "\r\n")
                                commandInput = ""
                            }
                        }),
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

                    Spacer(modifier = Modifier.width(8.dp))

                    IconButton(
                        onClick = {
                            if (commandInput.isNotEmpty()) {
                                service?.sendTerminalInput(currentSessionId, commandInput + "\r\n")
                                commandInput = ""
                            }
                        },
                        modifier = Modifier
                            .size(48.dp)
                            .clip(CircleShape)
                            .background(LiquidCyan)
                    ) {
                        Icon(Icons.Default.Send, contentDescription = "Send Command", tint = DeepSpace)
                    }
                }
            }
        }
    }

    // New Session Dialog
    if (showNewSessionDialog) {
        val shells = listOf("powershell", "cmd", "pwsh", "wsl")
        var selectedShell by remember { mutableStateOf("powershell") }

        AlertDialog(
            onDismissRequest = { showNewSessionDialog = false },
            title = { Text("Launch New Shell Session", color = TextPrimary) },
            text = {
                Column {
                    Text("Select Target Environment:", color = TextSecondary, style = MaterialTheme.typography.bodySmall)
                    Spacer(modifier = Modifier.height(12.dp))
                    shells.forEach { s ->
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable { selectedShell = s }
                                .padding(vertical = 8.dp)
                        ) {
                            RadioButton(
                                selected = selectedShell == s,
                                onClick = { selectedShell = s },
                                colors = RadioButtonDefaults.colors(selectedColor = LiquidCyan)
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                when (s) {
                                    "powershell" -> "Windows PowerShell (5.1)"
                                    "cmd" -> "Command Prompt (cmd.exe)"
                                    "pwsh" -> "PowerShell 7 Core (pwsh.exe)"
                                    "wsl" -> "Windows Subsystem for Linux (WSL)"
                                    else -> s
                                },
                                color = TextPrimary
                            )
                        }
                    }
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        service?.sendTerminalStart(selectedShell)
                        showNewSessionDialog = false
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = LiquidCyan)
                ) {
                    Text("Launch", color = DeepSpace)
                }
            },
            dismissButton = {
                TextButton(onClick = { showNewSessionDialog = false }) {
                    Text("Cancel", color = TextSecondary)
                }
            },
            containerColor = SurfaceElevated
        )
    }
}
