package com.tether.phone.ui.screens

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import com.tether.phone.*
import com.tether.phone.ui.components.DeepSpaceCanvasVisualizer
import com.tether.phone.ui.theme.*
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RemoteTerminalScreen(
    onBack: () -> Unit
) {
    val context = LocalContext.current
    val service = TetherLanService.instance
    val keyboardController = LocalSoftwareKeyboardController.current
    val focusRequester = remember { FocusRequester() }

    // Fullscreen state (portrait)
    var isFullscreen by remember { mutableStateOf(false) }
    BackHandler(enabled = isFullscreen) {
        isFullscreen = false
    }

    // Session tabs: id -> TerminalTab
    var activeSessions by remember {
        mutableStateOf(
            listOf(TerminalTab(id = "default", shellType = "powershell", workingDir = ""))
        )
    }
    var currentSessionId by remember { mutableStateOf("default") }
    // Session output buffers: id -> StringBuilder
    val sessionOutputs = remember { mutableStateMapOf<String, StringBuilder>() }
    if (!sessionOutputs.containsKey("default")) {
        sessionOutputs["default"] = StringBuilder("Windows PowerShell Interactive Console\nReady.\n\n")
    }

    // Direct inline Termux-style command input buffer
    var currentInput by remember { mutableStateOf("") }
    var cursorVisible by remember { mutableStateOf(true) }
    var showNewSessionDialog by remember { mutableStateOf(false) }
    val outputScrollState = rememberScrollState()

    // Blinking terminal block cursor (500ms cycle)
    LaunchedEffect(Unit) {
        while (isActive) {
            delay(500)
            cursorVisible = !cursorVisible
        }
    }

    // Focus terminal on appearance
    LaunchedEffect(Unit) {
        delay(200)
        focusRequester.requestFocus()
        keyboardController?.show()
    }

    DisposableEffect(context) {
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(ctx: Context?, intent: Intent?) {
                when (intent?.action) {
                    TetherLanService.ACTION_TERMINAL_OUTPUT -> {
                        val sessId = intent.getStringExtra("sessionId") ?: "default"
                        val data = intent.getStringExtra("data") ?: ""
                        val wd = intent.getStringExtra("workingDir")
                        if (!wd.isNullOrBlank()) {
                            activeSessions = activeSessions.map {
                                if (it.id == sessId || (it.id == "default" && activeSessions.size == 1)) it.copy(workingDir = wd) else it
                            }
                        }
                        if (currentSessionId == "default" && sessId != "default" && activeSessions.size == 1 && activeSessions[0].id == "default") {
                            activeSessions = listOf(TerminalTab(sessId, "powershell", wd ?: ""))
                            currentSessionId = sessId
                        }
                        val sb = sessionOutputs.getOrPut(sessId) { StringBuilder() }
                        sb.append(data)
                        sessionOutputs[sessId] = StringBuilder(sb.toString())
                    }
                    TetherLanService.ACTION_TERMINAL_SESSION -> {
                        val type = intent.getStringExtra("type") ?: ""
                        val sessId = intent.getStringExtra("sessionId") ?: ""
                        val shell = intent.getStringExtra("shellType") ?: "powershell"
                        val dir = intent.getStringExtra("workingDir") ?: ""
                        val success = intent.getBooleanExtra("success", true)

                        if (!success) {
                            val reason = intent.getStringExtra("reason") ?: "Failed to start terminal session"
                            val sb = sessionOutputs.getOrPut(currentSessionId) { StringBuilder() }
                            sb.append("\n[Error] $reason\n\n")
                            sessionOutputs[currentSessionId] = StringBuilder(sb.toString())
                        } else if (type == "TERMINAL_SESSION_STARTED" && sessId.isNotEmpty()) {
                            if (activeSessions.size == 1 && activeSessions[0].id == "default") {
                                activeSessions = listOf(TerminalTab(sessId, shell, dir))
                                currentSessionId = sessId
                                val sb = sessionOutputs.getOrPut(sessId) { StringBuilder() }
                                if (sb.isEmpty()) {
                                    sb.append("Session started: $shell ($sessId)\n\n")
                                    sessionOutputs[sessId] = StringBuilder(sb.toString())
                                }
                            } else if (activeSessions.none { it.id == sessId }) {
                                activeSessions = activeSessions + TerminalTab(sessId, shell, dir)
                                currentSessionId = sessId
                                val sb = sessionOutputs.getOrPut(sessId) { StringBuilder() }
                                if (sb.isEmpty()) {
                                    sb.append("Session started: $shell ($sessId)\n\n")
                                    sessionOutputs[sessId] = StringBuilder(sb.toString())
                                }
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

    LaunchedEffect(service) {
        if (service != null && activeSessions.all { it.id == "default" }) {
            service.sendTerminalStart()
        }
    }

    // Auto-scroll output when text updates
    val currentOutputText = sessionOutputs[currentSessionId]?.toString() ?: ""
    LaunchedEffect(currentOutputText, currentInput) {
        outputScrollState.scrollTo(outputScrollState.maxValue)
    }

    // Helper to send command and echo locally like a real interactive terminal
    fun sendCommand(cmd: String) {
        val targetId = if (currentSessionId != "default") currentSessionId else (activeSessions.firstOrNull { it.id != "default" }?.id ?: "default")
        service?.sendTerminalInput(targetId, cmd + "\r\n")
        val sb = sessionOutputs.getOrPut(currentSessionId) { StringBuilder() }
        sb.append(cmd).append("\n")
        sessionOutputs[currentSessionId] = StringBuilder(sb.toString())
        currentInput = ""
    }

    // Clear screen (equivalent to cls) while preserving the active directory prompt
    fun clearTerminal() {
        val targetId = if (currentSessionId != "default") currentSessionId else (activeSessions.firstOrNull { it.id != "default" }?.id ?: "default")
        service?.sendTerminalInput(targetId, "cls\r\n")
        currentInput = ""
        val currentTab = activeSessions.find { it.id == currentSessionId }
        val displayDir = currentTab?.workingDir?.ifBlank { "C:\\Users\\" } ?: "C:\\Users\\"
        sessionOutputs[currentSessionId] = StringBuilder("PS $displayDir> ")
    }

    // Full Termux-style terminal display combining output, inline typed text, and blinking cursor
    val fullTerminalDisplay = buildString {
        append(currentOutputText)
        append(currentInput)
        if (cursorVisible) {
            append("█")
        }
    }

    Box(modifier = Modifier.fillMaxSize()) {
        DeepSpaceCanvasVisualizer()

        Column(
            modifier = Modifier
                .fillMaxSize()
                .statusBarsPadding()
                .imePadding()
        ) {
            if (!isFullscreen) {
                // Top App Bar
                TopAppBar(
                    title = { Text("Remote Terminal", color = TextPrimary, fontWeight = FontWeight.SemiBold) },
                    navigationIcon = {
                        IconButton(onClick = onBack) {
                            Icon(Icons.Default.ArrowBack, contentDescription = "Back", tint = TextPrimary)
                        }
                    },
                    actions = {
                        IconButton(onClick = { isFullscreen = true }) {
                            Icon(Icons.Default.Fullscreen, contentDescription = "Fullscreen", tint = LiquidCyan)
                        }
                        IconButton(onClick = { showNewSessionDialog = true }) {
                            Icon(Icons.Default.Add, contentDescription = "New Terminal Session", tint = LiquidCyan)
                        }
                        IconButton(onClick = { clearTerminal() }) {
                            Icon(Icons.Default.DeleteSweep, contentDescription = "Clear Terminal (cls)", tint = TextSecondary)
                        }
                    },
                    colors = TopAppBarDefaults.topAppBarColors(containerColor = Color.Transparent)
                )

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

                // Working Directory Status Bar
                val currentTab = activeSessions.find { it.id == currentSessionId }
                val displayDir = currentTab?.workingDir?.ifBlank { "C:\\Users\\" } ?: "C:\\"
                Surface(
                    color = SurfaceElevated.copy(alpha = 0.5f),
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 12.dp, vertical = 4.dp),
                    shape = RoundedCornerShape(8.dp),
                    border = androidx.compose.foundation.BorderStroke(1.dp, GlassBorder)
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(Icons.Default.Folder, contentDescription = null, tint = LiquidCyan, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = displayDir,
                            color = TextPrimary,
                            fontSize = 11.sp,
                            fontFamily = FontFamily.Monospace,
                            maxLines = 1,
                            overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
                            modifier = Modifier.weight(1f)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Surface(
                            color = IntegrityGreen.copy(alpha = 0.15f),
                            shape = RoundedCornerShape(4.dp)
                        ) {
                            Text(
                                text = "NON-ADMIN SAFE",
                                color = IntegrityGreen,
                                fontSize = 9.sp,
                                fontWeight = FontWeight.Bold,
                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                            )
                        }
                    }
                }
            }

            // Direct Termux-Style Monospace Terminal Canvas
            Box(
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth()
                    .padding(if (isFullscreen) 4.dp else 12.dp)
                    .clip(RoundedCornerShape(12.dp))
                    .background(Color(0xFF0C0E14))
                    .border(1.dp, GlassBorder, RoundedCornerShape(12.dp))
                    .clickable(
                        interactionSource = remember { MutableInteractionSource() },
                        indication = null
                    ) {
                        focusRequester.requestFocus()
                        keyboardController?.show()
                    }
                    .padding(12.dp)
            ) {
                Text(
                    text = fullTerminalDisplay,
                    color = Color(0xFF4AF626), // Classic Phosphor Terminal Green
                    fontFamily = FontFamily.Monospace,
                    fontSize = 12.sp,
                    lineHeight = 16.sp,
                    modifier = Modifier
                        .fillMaxSize()
                        .verticalScroll(outputScrollState)
                )

                // Floating Exit Fullscreen Button
                if (isFullscreen) {
                    IconButton(
                        onClick = { isFullscreen = false },
                        modifier = Modifier
                            .align(Alignment.TopEnd)
                            .padding(4.dp)
                            .size(36.dp)
                            .background(SurfaceElevated.copy(alpha = 0.85f), CircleShape)
                            .border(1.dp, GlassBorder, CircleShape)
                    ) {
                        Icon(
                            Icons.Default.FullscreenExit,
                            contentDescription = "Exit Fullscreen",
                            tint = LiquidCyan,
                            modifier = Modifier.size(20.dp)
                        )
                    }
                }

                // Seamless Direct Key Capture
                BasicTextField(
                    value = currentInput,
                    onValueChange = { input ->
                        if (input.contains('\n') || input.contains('\r')) {
                            val cleanCmd = input.replace("\r", "").replace("\n", "")
                            val targetId = if (currentSessionId != "default") currentSessionId else (activeSessions.firstOrNull { it.id != "default" }?.id ?: "default")
                            service?.sendTerminalInput(targetId, cleanCmd + "\r\n")
                            val sb = sessionOutputs.getOrPut(currentSessionId) { StringBuilder() }
                            sb.append(cleanCmd).append("\n")
                            sessionOutputs[currentSessionId] = StringBuilder(sb.toString())
                            currentInput = ""
                        } else {
                            currentInput = input
                        }
                    },
                    modifier = Modifier
                        .focusRequester(focusRequester)
                        .size(1.dp)
                        .alpha(0.01f),
                    keyboardOptions = KeyboardOptions(
                        autoCorrectEnabled = false,
                        imeAction = ImeAction.Send
                    ),
                    keyboardActions = KeyboardActions(
                        onSend = {
                            val targetId = if (currentSessionId != "default") currentSessionId else (activeSessions.firstOrNull { it.id != "default" }?.id ?: "default")
                            if (currentInput.isNotEmpty()) {
                                service?.sendTerminalInput(targetId, currentInput + "\r\n")
                                val sb = sessionOutputs.getOrPut(currentSessionId) { StringBuilder() }
                                sb.append(currentInput).append("\n")
                                sessionOutputs[currentSessionId] = StringBuilder(sb.toString())
                                currentInput = ""
                            } else {
                                service?.sendTerminalInput(targetId, "\r\n")
                                val sb = sessionOutputs.getOrPut(currentSessionId) { StringBuilder() }
                                sb.append("\n")
                                sessionOutputs[currentSessionId] = StringBuilder(sb.toString())
                            }
                        }
                    ),
                    cursorBrush = SolidColor(Color.Transparent)
                )
            }

            // Virtual Terminal Shortcut Bar directly above the soft keyboard
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 8.dp, vertical = 4.dp)
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(6.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                fun sendKey(k: String) {
                    val targetId = if (currentSessionId != "default") currentSessionId else (activeSessions.firstOrNull { it.id != "default" }?.id ?: "default")
                    if (k == "\u0003") { // Ctrl+C
                        currentInput = ""
                        service?.sendTerminalInput(targetId, k)
                        val sb = sessionOutputs.getOrPut(currentSessionId) { StringBuilder() }
                        sb.append("^C\n")
                        sessionOutputs[currentSessionId] = StringBuilder(sb.toString())
                    } else if (k == "cls\r\n") {
                        clearTerminal()
                    } else if (k.endsWith("\r\n")) {
                        currentInput = ""
                        service?.sendTerminalInput(targetId, k)
                        val sb = sessionOutputs.getOrPut(currentSessionId) { StringBuilder() }
                        sb.append(k.trimEnd()).append("\n")
                        sessionOutputs[currentSessionId] = StringBuilder(sb.toString())
                    } else {
                        service?.sendTerminalInput(targetId, k)
                    }
                }

                // Keyboard toggle button
                OutlinedButton(
                    onClick = {
                        focusRequester.requestFocus()
                        keyboardController?.show()
                    },
                    contentPadding = PaddingValues(horizontal = 8.dp, vertical = 4.dp),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = LiquidCyan)
                ) {
                    Icon(Icons.Default.Keyboard, contentDescription = "Show Keyboard", modifier = Modifier.size(15.dp))
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
                    onClick = { clearTerminal() },
                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = LiquidCyan)
                ) {
                    Text("cls", fontSize = 11.sp)
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
                OutlinedButton(
                    onClick = { sendKey("dir\r\n") },
                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = LiquidCyan)
                ) {
                    Text("dir", fontSize = 11.sp)
                }
                OutlinedButton(
                    onClick = { sendKey("exit\r\n") },
                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = AlertRed)
                ) {
                    Text("exit", fontSize = 11.sp)
                }
            }
        }
    }

    // New Session Dialog
    if (showNewSessionDialog) {
        val isLinux = service?.connectedPeerOs.equals("linux", ignoreCase = true)
        val shells = if (isLinux) listOf("bash", "sh", "zsh", "pwsh") else listOf("powershell", "cmd", "pwsh", "wsl")
        var selectedShell by remember(isLinux) { mutableStateOf(if (isLinux) "bash" else "powershell") }

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
                                    "bash" -> "Linux Bash (/bin/bash)"
                                    "sh" -> "Standard Shell (/bin/sh)"
                                    "zsh" -> "Z Shell (/bin/zsh)"
                                    "powershell" -> "Windows PowerShell (5.1)"
                                    "cmd" -> "Command Prompt (cmd.exe)"
                                    "pwsh" -> "PowerShell 7 Core (pwsh)"
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
