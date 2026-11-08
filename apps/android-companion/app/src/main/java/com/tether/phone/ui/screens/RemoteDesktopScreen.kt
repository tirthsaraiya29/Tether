package com.tether.phone.ui.screens

import android.content.res.Configuration
import android.graphics.BitmapFactory
import android.view.HapticFeedbackConstants
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectDragGestures
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.gestures.detectVerticalDragGestures
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
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.IntSize
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.tether.phone.*
import com.tether.phone.ui.components.DeepSpaceCanvasVisualizer
import com.tether.phone.ui.components.ProfessionalGlassSurface
import com.tether.phone.ui.theme.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.Request
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RemoteDesktopScreen(
    onBack: () -> Unit
) {
    val context = LocalContext.current
    val view = LocalView.current
    val coroutineScope = rememberCoroutineScope()
    val service = TetherLanService.instance
    val hostIp = service?.connectedHostAddress

    val configuration = LocalConfiguration.current
    var isFullScreenLandscape by remember { mutableStateOf(false) }
    val isLandscape = configuration.orientation == Configuration.ORIENTATION_LANDSCAPE || isFullScreenLandscape

    var token by remember { mutableStateOf<String?>(null) }
    var currentFrame by remember { mutableStateOf<android.graphics.Bitmap?>(null) }
    var isStreaming by remember { mutableStateOf(true) }
    var streamError by remember { mutableStateOf<String?>(null) }
    var targetFps by remember { mutableIntStateOf(30) }
    var targetQuality by remember { mutableIntStateOf(65) }

    var showWindowDialog by remember { mutableStateOf(false) }
    var openWindows by remember { mutableStateOf<List<DesktopWindow>>(emptyList()) }
    var selectedWindow by remember { mutableStateOf<DesktopWindow?>(null) }

    var showScreenshotPreview by remember { mutableStateOf(false) }
    var screenshotBitmap by remember { mutableStateOf<android.graphics.Bitmap?>(null) }
    var isCapturingScreenshot by remember { mutableStateOf(false) }

    var imageBoxSize by remember { mutableStateOf(IntSize.Zero) }

    // Prioritization: Mark active heavy task so background sync yields completely
    DisposableEffect(Unit) {
        service?.isHeavyTaskActive = true
        service?.currentActiveScreen = "RemoteDesktop"
        onDispose {
            service?.isHeavyTaskActive = false
            service?.currentActiveScreen = null
            service?.triggerFullSyncIfNeeded()
        }
    }

    LaunchedEffect(Unit) {
        if (service != null && hostIp != null) {
            try {
                token = service.requestFileTransferToken()
            } catch (e: Exception) {
                streamError = "Failed to acquire session token: ${e.message}"
            }
        } else {
            streamError = "Windows host not connected."
        }
    }

    // High-performance MJPEG Streaming coroutine
    LaunchedEffect(hostIp, token, isStreaming, targetFps, targetQuality) {
        if (!isStreaming || hostIp == null || token == null) return@LaunchedEffect

        withContext(Dispatchers.IO) {
            try {
                val client = FileTransferClient.getPinnedClient(context)
                val url = "https://$hostIp:37124/api/desktop/stream?fps=$targetFps&quality=$targetQuality"
                val requestBuilder = Request.Builder().url(url)

                val timestampMs = System.currentTimeMillis().toString()
                val pinnedKey = FileTransferClient.resolvePinnedKey(context, null)
                if (pinnedKey != null) {
                    val winSpkiBase64 = android.util.Base64.encodeToString(pinnedKey, android.util.Base64.NO_WRAP)
                    val proofData = "$token:$timestampMs:$winSpkiBase64".toByteArray(Charsets.UTF_8)
                    val sig = ProductionSecurityEngine().signWithIdentityKey(proofData)
                    val proofBase64 = android.util.Base64.encodeToString(sig, android.util.Base64.NO_WRAP)
                    requestBuilder
                        .header("Authorization", "Bearer $token")
                        .header("X-Tether-Client-Proof", proofBase64)
                        .header("X-Tether-Client-Timestamp", timestampMs)
                        .header("X-Tether-Client-WinSpki", winSpkiBase64)
                }

                client.newCall(requestBuilder.build()).execute().use { response ->
                    if (!response.isSuccessful) {
                        streamError = "Stream connection failed: HTTP ${response.code}"
                        return@use
                    }
                    val rawStream: InputStream = response.body?.byteStream() ?: return@use
                    val bis = BufferedInputStream(rawStream, 65536)

                    val headerBuf = ByteArrayOutputStream(256)
                    val frameBuffer = ByteArrayOutputStream(65536)

                    fun readLine(): String {
                        headerBuf.reset()
                        var prev = -1
                        while (isActive && isStreaming) {
                            val c = bis.read()
                            if (c == -1) break
                            if (prev == '\r'.code && c == '\n'.code) {
                                val bytes = headerBuf.toByteArray()
                                return if (bytes.size > 1) String(bytes, 0, bytes.size - 1, Charsets.US_ASCII) else ""
                            }
                            headerBuf.write(c)
                            prev = c
                        }
                        return ""
                    }

                    while (isActive && isStreaming) {
                        var contentLength = -1
                        while (isActive && isStreaming) {
                            val line = readLine()
                            if (line.isEmpty()) break
                            if (line.startsWith("Content-Length:", ignoreCase = true)) {
                                contentLength = line.substringAfter(":").trim().toIntOrNull() ?: -1
                            }
                        }

                        if (contentLength > 0 && contentLength < 10_000_000) {
                            val imgBytes = ByteArray(contentLength)
                            var readTotal = 0
                            while (readTotal < contentLength && isActive && isStreaming) {
                                val r = bis.read(imgBytes, readTotal, contentLength - readTotal)
                                if (r == -1) break
                                readTotal += r
                            }

                            if (readTotal == contentLength) {
                                val bmp = BitmapFactory.decodeByteArray(imgBytes, 0, contentLength)
                                if (bmp != null) {
                                    currentFrame = bmp
                                }
                            }
                        } else {
                            val buf = ByteArray(8192)
                            val r = bis.read(buf)
                            if (r == -1) break
                            frameBuffer.write(buf, 0, r)
                            val b = frameBuffer.toByteArray()
                            var s = -1
                            var e = -1
                            for (i in 0 until b.size - 1) {
                                if (b[i] == 0xFF.toByte() && b[i + 1] == 0xD8.toByte()) s = i
                                if (s != -1 && b[i] == 0xFF.toByte() && b[i + 1] == 0xD9.toByte()) {
                                    e = i + 2
                                    break
                                }
                            }
                            if (s != -1 && e != -1 && e > s) {
                                val jpg = b.copyOfRange(s, e)
                                val bmp = BitmapFactory.decodeByteArray(jpg, 0, jpg.size)
                                if (bmp != null) currentFrame = bmp
                                frameBuffer.reset()
                                if (e < b.size) frameBuffer.write(b, e, b.size - e)
                            } else if (frameBuffer.size() > 2_000_000) {
                                frameBuffer.reset()
                            }
                        }
                    }
                }
            } catch (e: Exception) {
                if (isActive) {
                    streamError = "Stream interrupted: ${e.message}"
                }
            }
        }
    }

    fun sendClick(buttonId: Byte) {
        view.performHapticFeedback(HapticFeedbackConstants.VIRTUAL_KEY)
        val down = InputEvent.ButtonState(buttonId, BUTTON_STATE_DOWN).toBinaryFrame()
        val up = InputEvent.ButtonState(buttonId, BUTTON_STATE_UP).toBinaryFrame()
        service?.sendInputFrame(down)
        service?.sendInputFrame(up)
    }

    Box(modifier = Modifier.fillMaxSize()) {
        DeepSpaceCanvasVisualizer()

        if (isLandscape) {
            // Fullscreen Landscape Display Mode
            Box(modifier = Modifier.fillMaxSize()) {
                if (currentFrame != null) {
                    Image(
                        bitmap = currentFrame!!.asImageBitmap(),
                        contentDescription = "Desktop Stream Fullscreen",
                        modifier = Modifier
                            .fillMaxSize()
                            .onGloballyPositioned { coordinates ->
                                imageBoxSize = coordinates.size
                            }
                            .pointerInput(Unit) {
                                detectDragGestures { change, dragAmount ->
                                    change.consume()
                                    val dx = (dragAmount.x * 1.5f).toInt().coerceIn(-32000, 32000).toShort()
                                    val dy = (dragAmount.y * 1.5f).toInt().coerceIn(-32000, 32000).toShort()
                                    if (dx != 0.toShort() || dy != 0.toShort()) {
                                        service?.sendInputFrame(InputEvent.RelativeMove(dx, dy).toBinaryFrame())
                                    }
                                }
                            }
                            .pointerInput(Unit) {
                                detectTapGestures(
                                    onTap = { offset ->
                                        if (imageBoxSize.width > 0 && imageBoxSize.height > 0) {
                                            val normX = ((offset.x / imageBoxSize.width.toFloat()) * 65535f).toInt().coerceIn(0, 65535)
                                            val normY = ((offset.y / imageBoxSize.height.toFloat()) * 65535f).toInt().coerceIn(0, 65535)
                                            service?.sendInputFrame(InputEvent.AbsoluteMove(normX, normY).toBinaryFrame())
                                            sendClick(MOUSE_BUTTON_LEFT)
                                        }
                                    },
                                    onDoubleTap = { offset ->
                                        if (imageBoxSize.width > 0 && imageBoxSize.height > 0) {
                                            val normX = ((offset.x / imageBoxSize.width.toFloat()) * 65535f).toInt().coerceIn(0, 65535)
                                            val normY = ((offset.y / imageBoxSize.height.toFloat()) * 65535f).toInt().coerceIn(0, 65535)
                                            service?.sendInputFrame(InputEvent.AbsoluteMove(normX, normY).toBinaryFrame())
                                            sendClick(MOUSE_BUTTON_LEFT)
                                            sendClick(MOUSE_BUTTON_LEFT)
                                        }
                                    },
                                    onLongPress = { offset ->
                                        if (imageBoxSize.width > 0 && imageBoxSize.height > 0) {
                                            val normX = ((offset.x / imageBoxSize.width.toFloat()) * 65535f).toInt().coerceIn(0, 65535)
                                            val normY = ((offset.y / imageBoxSize.height.toFloat()) * 65535f).toInt().coerceIn(0, 65535)
                                            service?.sendInputFrame(InputEvent.AbsoluteMove(normX, normY).toBinaryFrame())
                                            sendClick(MOUSE_BUTTON_RIGHT)
                                        }
                                    }
                                )
                            },
                        contentScale = ContentScale.Fit
                    )
                }

                // Landscape Floating Controls Overlay
                Row(
                    modifier = Modifier
                        .align(Alignment.TopEnd)
                        .padding(12.dp)
                        .clip(CircleShape)
                        .background(SurfaceElevated.copy(alpha = 0.85f))
                        .padding(horizontal = 8.dp, vertical = 4.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    IconButton(onClick = { isFullScreenLandscape = false }) {
                        Icon(Icons.Default.FullscreenExit, contentDescription = "Exit Fullscreen", tint = LiquidCyan)
                    }
                    IconButton(onClick = { isStreaming = !isStreaming }) {
                        Icon(
                            if (isStreaming) Icons.Default.Pause else Icons.Default.PlayArrow,
                            contentDescription = "Toggle Stream",
                            tint = if (isStreaming) IntegrityGreen else MatrixGold
                        )
                    }
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.Close, contentDescription = "Close", tint = TextPrimary)
                    }
                }
            }
        } else {
            // Portrait Mode: Framed Screen at Top + Dedicated Trackpad & Controls Below
            Scaffold(
                topBar = {
                    TopAppBar(
                        title = {
                            Column {
                                Text("Remote Desktop", style = MaterialTheme.typography.titleMedium, color = TextPrimary)
                                Text(
                                    if (selectedWindow != null) selectedWindow!!.title else "Full Desktop Display",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = LiquidCyan
                                )
                            }
                        },
                        navigationIcon = {
                            IconButton(onClick = onBack) {
                                Icon(Icons.Default.ArrowBack, contentDescription = "Back", tint = TextPrimary)
                            }
                        },
                        actions = {
                            // Fullscreen Landscape Toggle
                            IconButton(onClick = { isFullScreenLandscape = true }) {
                                Icon(Icons.Default.Fullscreen, contentDescription = "Landscape Fullscreen", tint = LiquidCyan)
                            }

                            // Capture screenshot
                            IconButton(
                                onClick = {
                                    coroutineScope.launch {
                                        if (hostIp == null || token == null) return@launch
                                        isCapturingScreenshot = true
                                        try {
                                            val bytes = FileTransferClient.fetchScreenshotBytes(
                                                hostIp = hostIp,
                                                windowId = selectedWindow?.hwnd ?: 0L,
                                                quality = 90,
                                                token = token!!,
                                                context = context
                                            )
                                            if (bytes != null) {
                                                screenshotBitmap = BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
                                                showScreenshotPreview = true
                                            }
                                        } catch (e: Exception) {
                                            streamError = "Screenshot failed: ${e.message}"
                                        } finally {
                                            isCapturingScreenshot = false
                                        }
                                    }
                                }
                            ) {
                                Icon(Icons.Default.CameraAlt, contentDescription = "Capture Screenshot", tint = LiquidCyan)
                            }

                            // Select Window
                            IconButton(
                                onClick = {
                                    coroutineScope.launch {
                                        if (hostIp == null || token == null) return@launch
                                        try {
                                            openWindows = FileTransferClient.fetchDesktopWindows(hostIp, token!!, context)
                                            showWindowDialog = true
                                        } catch (e: Exception) {
                                            streamError = "Failed loading windows: ${e.message}"
                                        }
                                    }
                                }
                            ) {
                                Icon(Icons.Default.FeaturedPlayList, contentDescription = "Select Window", tint = TextPrimary)
                            }

                            // Pause / Resume Stream
                            IconButton(onClick = { isStreaming = !isStreaming }) {
                                Icon(
                                    if (isStreaming) Icons.Default.Pause else Icons.Default.PlayArrow,
                                    contentDescription = "Toggle Stream",
                                    tint = if (isStreaming) IntegrityGreen else MatrixGold
                                )
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
                        .padding(horizontal = 12.dp, vertical = 6.dp)
                ) {
                    // TOP: Laptop Screen Display Viewport
                    ProfessionalGlassSurface(
                        modifier = Modifier
                            .fillMaxWidth()
                            .weight(1.15f)
                            .clip(RoundedCornerShape(16.dp))
                    ) {
                        Box(modifier = Modifier.fillMaxSize()) {
                            if (currentFrame != null) {
                                Image(
                                    bitmap = currentFrame!!.asImageBitmap(),
                                    contentDescription = "Desktop Stream Viewport",
                                    modifier = Modifier
                                        .fillMaxSize()
                                        .onGloballyPositioned { coordinates ->
                                            imageBoxSize = coordinates.size
                                        }
                                        .pointerInput(Unit) {
                                            detectTapGestures(
                                                onTap = { offset ->
                                                    if (imageBoxSize.width > 0 && imageBoxSize.height > 0) {
                                                        val normX = ((offset.x / imageBoxSize.width.toFloat()) * 65535f).toInt().coerceIn(0, 65535)
                                                        val normY = ((offset.y / imageBoxSize.height.toFloat()) * 65535f).toInt().coerceIn(0, 65535)
                                                        service?.sendInputFrame(InputEvent.AbsoluteMove(normX, normY).toBinaryFrame())
                                                        sendClick(MOUSE_BUTTON_LEFT)
                                                    }
                                                },
                                                onDoubleTap = { offset ->
                                                    if (imageBoxSize.width > 0 && imageBoxSize.height > 0) {
                                                        val normX = ((offset.x / imageBoxSize.width.toFloat()) * 65535f).toInt().coerceIn(0, 65535)
                                                        val normY = ((offset.y / imageBoxSize.height.toFloat()) * 65535f).toInt().coerceIn(0, 65535)
                                                        service?.sendInputFrame(InputEvent.AbsoluteMove(normX, normY).toBinaryFrame())
                                                        sendClick(MOUSE_BUTTON_LEFT)
                                                        sendClick(MOUSE_BUTTON_LEFT)
                                                    }
                                                },
                                                onLongPress = { offset ->
                                                    if (imageBoxSize.width > 0 && imageBoxSize.height > 0) {
                                                        val normX = ((offset.x / imageBoxSize.width.toFloat()) * 65535f).toInt().coerceIn(0, 65535)
                                                        val normY = ((offset.y / imageBoxSize.height.toFloat()) * 65535f).toInt().coerceIn(0, 65535)
                                                        service?.sendInputFrame(InputEvent.AbsoluteMove(normX, normY).toBinaryFrame())
                                                        sendClick(MOUSE_BUTTON_RIGHT)
                                                    }
                                                }
                                            )
                                        },
                                    contentScale = ContentScale.Fit
                                )
                            } else if (streamError != null) {
                                Column(
                                    modifier = Modifier
                                        .align(Alignment.Center)
                                        .padding(16.dp),
                                    horizontalAlignment = Alignment.CenterHorizontally
                                ) {
                                    Icon(Icons.Default.Warning, contentDescription = null, tint = AlertRed, modifier = Modifier.size(36.dp))
                                    Spacer(modifier = Modifier.height(8.dp))
                                    Text(streamError!!, color = AlertRed, style = MaterialTheme.typography.bodySmall)
                                    Spacer(modifier = Modifier.height(10.dp))
                                    Button(
                                        onClick = {
                                            streamError = null
                                            isStreaming = true
                                        },
                                        colors = ButtonDefaults.buttonColors(containerColor = LiquidCyan)
                                    ) {
                                        Text("Retry", color = DeepSpace, style = MaterialTheme.typography.labelSmall)
                                    }
                                }
                            } else {
                                Column(
                                    modifier = Modifier.align(Alignment.Center),
                                    horizontalAlignment = Alignment.CenterHorizontally
                                ) {
                                    CircularProgressIndicator(color = LiquidCyan, modifier = Modifier.size(32.dp))
                                    Spacer(modifier = Modifier.height(8.dp))
                                    Text("Connecting Display Stream...", color = TextSecondary, style = MaterialTheme.typography.labelSmall)
                                }
                            }

                            // Minimal FPS/Quality badge inside screen
                            Row(
                                modifier = Modifier
                                    .align(Alignment.BottomEnd)
                                    .padding(8.dp)
                                    .clip(RoundedCornerShape(8.dp))
                                    .background(DeepSpace.copy(alpha = 0.75f))
                                    .padding(horizontal = 8.dp, vertical = 3.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text("${targetFps} FPS", color = LiquidCyan, style = MaterialTheme.typography.labelSmall, fontSize = 10.sp)
                                Spacer(modifier = Modifier.width(6.dp))
                                Text(if (isStreaming) "LIVE" else "PAUSED", color = if (isStreaming) IntegrityGreen else MatrixGold, style = MaterialTheme.typography.labelSmall, fontSize = 10.sp)
                            }
                        }
                    }

                    Spacer(modifier = Modifier.height(10.dp))

                    // BOTTOM: High-Precision Mouse Trackpad Area
                    ProfessionalGlassSurface(
                        modifier = Modifier
                            .fillMaxWidth()
                            .weight(1f)
                            .clip(RoundedCornerShape(16.dp))
                    ) {
                        Row(modifier = Modifier.fillMaxSize()) {
                            // Main Trackpad Surface
                            Box(
                                modifier = Modifier
                                    .weight(1f)
                                    .fillMaxHeight()
                                    .pointerInput(Unit) {
                                        detectDragGestures { change, dragAmount ->
                                            change.consume()
                                            // High-speed relative movement: input pump automatically aggregates micro deltas
                                            val dx = (dragAmount.x * 1.8f).toInt().coerceIn(-32000, 32000).toShort()
                                            val dy = (dragAmount.y * 1.8f).toInt().coerceIn(-32000, 32000).toShort()
                                            if (dx != 0.toShort() || dy != 0.toShort()) {
                                                service?.sendInputFrame(InputEvent.RelativeMove(dx, dy).toBinaryFrame())
                                            }
                                        }
                                    }
                                    .pointerInput(Unit) {
                                        detectTapGestures(
                                            onTap = {
                                                sendClick(MOUSE_BUTTON_LEFT)
                                            },
                                            onDoubleTap = {
                                                sendClick(MOUSE_BUTTON_LEFT)
                                                sendClick(MOUSE_BUTTON_LEFT)
                                            },
                                            onLongPress = {
                                                sendClick(MOUSE_BUTTON_RIGHT)
                                            }
                                        )
                                    }
                            ) {
                                Column(
                                    modifier = Modifier.align(Alignment.Center),
                                    horizontalAlignment = Alignment.CenterHorizontally
                                ) {
                                    Icon(Icons.Default.TouchApp, contentDescription = null, tint = LiquidCyan.copy(alpha = 0.4f), modifier = Modifier.size(36.dp))
                                    Spacer(modifier = Modifier.height(4.dp))
                                    Text("HIGH-SPEED TRACKPAD", color = TextMuted, style = MaterialTheme.typography.labelSmall, letterSpacing = 1.sp)
                                    Text("Slide to move cursor • Tap to click", color = TextMuted.copy(alpha = 0.6f), style = MaterialTheme.typography.labelSmall, fontSize = 9.sp)
                                }
                            }

                            // Right Edge Scroll Strip
                            Box(
                                modifier = Modifier
                                    .width(36.dp)
                                    .fillMaxHeight()
                                    .background(SurfaceElevated.copy(alpha = 0.5f))
                                    .pointerInput(Unit) {
                                        detectVerticalDragGestures { change, dragAmount ->
                                            change.consume()
                                            val delta = (-dragAmount * 8f).toInt().coerceIn(-1200, 1200).toShort()
                                            if (delta != 0.toShort()) {
                                                service?.sendInputFrame(InputEvent.ScrollDelta(delta).toBinaryFrame())
                                            }
                                        }
                                    },
                                contentAlignment = Alignment.Center
                            ) {
                                Icon(
                                    Icons.Default.UnfoldMore,
                                    contentDescription = "Scroll Strip",
                                    tint = LiquidCyan.copy(alpha = 0.5f),
                                    modifier = Modifier.size(20.dp)
                                )
                            }
                        }
                    }

                    Spacer(modifier = Modifier.height(8.dp))

                    // Left & Right Physical Mouse Click Buttons
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(52.dp),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Button(
                            onClick = { sendClick(MOUSE_BUTTON_LEFT) },
                            modifier = Modifier
                                .weight(1.5f)
                                .fillMaxHeight(),
                            shape = RoundedCornerShape(12.dp),
                            colors = ButtonDefaults.buttonColors(containerColor = SurfaceElevated)
                        ) {
                            Text("Left Click", color = TextPrimary, fontWeight = FontWeight.SemiBold)
                        }

                        Button(
                            onClick = { sendClick(MOUSE_BUTTON_RIGHT) },
                            modifier = Modifier
                                .weight(1f)
                                .fillMaxHeight(),
                            shape = RoundedCornerShape(12.dp),
                            colors = ButtonDefaults.buttonColors(containerColor = SurfaceElevated)
                        ) {
                            Text("Right Click", color = LiquidCyan, fontWeight = FontWeight.SemiBold)
                        }
                    }
                }
            }
        }
    }

    // Windows selector dialog
    if (showWindowDialog) {
        AlertDialog(
            onDismissRequest = { showWindowDialog = false },
            title = { Text("Select Capture Target", color = TextPrimary) },
            text = {
                LazyColumn(modifier = Modifier.fillMaxWidth().heightIn(max = 400.dp)) {
                    item {
                        Surface(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable {
                                    selectedWindow = null
                                    showWindowDialog = false
                                }
                                .padding(vertical = 8.dp),
                            color = Color.Transparent
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Default.DesktopWindows, contentDescription = null, tint = LiquidCyan)
                                Spacer(modifier = Modifier.width(12.dp))
                                Text("Entire Desktop Display", color = TextPrimary, fontWeight = FontWeight.SemiBold)
                            }
                        }
                        Divider(color = GlassBorder)
                    }
                    items(openWindows) { win ->
                        Surface(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable {
                                    selectedWindow = win
                                    showWindowDialog = false
                                }
                                .padding(vertical = 8.dp),
                            color = Color.Transparent
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Default.Window, contentDescription = null, tint = TextSecondary)
                                Spacer(modifier = Modifier.width(12.dp))
                                Column {
                                    Text(win.title, color = TextPrimary, fontWeight = FontWeight.Medium, maxLines = 1)
                                    Text(win.processName, color = TextMuted, style = MaterialTheme.typography.bodySmall)
                                }
                            }
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = { showWindowDialog = false }) {
                    Text("Cancel", color = LiquidCyan)
                }
            },
            containerColor = SurfaceElevated
        )
    }

    // Screenshot full preview dialog
    if (showScreenshotPreview && screenshotBitmap != null) {
        AlertDialog(
            onDismissRequest = { showScreenshotPreview = false },
            title = { Text("Screenshot Captured", color = TextPrimary) },
            text = {
                Image(
                    bitmap = screenshotBitmap!!.asImageBitmap(),
                    contentDescription = "Captured Screenshot",
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(300.dp)
                        .clip(RoundedCornerShape(12.dp)),
                    contentScale = ContentScale.Fit
                )
            },
            confirmButton = {
                TextButton(onClick = { showScreenshotPreview = false }) {
                    Text("Close", color = LiquidCyan)
                }
            },
            containerColor = SurfaceElevated
        )
    }
}
