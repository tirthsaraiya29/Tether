package com.tether.phone.ui.screens

import android.graphics.BitmapFactory
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectDragGestures
import androidx.compose.foundation.gestures.detectTapGestures
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
import androidx.compose.ui.platform.LocalContext
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
    val coroutineScope = rememberCoroutineScope()
    val service = TetherLanService.instance
    val hostIp = service?.connectedHostAddress

    var token by remember { mutableStateOf<String?>(null) }
    var currentFrame by remember { mutableStateOf<android.graphics.Bitmap?>(null) }
    var isStreaming by remember { mutableStateOf(true) }
    var streamError by remember { mutableStateOf<String?>(null) }
    var targetFps by remember { mutableIntStateOf(20) }
    var targetQuality by remember { mutableIntStateOf(50) }

    var showWindowDialog by remember { mutableStateOf(false) }
    var openWindows by remember { mutableStateOf<List<DesktopWindow>>(emptyList()) }
    var selectedWindow by remember { mutableStateOf<DesktopWindow?>(null) }

    var showScreenshotPreview by remember { mutableStateOf(false) }
    var screenshotBitmap by remember { mutableStateOf<android.graphics.Bitmap?>(null) }
    var isCapturingScreenshot by remember { mutableStateOf(false) }

    var imageBoxSize by remember { mutableStateOf(IntSize.Zero) }

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
                            // Fallback SOI/EOI scan if content-length missing
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

    Box(modifier = Modifier.fillMaxSize()) {
        DeepSpaceCanvasVisualizer()

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
            Box(
                modifier = Modifier
                    .padding(padding)
                    .fillMaxSize()
            ) {
                if (currentFrame != null) {
                    val bmp = currentFrame!!
                    Image(
                        bitmap = bmp.asImageBitmap(),
                        contentDescription = "Desktop Stream",
                        modifier = Modifier
                            .fillMaxSize()
                            .onGloballyPositioned { coordinates ->
                                imageBoxSize = coordinates.size
                            }
                            .pointerInput(Unit) {
                                detectDragGestures { change, dragAmount ->
                                    change.consume()
                                    // Smooth relative mouse navigation while dragging
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
                                            val absMove = InputEvent.AbsoluteMove(normX, normY).toBinaryFrame()
                                            val down = InputEvent.ButtonState(MOUSE_BUTTON_LEFT, BUTTON_STATE_DOWN).toBinaryFrame()
                                            val up = InputEvent.ButtonState(MOUSE_BUTTON_LEFT, BUTTON_STATE_UP).toBinaryFrame()
                                            service?.sendInputFrame(absMove)
                                            service?.sendInputFrame(down)
                                            service?.sendInputFrame(up)
                                        }
                                    },
                                    onDoubleTap = { offset ->
                                        if (imageBoxSize.width > 0 && imageBoxSize.height > 0) {
                                            val normX = ((offset.x / imageBoxSize.width.toFloat()) * 65535f).toInt().coerceIn(0, 65535)
                                            val normY = ((offset.y / imageBoxSize.height.toFloat()) * 65535f).toInt().coerceIn(0, 65535)
                                            val absMove = InputEvent.AbsoluteMove(normX, normY).toBinaryFrame()
                                            val down = InputEvent.ButtonState(MOUSE_BUTTON_LEFT, BUTTON_STATE_DOWN).toBinaryFrame()
                                            val up = InputEvent.ButtonState(MOUSE_BUTTON_LEFT, BUTTON_STATE_UP).toBinaryFrame()
                                            service?.sendInputFrame(absMove)
                                            service?.sendInputFrame(down)
                                            service?.sendInputFrame(up)
                                            service?.sendInputFrame(down)
                                            service?.sendInputFrame(up)
                                        }
                                    },
                                    onLongPress = { offset ->
                                        // Two-finger or long-press right click
                                        if (imageBoxSize.width > 0 && imageBoxSize.height > 0) {
                                            val normX = ((offset.x / imageBoxSize.width.toFloat()) * 65535f).toInt().coerceIn(0, 65535)
                                            val normY = ((offset.y / imageBoxSize.height.toFloat()) * 65535f).toInt().coerceIn(0, 65535)
                                            val absMove = InputEvent.AbsoluteMove(normX, normY).toBinaryFrame()
                                            val down = InputEvent.ButtonState(MOUSE_BUTTON_RIGHT, BUTTON_STATE_DOWN).toBinaryFrame()
                                            val up = InputEvent.ButtonState(MOUSE_BUTTON_RIGHT, BUTTON_STATE_UP).toBinaryFrame()
                                            service?.sendInputFrame(absMove)
                                            service?.sendInputFrame(down)
                                            service?.sendInputFrame(up)
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
                            .padding(24.dp),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Icon(Icons.Default.Warning, contentDescription = null, tint = AlertRed, modifier = Modifier.size(48.dp))
                        Spacer(modifier = Modifier.height(12.dp))
                        Text(streamError!!, color = AlertRed, style = MaterialTheme.typography.bodyMedium)
                        Spacer(modifier = Modifier.height(16.dp))
                        Button(
                            onClick = {
                                streamError = null
                                isStreaming = true
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = LiquidCyan)
                        ) {
                            Text("Retry Connection", color = DeepSpace)
                        }
                    }
                } else {
                    Column(
                        modifier = Modifier.align(Alignment.Center),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        CircularProgressIndicator(color = LiquidCyan)
                        Spacer(modifier = Modifier.height(16.dp))
                        Text("Establishing High-Speed Display Pipeline...", color = TextSecondary, style = MaterialTheme.typography.bodySmall)
                    }
                }

                // Streaming quality overlay pill
                Row(
                    modifier = Modifier
                        .align(Alignment.BottomCenter)
                        .padding(bottom = 20.dp)
                        .clip(CircleShape)
                        .background(SurfaceElevated.copy(alpha = 0.85f))
                        .border(1.dp, GlassBorder, CircleShape)
                        .padding(horizontal = 16.dp, vertical = 6.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text("${targetFps} FPS", color = LiquidCyan, style = MaterialTheme.typography.labelSmall, fontWeight = FontWeight.Bold)
                    Spacer(modifier = Modifier.width(12.dp))
                    Text("•", color = TextMuted)
                    Spacer(modifier = Modifier.width(12.dp))
                    Text("Q${targetQuality}", color = TextSecondary, style = MaterialTheme.typography.labelSmall)
                    Spacer(modifier = Modifier.width(12.dp))
                    Text("•", color = TextMuted)
                    Spacer(modifier = Modifier.width(12.dp))
                    Text(
                        if (isStreaming) "LIVE" else "PAUSED",
                        color = if (isStreaming) IntegrityGreen else MatrixGold,
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.Bold
                    )
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
