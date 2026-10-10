package com.tether.phone.ui.screens

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Keyboard
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Sensors
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.TouchApp
import androidx.compose.material.icons.filled.Tune
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Slider
import androidx.compose.material3.SliderDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.input.key.Key
import androidx.compose.ui.input.key.key
import androidx.compose.ui.input.key.onPreviewKeyEvent
import androidx.compose.ui.input.pointer.PointerEventPass
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.tether.phone.BUTTON_STATE_DOWN
import com.tether.phone.BUTTON_STATE_UP
import com.tether.phone.InputEvent
import com.tether.phone.MOUSE_BUTTON_LEFT
import com.tether.phone.MOUSE_BUTTON_MIDDLE
import com.tether.phone.MOUSE_BUTTON_RIGHT
import com.tether.phone.RemoteInputEngine
import com.tether.phone.TetherLanService
import com.tether.phone.TransportState
import com.tether.phone.VK_BACK
import com.tether.phone.VK_CONTROL
import com.tether.phone.VK_DELETE
import com.tether.phone.VK_DOWN
import com.tether.phone.VK_ESCAPE
import com.tether.phone.VK_LEFT
import com.tether.phone.VK_LWIN
import com.tether.phone.VK_MENU
import com.tether.phone.VK_RETURN
import com.tether.phone.VK_RIGHT
import com.tether.phone.VK_SHIFT
import com.tether.phone.VK_TAB
import com.tether.phone.VK_UP
import com.tether.phone.ui.components.DeepSpaceCanvasVisualizer
import com.tether.phone.ui.components.ProfessionalGlassSurface
import com.tether.phone.ui.theme.AlertRed
import com.tether.phone.ui.theme.GlassBorder
import com.tether.phone.ui.theme.IntegrityGreen
import com.tether.phone.ui.theme.LiquidCyan
import com.tether.phone.ui.theme.MatrixGold
import com.tether.phone.ui.theme.SurfaceElevated
import com.tether.phone.ui.theme.TextMuted
import com.tether.phone.ui.theme.TextPrimary
import com.tether.phone.ui.theme.TextSecondary
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

data class TouchPoint(val id: Long, val position: Offset)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RemoteInputScreen(
    transportState: TransportState = TetherLanService.instance?.currentState ?: TransportState.DISCONNECTED,
    onBackClick: () -> Unit = {}
) {
    val context = LocalContext.current
    val haptic = LocalHapticFeedback.current
    val keyboardController = LocalSoftwareKeyboardController.current
    val focusRequester = remember { FocusRequester() }

    val inputEngine = remember { RemoteInputEngine(context) }
    val isConnected = transportState == TransportState.READY || transportState == TransportState.AUTHENTICATED

    var isKeyboardVisible by remember { mutableStateOf(false) }
    var textBuffer by remember { mutableStateOf(TextFieldValue("")) }
    var showSensitivitySheet by remember { mutableStateOf(false) }

    val activeTouchPoints = remember { mutableStateListOf<TouchPoint>() }

    DisposableEffect(Unit) {
        onDispose {
            inputEngine.stopAirMouse()
            inputEngine.releaseAllModifiers()
        }
    }

    Box(modifier = Modifier.fillMaxSize()) {
        DeepSpaceCanvasVisualizer()

        // Hidden BasicTextField for Soft Keyboard IME Capture
        BasicTextField(
            value = textBuffer,
            onValueChange = { newValue ->
                val newText = newValue.text
                val oldText = textBuffer.text

                if (newText.length > oldText.length) {
                    val typedChar = newText.substring(oldText.length)
                    inputEngine.sendUnicodeText(typedChar)
                } else if (newText.length < oldText.length) {
                    val deleteCount = oldText.length - newText.length
                    repeat(deleteCount) {
                        inputEngine.triggerKeyTap(VK_BACK)
                    }
                }
                textBuffer = newValue
            },
            modifier = Modifier
                .size(1.dp)
                .focusRequester(focusRequester)
                .onPreviewKeyEvent { keyEvent ->
                    val isDown = keyEvent.nativeKeyEvent.action == android.view.KeyEvent.ACTION_DOWN
                    if (isDown) {
                        when (keyEvent.key) {
                            Key.Backspace -> {
                                inputEngine.triggerKeyTap(VK_BACK)
                                true
                            }
                            Key.Enter -> {
                                inputEngine.triggerKeyTap(VK_RETURN)
                                true
                            }
                            Key.Escape -> {
                                inputEngine.triggerKeyTap(VK_ESCAPE)
                                true
                            }
                            Key.Tab -> {
                                inputEngine.triggerKeyTap(VK_TAB)
                                true
                            }
                            Key.DirectionLeft -> {
                                inputEngine.triggerKeyTap(VK_LEFT)
                                true
                            }
                            Key.DirectionRight -> {
                                inputEngine.triggerKeyTap(VK_RIGHT)
                                true
                            }
                            Key.DirectionUp -> {
                                inputEngine.triggerKeyTap(VK_UP)
                                true
                            }
                            Key.DirectionDown -> {
                                inputEngine.triggerKeyTap(VK_DOWN)
                                true
                            }
                            Key.Delete -> {
                                inputEngine.triggerKeyTap(VK_DELETE)
                                true
                            }
                            else -> false
                        }
                    } else false
                }
        )

        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp)
        ) {
            // Top Bar
            RemoteInputTopBar(
                transportState = transportState,
                isAirMouseActive = inputEngine.isAirMouseActive,
                isKeyboardVisible = isKeyboardVisible,
                onToggleAirMouse = {
                    haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                    inputEngine.toggleAirMouse()
                },
                onToggleKeyboard = {
                    haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                    isKeyboardVisible = !isKeyboardVisible
                    if (isKeyboardVisible) {
                        focusRequester.requestFocus()
                        keyboardController?.show()
                    } else {
                        keyboardController?.hide()
                    }
                },
                onOpenSensitivity = {
                    haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                    showSensitivitySheet = true
                }
            )

            Spacer(modifier = Modifier.height(12.dp))

            // Quick Modifier Key Strip
            QuickModifierStrip(
                inputEngine = inputEngine,
                onKeyClick = { vkCode ->
                    haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                    inputEngine.toggleModifier(vkCode)
                }
            )

            Spacer(modifier = Modifier.height(12.dp))

            // Main Trackpad Touch Canvas Area
            Box(
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth()
            ) {
                ProfessionalGlassSurface(
                    modifier = Modifier.fillMaxSize(),
                    alpha = 0.15f
                ) {
                    Box(
                        modifier = Modifier
                            .fillMaxSize()
                            .clip(RoundedCornerShape(28.dp))
                            .pointerInput(isConnected) {
                                if (!isConnected) return@pointerInput

                                awaitPointerEventScope {
                                    while (true) {
                                        val event = awaitPointerEvent(PointerEventPass.Main)
                                        val changes = event.changes

                                        activeTouchPoints.clear()
                                        changes.filter { it.pressed }.forEach {
                                            activeTouchPoints.add(TouchPoint(it.id.value, it.position))
                                        }

                                        val pointerCount = changes.count { it.pressed }

                                        if (pointerCount == 1) {
                                            val change = changes.firstOrNull { it.pressed }
                                            if (change != null) {
                                                val dragAmount = change.position - change.previousPosition
                                                if (dragAmount.x != 0f || dragAmount.y != 0f) {
                                                    if (inputEngine.isTapAndHoldActive) {
                                                        inputEngine.processPointerDrag(dragAmount.x, dragAmount.y)
                                                    } else {
                                                        inputEngine.processPointerDrag(dragAmount.x, dragAmount.y)
                                                    }
                                                    change.consume()
                                                }
                                            }
                                        } else if (pointerCount == 2) {
                                            val change1 = changes[0]
                                            val change2 = changes[1]
                                            val drag1 = change1.position - change1.previousPosition
                                            val drag2 = change2.position - change2.previousPosition
                                            val avgDy = (drag1.y + drag2.y) / 2f

                                            if (kotlin.math.abs(avgDy) > 0.5f) {
                                                inputEngine.processScrollDrag(avgDy)
                                                change1.consume()
                                                change2.consume()
                                            }
                                        }

                                        if (changes.all { !it.pressed }) {
                                            activeTouchPoints.clear()
                                            if (inputEngine.isTapAndHoldActive) {
                                                inputEngine.stopTapAndHoldDrag()
                                            }
                                        }
                                    }
                                }
                            }
                            .pointerInput(isConnected) {
                                if (!isConnected) return@pointerInput
                                detectTapGestures(
                                    onTap = {
                                        haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                        inputEngine.triggerSingleTapClick()
                                    },
                                    onDoubleTap = {
                                        haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                        inputEngine.startTapAndHoldDrag()
                                    },
                                    onLongPress = {
                                        haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                                        inputEngine.triggerTwoFingerTapClick()
                                    }
                                )
                            }
                    ) {
                        // Canvas visualizer for touch contact ripples & feedback
                        Canvas(modifier = Modifier.fillMaxSize()) {
                            for (point in activeTouchPoints) {
                                drawCircle(
                                    brush = Brush.radialGradient(
                                        0.0f to LiquidCyan.copy(alpha = 0.5f),
                                        0.6f to LiquidCyan.copy(alpha = 0.15f),
                                        1.0f to Color.Transparent,
                                        center = point.position,
                                        radius = 60.dp.toPx()
                                    ),
                                    center = point.position,
                                    radius = 60.dp.toPx()
                                )
                                drawCircle(
                                    color = LiquidCyan,
                                    radius = 8.dp.toPx(),
                                    center = point.position
                                )
                            }
                        }

                        // Air Mouse Active Badge Indicator
                        if (inputEngine.isAirMouseActive) {
                            Box(
                                modifier = Modifier
                                    .padding(16.dp)
                                    .align(Alignment.TopEnd)
                                    .clip(RoundedCornerShape(12.dp))
                                    .background(LiquidCyan.copy(alpha = 0.2f))
                                    .border(1.dp, LiquidCyan, RoundedCornerShape(12.dp))
                                    .padding(horizontal = 12.dp, vertical = 6.dp)
                            ) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Icon(
                                        imageVector = Icons.Default.Sensors,
                                        contentDescription = null,
                                        tint = LiquidCyan,
                                        modifier = Modifier.size(16.dp)
                                    )
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text(
                                        text = "AIR MOUSE ACTIVE",
                                        style = MaterialTheme.typography.labelSmall,
                                        color = LiquidCyan,
                                        fontWeight = FontWeight.Bold
                                    )
                                }
                            }
                        }

                        // Disconnected / Offline Overlay
                        if (!isConnected) {
                            Box(
                                modifier = Modifier
                                    .fillMaxSize()
                                    .background(Color.Black.copy(alpha = 0.75f)),
                                contentAlignment = Alignment.Center
                            ) {
                                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                    Icon(
                                        imageVector = Icons.Default.Refresh,
                                        contentDescription = null,
                                        tint = AlertRed,
                                        modifier = Modifier.size(48.dp)
                                    )
                                    Spacer(modifier = Modifier.height(12.dp))
                                    Text(
                                        text = "RECONNECTING TO PC...",
                                        style = MaterialTheme.typography.titleMedium,
                                        color = TextPrimary,
                                        fontWeight = FontWeight.Bold
                                    )
                                    Spacer(modifier = Modifier.height(4.dp))
                                    Text(
                                        text = "Trackpad input suspended while link is offline",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = TextMuted
                                    )
                                }
                            }
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Lower Control Deck (Tactile Physical Target Buttons)
            LowerControlDeck(
                inputEngine = inputEngine,
                isEnabled = isConnected,
                onHaptic = { haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove) }
            )
        }

        // Sensitivity Settings Bottom Sheet
        if (showSensitivitySheet) {
            SensitivityBottomSheet(
                inputEngine = inputEngine,
                onDismiss = { showSensitivitySheet = false }
            )
        }
    }
}

@Composable
fun RemoteInputTopBar(
    transportState: TransportState,
    isAirMouseActive: Boolean,
    isKeyboardVisible: Boolean,
    onToggleAirMouse: () -> Unit,
    onToggleKeyboard: () -> Unit,
    onOpenSensitivity: () -> Unit
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        // Connection State Badge
        val (badgeColor, statusLabel) = when (transportState) {
            TransportState.READY, TransportState.AUTHENTICATED -> IntegrityGreen to "CONNECTED"
            TransportState.CONNECTING, TransportState.TLS_HANDSHAKE, TransportState.AUTHENTICATING -> MatrixGold to "CONNECTING..."
            else -> AlertRed to "DISCONNECTED"
        }

        Box(
            modifier = Modifier
                .clip(RoundedCornerShape(16.dp))
                .background(badgeColor.copy(alpha = 0.15f))
                .border(1.dp, badgeColor.copy(alpha = 0.5f), RoundedCornerShape(16.dp))
                .padding(horizontal = 12.dp, vertical = 6.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    modifier = Modifier
                        .size(8.dp)
                        .clip(CircleShape)
                        .background(badgeColor)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = statusLabel,
                    style = MaterialTheme.typography.labelSmall,
                    color = badgeColor,
                    fontWeight = FontWeight.Bold
                )
            }
        }

        // Action Buttons Row
        Row {
            // Air Mouse Toggle Button
            IconButton(
                onClick = onToggleAirMouse,
                modifier = Modifier
                    .clip(CircleShape)
                    .background(if (isAirMouseActive) LiquidCyan.copy(alpha = 0.25f) else SurfaceElevated)
                    .border(1.dp, if (isAirMouseActive) LiquidCyan else GlassBorder, CircleShape)
            ) {
                Icon(
                    imageVector = Icons.Default.Sensors,
                    contentDescription = "Air Mouse",
                    tint = if (isAirMouseActive) LiquidCyan else TextSecondary
                )
            }

            Spacer(modifier = Modifier.width(8.dp))

            // Soft Keyboard Toggle Button
            IconButton(
                onClick = onToggleKeyboard,
                modifier = Modifier
                    .clip(CircleShape)
                    .background(if (isKeyboardVisible) LiquidCyan.copy(alpha = 0.25f) else SurfaceElevated)
                    .border(1.dp, if (isKeyboardVisible) LiquidCyan else GlassBorder, CircleShape)
            ) {
                Icon(
                    imageVector = Icons.Default.Keyboard,
                    contentDescription = "Toggle Keyboard",
                    tint = if (isKeyboardVisible) LiquidCyan else TextSecondary
                )
            }

            Spacer(modifier = Modifier.width(8.dp))

            // Sensitivity Settings Button
            IconButton(
                onClick = onOpenSensitivity,
                modifier = Modifier
                    .clip(CircleShape)
                    .background(SurfaceElevated)
                    .border(1.dp, GlassBorder, CircleShape)
            ) {
                Icon(
                    imageVector = Icons.Default.Tune,
                    contentDescription = "Sensitivity Settings",
                    tint = TextSecondary
                )
            }
        }
    }
}

@Composable
fun QuickModifierStrip(
    inputEngine: RemoteInputEngine,
    onKeyClick: (Short) -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(16.dp))
            .background(SurfaceElevated.copy(alpha = 0.7f))
            .border(1.dp, GlassBorder, RoundedCornerShape(16.dp))
            .padding(horizontal = 8.dp, vertical = 6.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        ModifierKeyChip(
            label = "CTRL",
            isLatched = inputEngine.isCtrlLatched,
            onClick = { onKeyClick(VK_CONTROL) }
        )
        ModifierKeyChip(
            label = "ALT",
            isLatched = inputEngine.isAltLatched,
            onClick = { onKeyClick(VK_MENU) }
        )
        ModifierKeyChip(
            label = "SHIFT",
            isLatched = inputEngine.isShiftLatched,
            onClick = { onKeyClick(VK_SHIFT) }
        )
        ModifierKeyChip(
            label = "WIN",
            isLatched = inputEngine.isWinLatched,
            onClick = { onKeyClick(VK_LWIN) }
        )
        ModifierKeyChip(
            label = "ESC",
            isLatched = false,
            onClick = { onKeyClick(VK_ESCAPE) }
        )
        ModifierKeyChip(
            label = "TAB",
            isLatched = false,
            onClick = { onKeyClick(VK_TAB) }
        )
        ModifierKeyChip(
            label = "BACK",
            isLatched = false,
            onClick = { onKeyClick(VK_BACK) }
        )
    }
}

@Composable
fun ModifierKeyChip(
    label: String,
    isLatched: Boolean,
    onClick: () -> Unit
) {
    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(10.dp))
            .background(if (isLatched) LiquidCyan.copy(alpha = 0.25f) else Color.Transparent)
            .border(
                width = 1.dp,
                color = if (isLatched) LiquidCyan else GlassBorder,
                shape = RoundedCornerShape(10.dp)
            )
            .clickable { onClick() }
            .padding(horizontal = 10.dp, vertical = 8.dp),
        contentAlignment = Alignment.Center
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.labelSmall,
            color = if (isLatched) LiquidCyan else TextSecondary,
            fontWeight = if (isLatched) FontWeight.Bold else FontWeight.Medium
        )
    }
}

@Composable
fun LowerControlDeck(
    inputEngine: RemoteInputEngine,
    isEnabled: Boolean,
    onHaptic: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .height(64.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        // Left Click Button (40% width)
        TactileDeckButton(
            label = "LEFT CLICK",
            modifier = Modifier.weight(0.4f),
            isEnabled = isEnabled,
            onPressDown = {
                onHaptic()
                inputEngine.setButtonState(MOUSE_BUTTON_LEFT, true)
            },
            onPressUp = {
                inputEngine.setButtonState(MOUSE_BUTTON_LEFT, false)
            }
        )

        // Middle / Scroll Button (20% width)
        TactileDeckButton(
            label = "SCROLL",
            modifier = Modifier.weight(0.2f),
            isEnabled = isEnabled,
            onPressDown = {
                onHaptic()
                inputEngine.setButtonState(MOUSE_BUTTON_MIDDLE, true)
            },
            onPressUp = {
                inputEngine.setButtonState(MOUSE_BUTTON_MIDDLE, false)
            }
        )

        // Right Click Button (40% width)
        TactileDeckButton(
            label = "RIGHT CLICK",
            modifier = Modifier.weight(0.4f),
            isEnabled = isEnabled,
            onPressDown = {
                onHaptic()
                inputEngine.setButtonState(MOUSE_BUTTON_RIGHT, true)
            },
            onPressUp = {
                inputEngine.setButtonState(MOUSE_BUTTON_RIGHT, false)
            }
        )
    }
}

@Composable
fun TactileDeckButton(
    label: String,
    modifier: Modifier = Modifier,
    isEnabled: Boolean,
    onPressDown: () -> Unit,
    onPressUp: () -> Unit
) {
    val interactionSource = remember { MutableInteractionSource() }
    val isPressed by interactionSource.collectIsPressedAsState()

    LaunchedEffect(isPressed) {
        if (isPressed) onPressDown() else onPressUp()
    }

    Box(
        modifier = modifier
            .fillMaxHeight()
            .clip(RoundedCornerShape(16.dp))
            .background(
                if (isPressed) LiquidCyan.copy(alpha = 0.2f) else SurfaceElevated
            )
            .border(
                width = 1.dp,
                color = if (isPressed) LiquidCyan else GlassBorder,
                shape = RoundedCornerShape(16.dp)
            )
            .clickable(
                interactionSource = interactionSource,
                indication = null,
                enabled = isEnabled,
                onClick = {}
            ),
        contentAlignment = Alignment.Center
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.labelMedium,
            color = if (isPressed) LiquidCyan else TextSecondary,
            fontWeight = FontWeight.Bold
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SensitivityBottomSheet(
    inputEngine: RemoteInputEngine,
    onDismiss: () -> Unit
) {
    val sheetState = rememberModalBottomSheetState()
    val scope = rememberCoroutineScope()

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState,
        containerColor = SurfaceElevated,
        scrimColor = Color.Black.copy(alpha = 0.6f)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(24.dp)
        ) {
            Text(
                text = "INPUT SENSITIVITY CONFIGURATION",
                style = MaterialTheme.typography.titleMedium,
                color = LiquidCyan,
                fontWeight = FontWeight.Bold
            )
            Spacer(modifier = Modifier.height(16.dp))

            // Pointer Sensitivity
            Text(
                text = "Pointer Speed: ${String.format("%.1f", inputEngine.pointerSensitivity)}x",
                style = MaterialTheme.typography.bodyMedium,
                color = TextPrimary
            )
            Slider(
                value = inputEngine.pointerSensitivity,
                onValueChange = { inputEngine.pointerSensitivity = it },
                valueRange = 0.5f..3.0f,
                steps = 25,
                colors = SliderDefaults.colors(
                    thumbColor = LiquidCyan,
                    activeTrackColor = LiquidCyan,
                    inactiveTrackColor = GlassBorder
                )
            )

            Spacer(modifier = Modifier.height(12.dp))

            // Scroll Sensitivity
            Text(
                text = "Scroll Speed: ${String.format("%.1f", inputEngine.scrollSensitivity)}x",
                style = MaterialTheme.typography.bodyMedium,
                color = TextPrimary
            )
            Slider(
                value = inputEngine.scrollSensitivity,
                onValueChange = { inputEngine.scrollSensitivity = it },
                valueRange = 0.5f..3.0f,
                steps = 25,
                colors = SliderDefaults.colors(
                    thumbColor = LiquidCyan,
                    activeTrackColor = LiquidCyan,
                    inactiveTrackColor = GlassBorder
                )
            )

            Spacer(modifier = Modifier.height(12.dp))

            // Air Mouse Sensitivity
            Text(
                text = "Air Mouse Sensitivity: ${String.format("%.1f", inputEngine.airMouseSensitivity)}x",
                style = MaterialTheme.typography.bodyMedium,
                color = TextPrimary
            )
            Slider(
                value = inputEngine.airMouseSensitivity,
                onValueChange = { inputEngine.airMouseSensitivity = it },
                valueRange = 0.5f..3.0f,
                steps = 25,
                colors = SliderDefaults.colors(
                    thumbColor = LiquidCyan,
                    activeTrackColor = LiquidCyan,
                    inactiveTrackColor = GlassBorder
                )
            )

            Spacer(modifier = Modifier.height(20.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.End
            ) {
                TextButton(
                    onClick = {
                        inputEngine.pointerSensitivity = 1.0f
                        inputEngine.scrollSensitivity = 1.0f
                        inputEngine.airMouseSensitivity = 1.0f
                    }
                ) {
                    Text("RESET DEFAULTS", color = TextMuted)
                }
                Spacer(modifier = Modifier.width(8.dp))
                TextButton(
                    onClick = {
                        scope.launch { sheetState.hide() }.invokeOnCompletion {
                            onDismiss()
                        }
                    }
                ) {
                    Text("DONE", color = LiquidCyan, fontWeight = FontWeight.Bold)
                }
            }
        }
    }
}
