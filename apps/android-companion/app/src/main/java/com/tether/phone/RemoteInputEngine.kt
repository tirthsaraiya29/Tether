package com.tether.phone

import android.content.Context
import android.hardware.Sensor
import android.hardware.SensorEvent
import android.hardware.SensorEventListener
import android.hardware.SensorManager
import android.util.Log
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlin.math.abs
import kotlin.math.hypot
import kotlin.math.pow
import kotlin.math.roundToInt

class RemoteInputEngine(
    private val context: Context,
    private val sendFrameCallback: (ByteArray) -> Unit = { frame ->
        TetherLanService.instance?.sendInputFrame(frame)
    }
) : SensorEventListener {

    companion object {
        private const val TAG = "RemoteInputEngine"
        private const val CLICK_HOLD_DELAY_MS = 35L
        private const val GYRO_DEADZONE = 0.025f
        private const val GYRO_GAIN = 1200f
    }

    private val engineScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // Sensitivity Settings
    var pointerSensitivity by mutableFloatStateOf(1.0f)
    var scrollSensitivity by mutableFloatStateOf(1.0f)
    var airMouseSensitivity by mutableFloatStateOf(1.0f)

    // Air Mouse State
    var isAirMouseActive by mutableStateOf(false)
        private set

    // Modifier Latch States
    var isCtrlLatched by mutableStateOf(false)
        private set
    var isAltLatched by mutableStateOf(false)
        private set
    var isShiftLatched by mutableStateOf(false)
        private set
    var isWinLatched by mutableStateOf(false)
        private set

    // Tap-and-Hold State
    var isTapAndHoldActive by mutableStateOf(false)
        private set

    private val sensorManager = context.getSystemService(Context.SENSOR_SERVICE) as? SensorManager
    private val gyroSensor = sensorManager?.getDefaultSensor(Sensor.TYPE_GYROSCOPE)
    private val accelSensor = sensorManager?.getDefaultSensor(Sensor.TYPE_ACCELEROMETER)

    /**
     * Dispatch an InputEvent directly by serializing to binary frame
     */
    fun dispatchEvent(event: InputEvent) {
        val bytes = event.toBinaryFrame()
        sendFrameCallback(bytes)
    }

    /**
     * Dispatch a list of InputEvents sequentially
     */
    fun dispatchEvents(events: List<InputEvent>) {
        engineScope.launch {
            for (event in events) {
                dispatchEvent(event)
            }
        }
    }

    /**
     * Non-linear velocity scaling for Trackpad Pointer Drag.
     * Applies deadband filter + dynamic acceleration curve.
     */
    fun processPointerDrag(rawDx: Float, rawDy: Float) {
        val rawVel = hypot(rawDx, rawDy)
        if (rawVel < 0.2f) return

        // Dynamic Acceleration Curve:
        // Slow speed (rawVel < 2.0) -> subtle precision scaling
        // High speed (rawVel >= 5.0) -> exponential gain to cross 4K resolution
        val normalizedVel = (rawVel / 2.5f).coerceIn(0.1f, 15.0f)
        val accelMultiplier = 1.0f + pointerSensitivity * normalizedVel.pow(1.3f)

        val scaledDx = (rawDx * accelMultiplier * pointerSensitivity).roundToInt().coerceIn(-32768, 32767).toShort()
        val scaledDy = (rawDy * accelMultiplier * pointerSensitivity).roundToInt().coerceIn(-32768, 32767).toShort()

        if (scaledDx != 0.toShort() || scaledDy != 0.toShort()) {
            dispatchEvent(InputEvent.RelativeMove(scaledDx, scaledDy))
        }
    }

    /**
     * Process 2-finger vertical scroll drag.
     */
    fun processScrollDrag(rawDy: Float) {
        val scrollAmount = (rawDy * scrollSensitivity * 12f).roundToInt().coerceIn(-32768, 32767).toShort()
        if (scrollAmount != 0.toShort()) {
            dispatchEvent(InputEvent.ScrollDelta(scrollAmount))
        }
    }

    /**
     * Single Tap -> Left Button Click Sequence
     */
    fun triggerSingleTapClick() {
        engineScope.launch {
            dispatchEvent(InputEvent.ButtonState(MOUSE_BUTTON_LEFT, BUTTON_STATE_DOWN))
            delay(CLICK_HOLD_DELAY_MS)
            dispatchEvent(InputEvent.ButtonState(MOUSE_BUTTON_LEFT, BUTTON_STATE_UP))
        }
    }

    /**
     * Two-Finger Tap -> Right Button Click Sequence
     */
    fun triggerTwoFingerTapClick() {
        engineScope.launch {
            dispatchEvent(InputEvent.ButtonState(MOUSE_BUTTON_RIGHT, BUTTON_STATE_DOWN))
            delay(CLICK_HOLD_DELAY_MS)
            dispatchEvent(InputEvent.ButtonState(MOUSE_BUTTON_RIGHT, BUTTON_STATE_UP))
        }
    }

    /**
     * Start Tap-and-Hold Drag mode
     */
    fun startTapAndHoldDrag() {
        if (!isTapAndHoldActive) {
            isTapAndHoldActive = true
            dispatchEvent(InputEvent.ButtonState(MOUSE_BUTTON_LEFT, BUTTON_STATE_DOWN))
        }
    }

    /**
     * Stop Tap-and-Hold Drag mode
     */
    fun stopTapAndHoldDrag() {
        if (isTapAndHoldActive) {
            isTapAndHoldActive = false
            dispatchEvent(InputEvent.ButtonState(MOUSE_BUTTON_LEFT, BUTTON_STATE_UP))
        }
    }

    /**
     * Physical Left Button Down / Up Target Click
     */
    fun setButtonState(buttonId: Byte, isDown: Boolean) {
        val state = if (isDown) BUTTON_STATE_DOWN else BUTTON_STATE_UP
        dispatchEvent(InputEvent.ButtonState(buttonId, state))
    }

    /**
     * Toggle modifier key latch states
     */
    fun toggleModifier(vkCode: Short) {
        when (vkCode) {
            VK_CONTROL -> {
                isCtrlLatched = !isCtrlLatched
                val state = if (isCtrlLatched) BUTTON_STATE_DOWN else BUTTON_STATE_UP
                dispatchEvent(InputEvent.VirtualKey(VK_CONTROL, state))
            }
            VK_MENU -> {
                isAltLatched = !isAltLatched
                val state = if (isAltLatched) BUTTON_STATE_DOWN else BUTTON_STATE_UP
                dispatchEvent(InputEvent.VirtualKey(VK_MENU, state))
            }
            VK_SHIFT -> {
                isShiftLatched = !isShiftLatched
                val state = if (isShiftLatched) BUTTON_STATE_DOWN else BUTTON_STATE_UP
                dispatchEvent(InputEvent.VirtualKey(VK_SHIFT, state))
            }
            VK_LWIN -> {
                isWinLatched = !isWinLatched
                val state = if (isWinLatched) BUTTON_STATE_DOWN else BUTTON_STATE_UP
                dispatchEvent(InputEvent.VirtualKey(VK_LWIN, state))
            }
            else -> {
                // Tap key directly
                triggerKeyTap(vkCode)
            }
        }
    }

    /**
     * Single Virtual Key Tap (Down + Up sequence)
     */
    fun triggerKeyTap(vkCode: Short, isExtended: Boolean = false) {
        engineScope.launch {
            val flags = if (isExtended) KEY_STATE_EXTENDED else KEY_STATE_DOWN
            dispatchEvent(InputEvent.VirtualKey(vkCode, flags))
            delay(CLICK_HOLD_DELAY_MS)
            dispatchEvent(InputEvent.VirtualKey(vkCode, KEY_STATE_UP))
        }
    }

    /**
     * Serialize and transmit typed text buffer as Unicode chunks
     */
    fun sendUnicodeText(text: String) {
        if (text.isEmpty()) return
        val unicodeEvents = InputFactory.createUnicodeText(text)
        dispatchEvents(unicodeEvents)
    }

    /**
     * Reset/Release all latched modifiers
     */
    fun releaseAllModifiers() {
        if (isCtrlLatched) {
            isCtrlLatched = false
            dispatchEvent(InputEvent.VirtualKey(VK_CONTROL, KEY_STATE_UP))
        }
        if (isAltLatched) {
            isAltLatched = false
            dispatchEvent(InputEvent.VirtualKey(VK_MENU, KEY_STATE_UP))
        }
        if (isShiftLatched) {
            isShiftLatched = false
            dispatchEvent(InputEvent.VirtualKey(VK_SHIFT, KEY_STATE_UP))
        }
        if (isWinLatched) {
            isWinLatched = false
            dispatchEvent(InputEvent.VirtualKey(VK_LWIN, KEY_STATE_UP))
        }
    }

    /**
     * Toggle Air Mouse Sensor Fusion mode
     */
    fun toggleAirMouse(): Boolean {
        if (isAirMouseActive) {
            stopAirMouse()
        } else {
            startAirMouse()
        }
        return isAirMouseActive
    }

    /**
     * Start Air Mouse Sensor Fusion
     */
    fun startAirMouse() {
        if (sensorManager == null || gyroSensor == null) {
            Log.w(TAG, "Gyroscope sensor not available on this device")
            return
        }
        if (!isAirMouseActive) {
            isAirMouseActive = true
            sensorManager.registerListener(this, gyroSensor, SensorManager.SENSOR_DELAY_GAME)
            accelSensor?.let { sensorManager.registerListener(this, it, SensorManager.SENSOR_DELAY_GAME) }
            Log.i(TAG, "Air Mouse sensor fusion started")
        }
    }

    /**
     * Stop Air Mouse Sensor Fusion
     */
    fun stopAirMouse() {
        if (isAirMouseActive) {
            isAirMouseActive = false
            sensorManager?.unregisterListener(this)
            Log.i(TAG, "Air Mouse sensor fusion stopped")
        }
    }

    override fun onSensorChanged(event: SensorEvent?) {
        if (!isAirMouseActive || event == null) return

        if (event.sensor.type == Sensor.TYPE_GYROSCOPE) {
            // Gyro values: x (pitch rate), y (roll rate), z (yaw rate)
            val gyroX = event.values[0] // pitch velocity (rad/s)
            val gyroY = event.values[1] // roll velocity (rad/s)
            val gyroZ = event.values[2] // yaw velocity (rad/s)

            // Calculate rotational magnitude for deadzone filter
            val radMagnitude = hypot(gyroZ, gyroX)
            if (radMagnitude < GYRO_DEADZONE) return

            // Map Yaw (rotation around Z/Y axis) to DeltaX and Pitch (rotation around X axis) to DeltaY
            val deltaX = (-gyroZ * GYRO_GAIN * airMouseSensitivity).roundToInt().coerceIn(-32768, 32767).toShort()
            val deltaY = (-gyroX * GYRO_GAIN * airMouseSensitivity).roundToInt().coerceIn(-32768, 32767).toShort()

            if (deltaX != 0.toShort() || deltaY != 0.toShort()) {
                dispatchEvent(InputEvent.RelativeMove(deltaX, deltaY))
            }
        }
    }

    override fun onAccuracyChanged(sensor: Sensor?, accuracy: Int) {}
}
