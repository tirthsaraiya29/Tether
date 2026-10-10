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

        // Gyro tuning: gentler gain, larger deadzone. A typical gentle tilt
        // produces ~0.05 rad/s; a moderate flick ~0.5 rad/s. At 50 Hz sample
        // rate, gain 220 yields ~10-55 px per event, which is a controllable
        // pointer speed without feeling sluggish.
        private const val GYRO_DEADZONE = 0.05f
        private const val GYRO_GAIN = 220f

        // Trackpad pointer scaling.
        //   - BASE_SCALE converts raw touch-pixel deltas to cursor deltas.
        //     At 1.0 sensitivity, moving a finger across the whole screen
        //     should move the cursor across the whole desktop.
        //   - ACCEL_MAX caps the linear velocity-based boost.
        private const val POINTER_BASE_SCALE = 0.35f
        private const val POINTER_ACCEL_VEL_REF = 40f   // px per event to reach full accel
        private const val POINTER_ACCEL_MAX = 2.5f      // 1.0x baseline -> 2.5x max

        // Scroll scaling: rawDy * SCROLL_BASE_SCALE == wheel notches.
        // 0.10 -> ~3 notches for a 30 px drag event, which is one usable
        // Windows WHEEL_DELTA tick every few events.
        private const val SCROLL_BASE_SCALE = 0.10f
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

    fun dispatchEvent(event: InputEvent) {
        sendFrameCallback(event.toBinaryFrame())
    }

    fun dispatchEvents(events: List<InputEvent>) {
        engineScope.launch {
            for (event in events) {
                dispatchEvent(event)
            }
        }
    }

    /**
     * Trackpad pointer drag. Deliberately simple: linear base scale, plus a
     * bounded acceleration term driven by instantaneous speed only.
     */
    fun processPointerDrag(rawDx: Float, rawDy: Float) {
        val rawVel = hypot(rawDx, rawDy)
        // Deadzone: sub-pixel jitter from the touch panel.
        if (rawVel < 0.5f) return

        val accelFactor = 1.0f + (rawVel / POINTER_ACCEL_VEL_REF)
            .coerceIn(0f, POINTER_ACCEL_MAX - 1.0f)

        val scale = POINTER_BASE_SCALE * pointerSensitivity * accelFactor

        val scaledDx = (rawDx * scale).roundToInt().coerceIn(-32768, 32767).toShort()
        val scaledDy = (rawDy * scale).roundToInt().coerceIn(-32768, 32767).toShort()

        if (scaledDx != 0.toShort() || scaledDy != 0.toShort()) {
            dispatchEvent(InputEvent.RelativeMove(scaledDx, scaledDy))
        }
    }

    /**
     * Two-finger vertical scroll. `scrollDelta` on the wire is in Windows
     * WHEEL_DELTA ticks (each tick == 120 wheel units), so keep it small.
     */
    fun processScrollDrag(rawDy: Float) {
        val scrollAmount = (rawDy * SCROLL_BASE_SCALE * scrollSensitivity)
            .roundToInt()
            .coerceIn(-32768, 32767)
            .toShort()
        if (scrollAmount != 0.toShort()) {
            dispatchEvent(InputEvent.ScrollDelta(scrollAmount))
        }
    }

    fun triggerSingleTapClick() {
        engineScope.launch {
            dispatchEvent(InputEvent.ButtonState(MOUSE_BUTTON_LEFT, BUTTON_STATE_DOWN))
            delay(CLICK_HOLD_DELAY_MS)
            dispatchEvent(InputEvent.ButtonState(MOUSE_BUTTON_LEFT, BUTTON_STATE_UP))
        }
    }

    fun triggerTwoFingerTapClick() {
        engineScope.launch {
            dispatchEvent(InputEvent.ButtonState(MOUSE_BUTTON_RIGHT, BUTTON_STATE_DOWN))
            delay(CLICK_HOLD_DELAY_MS)
            dispatchEvent(InputEvent.ButtonState(MOUSE_BUTTON_RIGHT, BUTTON_STATE_UP))
        }
    }

    fun startTapAndHoldDrag() {
        if (!isTapAndHoldActive) {
            isTapAndHoldActive = true
            dispatchEvent(InputEvent.ButtonState(MOUSE_BUTTON_LEFT, BUTTON_STATE_DOWN))
        }
    }

    fun stopTapAndHoldDrag() {
        if (isTapAndHoldActive) {
            isTapAndHoldActive = false
            dispatchEvent(InputEvent.ButtonState(MOUSE_BUTTON_LEFT, BUTTON_STATE_UP))
        }
    }

    fun setButtonState(buttonId: Byte, isDown: Boolean) {
        val state = if (isDown) BUTTON_STATE_DOWN else BUTTON_STATE_UP
        dispatchEvent(InputEvent.ButtonState(buttonId, state))
    }

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
            else -> triggerKeyTap(vkCode)
        }
    }

    fun triggerKeyTap(vkCode: Short, isExtended: Boolean = false) {
        engineScope.launch {
            val flags = if (isExtended) KEY_STATE_EXTENDED else KEY_STATE_DOWN
            dispatchEvent(InputEvent.VirtualKey(vkCode, flags))
            delay(CLICK_HOLD_DELAY_MS)
            dispatchEvent(InputEvent.VirtualKey(vkCode, KEY_STATE_UP))
        }
    }

    fun sendUnicodeText(text: String) {
        if (text.isEmpty()) return
        dispatchEvents(InputFactory.createUnicodeText(text))
    }

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

    fun toggleAirMouse(): Boolean {
        if (isAirMouseActive) stopAirMouse() else startAirMouse()
        return isAirMouseActive
    }

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
            val gyroX = event.values[0]
            val gyroY = event.values[1]
            val gyroZ = event.values[2]

            val radMagnitude = hypot(gyroZ, gyroX)
            if (radMagnitude < GYRO_DEADZONE) return

            val deltaX = (-gyroZ * GYRO_GAIN * airMouseSensitivity)
                .roundToInt().coerceIn(-32768, 32767).toShort()
            val deltaY = (-gyroX * GYRO_GAIN * airMouseSensitivity)
                .roundToInt().coerceIn(-32768, 32767).toShort()

            if (deltaX != 0.toShort() || deltaY != 0.toShort()) {
                dispatchEvent(InputEvent.RelativeMove(deltaX, deltaY))
            }
        }
    }

    override fun onAccuracyChanged(sensor: Sensor?, accuracy: Int) {}
}