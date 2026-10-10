package com.tether.phone

import java.nio.ByteBuffer
import java.nio.ByteOrder

const val PACKET_TYPE_INPUT_EVENT: Byte = 0x05

const val SUBTYPE_RELATIVE_MOVE: Byte = 0x01
const val SUBTYPE_BUTTON_STATE: Byte = 0x02
const val SUBTYPE_SCROLL_DELTA: Byte = 0x03
const val SUBTYPE_VIRTUAL_KEY: Byte = 0x04
const val SUBTYPE_UNICODE_CHAR: Byte = 0x05

const val MOUSE_BUTTON_LEFT: Byte = 0x01
const val MOUSE_BUTTON_RIGHT: Byte = 0x02
const val MOUSE_BUTTON_MIDDLE: Byte = 0x03

const val BUTTON_STATE_UP: Byte = 0x00
const val BUTTON_STATE_DOWN: Byte = 0x01

const val KEY_STATE_UP: Byte = 0x00
const val KEY_STATE_DOWN: Byte = 0x01
const val KEY_STATE_EXTENDED: Byte = 0x02

const val VK_BACK: Short = 0x08
const val VK_TAB: Short = 0x09
const val VK_RETURN: Short = 0x0D
const val VK_SHIFT: Short = 0x10
const val VK_CONTROL: Short = 0x11
const val VK_MENU: Short = 0x12 // Alt
const val VK_PAUSE: Short = 0x13
const val VK_CAPITAL: Short = 0x14
const val VK_ESCAPE: Short = 0x1B
const val VK_SPACE: Short = 0x20
const val VK_PRIOR: Short = 0x21 // Page Up
const val VK_NEXT: Short = 0x22 // Page Down
const val VK_END: Short = 0x23
const val VK_HOME: Short = 0x24
const val VK_LEFT: Short = 0x25
const val VK_UP: Short = 0x26
const val VK_RIGHT: Short = 0x27
const val VK_DOWN: Short = 0x28
const val VK_INSERT: Short = 0x2D
const val VK_DELETE: Short = 0x2E
const val VK_LWIN: Short = 0x5B
const val VK_RWIN: Short = 0x5C

sealed class InputEvent {
    abstract fun toBinaryFrame(): ByteArray

    /**
     * Subtype 0x01: Relative Move
     * Payload: [0x01 (Byte)] [DeltaX (Short)] [DeltaY (Short)] (5 bytes payload)
     * Full Frame with 0x05 Header: 6 bytes total.
     */
    data class RelativeMove(
        val deltaX: Short,
        val deltaY: Short
    ) : InputEvent() {
        override fun toBinaryFrame(): ByteArray {
            return ByteBuffer.allocate(6).order(ByteOrder.BIG_ENDIAN)
                .put(PACKET_TYPE_INPUT_EVENT)
                .put(SUBTYPE_RELATIVE_MOVE)
                .putShort(deltaX)
                .putShort(deltaY)
                .array()
        }
    }

    /**
     * Subtype 0x02: Button State
     * Payload: [0x02 (Byte)] [ButtonId (Byte: 1=Left, 2=Right, 3=Middle)] [State (Byte: 1=Down, 0=Up)] (3 bytes payload)
     * Full Frame with 0x05 Header: 4 bytes total.
     */
    data class ButtonState(
        val buttonId: Byte,
        val state: Byte
    ) : InputEvent() {
        override fun toBinaryFrame(): ByteArray {
            return ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN)
                .put(PACKET_TYPE_INPUT_EVENT)
                .put(SUBTYPE_BUTTON_STATE)
                .put(buttonId)
                .put(state)
                .array()
        }
    }

    /**
     * Subtype 0x03: Scroll Delta
     * Payload: [0x03 (Byte)] [ScrollDelta (Short)] (3 bytes payload)
     * Full Frame with 0x05 Header: 4 bytes total.
     */
    data class ScrollDelta(
        val scrollDelta: Short
    ) : InputEvent() {
        override fun toBinaryFrame(): ByteArray {
            return ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN)
                .put(PACKET_TYPE_INPUT_EVENT)
                .put(SUBTYPE_SCROLL_DELTA)
                .putShort(scrollDelta)
                .array()
        }
    }

    /**
     * Subtype 0x04: Key Code / Virtual Key
     * Payload: [0x04 (Byte)] [WindowsVkCode (Short)] [Flags/State (Byte: 1=Down, 0=Up, 2=Extended)] (4 bytes payload)
     * Full Frame with 0x05 Header: 5 bytes total.
     */
    data class VirtualKey(
        val vkCode: Short,
        val flags: Byte
    ) : InputEvent() {
        override fun toBinaryFrame(): ByteArray {
            return ByteBuffer.allocate(5).order(ByteOrder.BIG_ENDIAN)
                .put(PACKET_TYPE_INPUT_EVENT)
                .put(SUBTYPE_VIRTUAL_KEY)
                .putShort(vkCode)
                .put(flags)
                .array()
        }
    }

    /**
     * Subtype 0x05: Unicode Text Chunk
     * Payload: [0x05 (Byte)] [UTF-16 Char Code (Short)] (3 bytes payload)
     * Full Frame with 0x05 Header: 4 bytes total.
     */
    data class UnicodeChar(
        val charCode: Short
    ) : InputEvent() {
        override fun toBinaryFrame(): ByteArray {
            return ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN)
                .put(PACKET_TYPE_INPUT_EVENT)
                .put(SUBTYPE_UNICODE_CHAR)
                .putShort(charCode)
                .array()
        }
    }
}

object InputFactory {
    fun createClick(buttonId: Byte): List<InputEvent> = listOf(
        InputEvent.ButtonState(buttonId, BUTTON_STATE_DOWN),
        InputEvent.ButtonState(buttonId, BUTTON_STATE_UP)
    )

    fun createKeyTap(vkCode: Short, flags: Byte = KEY_STATE_DOWN): List<InputEvent> = listOf(
        InputEvent.VirtualKey(vkCode, flags),
        InputEvent.VirtualKey(vkCode, KEY_STATE_UP)
    )

    fun createUnicodeText(text: String): List<InputEvent.UnicodeChar> {
        val events = ArrayList<InputEvent.UnicodeChar>(text.length)
        for (i in 0 until text.length) {
            val codeUnit = text[i].code.toShort()
            events.add(InputEvent.UnicodeChar(codeUnit))
        }
        return events
    }
}
