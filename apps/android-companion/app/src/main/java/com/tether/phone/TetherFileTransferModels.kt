package com.tether.phone

import org.json.JSONObject
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.util.UUID

/**
 * QUIC Transport Layer Error Codes (RFC 9000)
 */
object QuicTransportErrorCode {
    const val NO_ERROR: Long = 0x00
    const val INTERNAL_ERROR: Long = 0x01
    const val STREAM_CREATION_ERROR: Long = 0x02
    const val CLOSED_CRITICAL_STREAM: Long = 0x03
    const val PROTOCOL_VIOLATION: Long = 0x0A
    const val CRYPTO_ERROR_BASE: Long = 0x0100
}

/**
 * Application-Level Protocol Error Codes for Tether File Sharing
 */
enum class FileTransferErrorCode(val code: Int, val description: String) {
    UNAUTHORIZED_PEER(0x10, "Peer public key does not match pinned identity"),
    MISSING_CAPABILITY(0x11, "Peer lacks granted FILES capability"),
    PATH_TRAVERSAL_REJECTED(0x12, "Filename contained unsafe path separators or directory traversal sequences"),
    DISK_FULL(0x13, "Insufficient storage space on receiver device"),
    INTEGRITY_FAILED(0x14, "SHA-512 complete file digest mismatch"),
    RESUME_PREFIX_MISMATCH(0x15, "Partial file partialSha512 prefix digest mismatch during resume"),
    SOURCE_FILE_CHANGED(0x16, "Sender source file length or modification timestamp changed mid-transfer"),
    USER_CANCELLED(0x17, "File transfer explicitly cancelled by user"),
    SERVICE_TIMEOUT(0x18, "Foreground service execution time limit reached");

    companion object {
        fun fromCode(code: Int): FileTransferErrorCode? {
            return entries.firstOrNull { it.code == code }
        }
    }
}

/**
 * State of an active or queued file transfer operation
 */
enum class FileTransferState {
    IDLE,
    CONNECTING,
    REQUESTED,
    TRANSFERRING,
    PAUSED,
    VERIFYING,
    COMPLETED,
    FAILED,
    CANCELLED
}

/**
 * Control Stream Message Type Constants
 */
object ControlMessageType {
    const val CONTROL_INIT = "CONTROL_INIT"
    const val CONTROL_INIT_ACK = "CONTROL_INIT_ACK"
    const val BROWSE_ROOTS_REQUEST = "BROWSE_ROOTS_REQUEST"
    const val BROWSE_ROOTS_RESPONSE = "BROWSE_ROOTS_RESPONSE"
    const val LIST_DIR_REQUEST = "LIST_DIR_REQUEST"
    const val LIST_DIR_RESPONSE = "LIST_DIR_RESPONSE"
    const val QUEUE_SYNC_REQUEST = "QUEUE_SYNC_REQUEST"
    const val QUEUE_SYNC_SNAPSHOT = "QUEUE_SYNC_SNAPSHOT"
    const val TRANSFER_REQUEST = "TRANSFER_REQUEST"
    const val TRANSFER_RESPONSE = "TRANSFER_RESPONSE"
    const val TRANSFER_RESUME_REQUEST = "TRANSFER_RESUME_REQUEST"
    const val TRANSFER_RESUME_ACK = "TRANSFER_RESUME_ACK"
    const val TRANSFER_PAUSE = "TRANSFER_PAUSE"
    const val TRANSFER_CANCEL = "TRANSFER_CANCEL"
    const val TRANSFER_COMPLETE = "TRANSFER_COMPLETE"
    const val FS_DB_SYNC_REQUEST = "FS_DB_SYNC_REQUEST"
    const val FS_DB_SYNC_RESPONSE = "FS_DB_SYNC_RESPONSE"
    const val FS_DELTA_UPDATE = "FS_DELTA_UPDATE"
    const val FS_ON_DEMAND_SCAN = "FS_ON_DEMAND_SCAN"
}

/**
 * Data Stream Chunk Message Constants
 */
object DataChunkMessageType {
    const val MSG_DATA_CHUNK: Byte = 0x01
    const val MSG_DATA_END: Byte = 0x02
}

internal object JsonParserUtils {
    fun getString(jsonStr: String, key: String, default: String): String {
        val regex = Regex("\"$key\"\\s*:\\s*\"([^\"]*)\"")
        val match = regex.find(jsonStr)?.groupValues?.get(1)
        if (match != null) return match
        return try {
            val json = JSONObject(jsonStr)
            if (json.has(key)) json.optString(key, default) else default
        } catch (_: Throwable) {
            default
        }
    }

    fun getLong(jsonStr: String, key: String, default: Long): Long {
        val regex = Regex("\"$key\"\\s*:\\s*\"?(\\d+)\"?")
        val match = regex.find(jsonStr)?.groupValues?.get(1)?.toLongOrNull()
        if (match != null) return match
        return try {
            val json = JSONObject(jsonStr)
            if (json.has(key)) json.optLong(key, default) else default
        } catch (_: Throwable) {
            default
        }
    }

    fun getInt(jsonStr: String, key: String, default: Int): Int {
        val regex = Regex("\"$key\"\\s*:\\s*\"?(\\d+)\"?")
        val match = regex.find(jsonStr)?.groupValues?.get(1)?.toIntOrNull()
        if (match != null) return match
        return try {
            val json = JSONObject(jsonStr)
            if (json.has(key)) json.optInt(key, default) else default
        } catch (_: Throwable) {
            default
        }
    }
}

/**
 * Transfer Request Metadata Frame
 */
data class TransferRequestFrame(
    val version: String = "1.0",
    val transferId: String = UUID.randomUUID().toString(),
    val fileName: String,
    val fileSize: Long,
    val mimeType: String = "application/octet-stream",
    val expectedSha512: String,
    val chunkSize: Int = 65536,
    val totalChunks: Long = if (fileSize > 0) (fileSize + chunkSize - 1) / chunkSize else 0L,
    val sourceLastModified: Long = System.currentTimeMillis(),
) {
    fun toJsonString(): String = "{\"type\":\"${ControlMessageType.TRANSFER_REQUEST}\",\"version\":\"$version\",\"transferId\":\"$transferId\",\"fileName\":\"$fileName\",\"fileSize\":$fileSize,\"mimeType\":\"$mimeType\",\"expectedSha512\":\"$expectedSha512\",\"chunkSize\":$chunkSize,\"totalChunks\":$totalChunks,\"sourceLastModified\":$sourceLastModified}"

    fun toJson(): JSONObject = try { JSONObject(toJsonString()) } catch (_: Exception) { JSONObject() }

    companion object {
        fun parseJsonString(jsonStr: String): TransferRequestFrame {
            return TransferRequestFrame(
                version = JsonParserUtils.getString(jsonStr, "version", "1.0"),
                transferId = JsonParserUtils.getString(jsonStr, "transferId", UUID.randomUUID().toString()),
                fileName = JsonParserUtils.getString(jsonStr, "fileName", "unnamed_file"),
                fileSize = JsonParserUtils.getLong(jsonStr, "fileSize", 0L),
                mimeType = JsonParserUtils.getString(jsonStr, "mimeType", "application/octet-stream"),
                expectedSha512 = JsonParserUtils.getString(jsonStr, "expectedSha512", ""),
                chunkSize = JsonParserUtils.getInt(jsonStr, "chunkSize", 65536),
                totalChunks = JsonParserUtils.getLong(jsonStr, "totalChunks", 0L),
                sourceLastModified = JsonParserUtils.getLong(jsonStr, "sourceLastModified", 0L),
            )
        }

        fun parseJson(json: JSONObject): TransferRequestFrame = parseJsonString(json.toString())
    }
}

/**
 * Response Frame for Transfer Acceptance or Rejection
 */
data class TransferResponseFrame(
    val transferId: String,
    val status: String, // ACCEPTED, REJECTED, RESUME_ACK
    val resumeOffset: Long = 0L,
    val errorCode: Int = 0,
    val reason: String = "",
) {
    fun toJsonString(): String = "{\"type\":\"${ControlMessageType.TRANSFER_RESPONSE}\",\"transferId\":\"$transferId\",\"status\":\"$status\",\"resumeOffset\":$resumeOffset,\"errorCode\":$errorCode,\"reason\":\"$reason\"}"

    fun toJson(): JSONObject = try { JSONObject(toJsonString()) } catch (_: Exception) { JSONObject() }

    companion object {
        fun parseJsonString(jsonStr: String): TransferResponseFrame {
            return TransferResponseFrame(
                transferId = JsonParserUtils.getString(jsonStr, "transferId", ""),
                status = JsonParserUtils.getString(jsonStr, "status", "REJECTED"),
                resumeOffset = JsonParserUtils.getLong(jsonStr, "resumeOffset", 0L),
                errorCode = JsonParserUtils.getInt(jsonStr, "errorCode", 0),
                reason = JsonParserUtils.getString(jsonStr, "reason", ""),
            )
        }

        fun parseJson(json: JSONObject): TransferResponseFrame = parseJsonString(json.toString())
    }
}

/**
 * Resumable Transfer Request Frame
 */
data class TransferResumeRequestFrame(
    val transferId: String,
    val requestedOffset: Long,
    val sourceLastModified: Long,
    val sourceSize: Long,
) {
    fun toJsonString(): String = "{\"type\":\"${ControlMessageType.TRANSFER_RESUME_REQUEST}\",\"transferId\":\"$transferId\",\"requestedOffset\":$requestedOffset,\"sourceLastModified\":$sourceLastModified,\"sourceSize\":$sourceSize}"

    fun toJson(): JSONObject = try { JSONObject(toJsonString()) } catch (_: Exception) { JSONObject() }

    companion object {
        fun parseJsonString(jsonStr: String): TransferResumeRequestFrame {
            return TransferResumeRequestFrame(
                transferId = JsonParserUtils.getString(jsonStr, "transferId", ""),
                requestedOffset = JsonParserUtils.getLong(jsonStr, "requestedOffset", 0L),
                sourceLastModified = JsonParserUtils.getLong(jsonStr, "sourceLastModified", 0L),
                sourceSize = JsonParserUtils.getLong(jsonStr, "sourceSize", 0L),
            )
        }

        fun parseJson(json: JSONObject): TransferResumeRequestFrame = parseJsonString(json.toString())
    }
}

/**
 * Resumable Transfer Acknowledgement Frame with Partial SHA-512 Prefix Verification
 */
data class TransferResumeAckFrame(
    val transferId: String,
    val status: String, // ACCEPTED, REJECTED
    val resumeOffset: Long,
    val partialSha512: String,
    val errorCode: Int = 0,
    val reason: String = "",
) {
    fun toJsonString(): String = "{\"type\":\"${ControlMessageType.TRANSFER_RESUME_ACK}\",\"transferId\":\"$transferId\",\"status\":\"$status\",\"resumeOffset\":$resumeOffset,\"partialSha512\":\"$partialSha512\",\"errorCode\":$errorCode,\"reason\":\"$reason\"}"

    fun toJson(): JSONObject = try { JSONObject(toJsonString()) } catch (_: Exception) { JSONObject() }

    companion object {
        fun parseJsonString(jsonStr: String): TransferResumeAckFrame {
            return TransferResumeAckFrame(
                transferId = JsonParserUtils.getString(jsonStr, "transferId", ""),
                status = JsonParserUtils.getString(jsonStr, "status", "REJECTED"),
                resumeOffset = JsonParserUtils.getLong(jsonStr, "resumeOffset", 0L),
                partialSha512 = JsonParserUtils.getString(jsonStr, "partialSha512", ""),
                errorCode = JsonParserUtils.getInt(jsonStr, "errorCode", 0),
                reason = JsonParserUtils.getString(jsonStr, "reason", ""),
            )
        }

        fun parseJson(json: JSONObject): TransferResumeAckFrame = parseJsonString(json.toString())
    }
}
/**
 * Binary Framing Helper for Data Stream Chunks
 * Chunk Header Layout (29 bytes total):
 * - 4 bytes: Total frame length (Int big-endian)
 * - 1 byte:  MsgType (0x01 DATA_CHUNK, 0x02 DATA_END)
 * - 16 bytes: UUID TransferId
 * - 8 bytes: Chunk Index (Long big-endian)
 * - 8 bytes: File Offset (Long big-endian)
 * - 4 bytes: Payload Length (Int big-endian)
 * - N bytes: Binary Payload
 */
object DataChunkFraming {
    const val HEADER_SIZE_BYTES = 41 // 4 + 1 + 16 + 8 + 8 + 4

    fun serializeChunk(
        transferIdUuid: UUID,
        chunkIndex: Long,
        offset: Long,
        payload: ByteArray,
        payloadOffset: Int = 0,
        payloadLength: Int = payload.size,
    ): ByteArray {
        val totalFrameLength = HEADER_SIZE_BYTES - 4 + payloadLength
        val buffer = ByteBuffer.allocate(HEADER_SIZE_BYTES + payloadLength)
        buffer.putInt(totalFrameLength)
        buffer.put(DataChunkMessageType.MSG_DATA_CHUNK)
        buffer.putLong(transferIdUuid.mostSignificantBits)
        buffer.putLong(transferIdUuid.leastSignificantBits)
        buffer.putLong(chunkIndex)
        buffer.putLong(offset)
        buffer.putInt(payloadLength)
        buffer.put(payload, payloadOffset, payloadLength)
        return buffer.array()
    }

    fun serializeEndSignal(transferIdUuid: UUID): ByteArray {
        val totalFrameLength = HEADER_SIZE_BYTES - 4
        val buffer = ByteBuffer.allocate(HEADER_SIZE_BYTES)
        buffer.putInt(totalFrameLength)
        buffer.put(DataChunkMessageType.MSG_DATA_END)
        buffer.putLong(transferIdUuid.mostSignificantBits)
        buffer.putLong(transferIdUuid.leastSignificantBits)
        buffer.putLong(0L) // chunkIndex
        buffer.putLong(0L) // offset
        buffer.putInt(0)  // payloadLength
        return buffer.array()
    }

    data class ParsedChunkHeader(
        val msgType: Byte,
        val transferId: UUID,
        val chunkIndex: Long,
        val offset: Long,
        val payloadLength: Int,
    )

    fun parseHeader(headerBytes: ByteArray): ParsedChunkHeader {
        require(headerBytes.size >= HEADER_SIZE_BYTES - 4) { "Header bytes smaller than minimum header size" }
        val buffer = ByteBuffer.wrap(headerBytes)
        val msgType = buffer.get()
        val mostSigBits = buffer.getLong()
        val leastSigBits = buffer.getLong()
        val transferId = UUID(mostSigBits, leastSigBits)
        val chunkIndex = buffer.getLong()
        val offset = buffer.getLong()
        val payloadLength = buffer.getInt()
        return ParsedChunkHeader(
            msgType = msgType,
            transferId = transferId,
            chunkIndex = chunkIndex,
            offset = offset,
            payloadLength = payloadLength,
        )
    }
}

/**
 * Active Transfer UI Progress Model
 */
data class TransferProgress(
    val transferId: String,
    val fileName: String,
    val fileSize: Long,
    val bytesTransferred: Long,
    val speedBytesPerSec: Double,
    val state: FileTransferState,
    val isIncoming: Boolean,
    val peerName: String,
    val errorMessage: String? = null,
) {
    val progressFraction: Float
        get() = if (fileSize > 0) (bytesTransferred.toFloat() / fileSize.toFloat()).coerceIn(0f, 1f) else 0f

    val progressPercentage: Int
        get() = (progressFraction * 100).toInt()

    val speedMbPerSec: Double
        get() = speedBytesPerSec / (1024.0 * 1024.0)

    val etaSeconds: Long
        get() = if (speedBytesPerSec > 0 && fileSize > bytesTransferred) {
            ((fileSize - bytesTransferred) / speedBytesPerSec).toLong()
        } else {
            0L
        }
}

data class FilesystemRootItem(
    val name: String,
    val path: String,
    val rootType: String,
    val isReadable: Boolean = true,
)

data class DirectoryListingItem(
    val name: String,
    val relativePath: String,
    val isDirectory: Boolean,
    val fileSize: Long = 0L,
    val lastModifiedMs: Long = 0L,
    val isReadable: Boolean = true,
)

data class BrowseRootsRequestFrame(
    val requestId: String = UUID.randomUUID().toString(),
) {
    fun toJsonString(): String = "{\"type\":\"${ControlMessageType.BROWSE_ROOTS_REQUEST}\",\"requestId\":\"$requestId\"}"
}

data class ListDirRequestFrame(
    val requestId: String = UUID.randomUUID().toString(),
    val path: String,
) {
    fun toJsonString(): String = "{\"type\":\"${ControlMessageType.LIST_DIR_REQUEST}\",\"requestId\":\"$requestId\",\"path\":\"$path\"}"
}

data class FsDbSyncRequestFrame(
    val requestId: String = UUID.randomUUID().toString(),
    val platform: String = "ANDROID"
) {
    fun toJsonString(): String = "{\"type\":\"${ControlMessageType.FS_DB_SYNC_REQUEST}\",\"requestId\":\"$requestId\",\"platform\":\"$platform\"}"
}

data class FsDbSyncResponseFrame(
    val requestId: String,
    val status: String,
    val dbSize: Long,
    val checksum: String
) {
    fun toJsonString(): String = "{\"type\":\"${ControlMessageType.FS_DB_SYNC_RESPONSE}\",\"requestId\":\"$requestId\",\"status\":\"$status\",\"dbSize\":$dbSize,\"checksum\":\"$checksum\"}"
}

data class FsOnDemandScanFrame(
    val requestId: String = UUID.randomUUID().toString(),
    val targetPath: String
) {
    fun toJsonString(): String = "{\"type\":\"${ControlMessageType.FS_ON_DEMAND_SCAN}\",\"requestId\":\"$requestId\",\"targetPath\":\"$targetPath\"}"
}
