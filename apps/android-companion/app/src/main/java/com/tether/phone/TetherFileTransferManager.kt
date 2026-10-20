package com.tether.phone

import android.content.ContentValues
import android.content.Context
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Locale
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

class TetherFileTransferManager(
    private val appContext: Context,
    private val capabilityManager: TetherCapabilityManager,
    private val coroutineScope: CoroutineScope,
) {

    companion object {
        private const val TAG = "TetherFileTransferManager"
        private const val BUFFER_SIZE = 65536 // 64 KB
        private const val PROGRESS_EMIT_INTERVAL_MS = 100L
        private const val STAGING_DIR_NAME = "tether_staging"

        fun sanitizeFilename(rawName: String?): String {
            if (rawName.isNullOrBlank()) return "tether_received_file"
            val basename = File(rawName).name
            val sanitized = basename
                .replace(Regex("[^a-zA-Z0-9._-]"), "_")
                .take(255)
                .trim()
            return if (sanitized.isBlank() || sanitized == "." || sanitized == "..") {
                "tether_received_file"
            } else {
                sanitized
            }
        }

        fun computeFileSha512Hex(file: File, maxBytes: Long = Long.MAX_VALUE): String {
            if (!file.exists() || file.length() == 0L) return ""
            val digest = MessageDigest.getInstance("SHA-512")
            val buffer = ByteArray(BUFFER_SIZE)
            var bytesReadTotal = 0L

            FileInputStream(file).use { fis ->
                while (bytesReadTotal < maxBytes) {
                    val toRead = minOf(buffer.size.toLong(), maxBytes - bytesReadTotal).toInt()
                    val read = fis.read(buffer, 0, toRead)
                    if (read <= 0) break
                    digest.update(buffer, 0, read)
                    bytesReadTotal += read
                }
            }
            return digest.digest().joinToString("") { String.format(Locale.US, "%02X", it) }
        }
    }

    private val stagingDir: File by lazy {
        File(appContext.cacheDir, STAGING_DIR_NAME).apply {
            if (!exists()) mkdirs()
        }
    }

    private val activeTransfers = ConcurrentHashMap<String, TransferProgress>()
    private val _transferListFlow = MutableStateFlow<List<TransferProgress>>(emptyList())
    val transferListFlow: StateFlow<List<TransferProgress>> = _transferListFlow.asStateFlow()

    private val transferJobs = ConcurrentHashMap<String, Job>()

    private fun updateProgress(progress: TransferProgress) {
        activeTransfers[progress.transferId] = progress
        _transferListFlow.value = activeTransfers.values.toList()
    }

    fun getStagingFile(transferId: String): File {
        return File(stagingDir, "$transferId.tmp")
    }

    /**
     * Executes an incoming file transfer stream from transport into staging file
     */
    suspend fun handleIncomingTransfer(
        transport: TetherQuicTransport,
        request: TransferRequestFrame,
        peerName: String,
    ): Boolean = withContext(Dispatchers.IO) {
        val transferId = request.transferId
        val sanitizedName = sanitizeFilename(request.fileName)
        val expectedSha512 = request.expectedSha512.uppercase(Locale.US)

        if (!capabilityManager.isCapabilityGranted(TetherCapability.FILES)) {
            Log.w(TAG, "Incoming transfer $transferId denied: missing FILES capability")
            val resp = TransferResponseFrame(
                transferId = transferId,
                status = "REJECTED",
                errorCode = FileTransferErrorCode.MISSING_CAPABILITY.code,
                reason = FileTransferErrorCode.MISSING_CAPABILITY.description,
            )
            transport.sendControlFrame(resp.toJson().toString().toByteArray(StandardCharsets.UTF_8))
            return@withContext false
        }

        val stagingFile = getStagingFile(transferId)
        if (stagingFile.exists()) {
            stagingFile.delete()
        }

        var progress = TransferProgress(
            transferId = transferId,
            fileName = sanitizedName,
            fileSize = request.fileSize,
            bytesTransferred = 0L,
            speedBytesPerSec = 0.0,
            state = FileTransferState.TRANSFERRING,
            isIncoming = true,
            peerName = peerName,
        )
        updateProgress(progress)

        val acceptResp = TransferResponseFrame(
            transferId = transferId,
            status = "ACCEPTED",
            resumeOffset = 0L,
        )
        transport.sendControlFrame(acceptResp.toJson().toString().toByteArray(StandardCharsets.UTF_8))

        val digest = MessageDigest.getInstance("SHA-512")
        val startTimeMs = System.currentTimeMillis()
        var lastEmitTimeMs = startTimeMs
        var bytesTransferred = 0L

        try {
            FileOutputStream(stagingFile).use { fos ->
                while (bytesTransferred < request.fileSize) {
                    val chunkBytes = transport.readDataChunk() ?: break
                    if (chunkBytes.size < DataChunkFraming.HEADER_SIZE_BYTES - 4) break

                    val header = DataChunkFraming.parseHeader(chunkBytes)
                    if (header.msgType == DataChunkMessageType.MSG_DATA_END) {
                        Log.i(TAG, "Received DATA_END signal for transfer $transferId")
                        break
                    }

                    val payloadOffset = DataChunkFraming.HEADER_SIZE_BYTES
                    val payloadLen = header.payloadLength
                    if (payloadLen <= 0 || payloadOffset + payloadLen > chunkBytes.size) break

                    fos.write(chunkBytes, payloadOffset, payloadLen)
                    digest.update(chunkBytes, payloadOffset, payloadLen)
                    bytesTransferred += payloadLen

                    val now = System.currentTimeMillis()
                    if (now - lastEmitTimeMs >= PROGRESS_EMIT_INTERVAL_MS) {
                        val elapsedSec = (now - startTimeMs) / 1000.0
                        val speed = if (elapsedSec > 0) bytesTransferred / elapsedSec else 0.0
                        progress = progress.copy(
                            bytesTransferred = bytesTransferred,
                            speedBytesPerSec = speed,
                            state = FileTransferState.TRANSFERRING,
                        )
                        updateProgress(progress)
                        lastEmitTimeMs = now
                    }
                }
            }

            progress = progress.copy(
                bytesTransferred = bytesTransferred,
                state = FileTransferState.VERIFYING,
            )
            updateProgress(progress)

            val computedSha512Hex = computeFileSha512Hex(stagingFile).uppercase(Locale.US)
            val expectedSha512Bytes = expectedSha512.toByteArray(StandardCharsets.UTF_8)
            val computedSha512Bytes = computedSha512Hex.toByteArray(StandardCharsets.UTF_8)

            if (!MessageDigest.isEqual(expectedSha512Bytes, computedSha512Bytes)) {
                Log.e(TAG, "SHA-512 integrity failure for $transferId! Expected: $expectedSha512, Computed: $computedSha512Hex")
                stagingFile.delete()
                progress = progress.copy(
                    state = FileTransferState.FAILED,
                    errorMessage = "SHA-512 integrity verification failed",
                )
                updateProgress(progress)
                return@withContext false
            }

            Log.i(TAG, "SHA-512 integrity verified successfully for $sanitizedName ($bytesTransferred bytes)!")
            val promoted = promoteStagingFileToStorage(appContext, stagingFile, sanitizedName, request.mimeType)

            progress = progress.copy(
                bytesTransferred = bytesTransferred,
                state = if (promoted) FileTransferState.COMPLETED else FileTransferState.FAILED,
                errorMessage = if (promoted) null else "Failed promoting file to MediaStore storage",
            )
            updateProgress(progress)
            return@withContext promoted

        } catch (e: Exception) {
            Log.e(TAG, "Error handling incoming transfer $transferId: ${e.message}", e)
            stagingFile.delete()
            progress = progress.copy(
                state = FileTransferState.FAILED,
                errorMessage = e.message,
            )
            updateProgress(progress)
            return@withContext false
        }
    }

    /**
     * Handles incoming resume request for interrupted transfer
     */
    suspend fun handleResumeRequest(
        transport: TetherQuicTransport,
        resumeReq: TransferResumeRequestFrame,
    ): Boolean = withContext(Dispatchers.IO) {
        val transferId = resumeReq.transferId
        val stagingFile = getStagingFile(transferId)

        if (!stagingFile.exists()) {
            Log.w(TAG, "Resume failed for $transferId: Staging file does not exist")
            val rejectAck = TransferResumeAckFrame(
                transferId = transferId,
                status = "REJECTED",
                resumeOffset = 0L,
                partialSha512 = "",
                errorCode = FileTransferErrorCode.RESUME_PREFIX_MISMATCH.code,
                reason = "Staging file missing on receiver",
            )
            transport.sendControlFrame(rejectAck.toJson().toString().toByteArray(StandardCharsets.UTF_8))
            return@withContext false
        }

        val existingLen = stagingFile.length()
        if (existingLen != resumeReq.requestedOffset) {
            Log.w(TAG, "Resume failed for $transferId: Offset mismatch (Existing: $existingLen, Requested: ${resumeReq.requestedOffset})")
            stagingFile.delete()
            val rejectAck = TransferResumeAckFrame(
                transferId = transferId,
                status = "REJECTED",
                resumeOffset = 0L,
                partialSha512 = "",
                errorCode = FileTransferErrorCode.RESUME_PREFIX_MISMATCH.code,
                reason = "Partial file size mismatch",
            )
            transport.sendControlFrame(rejectAck.toJson().toString().toByteArray(StandardCharsets.UTF_8))
            return@withContext false
        }

        val partialSha512Hex = computeFileSha512Hex(stagingFile, existingLen).uppercase(Locale.US)
        val acceptAck = TransferResumeAckFrame(
            transferId = transferId,
            status = "ACCEPTED",
            resumeOffset = existingLen,
            partialSha512 = partialSha512Hex,
        )
        transport.sendControlFrame(acceptAck.toJson().toString().toByteArray(StandardCharsets.UTF_8))
        return@withContext true
    }

    /**
     * Promotes verified staging file to public Downloads directory / MediaStore
     */
    private fun promoteStagingFileToStorage(
        context: Context,
        stagingFile: File,
        displayName: String,
        mimeType: String,
    ): Boolean {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                val resolver = context.contentResolver
                val contentValues = ContentValues().apply {
                    put(MediaStore.MediaColumns.DISPLAY_NAME, displayName)
                    put(MediaStore.MediaColumns.MIME_TYPE, mimeType)
                    put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS + "/Tether")
                }

                val uri: Uri? = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, contentValues)
                if (uri == null) {
                    Log.e(TAG, "MediaStore insert returned null URI for $displayName")
                    return false
                }

                resolver.openOutputStream(uri)?.use { os ->
                    FileInputStream(stagingFile).use { fis ->
                        fis.copyTo(os, BUFFER_SIZE)
                    }
                }
                stagingFile.delete()
                Log.i(TAG, "Promoted file to MediaStore: $uri")
                true
            } else {
                val downloadsDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
                val tetherDir = File(downloadsDir, "Tether").apply { if (!exists()) mkdirs() }
                val destFile = File(tetherDir, displayName)
                if (destFile.exists()) destFile.delete()

                val moved = stagingFile.renameTo(destFile)
                if (!moved) {
                    FileInputStream(stagingFile).use { fis ->
                        FileOutputStream(destFile).use { fos ->
                            fis.copyTo(fos, BUFFER_SIZE)
                        }
                    }
                    stagingFile.delete()
                }
                Log.i(TAG, "Promoted file to filesystem: ${destFile.absolutePath}")
                true
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed promoting staging file to storage: ${e.message}", e)
            false
        }
    }

    fun cancelTransfer(transferId: String) {
        transferJobs[transferId]?.cancel()
        transferJobs.remove(transferId)
        val stagingFile = getStagingFile(transferId)
        if (stagingFile.exists()) stagingFile.delete()

        activeTransfers[transferId]?.let {
            val updated = it.copy(state = FileTransferState.CANCELLED, errorMessage = "Cancelled by user")
            updateProgress(updated)
        }
    }

    fun clearHistory() {
        activeTransfers.clear()
        _transferListFlow.value = emptyList()
    }
}
