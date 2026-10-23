package com.tether.phone

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import android.provider.OpenableColumns
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
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Locale
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import org.json.JSONObject

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

        fun sanitizeLogInput(input: String): String {
            return input.replace("\r", "_").replace("\n", "_").replace(Regex("[\\r\\n\\t\\p{Cntrl}]"), "_")
        }

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
            if (!file.exists()) return ""
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
        showTransferNotification(progress)
    }

    private fun showTransferNotification(progress: TransferProgress) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                if (androidx.core.content.ContextCompat.checkSelfPermission(
                        appContext,
                        android.Manifest.permission.POST_NOTIFICATIONS
                    ) != android.content.pm.PackageManager.PERMISSION_GRANTED
                ) {
                    return
                }
            }

            val notificationManager = androidx.core.app.NotificationManagerCompat.from(appContext)
            val notifId = progress.transferId.hashCode()

            when (progress.state) {
                FileTransferState.TRANSFERRING, FileTransferState.VERIFYING -> {
                    val directionText = if (progress.isIncoming) "Receiving" else "Sending"
                    val speedText = String.format(Locale.US, "%.1f MB/s", progress.speedMbPerSec)
                    val title = "$directionText ${progress.fileName}"
                    val content = "${progress.progressPercentage}% • $speedText • ${progress.peerName}"

                    val notification = androidx.core.app.NotificationCompat.Builder(
                        appContext,
                        TetherNotificationChannels.CHANNEL_FILE_TRANSFER
                    )
                        .setSmallIcon(android.R.drawable.stat_sys_download)
                        .setContentTitle(title)
                        .setContentText(content)
                        .setProgress(100, progress.progressPercentage, progress.state == FileTransferState.VERIFYING)
                        .setOngoing(true)
                        .setOnlyAlertOnce(true)
                        .setPriority(androidx.core.app.NotificationCompat.PRIORITY_LOW)
                        .build()

                    notificationManager.notify(notifId, notification)
                }

                FileTransferState.COMPLETED -> {
                    val title = "Transfer Complete: ${progress.fileName}"
                    val content = "Successfully saved (${progress.fileSize / 1024} KB)"
                    val notification = androidx.core.app.NotificationCompat.Builder(
                        appContext,
                        TetherNotificationChannels.CHANNEL_FILE_TRANSFER
                    )
                        .setSmallIcon(android.R.drawable.stat_sys_download_done)
                        .setContentTitle(title)
                        .setContentText(content)
                        .setOngoing(false)
                        .setPriority(androidx.core.app.NotificationCompat.PRIORITY_LOW)
                        .build()

                    notificationManager.notify(notifId, notification)
                }

                FileTransferState.FAILED, FileTransferState.CANCELLED -> {
                    val title = "Transfer Failed: ${progress.fileName}"
                    val content = progress.errorMessage ?: "Transfer stopped"
                    val notification = androidx.core.app.NotificationCompat.Builder(
                        appContext,
                        TetherNotificationChannels.CHANNEL_FILE_TRANSFER
                    )
                        .setSmallIcon(android.R.drawable.stat_notify_error)
                        .setContentTitle(title)
                        .setContentText(content)
                        .setOngoing(false)
                        .setPriority(androidx.core.app.NotificationCompat.PRIORITY_LOW)
                        .build()

                    notificationManager.notify(notifId, notification)
                }

                else -> {}
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed posting transfer notification: ${e.message}")
        }
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
        var hasReceivedDataEnd = false

        try {
            FileOutputStream(stagingFile).use { fos ->
                while (bytesTransferred < request.fileSize) {
                    val chunkBytes = transport.readDataChunk() ?: break
                    if (chunkBytes.size < DataChunkFraming.HEADER_SIZE_BYTES - 4) break

                    val header = DataChunkFraming.parseHeader(chunkBytes)
                    if (header.msgType == DataChunkMessageType.MSG_DATA_END) {
                        Log.i(TAG, "Received DATA_END signal for transfer $transferId")
                        hasReceivedDataEnd = true
                        break
                    }

                    val payloadOffset = DataChunkFraming.HEADER_SIZE_BYTES - 4
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

            if (!hasReceivedDataEnd) {
                try {
                    val trailingChunk = transport.readDataChunk()
                    if (trailingChunk != null && trailingChunk.size >= DataChunkFraming.HEADER_SIZE_BYTES - 4) {
                        val header = DataChunkFraming.parseHeader(trailingChunk)
                        if (header.msgType == DataChunkMessageType.MSG_DATA_END) {
                            Log.i(TAG, "Consumed trailing MSG_DATA_END for transfer $transferId")
                        }
                    }
                } catch (e: Exception) {
                    Log.d(TAG, "Trailing MSG_DATA_END check: ${e.message}")
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
            
            val promoted = if (sanitizedName == "windows_fs.db") {
                try {
                    val dbPath = appContext.getDatabasePath("windows_fs.db")
                    dbPath.parentFile?.mkdirs()
                    SQLiteDatabase.releaseMemory()
                    if (dbPath.exists()) {
                        try { dbPath.delete() } catch (_: Exception) {}
                    }
                    val moved = stagingFile.renameTo(dbPath)
                    if (!moved) {
                        FileInputStream(stagingFile).use { fis ->
                            FileOutputStream(dbPath).use { fos ->
                                fis.copyTo(fos, BUFFER_SIZE)
                            }
                        }
                        try { stagingFile.delete() } catch (_: Exception) {}
                    }
                    Log.i(TAG, "Installed windows_fs.db to app databases folder")
                    true
                } catch (e: Exception) {
                    Log.e(TAG, "Error installing windows_fs.db: ${e.message}", e)
                    false
                }
            } else {
                promoteStagingFileToStorage(appContext, stagingFile, sanitizedName, request.mimeType)
            }

            progress = progress.copy(
                bytesTransferred = bytesTransferred,
                state = if (promoted) FileTransferState.COMPLETED else FileTransferState.FAILED,
                errorMessage = if (promoted) null else "Failed promoting file to MediaStore storage",
            )
            updateProgress(progress)

            if (promoted) {
                val completeFrameObj = JSONObject().apply {
                    put("type", ControlMessageType.TRANSFER_COMPLETE)
                    put("transferId", transferId)
                    put("status", "SUCCESS")
                    put("errorCode", 0)
                }
                try {
                    transport.sendControlFrame(completeFrameObj.toString().toByteArray(StandardCharsets.UTF_8))
                } catch (e: Exception) {
                    Log.w(TAG, "Failed sending TRANSFER_COMPLETE: ${e.message}")
                }
            } else {
                val failFrameObj = JSONObject().apply {
                    put("type", ControlMessageType.TRANSFER_COMPLETE)
                    put("transferId", transferId)
                    put("status", "FAILED")
                    put("errorCode", FileTransferErrorCode.DISK_FULL.code)
                    put("reason", "Failed promoting file to storage")
                }
                try {
                    transport.sendControlFrame(failFrameObj.toString().toByteArray(StandardCharsets.UTF_8))
                } catch (_: Exception) {}
            }

            return@withContext promoted

        } catch (e: Exception) {
            Log.e(TAG, "Error handling incoming transfer $transferId: ${e.message}", e)
            stagingFile.delete()
            progress = progress.copy(
                state = FileTransferState.FAILED,
                errorMessage = e.message,
            )
            updateProgress(progress)

            val failFrameObj = JSONObject().apply {
                put("type", ControlMessageType.TRANSFER_COMPLETE)
                put("transferId", transferId)
                put("status", "FAILED")
                put("errorCode", FileTransferErrorCode.INTEGRITY_FAILED.code)
                put("reason", e.message ?: "Transfer failed")
            }
            try {
                transport.sendControlFrame(failFrameObj.toString().toByteArray(StandardCharsets.UTF_8))
            } catch (_: Exception) {}

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
        val safeMimeType = if (mimeType.isBlank() || mimeType == "*/*") "application/octet-stream" else mimeType
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                val resolver = context.contentResolver
                val contentValues = ContentValues().apply {
                    put(MediaStore.MediaColumns.DISPLAY_NAME, displayName)
                    put(MediaStore.MediaColumns.MIME_TYPE, safeMimeType)
                    put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS + "/Tether")
                }

                val uri: Uri? = try {
                    resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, contentValues)
                } catch (e: Exception) {
                    Log.w(TAG, "MediaStore insert failed: ${e.message}")
                    null
                }

                if (uri != null) {
                    try {
                        resolver.openOutputStream(uri)?.use { os ->
                            FileInputStream(stagingFile).use { fis ->
                                fis.copyTo(os, BUFFER_SIZE)
                            }
                        }
                        stagingFile.delete()
                        Log.i(TAG, "Promoted file to MediaStore: $uri")
                        return true
                    } catch (e: Exception) {
                        Log.e(TAG, "Failed writing to MediaStore OutputStream for $uri: ${e.message}")
                        try { resolver.delete(uri, null, null) } catch (_: Exception) {}
                    }
                }
            }

            val downloadsDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
            val tetherDir = File(downloadsDir, "Tether")
            if (!tetherDir.exists() && !tetherDir.mkdirs()) {
                Log.e(TAG, "Failed creating target directory: ${tetherDir.absolutePath}")
                return false
            }

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

    fun sendFile(
        securityEngine: ProductionSecurityEngine,
        host: String,
        port: Int = 37125,
        uri: Uri,
        peerName: String,
    ) {
        val transferId = UUID.randomUUID().toString()
        val job = coroutineScope.launch(Dispatchers.IO) {
            val resolver = appContext.contentResolver
            var fileName = "tether_upload_file"
            var fileSize = 0L
            var mimeType = "application/octet-stream"

            try {
                resolver.query(uri, null, null, null, null)?.use { cursor ->
                    if (cursor.moveToFirst()) {
                        val nameIdx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                        val sizeIdx = cursor.getColumnIndex(OpenableColumns.SIZE)
                        if (nameIdx >= 0) fileName = cursor.getString(nameIdx) ?: "tether_upload_file"
                        if (sizeIdx >= 0) fileSize = cursor.getLong(sizeIdx)
                    }
                }
                mimeType = resolver.getType(uri) ?: "application/octet-stream"
            } catch (e: Exception) {
                Log.w(TAG, "Failed resolving file details from Uri: ${e.message}")
            }
            if (fileName == "tether_upload_file" && uri.lastPathSegment != null) {
                fileName = uri.lastPathSegment ?: "tether_upload_file"
            }

            fileName = sanitizeFilename(fileName)

            var progress = TransferProgress(
                transferId = transferId,
                fileName = fileName,
                fileSize = fileSize,
                bytesTransferred = 0L,
                speedBytesPerSec = 0.0,
                state = FileTransferState.CONNECTING,
                isIncoming = false,
                peerName = peerName,
            )
            updateProgress(progress)

            val stagingFile = getStagingFile(transferId)
            if (stagingFile.exists()) stagingFile.delete()

            val digest = MessageDigest.getInstance("SHA-512")
            try {
                val inputStream = if (uri.scheme == "file" && uri.path != null) {
                    FileInputStream(File(uri.path!!))
                } else {
                    resolver.openInputStream(uri)
                }

                inputStream?.use { input ->
                    FileOutputStream(stagingFile).use { output ->
                        val buffer = ByteArray(BUFFER_SIZE)
                        var read: Int
                        while (input.read(buffer).also { read = it } > 0) {
                            output.write(buffer, 0, read)
                            digest.update(buffer, 0, read)
                        }
                    }
                }
                fileSize = stagingFile.length()
                val expectedSha512Hex = digest.digest().joinToString("") { String.format(Locale.US, "%02X", it) }

                progress = progress.copy(fileSize = fileSize, state = FileTransferState.CONNECTING)
                updateProgress(progress)

                val transport = TetherQuicTransportImpl(appContext, securityEngine)
                try {
                    Log.i(TAG, "Connecting QUIC transport to $host:$port to send $fileName ($fileSize bytes)...")
                    transport.connect(host, port, timeoutMs = 5000)

                    val myPublicKeyBytes = securityEngine.getPublicKeyBytes()
                    val myFingerprint = securityEngine.computePublicKeyFingerprint(myPublicKeyBytes)

                    val initReqJson = "{\"type\":\"${ControlMessageType.CONTROL_INIT}\",\"protocolVersion\":\"1.0\",\"deviceId\":\"$myFingerprint\"}"
                    transport.sendControlFrame(initReqJson.toByteArray(StandardCharsets.UTF_8))

                    val initAckRaw = transport.readControlFrame()
                        ?: throw IOException("No CONTROL_INIT_ACK received from server")

                    val reqFrame = TransferRequestFrame(
                        version = "1.0",
                        transferId = transferId,
                        fileName = fileName,
                        fileSize = fileSize,
                        mimeType = mimeType,
                        expectedSha512 = expectedSha512Hex,
                        chunkSize = BUFFER_SIZE,
                        totalChunks = if (fileSize > 0) (fileSize + BUFFER_SIZE - 1) / BUFFER_SIZE else 0L,
                        sourceLastModified = System.currentTimeMillis(),
                    )
                    transport.sendControlFrame(reqFrame.toJson().toString().toByteArray(StandardCharsets.UTF_8))

                    val respRaw = transport.readControlFrame()
                        ?: throw IOException("No TRANSFER_RESPONSE received from server")

                    val respStr = String(respRaw, StandardCharsets.UTF_8)
                    val respFrame = TransferResponseFrame.parseJsonString(respStr)

                    if (respFrame.status != "ACCEPTED") {
                        throw IOException("Transfer rejected by server: ${respFrame.reason} (code=${respFrame.errorCode})")
                    }

                    progress = progress.copy(state = FileTransferState.TRANSFERRING)
                    updateProgress(progress)

                    val startTimeMs = System.currentTimeMillis()
                    var lastEmitTimeMs = startTimeMs
                    var bytesSent = 0L
                    var chunkIndex = 0L

                    FileInputStream(stagingFile).use { fis ->
                        val chunkBuf = ByteArray(BUFFER_SIZE)
                        var readLen: Int
                        val uuid = UUID.fromString(transferId)

                        while (fis.read(chunkBuf).also { readLen = it } > 0) {
                            val frameBytes = DataChunkFraming.serializeChunk(
                                transferIdUuid = uuid,
                                chunkIndex = chunkIndex++,
                                offset = bytesSent,
                                payload = chunkBuf,
                                payloadOffset = 0,
                                payloadLength = readLen,
                            )
                            transport.sendDataChunk(frameBytes)
                            bytesSent += readLen

                            val now = System.currentTimeMillis()
                            if (now - lastEmitTimeMs >= PROGRESS_EMIT_INTERVAL_MS) {
                                val elapsedSec = (now - startTimeMs) / 1000.0
                                val speed = if (elapsedSec > 0) bytesSent / elapsedSec else 0.0
                                progress = progress.copy(
                                    bytesTransferred = bytesSent,
                                    speedBytesPerSec = speed,
                                    state = FileTransferState.TRANSFERRING,
                                )
                                updateProgress(progress)
                                lastEmitTimeMs = now
                            }
                        }

                        val endSignal = DataChunkFraming.serializeEndSignal(uuid)
                        transport.sendDataChunk(endSignal)
                    }

                    progress = progress.copy(bytesTransferred = fileSize, state = FileTransferState.VERIFYING)
                    updateProgress(progress)

                    val completeRaw = transport.readControlFrame()
                        ?: throw IOException("No TRANSFER_COMPLETE received from server")

                    val completeStr = String(completeRaw, StandardCharsets.UTF_8)
                    val safeCompleteStr = sanitizeLogInput(completeStr)
                    Log.i(TAG, "Server completed transfer response: $safeCompleteStr")

                    val type = JsonParserUtils.getString(completeStr, "type", "")
                    val status = JsonParserUtils.getString(completeStr, "status", "OK")
                    if (type == ControlMessageType.TRANSFER_COMPLETE && status != "OK" && status != "SUCCESS") {
                        val reason = JsonParserUtils.getString(completeStr, "reason", "Unknown error")
                        throw IOException("Receiver reported transfer failure: $reason")
                    } else if (status == "ERROR" || status == "REJECTED") {
                        val reason = JsonParserUtils.getString(completeStr, "reason", "Unknown error")
                        throw IOException("Receiver reported failure: $reason")
                    }

                    progress = progress.copy(
                        bytesTransferred = fileSize,
                        state = FileTransferState.COMPLETED,
                        errorMessage = null,
                    )
                    updateProgress(progress)
                    Log.i(TAG, "Successfully sent file $fileName ($fileSize bytes) to $peerName!")

                } finally {
                    transport.disconnect("Transfer finished")
                }

            } catch (e: Exception) {
                Log.e(TAG, "Error sending file $fileName ($transferId): ${e.message}", e)
                progress = progress.copy(
                    state = FileTransferState.FAILED,
                    errorMessage = e.message ?: "Transfer failed",
                )
                updateProgress(progress)
            } finally {
                stagingFile.delete()
                transferJobs.remove(transferId)
            }
        }
        transferJobs[transferId] = job
    }

    fun requestWindowsDbSync(securityEngine: ProductionSecurityEngine, host: String, port: Int = 37125) {
        coroutineScope.launch(Dispatchers.IO) {
            var transport: TetherQuicTransportImpl? = null
            try {
                transport = TetherQuicTransportImpl(appContext, securityEngine)
                transport.connect(host, port, timeoutMs = 5000)
                val myPublicKeyBytes = securityEngine.getPublicKeyBytes()
                val myFingerprint = securityEngine.computePublicKeyFingerprint(myPublicKeyBytes)
                val initReqJson = "{\"type\":\"${ControlMessageType.CONTROL_INIT}\",\"protocolVersion\":\"1.0\",\"deviceId\":\"$myFingerprint\"}"
                transport.sendControlFrame(initReqJson.toByteArray(StandardCharsets.UTF_8))
                transport.readControlFrame() // Wait for ACK
                
                val req = FsDbSyncRequestFrame()
                transport.sendControlFrame(req.toJsonString().toByteArray(StandardCharsets.UTF_8))
                
                val respRaw = transport.readControlFrame()
                if (respRaw != null) {
                    Log.i(TAG, "Received FS_DB_SYNC_RESPONSE: ${String(respRaw, StandardCharsets.UTF_8)}")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed requesting Windows DB Sync: ${e.message}")
            } finally {
                transport?.disconnect("Sync request finished")
            }
        }
    }

    fun requestWindowsFileDownload(securityEngine: ProductionSecurityEngine, host: String, port: Int = 37125, remotePath: String) {
        coroutineScope.launch(Dispatchers.IO) {
            var transport: TetherQuicTransportImpl? = null
            try {
                transport = TetherQuicTransportImpl(appContext, securityEngine)
                transport.connect(host, port, timeoutMs = 5000)
                val myPublicKeyBytes = securityEngine.getPublicKeyBytes()
                val myFingerprint = securityEngine.computePublicKeyFingerprint(myPublicKeyBytes)
                val initReqJson = "{\"type\":\"${ControlMessageType.CONTROL_INIT}\",\"protocolVersion\":\"1.0\",\"deviceId\":\"$myFingerprint\"}"
                transport.sendControlFrame(initReqJson.toByteArray(StandardCharsets.UTF_8))
                transport.readControlFrame() // Wait for ACK

                val req = FileDownloadRequestFrame(filePath = remotePath)
                transport.sendControlFrame(req.toJsonString().toByteArray(StandardCharsets.UTF_8))
                Log.i(TAG, "Sent FILE_DOWNLOAD_REQUEST for '$remotePath' to Windows PC")
            } catch (e: Exception) {
                Log.e(TAG, "Failed requesting Windows file download: ${e.message}")
            } finally {
                transport?.disconnect("Download request sent")
            }
        }
    }

    /**
     * Sends BROWSE_ROOTS_REQUEST to Windows PC and returns permitted roots
     */
    suspend fun requestWindowsRoots(transport: TetherQuicTransport): List<FilesystemRootItem> = withContext(Dispatchers.IO) {
        try {
            val req = BrowseRootsRequestFrame()
            transport.sendControlFrame(req.toJsonString().toByteArray(StandardCharsets.UTF_8))

            val respRaw = transport.readControlFrame() ?: return@withContext emptyList()
            val respStr = String(respRaw, StandardCharsets.UTF_8)
            val json = JSONObject(respStr)

            val rootsList = mutableListOf<FilesystemRootItem>()
            if (json.optString("status") == "OK" && json.has("roots")) {
                val array = json.getJSONArray("roots")
                for (i in 0 until array.length()) {
                    val obj = array.getJSONObject(i)
                    rootsList.add(
                        FilesystemRootItem(
                            name = obj.optString("Name", obj.optString("name", "Root")),
                            path = obj.optString("Path", obj.optString("path", "")),
                            rootType = obj.optString("RootType", obj.optString("rootType", "FOLDER")),
                            isReadable = obj.optBoolean("IsReadable", obj.optBoolean("isReadable", true)),
                        )
                    )
                }
            }
            return@withContext rootsList
        } catch (e: Exception) {
            Log.e(TAG, "Failed requesting Windows roots: ${e.message}", e)
            return@withContext emptyList()
        }
    }

    /**
     * Sends LIST_DIR_REQUEST to Windows PC for a specific path
     */
    suspend fun requestWindowsDirectory(transport: TetherQuicTransport, path: String): List<DirectoryListingItem> = withContext(Dispatchers.IO) {
        try {
            val req = ListDirRequestFrame(path = path)
            transport.sendControlFrame(req.toJsonString().toByteArray(StandardCharsets.UTF_8))

            val respRaw = transport.readControlFrame() ?: return@withContext emptyList()
            val respStr = String(respRaw, StandardCharsets.UTF_8)
            val json = JSONObject(respStr)

            val itemsList = mutableListOf<DirectoryListingItem>()
            if (json.optString("status") == "OK" && json.has("items")) {
                val array = json.getJSONArray("items")
                for (i in 0 until array.length()) {
                    val obj = array.getJSONObject(i)
                    itemsList.add(
                        DirectoryListingItem(
                            name = obj.optString("Name", obj.optString("name", "")),
                            relativePath = obj.optString("RelativePath", obj.optString("relativePath", "")),
                            isDirectory = obj.optBoolean("IsDirectory", obj.optBoolean("isDirectory", false)),
                            fileSize = obj.optLong("FileSize", obj.optLong("fileSize", 0L)),
                            lastModifiedMs = obj.optLong("LastModifiedMs", obj.optLong("lastModifiedMs", 0L)),
                            isReadable = obj.optBoolean("IsReadable", obj.optBoolean("isReadable", true)),
                        )
                    )
                }
            }
            return@withContext itemsList
        } catch (e: Exception) {
            Log.e(TAG, "Failed listing Windows directory '$path': ${e.message}", e)
            return@withContext emptyList()
        }
    }
}
