package com.tether.phone

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Ignore
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.util.UUID

@Ignore("File transfer feature cleanly discarded across repo")
class TetherFileTransferTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    @Test
    fun testFilenamePathTraversalSanitization() {
        assertEquals("passwd", TetherFileTransferManager.sanitizeFilename("../../../../../etc/passwd"))
        assertEquals("cmd.exe", TetherFileTransferManager.sanitizeFilename("C:\\Windows\\System32\\cmd.exe"))
        assertEquals("normal_file.pdf", TetherFileTransferManager.sanitizeFilename("normal_file.pdf"))
        assertEquals("tether_received_file", TetherFileTransferManager.sanitizeFilename(""))
        assertEquals("tether_received_file", TetherFileTransferManager.sanitizeFilename(".."))
    }

    @Test
    fun testFilesCapabilityEnforcement() {
        val capManager = TetherCapabilityManager()

        capManager.negotiateCapabilities("CLIPBOARD,NOTIFICATIONS,MEDIA")
        assertFalse(capManager.isCapabilityGranted(TetherCapability.FILES))
        assertFalse(capManager.canExecuteCommand("file_transfer"))

        capManager.negotiateCapabilities("CLIPBOARD,FILES,NOTIFICATIONS,MEDIA")
        assertTrue(capManager.isCapabilityGranted(TetherCapability.FILES))
        assertTrue(capManager.canExecuteCommand("file_transfer"))
    }

    @Test
    fun testSha512IntegrityVerificationPassAndFail() {
        val testFile = tempFolder.newFile("test_data.bin")
        val sampleData = "Tether QUIC High-Performance File Sharing Test Payload".toByteArray(Charsets.UTF_8)
        testFile.writeBytes(sampleData)

        val initialSha512 = TetherFileTransferManager.computeFileSha512Hex(testFile)
        assertNotNull(initialSha512)
        assertEquals(128, initialSha512.length) // SHA-512 Hex string is 128 characters

        // Verify re-computation returns identical hash
        val secondSha512 = TetherFileTransferManager.computeFileSha512Hex(testFile)
        assertEquals(initialSha512, secondSha512)

        // Corrupt single byte in file
        sampleData[0] = (sampleData[0] + 1).toByte()
        testFile.writeBytes(sampleData)

        val corruptedSha512 = TetherFileTransferManager.computeFileSha512Hex(testFile)
        assertNotEquals(initialSha512, corruptedSha512)
    }

    @Test
    fun testDataChunkFramingSerializationAndParsing() {
        val transferId = UUID.randomUUID()
        val chunkIndex = 42L
        val offset = 2752512L
        val payload = "Hello QUIC Data Chunk Payload!".toByteArray(Charsets.UTF_8)

        val serializedChunk = DataChunkFraming.serializeChunk(
            transferIdUuid = transferId,
            chunkIndex = chunkIndex,
            offset = offset,
            payload = payload,
        )

        assertTrue(serializedChunk.size > DataChunkFraming.HEADER_SIZE_BYTES)

        val headerBytes = serializedChunk.copyOfRange(4, DataChunkFraming.HEADER_SIZE_BYTES + 4)
        val parsed = DataChunkFraming.parseHeader(headerBytes)

        assertEquals(DataChunkMessageType.MSG_DATA_CHUNK, parsed.msgType)
        assertEquals(transferId, parsed.transferId)
        assertEquals(chunkIndex, parsed.chunkIndex)
        assertEquals(offset, parsed.offset)
        assertEquals(payload.size, parsed.payloadLength)
    }

    @Test
    fun testTransferRequestAndResponseJsonRoundtrip() {
        val req = TransferRequestFrame(
            version = "1.0",
            transferId = UUID.randomUUID().toString(),
            fileName = "document.pdf",
            fileSize = 10485760L,
            mimeType = "application/pdf",
            expectedSha512 = "3C0123456789ABCDEF",
            chunkSize = 65536,
            totalChunks = 160L,
        )

        val jsonStr = req.toJsonString()
        val parsedReq = TransferRequestFrame.parseJsonString(jsonStr)

        assertEquals(req.transferId, parsedReq.transferId)
        assertEquals(req.fileName, parsedReq.fileName)
        assertEquals(req.fileSize, parsedReq.fileSize)
        assertEquals(req.expectedSha512, parsedReq.expectedSha512)

        val resp = TransferResponseFrame(
            transferId = req.transferId,
            status = "ACCEPTED",
            resumeOffset = 0L,
        )

        val respJsonStr = resp.toJsonString()
        val parsedResp = TransferResponseFrame.parseJsonString(respJsonStr)

        assertEquals(resp.transferId, parsedResp.transferId)
        assertEquals("ACCEPTED", parsedResp.status)
        assertEquals(0L, parsedResp.resumeOffset)
    }

    @Test
    fun testBrowseRootsAndListDirRequestJsonFraming() {
        val req = BrowseRootsRequestFrame()
        val jsonStr = req.toJsonString()

        assertEquals("BROWSE_ROOTS_REQUEST", JsonParserUtils.getString(jsonStr, "type", ""))
        assertNotNull(JsonParserUtils.getString(jsonStr, "requestId", ""))

        val listReq = ListDirRequestFrame(path = "C:\\Users\\Downloads")
        val listJsonStr = listReq.toJsonString()

        assertEquals("LIST_DIR_REQUEST", JsonParserUtils.getString(listJsonStr, "type", ""))
        assertEquals("C:\\Users\\Downloads", JsonParserUtils.getString(listJsonStr, "path", ""))
    }

    private class FakeTestTransport(
        private val chunkDataSupplier: () -> ByteArray?,
    ) : TetherQuicTransport {
        override val generationId: Long = 1L
        override fun connect(host: String, port: Int, timeoutMs: Int) {}
        override fun disconnect(reason: String) {}
        override fun isConnected(): Boolean = true

        val sentControlFrames = mutableListOf<String>()

        override fun sendControlFrame(data: ByteArray) {
            sentControlFrames.add(String(data, Charsets.UTF_8))
        }

        override fun readControlFrame(maxSizeBytes: Int): ByteArray? = null
        override fun sendDataChunk(chunkData: ByteArray) {}

        override fun readDataChunk(maxSizeBytes: Int): ByteArray? {
            return chunkDataSupplier()
        }

        override fun getPeerCertificate(): java.security.cert.X509Certificate? = null
        override fun getPeerIdentityFingerprint(): String = "TEST_FINGERPRINT"
    }

    private open class TestContext : android.content.ContextWrapper(null) {
        override fun getDatabasePath(name: String): File {
            return File(System.getProperty("java.io.tmpdir") ?: ".", name)
        }
        override fun getContentResolver(): android.content.ContentResolver? = null
        override fun getSystemService(name: String): Any? = null
        override fun getApplicationContext(): android.content.Context = this
    }

    @Test
    fun testIncomingTransferSha512MismatchSendsFailureFrame() = kotlinx.coroutines.runBlocking {
        val capManager = TetherCapabilityManager()
        capManager.negotiateCapabilities("FILES")

        val stagingDir = tempFolder.newFolder("tether_staging")
        val manager = TetherFileTransferManager(
            appContext = TestContext(),
            capabilityManager = capManager,
            coroutineScope = kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.Unconfined),
            customStagingDir = stagingDir,
        )

        val transferId = UUID.randomUUID().toString()
        val payload = "Corrupted Data Stream".toByteArray(Charsets.UTF_8)

        val rawChunk = DataChunkFraming.serializeChunk(
            transferIdUuid = UUID.fromString(transferId),
            chunkIndex = 0L,
            offset = 0L,
            payload = payload,
        )
        val chunkFrame = rawChunk.copyOfRange(4, rawChunk.size)

        val rawEnd = DataChunkFraming.serializeEndSignal(UUID.fromString(transferId))
        val endFrame = rawEnd.copyOfRange(4, rawEnd.size)

        var chunkIndex = 0
        val fakeTransport = FakeTestTransport {
            when (chunkIndex++) {
                0 -> chunkFrame
                1 -> endFrame
                else -> null
            }
        }

        val req = TransferRequestFrame(
            version = "1.0",
            transferId = transferId,
            fileName = "corrupted.txt",
            fileSize = payload.size.toLong(),
            mimeType = "text/plain",
            expectedSha512 = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            chunkSize = 65536,
            totalChunks = 1L,
        )

        val success = manager.handleIncomingTransfer(fakeTransport, req, "TestPeer")

        assertFalse(success)
        val completeFrame = fakeTransport.sentControlFrames.find { it.contains("TRANSFER_COMPLETE") }
        assertNotNull(completeFrame)
        assertTrue(completeFrame!!.contains("\"status\":\"FAILED\""))
        assertTrue(completeFrame.contains("\"errorCode\":${FileTransferErrorCode.INTEGRITY_FAILED.code}"))
    }

    @Test
    fun testIncomingTransferImmediateSocketErrorSendsFailureFrame() = kotlinx.coroutines.runBlocking {
        val capManager = TetherCapabilityManager()
        capManager.negotiateCapabilities("FILES")

        val stagingDir = tempFolder.newFolder("tether_staging_error")
        val manager = TetherFileTransferManager(
            appContext = TestContext(),
            capabilityManager = capManager,
            coroutineScope = kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.Unconfined),
            customStagingDir = stagingDir,
        )

        val transferId = UUID.randomUUID().toString()
        val fakeTransport = FakeTestTransport { null }

        val req = TransferRequestFrame(
            version = "1.0",
            transferId = transferId,
            fileName = "empty.txt",
            fileSize = 1000L,
            mimeType = "text/plain",
            expectedSha512 = "ABCDEF",
            chunkSize = 65536,
            totalChunks = 1L,
        )

        val success = manager.handleIncomingTransfer(fakeTransport, req, "TestPeer")

        assertFalse(success)
        val completeFrame = fakeTransport.sentControlFrames.find { it.contains("TRANSFER_COMPLETE") }
        assertNotNull(completeFrame)
        assertTrue(completeFrame!!.contains("\"status\":\"FAILED\""))
    }
}
