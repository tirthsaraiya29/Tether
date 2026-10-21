package com.tether.phone

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.util.UUID

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
}
