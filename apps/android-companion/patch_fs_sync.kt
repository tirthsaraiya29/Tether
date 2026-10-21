    fun requestWindowsDbSync(securityEngine: ProductionSecurityEngine, host: String, port: Int = 37125) {
        coroutineScope.launch(Dispatchers.IO) {
            val transport = TetherQuicTransportImpl(appContext, securityEngine)
            try {
                transport.connect(host, port, timeoutMs = 5000)
                val myPublicKeyBytes = securityEngine.getPublicKeyBytes()
                val myFingerprint = securityEngine.computePublicKeyFingerprint(myPublicKeyBytes)
                val initReqJson = "{\"type\":\"${ControlMessageType.CONTROL_INIT}\",\"protocolVersion\":\"1.0\",\"deviceId\":\"$myFingerprint\"}"
                transport.sendControlFrame(initReqJson.toByteArray(StandardCharsets.UTF_8))
                transport.readControlFrame() // Wait for ACK
                
                val req = FsDbSyncRequestFrame()
                transport.sendControlFrame(req.toJsonString().toByteArray(StandardCharsets.UTF_8))
                
                // We don't read the DB here; the Windows PC will enqueue it and send it as a regular file transfer back to our TetherFileTransferServer
            } catch (e: Exception) {
                Log.e(TAG, "Failed requesting Windows DB Sync: ${e.message}")
            } finally {
                transport.disconnect("Sync request sent")
            }
        }
    }
