                    ControlMessageType.FS_DB_SYNC_REQUEST -> {
                        if (!isAuthenticated) break
                        val reqId = JsonParserUtils.getString(jsonStr, "requestId", "")
                        
                        coroutineScope.launch {
                            try {
                                val indexer = AndroidFilesystemIndexer(appContext)
                                val dbFile = indexer.buildDatabase()
                                val checksum = TetherFileTransferManager.computeFileSha512Hex(dbFile)
                                
                                val resp = FsDbSyncResponseFrame(
                                    requestId = reqId,
                                    status = "OK",
                                    dbSize = dbFile.length(),
                                    checksum = checksum
                                )
                                sendFrame(dos, resp.toJsonString().toByteArray(StandardCharsets.UTF_8))
                                
                                // Send the DB file
                                fileTransferManager.sendFile(
                                    securityEngine,
                                    socket.inetAddress.hostAddress ?: "",
                                    SERVER_PORT, // Assuming desktop listens on same port or we just use active
                                    android.net.Uri.fromFile(dbFile),
                                    "Windows PC"
                                )
                            } catch (e: Exception) {
                                val resp = FsDbSyncResponseFrame(requestId = reqId, status = "ERROR", dbSize = 0, checksum = "")
                                sendFrame(dos, resp.toJsonString().toByteArray(StandardCharsets.UTF_8))
                            }
                        }
                    }
