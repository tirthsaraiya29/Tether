                    case ControlMessageType.FS_DB_SYNC_REQUEST:
                        if (!isAuthenticated) return;
                        var syncReq = JsonSerializer.Deserialize<FsDbSyncRequestFrame>(jsonStr);
                        if (syncReq != null)
                        {
                            _ = Task.Run(async () =>
                            {
                                try
                                {
                                    var indexer = new WindowsFilesystemIndexer(_logger);
                                    string dbPath = await indexer.BuildDatabaseAsync();

                                    var resp = new FsDbSyncResponseFrame
                                    {
                                        RequestId = syncReq.RequestId,
                                        Status = "OK",
                                        DbSize = new FileInfo(dbPath).Length,
                                        Checksum = "unknown_for_now"
                                    };
                                    await SendControlFrameAsync(stream, JsonSerializer.Serialize(resp), ct);

                                    _durableQueue.EnqueueOutgoingItem(dbPath, "windows_fs.db", authenticatedPeerName, "Tether Companion");
                                }
                                catch (Exception ex)
                                {
                                    var resp = new FsDbSyncResponseFrame
                                    {
                                        RequestId = syncReq.RequestId,
                                        Status = "ERROR"
                                    };
                                    await SendControlFrameAsync(stream, JsonSerializer.Serialize(resp), ct);
                                }
                            });
                        }
                        break;
