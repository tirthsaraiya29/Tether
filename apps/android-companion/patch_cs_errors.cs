                case ControlMessageType.QUEUE_SYNC_REQUEST:
                    if (!isAuthenticated)
                    {
                        _logger.Warning("QUEUE_SYNC_REQUEST received before CONTROL_INIT.");
                        return;
                    }
                    var qSyncReq = JsonSerializer.Deserialize<QueueSyncRequestFrame>(jsonStr);
                    var queueItems = _durableQueue.GetAllItems().ToList();
                    var syncSnapshot = new QueueSyncSnapshotFrame
                    {
                        RequestId = qSyncReq?.RequestId ?? "",
                        Items = queueItems
                    };
                    await SendControlFrameAsync(stream, JsonSerializer.Serialize(syncSnapshot), ct);
                    break;
