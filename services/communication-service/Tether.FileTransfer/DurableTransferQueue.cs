using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using Tether.FileTransfer.Protocol;
using Tether.Shared.Logging;

namespace Tether.FileTransfer;

public sealed record DurableTransferItem
{
    [JsonPropertyName("transferId")] public required string TransferId { get; init; }
    [JsonPropertyName("sourceDeviceId")] public string SourceDeviceId { get; init; } = "";
    [JsonPropertyName("destinationDeviceId")] public string DestinationDeviceId { get; init; } = "";
    [JsonPropertyName("fileName")] public required string FileName { get; init; }
    [JsonPropertyName("sourcePath")] public string SourcePath { get; init; } = "";
    [JsonPropertyName("relativePath")] public string RelativePath { get; init; } = "";
    [JsonPropertyName("fileSize")] public long FileSize { get; init; }
    [JsonPropertyName("bytesTransferred")] public long BytesTransferred { get; init; }
    [JsonPropertyName("state")] public FileTransferState State { get; init; } = FileTransferState.IDLE;
    [JsonPropertyName("isIncoming")] public bool IsIncoming { get; init; }
    [JsonPropertyName("createdUtc")] public DateTime CreatedUtc { get; init; } = DateTime.UtcNow;
    [JsonPropertyName("lastUpdatedUtc")] public DateTime LastUpdatedUtc { get; init; } = DateTime.UtcNow;
    [JsonPropertyName("sourceLastModified")] public long SourceLastModified { get; init; }
    [JsonPropertyName("expectedSha512")] public string ExpectedSha512 { get; init; } = "";
    [JsonPropertyName("errorCode")] public int ErrorCode { get; init; }
    [JsonPropertyName("errorMessage")] public string? ErrorMessage { get; init; }
    [JsonPropertyName("retryCount")] public int RetryCount { get; init; }
}

public sealed class DurableTransferQueue
{
    private readonly ITetherLogger _logger;
    private readonly string _queueFilePath;
    private readonly ConcurrentDictionary<string, DurableTransferItem> _items = new(StringComparer.OrdinalIgnoreCase);
    private readonly SemaphoreSlim _lock = new(1, 1);

    public DurableTransferQueue(ITetherLogger logger, string? customQueueDir = null)
    {
        _logger = logger;
        string baseDir = customQueueDir ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Tether");

        Directory.CreateDirectory(baseDir);
        _queueFilePath = Path.Combine(baseDir, "transfer_queue.json");
        LoadFromDisk();
    }

    public IReadOnlyCollection<DurableTransferItem> GetAllItems() =>
        _items.Values.OrderByDescending(i => i.LastUpdatedUtc).ToArray();

    public DurableTransferItem? GetItem(string transferId) =>
        _items.TryGetValue(transferId, out var item) ? item : null;

    public DurableTransferItem EnqueueOutgoing(string sourcePath, string targetDeviceId, string relativePath = "")
    {
        var existing = _items.Values.FirstOrDefault(i => !i.IsIncoming &&
            string.Equals(i.SourcePath, sourcePath, StringComparison.OrdinalIgnoreCase) &&
            (i.State == FileTransferState.REQUESTED || i.State == FileTransferState.TRANSFERRING || i.State == FileTransferState.CONNECTING));

        if (existing != null)
        {
            return existing;
        }

        var fileInfo = new FileInfo(sourcePath);
        if (!fileInfo.Exists && !Directory.Exists(sourcePath))
        {
            throw new FileNotFoundException($"Source item does not exist: {sourcePath}");
        }

        bool isDir = Directory.Exists(sourcePath);
        long size = isDir ? 0L : fileInfo.Length;

        var item = new DurableTransferItem
        {
            TransferId = Guid.NewGuid().ToString(),
            SourceDeviceId = "LOCAL_WIN",
            DestinationDeviceId = targetDeviceId,
            FileName = Path.GetFileName(sourcePath),
            SourcePath = sourcePath,
            RelativePath = relativePath,
            FileSize = size,
            BytesTransferred = 0L,
            State = FileTransferState.REQUESTED, // WAITING / QUEUED
            IsIncoming = false,
            CreatedUtc = DateTime.UtcNow,
            LastUpdatedUtc = DateTime.UtcNow,
            SourceLastModified = isDir ? DateTime.UtcNow.Ticks : fileInfo.LastWriteTimeUtc.Ticks,
            ExpectedSha512 = "",
            RetryCount = 0
        };

        _items[item.TransferId] = item;
        SaveToDisk();
        _logger.Info($"DurableQueue: Enqueued outgoing transfer {item.TransferId} ({item.FileName}) -> {targetDeviceId}");
        return item;
    }

    public DurableTransferItem EnqueueIncoming(TransferRequestFrame request, string sourceDeviceId)
    {
        var item = new DurableTransferItem
        {
            TransferId = request.TransferId,
            SourceDeviceId = sourceDeviceId,
            DestinationDeviceId = "LOCAL_WIN",
            FileName = request.FileName,
            SourcePath = "",
            RelativePath = "",
            FileSize = request.FileSize,
            BytesTransferred = 0L,
            State = FileTransferState.REQUESTED,
            IsIncoming = true,
            CreatedUtc = DateTime.UtcNow,
            LastUpdatedUtc = DateTime.UtcNow,
            SourceLastModified = request.SourceLastModified,
            ExpectedSha512 = request.ExpectedSha512,
            RetryCount = 0
        };

        _items[item.TransferId] = item;
        SaveToDisk();
        _logger.Info($"DurableQueue: Enqueued incoming transfer {item.TransferId} ({item.FileName}) from {sourceDeviceId}");
        return item;
    }

    public void UpdateState(
        string transferId,
        FileTransferState newState,
        long bytesTransferred = -1,
        string? errorMessage = null,
        int errorCode = 0)
    {
        if (_items.TryGetValue(transferId, out var existing))
        {
            int newRetryCount = newState == FileTransferState.FAILED
                ? existing.RetryCount + 1
                : (newState == FileTransferState.TRANSFERRING || newState == FileTransferState.COMPLETED ? 0 : existing.RetryCount);

            var updated = existing with
            {
                State = newState,
                BytesTransferred = bytesTransferred >= 0 ? bytesTransferred : existing.BytesTransferred,
                ErrorMessage = errorMessage ?? existing.ErrorMessage,
                ErrorCode = errorCode != 0 ? errorCode : existing.ErrorCode,
                RetryCount = newRetryCount,
                LastUpdatedUtc = DateTime.UtcNow
            };

            _items[transferId] = updated;
            SaveToDisk();
        }
    }

    public void RemoveItem(string transferId)
    {
        if (_items.TryRemove(transferId, out _))
        {
            SaveToDisk();
        }
    }

    public void ClearCompleted()
    {
        var toRemove = _items.Values
            .Where(i => i.State == FileTransferState.COMPLETED || i.State == FileTransferState.CANCELLED)
            .Select(i => i.TransferId)
            .ToList();

        foreach (var id in toRemove)
        {
            _items.TryRemove(id, out _);
        }

        if (toRemove.Count > 0)
        {
            SaveToDisk();
        }
    }

    private void LoadFromDisk()
    {
        try
        {
            if (File.Exists(_queueFilePath))
            {
                string json = File.ReadAllText(_queueFilePath);
                var loaded = JsonSerializer.Deserialize<List<DurableTransferItem>>(json);
                if (loaded != null)
                {
                    _items.Clear();
                    foreach (var item in loaded)
                    {
                        // Interrupted or transferring items on load transition to Interrupted/Requested for resume
                        var stateOnLoad = (item.State == FileTransferState.TRANSFERRING || item.State == FileTransferState.VERIFYING)
                            ? FileTransferState.REQUESTED
                            : item.State;

                        _items[item.TransferId] = item with { State = stateOnLoad };
                    }
                    _logger.Info($"DurableQueue: Loaded {_items.Count} items from disk.");
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Error($"DurableQueue: Failed to load queue from disk, backing up corrupt file: {ex.Message}");
            try
            {
                if (File.Exists(_queueFilePath))
                {
                    File.Move(_queueFilePath, _queueFilePath + ".bak", overwrite: true);
                }
            }
            catch { }
        }
    }

    private void SaveToDisk()
    {
        _lock.Wait();
        try
        {
            string tmpPath = _queueFilePath + ".tmp";
            string json = JsonSerializer.Serialize(_items.Values.ToList(), new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(tmpPath, json);
            File.Move(tmpPath, _queueFilePath, overwrite: true);
        }
        catch (Exception ex)
        {
            _logger.Error($"DurableQueue: Failed to persist queue to disk: {ex.Message}");
        }
        finally
        {
            _lock.Release();
        }
    }
}
