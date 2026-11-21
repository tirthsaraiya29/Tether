using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Win32.SafeHandles;
using Tether.CommunicationService.Devices;
using Tether.CommunicationService.FileTransfer;
using Tether.CommunicationService.Sessions;
using Tether.CommunicationService.Transport;
using Tether.Shared.Logging;
using Xunit;

namespace Tether.Tests;

public class TETH_SEC_005_FilesystemAndDeviceBindingTests : IDisposable
{
    private sealed class NoOpLogger : ITetherLogger
    {
        public void Debug(string message) { }
        public void Info(string message) { }
        public void Warning(string message) { }
        public void Error(string message, Exception? ex = null) { }
        public void Critical(string message, Exception? ex = null) { }
    }

    private readonly string _testBaseDir;

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    private const uint GENERIC_READ = 0x80000000;
    private const uint GENERIC_WRITE = 0x40000000;
    private const uint DELETE = 0x00010000;
    private const uint FILE_LIST_DIRECTORY = 0x0001;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint FILE_SHARE_WRITE = 0x00000002;
    private const uint FILE_SHARE_DELETE = 0x00000004;
    private const uint OPEN_EXISTING = 3;
    private const uint CREATE_ALWAYS = 2;
    private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;

    public TETH_SEC_005_FilesystemAndDeviceBindingTests()
    {
        _testBaseDir = Path.Combine(Path.GetTempPath(), "tether_fs_test_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_testBaseDir);
        FileTransferServer.ClearPendingRequestsForTest();
    }

    public void Dispose()
    {
        FileTransferServer.ClearPendingRequestsForTest();
        try
        {
            if (Directory.Exists(_testBaseDir))
            {
                Directory.Delete(_testBaseDir, true);
            }
        }
        catch { }
    }

    private static bool CreateDirectoryJunction(string junctionPath, string targetPath)
    {
        var psi = new ProcessStartInfo("cmd.exe", $"/c mklink /J \"{junctionPath}\" \"{targetPath}\"")
        {
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        using var process = Process.Start(psi);
        process?.WaitForExit(5000);
        return process?.ExitCode == 0;
    }

    private static string GenerateValidFingerprint(char fillChar = 'A')
    {
        var parts = new string[32];
        for (int i = 0; i < 32; i++)
        {
            parts[i] = $"{fillChar}{fillChar}";
        }
        return string.Join(":", parts);
    }

    #region Requirement R1: Filesystem Security Remediation

    [Fact]
    public void ValidateHandleSecurity_RejectsJunctionAndReparsePointWhenNotAllowed()
    {
        string targetDir = Path.Combine(_testBaseDir, "TargetDir");
        string linkDir = Path.Combine(_testBaseDir, "JunctionLink");
        Directory.CreateDirectory(targetDir);

        bool junctionCreated = CreateDirectoryJunction(linkDir, targetDir);
        Assert.True(junctionCreated, "Failed creating NTFS directory junction for test.");

        using var hJunction = CreateFile(
            linkDir,
            FILE_LIST_DIRECTORY | GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            IntPtr.Zero,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            IntPtr.Zero);

        Assert.False(hJunction.IsInvalid, "Handle to junction should be opened with OPEN_REPARSE_POINT.");

        // When allowReparsePoint is false (default across download, list, etc.): MUST REJECT
        bool rejected = FileTransferServer.ValidateHandleSecurity(
            hJunction,
            expectedRootDirectory: null,
            expectedVolumeSerial: null,
            out string resolvedPath,
            out uint volumeSerial,
            allowReparsePoint: false);

        Assert.False(rejected, "Junction reparse point must be rejected when allowReparsePoint=false.");

        // When allowReparsePoint is true: can validate handle
        bool accepted = FileTransferServer.ValidateHandleSecurity(
            hJunction,
            expectedRootDirectory: null,
            expectedVolumeSerial: null,
            out string resolvedPathAllowed,
            out uint volumeSerialAllowed,
            allowReparsePoint: true);

        Assert.True(accepted, "Junction reparse point should be accepted when allowReparsePoint=true.");
    }

    [Fact]
    public void DeleteDirectoryRecursiveSafe_DeletesJunctionWithoutDeletingTargetContents()
    {
        // Setup:
        // _testBaseDir/
        //   ├── ParentToDelete/
        //   │   ├── normal.txt
        //   │   └── JunctionToExternal (junction -> OutsideSensitiveDir)
        //   └── OutsideSensitiveDir/
        //       └── sensitive_secret.txt
        string parentToDelete = Path.Combine(_testBaseDir, "ParentToDelete");
        string outsideSensitiveDir = Path.Combine(_testBaseDir, "OutsideSensitiveDir");
        Directory.CreateDirectory(parentToDelete);
        Directory.CreateDirectory(outsideSensitiveDir);

        string sensitiveFile = Path.Combine(outsideSensitiveDir, "sensitive_secret.txt");
        File.WriteAllText(sensitiveFile, "CONFIDENTIAL_PAYLOAD");

        string normalFile = Path.Combine(parentToDelete, "normal.txt");
        File.WriteAllText(normalFile, "NORMAL_DATA");

        string junctionPath = Path.Combine(parentToDelete, "JunctionToExternal");
        bool junctionCreated = CreateDirectoryJunction(junctionPath, outsideSensitiveDir);
        Assert.True(junctionCreated, "Failed creating test directory junction.");

        // Open parent handle to get initial volume serial
        using var hParent = CreateFile(
            parentToDelete,
            FILE_LIST_DIRECTORY | GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            IntPtr.Zero,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            IntPtr.Zero);

        Assert.True(FileTransferServer.ValidateHandleSecurity(hParent, null, null, out string resolvedRoot, out uint volumeSerial, allowReparsePoint: false));
        hParent.Dispose();

        // Perform safe recursive delete
        bool deleteResult = FileTransferServer.DeleteDirectoryRecursiveSafe(resolvedRoot, resolvedRoot, volumeSerial);
        Assert.True(deleteResult, "Safe recursive directory delete should succeed.");

        // Verify: parent directory and junction are gone
        Assert.False(Directory.Exists(parentToDelete), "Parent directory must be deleted.");
        Assert.False(Directory.Exists(junctionPath), "Junction link inside parent directory must be unlinked.");

        // Critical Security Invariant: The outside sensitive target directory and its contents MUST REMAIN INTACT!
        Assert.True(Directory.Exists(outsideSensitiveDir), "Target of junction must NOT be deleted!");
        Assert.True(File.Exists(sensitiveFile), "Files inside junction target must NOT be deleted!");
        Assert.Equal("CONFIDENTIAL_PAYLOAD", File.ReadAllText(sensitiveFile));
    }

    [Fact]
    public void ValidateHandleSecurity_RejectsRootBoundaryEscape()
    {
        string allowedRoot = Path.Combine(_testBaseDir, "AllowedRoot");
        string outsideDir = Path.Combine(_testBaseDir, "OutsideRoot");
        Directory.CreateDirectory(allowedRoot);
        Directory.CreateDirectory(outsideDir);

        string outsideFile = Path.Combine(outsideDir, "escape.txt");
        File.WriteAllText(outsideFile, "ESCAPED");

        using var hFile = CreateFile(
            outsideFile,
            GENERIC_READ,
            FILE_SHARE_READ,
            IntPtr.Zero,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            IntPtr.Zero);

        Assert.False(hFile.IsInvalid);

        // Attempting to validate handle with allowedRoot should fail closed
        bool valid = FileTransferServer.ValidateHandleSecurity(
            hFile,
            expectedRootDirectory: allowedRoot,
            expectedVolumeSerial: null,
            out _,
            out _,
            allowReparsePoint: false);

        Assert.False(valid, "Handle pointing outside expectedRootDirectory must be rejected.");
    }

    [Fact]
    public void ValidateHandleSecurity_RejectsVolumeSerialMismatch()
    {
        string testFile = Path.Combine(_testBaseDir, "vol_test.txt");
        File.WriteAllText(testFile, "DATA");

        using var hFile = CreateFile(
            testFile,
            GENERIC_READ,
            FILE_SHARE_READ,
            IntPtr.Zero,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            IntPtr.Zero);

        Assert.False(hFile.IsInvalid);

        // Expected volume serial != actual volume serial
        bool valid = FileTransferServer.ValidateHandleSecurity(
            hFile,
            expectedRootDirectory: null,
            expectedVolumeSerial: 0x12345678, // mismatch
            out _,
            out _,
            allowReparsePoint: false);

        Assert.False(valid, "Volume serial mismatch must be rejected fail-closed.");
    }

    [Fact]
    public void PromoteFileHandle_ExecutesAtomicHandleRename()
    {
        string sourceFile = Path.Combine(_testBaseDir, "source.txt");
        string destFile = Path.Combine(_testBaseDir, "dest.txt");
        File.WriteAllText(sourceFile, "ATOMIC_CONTENT");

        using var hFile = CreateFile(
            sourceFile,
            GENERIC_READ | GENERIC_WRITE | DELETE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            IntPtr.Zero,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            IntPtr.Zero);

        Assert.False(hFile.IsInvalid);

        bool promoted = FileTransferServer.PromoteFileHandle(hFile, destFile, replaceIfExists: true);
        Assert.True(promoted, "Atomic handle promotion via FILE_RENAME_INFO must succeed.");

        hFile.Dispose();

        Assert.False(File.Exists(sourceFile), "Original file path should no longer exist after handle promotion.");
        Assert.True(File.Exists(destFile), "Destination file path must exist with promoted contents.");
        Assert.Equal("ATOMIC_CONTENT", File.ReadAllText(destFile));
    }

    #endregion

    #region Requirement R2: Remote Filesystem Device Identity Binding

    [Fact]
    public void HandleRemoteResponse_RejectsMismatchedCallerFingerprint()
    {
        string validFp1 = GenerateValidFingerprint('A');
        string validFp2 = GenerateValidFingerprint('B');

        var tcs = new TaskCompletionSource<string>();
        var pending = new FileTransferServer.PendingRemoteRequest
        {
            RequestId = "req-fp-mismatch",
            Tcs = tcs,
            ExpectedSessionId = "session-100",
            ExpectedFingerprint = validFp1,
            ExpectedOperation = "FS_LIST",
            CreatedAtUtc = DateTime.UtcNow
        };

        FileTransferServer.RegisterPendingRequest("req-fp-mismatch", pending);

        var responseJson = JsonSerializer.Serialize(new
        {
            requestId = "req-fp-mismatch",
            status = "OK",
            entries = Array.Empty<string>()
        });

        // Calling with validFp2 (mismatched fingerprint)
        bool matched = FileTransferServer.HandleRemoteResponse("FS_LIST_RESULT", responseJson, callerFingerprint: validFp2, callerSessionId: "session-100");

        Assert.False(matched, "Response with mismatched caller fingerprint must be rejected.");
        Assert.True(FileTransferServer.HasPendingRequest("req-fp-mismatch"), "Pending request must not be removed on rejected response.");
        Assert.False(tcs.Task.IsCompleted, "TaskCompletionSource must not be completed on fingerprint mismatch.");
    }

    [Fact]
    public void HandleRemoteResponse_RejectsMissingOrMalformedCallerFingerprint()
    {
        var tcs = new TaskCompletionSource<string>();
        string validFp = GenerateValidFingerprint('C');
        var pending = new FileTransferServer.PendingRemoteRequest
        {
            RequestId = "req-fp-missing",
            Tcs = tcs,
            ExpectedSessionId = "session-101",
            ExpectedFingerprint = validFp,
            ExpectedOperation = "FS_LIST",
            CreatedAtUtc = DateTime.UtcNow
        };
        FileTransferServer.RegisterPendingRequest("req-fp-missing", pending);

        var responseJson = JsonSerializer.Serialize(new { requestId = "req-fp-missing", status = "OK" });

        // Null fingerprint
        Assert.False(FileTransferServer.HandleRemoteResponse("FS_LIST_RESULT", responseJson, callerFingerprint: null, callerSessionId: "session-101"));

        // Empty/whitespace fingerprint
        Assert.False(FileTransferServer.HandleRemoteResponse("FS_LIST_RESULT", responseJson, callerFingerprint: "", callerSessionId: "session-101"));
        Assert.False(FileTransferServer.HandleRemoteResponse("FS_LIST_RESULT", responseJson, callerFingerprint: "   ", callerSessionId: "session-101"));

        // Malformed fingerprint (not 95 chars / 32 colons)
        Assert.False(FileTransferServer.HandleRemoteResponse("FS_LIST_RESULT", responseJson, callerFingerprint: "malformed:fingerprint", callerSessionId: "session-101"));
    }

    [Fact]
    public void HandleRemoteResponse_RejectsCrossSessionResponse()
    {
        string validFp = GenerateValidFingerprint('D');
        var tcs = new TaskCompletionSource<string>();
        var pending = new FileTransferServer.PendingRemoteRequest
        {
            RequestId = "req-cross-session",
            Tcs = tcs,
            ExpectedSessionId = "origin-session-123",
            ExpectedFingerprint = validFp,
            ExpectedOperation = "FS_LIST",
            CreatedAtUtc = DateTime.UtcNow
        };
        FileTransferServer.RegisterPendingRequest("req-cross-session", pending);

        var responseJson = JsonSerializer.Serialize(new { requestId = "req-cross-session", status = "OK" });

        // Secondary session tries to respond for primary session's request ID
        bool matched = FileTransferServer.HandleRemoteResponse("FS_LIST_RESULT", responseJson, callerFingerprint: validFp, callerSessionId: "different-session-456");

        Assert.False(matched, "Cross-session response must be rejected.");
        Assert.True(FileTransferServer.HasPendingRequest("req-cross-session"));
        Assert.False(tcs.Task.IsCompleted);
    }

    [Fact]
    public void HandleRemoteResponse_RejectsOperationTypeMismatch()
    {
        string validFp = GenerateValidFingerprint('E');
        var tcs = new TaskCompletionSource<string>();
        var pending = new FileTransferServer.PendingRemoteRequest
        {
            RequestId = "req-op-mismatch",
            Tcs = tcs,
            ExpectedSessionId = "session-102",
            ExpectedFingerprint = validFp,
            ExpectedOperation = "FS_LIST",
            CreatedAtUtc = DateTime.UtcNow
        };
        FileTransferServer.RegisterPendingRequest("req-op-mismatch", pending);

        var responseJson = JsonSerializer.Serialize(new { requestId = "req-op-mismatch", status = "OK" });

        // Incompatible operation type
        bool matched = FileTransferServer.HandleRemoteResponse("FS_TRANSFER_STATUS", responseJson, callerFingerprint: validFp, callerSessionId: "session-102");

        Assert.False(matched, "Operation type mismatch must be rejected.");
        Assert.True(FileTransferServer.HasPendingRequest("req-op-mismatch"));
        Assert.False(tcs.Task.IsCompleted);
    }

    [Fact]
    public void HandleRemoteResponse_AcceptsMatchingResponse_AndRejectsDuplicateReplay()
    {
        string validFp = GenerateValidFingerprint('F');
        var tcs = new TaskCompletionSource<string>();
        var pending = new FileTransferServer.PendingRemoteRequest
        {
            RequestId = "req-replay-test",
            Tcs = tcs,
            ExpectedSessionId = "session-103",
            ExpectedFingerprint = validFp,
            ExpectedOperation = "FS_LIST",
            CreatedAtUtc = DateTime.UtcNow
        };
        FileTransferServer.RegisterPendingRequest("req-replay-test", pending);

        var responseJson = JsonSerializer.Serialize(new { requestId = "req-replay-test", status = "SUCCESS" });

        // First matching response: MUST SUCCEED
        bool firstResult = FileTransferServer.HandleRemoteResponse("FS_LIST_RESULT", responseJson, callerFingerprint: validFp, callerSessionId: "session-103");
        Assert.True(firstResult, "Matching response must be accepted.");
        Assert.True(tcs.Task.IsCompletedSuccessfully, "TaskCompletionSource must complete.");
        Assert.False(FileTransferServer.HasPendingRequest("req-replay-test"), "Pending request must be removed atomically.");

        // Duplicate replay of same requestId: MUST BE REJECTED
        bool replayResult = FileTransferServer.HandleRemoteResponse("FS_LIST_RESULT", responseJson, callerFingerprint: validFp, callerSessionId: "session-103");
        Assert.False(replayResult, "Replayed duplicate response must be rejected.");
    }

    [Fact]
    public void CancelPendingRequestsForSession_EvictsAndFaultsRequestsOnDisconnect()
    {
        string targetSession = "session-to-disconnect-999";
        string validFp = GenerateValidFingerprint('G');

        var tcs1 = new TaskCompletionSource<string>();
        var tcs2 = new TaskCompletionSource<string>();

        FileTransferServer.RegisterPendingRequest("req-dc-1", new FileTransferServer.PendingRemoteRequest
        {
            RequestId = "req-dc-1",
            Tcs = tcs1,
            ExpectedSessionId = targetSession,
            ExpectedFingerprint = validFp,
            ExpectedOperation = "FS_LIST",
            CreatedAtUtc = DateTime.UtcNow
        });

        FileTransferServer.RegisterPendingRequest("req-dc-2", new FileTransferServer.PendingRemoteRequest
        {
            RequestId = "req-dc-2",
            Tcs = tcs2,
            ExpectedSessionId = "other-session",
            ExpectedFingerprint = validFp,
            ExpectedOperation = "FS_LIST",
            CreatedAtUtc = DateTime.UtcNow
        });

        // Disconnect targetSession
        FileTransferServer.CancelPendingRequestsForSession(targetSession);

        // req-dc-1 must be evicted and faulted
        Assert.False(FileTransferServer.HasPendingRequest("req-dc-1"));
        Assert.True(tcs1.Task.IsFaulted);
        Assert.IsType<IOException>(tcs1.Task.Exception?.InnerException);
        Assert.Equal("Device session disconnected", tcs1.Task.Exception?.InnerException?.Message);

        // req-dc-2 (bound to other-session) must remain untouched
        Assert.True(FileTransferServer.HasPendingRequest("req-dc-2"));
        Assert.False(tcs2.Task.IsCompleted);

        // Disconnected session cannot reconnect and answer old request
        var responseJson = JsonSerializer.Serialize(new { requestId = "req-dc-1", status = "OK" });
        bool answered = FileTransferServer.HandleRemoteResponse("FS_LIST_RESULT", responseJson, callerFingerprint: validFp, callerSessionId: targetSession);
        Assert.False(answered, "Evicted request cannot be answered upon reconnection.");
    }

    [Fact]
    public void TryResolveTargetSession_RejectsMissingOrMalformedFingerprint_WithBadRequest()
    {
        var server = (FileTransferServer)System.Runtime.CompilerServices.RuntimeHelpers.GetUninitializedObject(typeof(FileTransferServer));
        var sessionManager = (SessionManager)System.Runtime.CompilerServices.RuntimeHelpers.GetUninitializedObject(typeof(SessionManager));
        typeof(SessionManager).GetField("_activeSessions", BindingFlags.NonPublic | BindingFlags.Instance)!.SetValue(sessionManager, new System.Collections.Concurrent.ConcurrentDictionary<string, TetherSession>());
        typeof(FileTransferServer).GetField("_sessionManager", BindingFlags.NonPublic | BindingFlags.Instance)!.SetValue(server, sessionManager);

        var method = typeof(FileTransferServer).GetMethod("TryResolveTargetSession", BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(method);

        // Test 1: Empty fingerprint in JSON
        var emptyDoc = JsonDocument.Parse("{\"fingerprint\":\"\"}");
        object[] args1 = new object[] { emptyDoc.RootElement, null!, "" };
        var result1 = (IResult?)method.Invoke(server, args1);
        Assert.NotNull(result1);
        Assert.StartsWith("BadRequest", result1.GetType().Name);

        // Test 2: Whitespace fingerprint
        var wsDoc = JsonDocument.Parse("{\"fingerprint\":\"   \"}");
        object[] args2 = new object[] { wsDoc.RootElement, null!, "" };
        var result2 = (IResult?)method.Invoke(server, args2);
        Assert.NotNull(result2);
        Assert.StartsWith("BadRequest", result2.GetType().Name);

        // Test 3: Malformed fingerprint
        var malDoc = JsonDocument.Parse("{\"fingerprint\":\"bad:fp\"}");
        object[] args3 = new object[] { malDoc.RootElement, null!, "" };
        var result3 = (IResult?)method.Invoke(server, args3);
        Assert.NotNull(result3);
        Assert.StartsWith("BadRequest", result3.GetType().Name);

        // Test 4: Empty deviceId
        var emptyDeviceDoc = JsonDocument.Parse("{\"deviceId\":\"\"}");
        object[] args4 = new object[] { emptyDeviceDoc.RootElement, null!, "" };
        var result4 = (IResult?)method.Invoke(server, args4);
        Assert.NotNull(result4);
        Assert.StartsWith("BadRequest", result4.GetType().Name);

        // Test 5: Omitted target when zero devices connected
        var noTargetDoc = JsonDocument.Parse("{}");
        object[] args5 = new object[] { noTargetDoc.RootElement, null!, "" };
        var result5 = (IResult?)method.Invoke(server, args5);
        Assert.NotNull(result5);
        Assert.StartsWith("NotFound", result5.GetType().Name);
    }

    #endregion
}
