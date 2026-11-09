using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace Tether.SessionHelper;

internal sealed class TerminalSessionManager
{
    private sealed class TerminalSession : IDisposable
    {
        public string Id { get; }
        public string ShellType { get; }
        public string CurrentDirectory { get; set; }
        public Process Process { get; }
        public StreamWriter Stdin { get; }
        public List<string> HistoryBuffer { get; } = new(500);
        public object Lock { get; } = new();
        public string OwnerDeviceId { get; }

        public TerminalSession(string id, string shellType, string currentDirectory, Process process, StreamWriter stdin, string ownerDeviceId)
        {
            Id = id;
            ShellType = shellType;
            CurrentDirectory = currentDirectory;
            Process = process;
            Stdin = stdin;
            OwnerDeviceId = ownerDeviceId;
        }

        public void AppendHistory(string text)
        {
            lock (Lock)
            {
                if (HistoryBuffer.Count > 1000)
                {
                    HistoryBuffer.RemoveRange(0, 500);
                }
                HistoryBuffer.Add(text);
            }
        }

        public void Dispose()
        {
            try { Stdin.Dispose(); } catch { }
            try
            {
                if (!Process.HasExited)
                {
                    Process.Kill(true);
                }
                Process.Dispose();
            }
            catch { }
        }
    }

    private static readonly string[] RestrictedAdminPatterns = new[]
    {
        "runas", "sudo", "gsudo", "-verb runas", "start-process -verb",
        "diskpart", "bcdedit", "format-volume", "vssadmin",
        "net localgroup administrators", "net user ", "set-executionpolicy unrestricted",
        "takeown", "icacls /grant"
    };

    private const int MaxActiveSessions = 8;
    private readonly object _sessionLock = new();
    private readonly ConcurrentDictionary<string, TerminalSession> _sessions = new();
    private readonly Action<string, string, string, string> _onOutputReceived;

    public TerminalSessionManager(Action<string, string, string> legacyCallback)
        : this((id, text, dir, _) => legacyCallback(id, text, dir))
    {
    }

    public TerminalSessionManager(Action<string, string, string, string> onOutputReceived)
    {
        _onOutputReceived = onOutputReceived;
    }

    #region Win32 Process Creation with Limited User Token

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(IntPtr TokenHandle, int TokenInformationClass, IntPtr TokenInformation, uint TokenInformationLength, out uint ReturnLength);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes, int ImpersonationLevel, int TokenType, out IntPtr phNewToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CreateRestrictedToken(
        IntPtr ExistingTokenHandle,
        uint Flags,
        uint DisableSidCount,
        IntPtr SidsToDisable,
        uint DeletePrivilegeCount,
        IntPtr PrivilegesToDelete,
        uint RestrictedSidCount,
        IntPtr SidsToRestrict,
        out IntPtr NewTokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern IntPtr GetSidSubAuthority(IntPtr pSid, uint nSubAuthority);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern IntPtr GetSidSubAuthorityCount(IntPtr pSid);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe, ref SECURITY_ATTRIBUTES lpPipeAttributes, uint nSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetHandleInformation(IntPtr hObject, uint dwMask, uint dwFlags);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessWithTokenW(
        IntPtr hToken,
        uint dwLogonFlags,
        string? lpApplicationName,
        string lpCommandLine,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string? lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [StructLayout(LayoutKind.Sequential)]
    private struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public bool bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public int cb;
        public string? lpReserved;
        public string? lpDesktop;
        public string? lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    private const int STARTF_USESTDHANDLES = 0x00000100;
    private const uint CREATE_NO_WINDOW = 0x08000000;
    private const uint HANDLE_FLAG_INHERIT = 0x00000001;
    private const uint TOKEN_QUERY = 0x0008;
    private const uint TOKEN_DUPLICATE = 0x0002;
    private const uint MAXIMUM_ALLOWED = 0x02000000;
    private const int TokenElevationType = 18;
    private const int TokenLinkedToken = 19;
    private const int TokenElevation = 20;
    private const int TokenIntegrityLevel = 25;
    private const int SECURITY_MANDATORY_MEDIUM_RID = 0x00002000;
    private const uint LUA_TOKEN = 0x00000004;

    private static bool IsTokenSafeAndLimited(IntPtr hToken)
    {
        if (hToken == IntPtr.Zero) return false;

        IntPtr pInfo = IntPtr.Zero;
        try
        {
            // 1. Verify elevation is strictly FALSE
            pInfo = Marshal.AllocHGlobal(sizeof(int));
            if (GetTokenInformation(hToken, TokenElevation, pInfo, sizeof(int), out _))
            {
                int isElevated = Marshal.ReadInt32(pInfo);
                if (isElevated != 0) return false;
            }
            else
            {
                return false;
            }
            Marshal.FreeHGlobal(pInfo);
            pInfo = IntPtr.Zero;

            // 2. Verify integrity level is <= Medium (RID <= 0x2000)
            GetTokenInformation(hToken, TokenIntegrityLevel, IntPtr.Zero, 0, out uint lenNeeded);
            if (lenNeeded == 0) return false;

            pInfo = Marshal.AllocHGlobal((int)lenNeeded);
            if (!GetTokenInformation(hToken, TokenIntegrityLevel, pInfo, lenNeeded, out _))
            {
                return false;
            }

            IntPtr pSid = Marshal.ReadIntPtr(pInfo); // Label.Sid
            if (pSid == IntPtr.Zero) return false;

            IntPtr pSubAuthCount = GetSidSubAuthorityCount(pSid);
            if (pSubAuthCount == IntPtr.Zero) return false;
            byte subAuthCount = Marshal.ReadByte(pSubAuthCount);
            if (subAuthCount == 0) return false;

            IntPtr pSubAuth = GetSidSubAuthority(pSid, (uint)(subAuthCount - 1));
            if (pSubAuth == IntPtr.Zero) return false;
            int integrityRid = Marshal.ReadInt32(pSubAuth);

            if (integrityRid > SECURITY_MANDATORY_MEDIUM_RID)
            {
                return false; // Rejects High, System, or untrusted higher-integrity tokens
            }

            return true;
        }
        catch
        {
            return false;
        }
        finally
        {
            if (pInfo != IntPtr.Zero) Marshal.FreeHGlobal(pInfo);
        }
    }

    private static bool TryGetLimitedUserToken(out IntPtr limitedToken)
    {
        limitedToken = IntPtr.Zero;
        IntPtr hProcessToken = IntPtr.Zero;
        IntPtr pInfo = IntPtr.Zero;

        try
        {
            if (!OpenProcessToken(Process.GetCurrentProcess().Handle, TOKEN_QUERY | TOKEN_DUPLICATE | 0x0008, out hProcessToken))
            {
                return false;
            }

            // Query TokenElevationType
            pInfo = Marshal.AllocHGlobal(sizeof(int));
            int elevType = 0;
            if (GetTokenInformation(hProcessToken, TokenElevationType, pInfo, sizeof(int), out _))
            {
                elevType = Marshal.ReadInt32(pInfo);
            }
            Marshal.FreeHGlobal(pInfo);
            pInfo = IntPtr.Zero;

            // Elevated process (elevType == 2): retrieve medium linked token
            if (elevType == 2)
            {
                pInfo = Marshal.AllocHGlobal(IntPtr.Size);
                if (GetTokenInformation(hProcessToken, TokenLinkedToken, pInfo, (uint)IntPtr.Size, out _))
                {
                    IntPtr rawLinked = Marshal.ReadIntPtr(pInfo);
                    if (rawLinked != IntPtr.Zero)
                    {
                        try
                        {
                            if (DuplicateTokenEx(rawLinked, MAXIMUM_ALLOWED, IntPtr.Zero, 2, 1, out IntPtr candidate))
                            {
                                if (IsTokenSafeAndLimited(candidate))
                                {
                                    limitedToken = candidate;
                                    return true;
                                }
                                CloseHandle(candidate);
                            }
                        }
                        finally
                        {
                            CloseHandle(rawLinked);
                        }
                    }
                }
                Marshal.FreeHGlobal(pInfo);
                pInfo = IntPtr.Zero;

                // Fallback for elevated: create restricted LUA token
                if (CreateRestrictedToken(hProcessToken, LUA_TOKEN, 0, IntPtr.Zero, 0, IntPtr.Zero, 0, IntPtr.Zero, out IntPtr hRestricted))
                {
                    try
                    {
                        if (DuplicateTokenEx(hRestricted, MAXIMUM_ALLOWED, IntPtr.Zero, 2, 1, out IntPtr candidate))
                        {
                            if (IsTokenSafeAndLimited(candidate))
                            {
                                limitedToken = candidate;
                                return true;
                            }
                            CloseHandle(candidate);
                        }
                    }
                    finally
                    {
                        CloseHandle(hRestricted);
                    }
                }
                return false;
            }

            // Non-elevated process (elevType == 1 or 3): duplicate current token directly if already limited
            if (DuplicateTokenEx(hProcessToken, MAXIMUM_ALLOWED, IntPtr.Zero, 2, 1, out IntPtr dupCurrent))
            {
                if (IsTokenSafeAndLimited(dupCurrent))
                {
                    limitedToken = dupCurrent;
                    return true;
                }
                CloseHandle(dupCurrent);
            }

            // Create restricted LUA token
            if (CreateRestrictedToken(hProcessToken, LUA_TOKEN, 0, IntPtr.Zero, 0, IntPtr.Zero, 0, IntPtr.Zero, out IntPtr restricted))
            {
                try
                {
                    if (DuplicateTokenEx(restricted, MAXIMUM_ALLOWED, IntPtr.Zero, 2, 1, out IntPtr candidate))
                    {
                        if (IsTokenSafeAndLimited(candidate))
                        {
                            limitedToken = candidate;
                            return true;
                        }
                        CloseHandle(candidate);
                    }
                }
                finally
                {
                    CloseHandle(restricted);
                }
            }

            return false;
        }
        catch
        {
            return false;
        }
        finally
        {
            if (pInfo != IntPtr.Zero) Marshal.FreeHGlobal(pInfo);
            if (hProcessToken != IntPtr.Zero) CloseHandle(hProcessToken);
        }
    }

    private static bool TrySpawnLimitedProcess(
        string exeName,
        string arguments,
        string workingDir,
        out Process proc,
        out StreamWriter stdin,
        out StreamReader stdout,
        out StreamReader stderr)
    {
        proc = null!;
        stdin = null!;
        stdout = null!;
        stderr = null!;

        if (!TryGetLimitedUserToken(out IntPtr hLimitedToken))
        {
            return false;
        }

        IntPtr hChildStdinRead = IntPtr.Zero;
        IntPtr hParentStdinWrite = IntPtr.Zero;
        IntPtr hParentStdoutRead = IntPtr.Zero;
        IntPtr hChildStdoutWrite = IntPtr.Zero;
        IntPtr hParentStderrRead = IntPtr.Zero;
        IntPtr hChildStderrWrite = IntPtr.Zero;

        try
        {
            var sa = new SECURITY_ATTRIBUTES
            {
                nLength = Marshal.SizeOf<SECURITY_ATTRIBUTES>(),
                bInheritHandle = true,
                lpSecurityDescriptor = IntPtr.Zero
            };

            if (!CreatePipe(out hChildStdinRead, out hParentStdinWrite, ref sa, 0) ||
                !CreatePipe(out hParentStdoutRead, out hChildStdoutWrite, ref sa, 0) ||
                !CreatePipe(out hParentStderrRead, out hChildStderrWrite, ref sa, 0))
            {
                return false;
            }

            SetHandleInformation(hParentStdinWrite, HANDLE_FLAG_INHERIT, 0);
            SetHandleInformation(hParentStdoutRead, HANDLE_FLAG_INHERIT, 0);
            SetHandleInformation(hParentStderrRead, HANDLE_FLAG_INHERIT, 0);

            var si = new STARTUPINFO
            {
                cb = Marshal.SizeOf<STARTUPINFO>(),
                dwFlags = STARTF_USESTDHANDLES,
                hStdInput = hChildStdinRead,
                hStdOutput = hChildStdoutWrite,
                hStdError = hChildStderrWrite
            };

            string cmdLine = string.IsNullOrEmpty(arguments) ? ("\"" + exeName + "\"") : ("\"" + exeName + "\" " + arguments);

            if (!CreateProcessWithTokenW(
                hLimitedToken,
                0,
                null,
                cmdLine,
                CREATE_NO_WINDOW,
                IntPtr.Zero,
                workingDir,
                ref si,
                out PROCESS_INFORMATION pi))
            {
                return false;
            }

            CloseHandle(pi.hThread);
            CloseHandle(hChildStdinRead);
            CloseHandle(hChildStdoutWrite);
            CloseHandle(hChildStderrWrite);
            hChildStdinRead = IntPtr.Zero;
            hChildStdoutWrite = IntPtr.Zero;
            hChildStderrWrite = IntPtr.Zero;

            proc = Process.GetProcessById(pi.dwProcessId);
            CloseHandle(pi.hProcess);

            var safeIn = new SafeFileHandle(hParentStdinWrite, true);
            hParentStdinWrite = IntPtr.Zero;
            var safeOut = new SafeFileHandle(hParentStdoutRead, true);
            hParentStdoutRead = IntPtr.Zero;
            var safeErr = new SafeFileHandle(hParentStderrRead, true);
            hParentStderrRead = IntPtr.Zero;

            var stdinStream = new FileStream(safeIn, FileAccess.Write, 4096, false);
            var stdoutStream = new FileStream(safeOut, FileAccess.Read, 4096, false);
            var stderrStream = new FileStream(safeErr, FileAccess.Read, 4096, false);

            stdin = new StreamWriter(stdinStream, new UTF8Encoding(false)) { AutoFlush = true };
            stdout = new StreamReader(stdoutStream, Encoding.UTF8);
            stderr = new StreamReader(stderrStream, Encoding.UTF8);
            return true;
        }
        catch
        {
            if (hChildStdinRead != IntPtr.Zero) CloseHandle(hChildStdinRead);
            if (hParentStdinWrite != IntPtr.Zero) CloseHandle(hParentStdinWrite);
            if (hParentStdoutRead != IntPtr.Zero) CloseHandle(hParentStdoutRead);
            if (hChildStdoutWrite != IntPtr.Zero) CloseHandle(hChildStdoutWrite);
            if (hParentStderrRead != IntPtr.Zero) CloseHandle(hParentStderrRead);
            if (hChildStderrWrite != IntPtr.Zero) CloseHandle(hChildStderrWrite);
            return false;
        }
        finally
        {
            if (hLimitedToken != IntPtr.Zero) CloseHandle(hLimitedToken);
        }
    }

    #endregion

    public TerminalSessionInfo StartSession(string shellType, string? initialDir = null, string? customId = null, string? ownerDeviceId = null)
    {
        lock (_sessionLock)
        {
            string effectiveOwner = !string.IsNullOrWhiteSpace(ownerDeviceId) ? ownerDeviceId : "unknown";

            // Evict exited processes
            foreach (var kvp in _sessions)
            {
                if (kvp.Value.Process.HasExited)
                {
                    if (_sessions.TryRemove(kvp.Key, out var dead)) dead.Dispose();
                }
            }

            if (_sessions.Count >= MaxActiveSessions)
            {
                throw new InvalidOperationException($"Maximum terminal session capacity ({MaxActiveSessions}) reached.");
            }

            string id;
            if (!string.IsNullOrEmpty(customId) && Regex.IsMatch(customId, @"^[a-zA-Z0-9_\-]{1,32}$"))
            {
                if (_sessions.TryGetValue(customId, out var existing))
                {
                    if (!string.Equals(existing.OwnerDeviceId, effectiveOwner, StringComparison.OrdinalIgnoreCase))
                    {
                        throw new UnauthorizedAccessException($"Terminal session '{customId}' is owned by another device.");
                    }

                    if (!existing.Process.HasExited)
                    {
                        return new TerminalSessionInfo
                        {
                            Id = existing.Id,
                            ShellType = existing.ShellType,
                            WorkingDir = existing.CurrentDirectory,
                            OwnerDeviceId = existing.OwnerDeviceId
                        };
                    }
                    _sessions.TryRemove(customId, out _);
                    existing.Dispose();
                }
                id = customId;
            }
            else
            {
                id = Guid.NewGuid().ToString("N")[..8];
            }

            string workingDir = !string.IsNullOrEmpty(initialDir) && Directory.Exists(initialDir)
                ? initialDir
                : Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

            string exeName = shellType.ToLowerInvariant() switch
            {
                "cmd" => "cmd.exe",
                "powershell" or "powershell5" or "winpowershell" => "powershell.exe",
                "pwsh" or "powershell7" => "pwsh.exe",
                "wsl" or "bash" => "wsl.exe",
                _ => "powershell.exe"
            };

            string arguments = (exeName == "powershell.exe" || exeName == "pwsh.exe") ? "-NoLogo -NoExit" : "";

            if (!TrySpawnLimitedProcess(exeName, arguments, workingDir, out var proc, out var stdinWriter, out var stdoutReader, out var stderrReader))
            {
                throw new System.Security.SecurityException("Failed to launch remote terminal: cannot acquire a verified restricted token. Elevating terminal processes is strictly prohibited (fail-closed).");
            }

            var session = new TerminalSession(id, exeName, workingDir, proc, stdinWriter, effectiveOwner);
            _sessions[id] = session;

            Task.Run(() => ReadStreamLoop(stdoutReader, id, session));
            Task.Run(() => ReadStreamLoop(stderrReader, id, session));

            string intro = $"Tether Remote Console [{exeName}]\r\nWorking Directory: {workingDir}\r\nSession ID: {id}\r\n\r\n";
            session.AppendHistory(intro);
            _onOutputReceived(id, intro, workingDir, session.OwnerDeviceId);

            return new TerminalSessionInfo
            {
                Id = id,
                ShellType = exeName,
                WorkingDir = workingDir,
                OwnerDeviceId = effectiveOwner
            };
        }
    }

    public bool SendInput(string sessionId, string input, string? ownerDeviceId = null)
    {
        TerminalSession? session = null;
        if (!string.IsNullOrEmpty(sessionId) && _sessions.TryGetValue(sessionId, out var s))
        {
            session = s;
        }

        if (session == null || session.Process.HasExited)
        {
            return false;
        }

        if (!string.IsNullOrEmpty(ownerDeviceId) &&
            !string.Equals(session.OwnerDeviceId, ownerDeviceId, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        string lower = input.ToLowerInvariant();
        foreach (var pattern in RestrictedAdminPatterns)
        {
            if (lower.Contains(pattern))
            {
                string alert = $"\r\n[Security Notice] Command blocked: administrative elevation ({pattern}) is restricted in remote terminal.\r\n";
                session.AppendHistory(alert);
                _onOutputReceived(session.Id, alert, session.CurrentDirectory, session.OwnerDeviceId);
                return false;
            }
        }

        try
        {
            session.Stdin.Write(input);
            session.Stdin.Flush();
            return true;
        }
        catch { }

        return false;
    }

    public List<string> GetHistory(string sessionId, string? ownerDeviceId = null)
    {
        if (_sessions.TryGetValue(sessionId, out var session))
        {
            if (!string.IsNullOrEmpty(ownerDeviceId) &&
                !string.Equals(session.OwnerDeviceId, ownerDeviceId, StringComparison.OrdinalIgnoreCase))
            {
                return new List<string>();
            }

            lock (session.Lock)
            {
                return new List<string>(session.HistoryBuffer);
            }
        }
        return new List<string>();
    }

    public bool CloseSession(string sessionId, string? ownerDeviceId = null)
    {
        if (_sessions.TryGetValue(sessionId, out var existing))
        {
            if (!string.IsNullOrEmpty(ownerDeviceId) &&
                !string.Equals(existing.OwnerDeviceId, ownerDeviceId, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            if (_sessions.TryRemove(sessionId, out var session))
            {
                session.Dispose();
                return true;
            }
        }
        return false;
    }

    public List<TerminalSessionInfo> ListSessions(string? ownerDeviceId = null)
    {
        var list = new List<TerminalSessionInfo>();
        foreach (var s in _sessions.Values)
        {
            if (!string.IsNullOrEmpty(ownerDeviceId) &&
                !string.Equals(s.OwnerDeviceId, ownerDeviceId, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            list.Add(new TerminalSessionInfo
            {
                Id = s.Id,
                ShellType = s.ShellType,
                WorkingDir = s.CurrentDirectory,
                IsAlive = !s.Process.HasExited,
                OwnerDeviceId = s.OwnerDeviceId
            });
        }
        return list;
    }

    private async Task ReadStreamLoop(StreamReader reader, string sessionId, TerminalSession session)
    {
        var buffer = new char[4096];
        try
        {
            while (true)
            {
                int read = await reader.ReadAsync(buffer, 0, buffer.Length);
                if (read <= 0) break;

                string text = new string(buffer, 0, read);
                session.AppendHistory(text);

                // Detect prompt directory changes
                var match = Regex.Match(text, @"(?:PS\s+)?([a-zA-Z]:\\[^\r\n<>]+)>");
                if (match.Success)
                {
                    string parsedDir = match.Groups[1].Value.Trim();
                    if (Directory.Exists(parsedDir))
                    {
                        session.CurrentDirectory = parsedDir;
                    }
                }

                _onOutputReceived(sessionId, text, session.CurrentDirectory, session.OwnerDeviceId);
            }
        }
        catch { }
    }
}

public sealed class TerminalSessionInfo
{
    public string Id { get; set; } = string.Empty;
    public string SessionId => Id;
    public string ShellType { get; set; } = string.Empty;
    public string WorkingDir { get; set; } = string.Empty;
    public bool IsAlive { get; set; } = true;
    public string OwnerDeviceId { get; set; } = string.Empty;
}
