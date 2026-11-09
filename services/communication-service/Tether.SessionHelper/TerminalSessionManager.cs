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

        public TerminalSession(string id, string shellType, string currentDirectory, Process process, StreamWriter stdin)
        {
            Id = id;
            ShellType = shellType;
            CurrentDirectory = currentDirectory;
            Process = process;
            Stdin = stdin;
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
    private readonly Action<string, string, string> _onOutputReceived;

    public TerminalSessionManager(Action<string, string, string> onOutputReceived)
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

    private static bool TryGetLimitedUserToken(out IntPtr limitedToken)
    {
        limitedToken = IntPtr.Zero;
        IntPtr hToken = IntPtr.Zero;
        IntPtr pLinked = IntPtr.Zero;
        try
        {
            if (OpenProcessToken(Process.GetCurrentProcess().Handle, 0x0008 | 0x0002 /* TOKEN_QUERY | TOKEN_DUPLICATE */, out hToken))
            {
                pLinked = Marshal.AllocHGlobal(IntPtr.Size);
                if (GetTokenInformation(hToken, 19 /* TokenLinkedToken */, pLinked, (uint)IntPtr.Size, out _))
                {
                    IntPtr rawLinked = Marshal.ReadIntPtr(pLinked);
                    if (rawLinked != IntPtr.Zero)
                    {
                        if (DuplicateTokenEx(rawLinked, 0x10000000 /* MAXIMUM_ALLOWED */, IntPtr.Zero, 2, 1, out limitedToken))
                        {
                            return true;
                        }
                    }
                }
            }
        }
        catch { }
        finally
        {
            if (pLinked != IntPtr.Zero) Marshal.FreeHGlobal(pLinked);
            if (hToken != IntPtr.Zero) CloseHandle(hToken);
        }
        return false;
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

            var stdinStream = new FileStream(new SafeFileHandle(hParentStdinWrite, true), FileAccess.Write, 4096, false);
            var stdoutStream = new FileStream(new SafeFileHandle(hParentStdoutRead, true), FileAccess.Read, 4096, false);
            var stderrStream = new FileStream(new SafeFileHandle(hParentStderrRead, true), FileAccess.Read, 4096, false);

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

    public TerminalSessionInfo StartSession(string shellType, string? initialDir = null, string? customId = null)
    {
        lock (_sessionLock)
        {
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
                    if (!existing.Process.HasExited)
                    {
                        return new TerminalSessionInfo
                        {
                            Id = existing.Id,
                            ShellType = existing.ShellType,
                            WorkingDir = existing.CurrentDirectory
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

            Process proc;
            StreamWriter stdinWriter;
            StreamReader stdoutReader;
            StreamReader stderrReader;

            if (TrySpawnLimitedProcess(exeName, arguments, workingDir, out var limProc, out var limStdin, out var limStdout, out var limStderr))
            {
                proc = limProc;
                stdinWriter = limStdin;
                stdoutReader = limStdout;
                stderrReader = limStderr;
            }
            else
            {
                // Fallback to standard process start
                var psi = new ProcessStartInfo
                {
                    FileName = exeName,
                    Arguments = arguments,
                    WorkingDirectory = workingDir,
                    RedirectStandardInput = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    StandardOutputEncoding = Encoding.UTF8,
                    StandardErrorEncoding = Encoding.UTF8
                };

                try
                {
                    proc = Process.Start(psi) ?? throw new InvalidOperationException($"Failed to spawn {exeName}");
                }
                catch (Exception ex)
                {
                    if (exeName != "cmd.exe")
                    {
                        psi.FileName = "cmd.exe";
                        psi.Arguments = "";
                        proc = Process.Start(psi) ?? throw new InvalidOperationException($"Fallback to cmd failed: {ex.Message}");
                        exeName = "cmd.exe";
                    }
                    else
                    {
                        throw;
                    }
                }

                stdinWriter = proc.StandardInput;
                stdoutReader = proc.StandardOutput;
                stderrReader = proc.StandardError;
            }

            var session = new TerminalSession(id, exeName, workingDir, proc, stdinWriter);
            _sessions[id] = session;

            Task.Run(() => ReadStreamLoop(stdoutReader, id, session));
            Task.Run(() => ReadStreamLoop(stderrReader, id, session));

            string intro = $"Tether Remote Console [{exeName}]\r\nWorking Directory: {workingDir}\r\nSession ID: {id}\r\n\r\n";
            session.AppendHistory(intro);
            _onOutputReceived(id, intro, workingDir);

            return new TerminalSessionInfo
            {
                Id = id,
                ShellType = exeName,
                WorkingDir = workingDir
            };
        }
    }

    public bool SendInput(string sessionId, string input)
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

        string lower = input.ToLowerInvariant();
        foreach (var pattern in RestrictedAdminPatterns)
        {
            if (lower.Contains(pattern))
            {
                string alert = $"\r\n[Security Notice] Command blocked: administrative elevation ({pattern}) is restricted in remote terminal.\r\n";
                session.AppendHistory(alert);
                _onOutputReceived(session.Id, alert, session.CurrentDirectory);
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

    public List<string> GetHistory(string sessionId)
    {
        if (_sessions.TryGetValue(sessionId, out var session))
        {
            lock (session.Lock)
            {
                return new List<string>(session.HistoryBuffer);
            }
        }
        return new List<string>();
    }

    public bool CloseSession(string sessionId)
    {
        if (_sessions.TryRemove(sessionId, out var session))
        {
            session.Dispose();
            return true;
        }
        return false;
    }

    public List<TerminalSessionInfo> ListSessions()
    {
        var list = new List<TerminalSessionInfo>();
        foreach (var s in _sessions.Values)
        {
            list.Add(new TerminalSessionInfo
            {
                Id = s.Id,
                ShellType = s.ShellType,
                WorkingDir = s.CurrentDirectory,
                IsAlive = !s.Process.HasExited
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
                var match = Regex.Match(text, @"(?:PS\s+)?([a-zA-Z]:\[^

<>]+)>");
                if (match.Success)
                {
                    string parsedDir = match.Groups[1].Value.Trim();
                    if (Directory.Exists(parsedDir))
                    {
                        session.CurrentDirectory = parsedDir;
                    }
                }

                _onOutputReceived(sessionId, text, session.CurrentDirectory);
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
}
