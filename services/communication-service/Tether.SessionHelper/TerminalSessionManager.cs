using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

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

    private readonly ConcurrentDictionary<string, TerminalSession> _sessions = new();
    private readonly Action<string, string, string> _onOutputReceived;

    public TerminalSessionManager(Action<string, string, string> onOutputReceived)
    {
        _onOutputReceived = onOutputReceived;
    }

    private const int MaxActiveSessions = 8;

    public TerminalSessionInfo StartSession(string shellType, string? initialDir = null, string? customId = null)
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

        string id = string.IsNullOrEmpty(customId) ? Guid.NewGuid().ToString("N")[..8] : customId;
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

        var psi = new ProcessStartInfo
        {
            FileName = exeName,
            WorkingDirectory = workingDir,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };

        if (exeName == "powershell.exe" || exeName == "pwsh.exe")
        {
            psi.Arguments = "-NoLogo -NoExit";
        }

        Process proc;
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

        var session = new TerminalSession(id, exeName, workingDir, proc, proc.StandardInput);
        _sessions[id] = session;

        Task.Run(() => ReadStreamLoop(proc.StandardOutput, id, session));
        Task.Run(() => ReadStreamLoop(proc.StandardError, id, session));

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

    public bool SendInput(string sessionId, string input)
    {
        TerminalSession? session = null;
        if (!string.IsNullOrEmpty(sessionId) && _sessions.TryGetValue(sessionId, out var s))
        {
            session = s;
        }
        else if (_sessions.Count > 0)
        {
            // Fallback to the first active session if sessionId is "default" or mismatch
            foreach (var active in _sessions.Values)
            {
                if (!active.Process.HasExited)
                {
                    session = active;
                    break;
                }
            }
        }

        if (session == null)
        {
            // Auto-start a default session if none exists
            var newSession = StartSession("powershell", null, string.IsNullOrEmpty(sessionId) || sessionId == "default" ? null : sessionId);
            _sessions.TryGetValue(newSession.Id, out session);
        }

        if (session != null)
        {
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
        }
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
                var match = System.Text.RegularExpressions.Regex.Match(text, @"(?:PS\s+)?([a-zA-Z]:\\[^\r\n<>]+)>");
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
