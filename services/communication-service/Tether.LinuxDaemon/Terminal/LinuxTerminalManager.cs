using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Tether.LinuxDaemon.Common;
using Tether.Shared.Logging;

namespace Tether.LinuxDaemon.Terminal;

public sealed class TerminalSessionInfo
{
    public string Id { get; init; } = "";
    public string SessionId => Id;
    public string ShellType { get; init; } = "";
    public string WorkingDir { get; init; } = "";
    public bool IsAlive { get; init; } = true;
    public string OwnerDeviceId { get; init; } = "";
}

public sealed class LinuxTerminalManager : IDisposable
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

    [DllImport("libc", SetLastError = true)]
    private static extern uint geteuid();

    private static readonly string[] RestrictedAdminPatterns =
    {
        "sudo ", "sudo\t", "sudo\n", "sudo\r",
        "su ", "su\t", "su\n", "su\r",
        "pkexec", "doas", "passwd "
    };

    private const int MaxActiveSessions = 8;
    private readonly object _sessionLock = new();
    private readonly ConcurrentDictionary<string, TerminalSession> _sessions = new(StringComparer.OrdinalIgnoreCase);
    private readonly ITetherLogger _logger;
    private volatile bool _disposed;

    // Callback: (sessionId, outputChunk, currentDir, ownerDeviceId)
    public Action<string, string, string, string>? OnOutputReceived { get; set; }

    public LinuxTerminalManager(ITetherLogger logger)
    {
        _logger = logger;
    }

    public TerminalSessionInfo StartSession(string shellType, string? initialDir = null, string? customId = null, string? ownerDeviceId = null)
    {
        if (string.IsNullOrWhiteSpace(ownerDeviceId))
        {
            throw new ArgumentException("Terminal session owner device ID is mandatory.", nameof(ownerDeviceId));
        }

        lock (_sessionLock)
        {
            string effectiveOwner = ownerDeviceId.Trim();

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
                        string history;
                        lock (existing.Lock)
                        {
                            history = string.Join("", existing.HistoryBuffer);
                        }
                        if (!string.IsNullOrEmpty(history))
                        {
                            OnOutputReceived?.Invoke(existing.Id, history, existing.CurrentDirectory, existing.OwnerDeviceId);
                        }

                        return new TerminalSessionInfo
                        {
                            Id = existing.Id,
                            ShellType = existing.ShellType,
                            WorkingDir = existing.CurrentDirectory,
                            OwnerDeviceId = existing.OwnerDeviceId,
                            IsAlive = true
                        };
                    }

                    _sessions.TryRemove(customId, out _);
                    existing.Dispose();
                }
                id = customId;
            }
            else
            {
                byte[] randomBytes = new byte[16];
                RandomNumberGenerator.Fill(randomBytes);
                id = Convert.ToHexString(randomBytes).ToLowerInvariant();
            }

            var sessionInfo = PlatformDetection.GetActiveSessionInfo();
            string userHome = !string.IsNullOrEmpty(sessionInfo.UserName) && sessionInfo.UserName != "root"
                ? $"/home/{sessionInfo.UserName}"
                : Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

            string workingDir = !string.IsNullOrEmpty(initialDir) && Directory.Exists(initialDir)
                ? initialDir
                : (Directory.Exists(userHome) ? userHome : "/");

            string selectedShell = ResolveShell(shellType);
            bool isRoot = geteuid() == 0;

            ProcessStartInfo psi;
            if (isRoot && !string.IsNullOrEmpty(sessionInfo.UserName) && sessionInfo.UserName != "root")
            {
                // Drop privileges to active session user via runuser
                psi = new ProcessStartInfo
                {
                    FileName = "runuser",
                    Arguments = $"-u {sessionInfo.UserName} -- {selectedShell}",
                    WorkingDirectory = workingDir,
                    RedirectStandardInput = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    StandardOutputEncoding = Encoding.UTF8,
                    StandardErrorEncoding = Encoding.UTF8,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
            }
            else
            {
                // Direct user-level execution
                psi = new ProcessStartInfo
                {
                    FileName = selectedShell,
                    WorkingDirectory = workingDir,
                    RedirectStandardInput = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    StandardOutputEncoding = Encoding.UTF8,
                    StandardErrorEncoding = Encoding.UTF8,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
            }

            psi.EnvironmentVariables["TERM"] = "xterm-256color";
            psi.EnvironmentVariables["COLORTERM"] = "truecolor";

            Process proc;
            try
            {
                proc = Process.Start(psi) ?? throw new InvalidOperationException($"Failed to spawn shell process '{selectedShell}'.");
            }
            catch (Exception ex)
            {
                _logger.Error($"LinuxTerminalManager: Spawn exception: {ex.Message}");
                throw;
            }

            var stdinWriter = proc.StandardInput;
            var session = new TerminalSession(id, selectedShell, workingDir, proc, stdinWriter, effectiveOwner);
            _sessions[id] = session;

            Task.Run(() => ReadStreamLoop(proc.StandardOutput, id, session));
            Task.Run(() => ReadStreamLoop(proc.StandardError, id, session));

            string intro = $"Tether Linux Remote Terminal [{selectedShell}]\r\nWorking Directory: {workingDir}\r\nSession ID: {id}\r\n\r\n";
            session.AppendHistory(intro);
            OnOutputReceived?.Invoke(id, intro, workingDir, effectiveOwner);

            return new TerminalSessionInfo
            {
                Id = id,
                ShellType = selectedShell,
                WorkingDir = workingDir,
                OwnerDeviceId = effectiveOwner,
                IsAlive = true
            };
        }
    }

    public bool SendInput(string sessionId, string input, string? ownerDeviceId = null)
    {
        if (string.IsNullOrWhiteSpace(ownerDeviceId) || string.IsNullOrEmpty(sessionId) || input == null || input.Contains('\0'))
        {
            return false;
        }

        if (!_sessions.TryGetValue(sessionId, out var session) || session.Process.HasExited)
        {
            return false;
        }

        if (!string.Equals(session.OwnerDeviceId, ownerDeviceId.Trim(), StringComparison.OrdinalIgnoreCase))
        {
            _logger.Warning($"LinuxTerminalManager: Cross-device terminal access rejected for session {sessionId}.");
            return false;
        }

        string lower = input.ToLowerInvariant();
        foreach (var pattern in RestrictedAdminPatterns)
        {
            if (lower.Contains(pattern))
            {
                string alert = $"\r\n[Security Notice] Command blocked: administrative elevation ({pattern.Trim()}) is restricted in remote terminal.\r\n";
                session.AppendHistory(alert);
                OnOutputReceived?.Invoke(session.Id, alert, session.CurrentDirectory, session.OwnerDeviceId);
                return false;
            }
        }

        try
        {
            lock (session.Lock)
            {
                session.Stdin.Write(input);
                session.Stdin.Flush();
            }
            return true;
        }
        catch (Exception ex)
        {
            _logger.Warning($"LinuxTerminalManager: SendInput failed: {ex.Message}");
            return false;
        }
    }

    public bool CloseSession(string sessionId, string? ownerDeviceId = null)
    {
        if (string.IsNullOrWhiteSpace(ownerDeviceId) || string.IsNullOrEmpty(sessionId)) return false;

        if (_sessions.TryGetValue(sessionId, out var session))
        {
            if (!string.Equals(session.OwnerDeviceId, ownerDeviceId.Trim(), StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            if (_sessions.TryRemove(sessionId, out var removed))
            {
                removed.Dispose();
                return true;
            }
        }

        return false;
    }

    public List<string> GetHistory(string sessionId, string? ownerDeviceId = null)
    {
        if (string.IsNullOrWhiteSpace(ownerDeviceId) || string.IsNullOrEmpty(sessionId)) return new();

        if (_sessions.TryGetValue(sessionId, out var session))
        {
            if (!string.Equals(session.OwnerDeviceId, ownerDeviceId.Trim(), StringComparison.OrdinalIgnoreCase))
            {
                return new();
            }

            lock (session.Lock)
            {
                return new List<string>(session.HistoryBuffer);
            }
        }

        return new();
    }

    public List<TerminalSessionInfo> ListSessions(string? ownerDeviceId = null)
    {
        if (string.IsNullOrWhiteSpace(ownerDeviceId)) return new();
        string effectiveOwner = ownerDeviceId.Trim();

        return _sessions.Values
            .Where(s => string.Equals(s.OwnerDeviceId, effectiveOwner, StringComparison.OrdinalIgnoreCase))
            .Select(s => new TerminalSessionInfo
            {
                Id = s.Id,
                ShellType = s.ShellType,
                WorkingDir = s.CurrentDirectory,
                IsAlive = !s.Process.HasExited,
                OwnerDeviceId = s.OwnerDeviceId
            })
            .ToList();
    }

    private async Task ReadStreamLoop(StreamReader reader, string sessionId, TerminalSession session)
    {
        var buffer = new char[4096];
        try
        {
            while (!_disposed)
            {
                int read = await reader.ReadAsync(buffer, 0, buffer.Length);
                if (read <= 0) break;

                string text = new string(buffer, 0, read);
                session.AppendHistory(text);

                // Check directory change prompts (e.g. user@host:path$ or /path $)
                var match = Regex.Match(text, @"[:\s](/[a-zA-Z0-9_\-\./]+)\s*[\$#>]");
                if (match.Success)
                {
                    string parsedDir = match.Groups[1].Value.Trim();
                    if (Directory.Exists(parsedDir))
                    {
                        session.CurrentDirectory = parsedDir;
                    }
                }

                OnOutputReceived?.Invoke(sessionId, text, session.CurrentDirectory, session.OwnerDeviceId);
            }
        }
        catch { }
    }

    private static string ResolveShell(string requested)
    {
        string reqLower = (requested ?? "").Trim().ToLowerInvariant();

        if (reqLower == "pwsh" || reqLower == "powershell" || reqLower == "powershell7")
        {
            if (File.Exists("/usr/bin/pwsh")) return "/usr/bin/pwsh";
            if (File.Exists("/bin/pwsh")) return "/bin/pwsh";
        }

        if (reqLower == "zsh")
        {
            if (File.Exists("/usr/bin/zsh")) return "/usr/bin/zsh";
            if (File.Exists("/bin/zsh")) return "/bin/zsh";
        }

        if (reqLower == "sh")
        {
            if (File.Exists("/bin/sh")) return "/bin/sh";
            if (File.Exists("/usr/bin/sh")) return "/usr/bin/sh";
        }

        if (File.Exists("/bin/bash")) return "/bin/bash";
        if (File.Exists("/usr/bin/bash")) return "/usr/bin/bash";
        if (File.Exists("/bin/sh")) return "/bin/sh";

        return "/bin/sh";
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        lock (_sessionLock)
        {
            foreach (var kvp in _sessions)
            {
                kvp.Value.Dispose();
            }
            _sessions.Clear();
        }
    }
}
