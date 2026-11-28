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

    [DllImport("libc", SetLastError = true)]
    private static extern int kill(int pid, int sig);

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

    // Callback: (sessionId, ownerDeviceId)
    public Action<string, string>? OnSessionExited { get; set; }

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
            string? targetUser = GetInteractiveNonRootUser(sessionInfo);
            string? passwdHome = GetUserHomeDirectory(targetUser);
            string userHome = !string.IsNullOrEmpty(passwdHome)
                ? passwdHome
                : (!string.IsNullOrEmpty(targetUser)
                    ? $"/home/{targetUser}"
                    : Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));

            string workingDir = !string.IsNullOrEmpty(initialDir) && Directory.Exists(initialDir)
                ? initialDir
                : (Directory.Exists(userHome) ? userHome : (OperatingSystem.IsWindows() ? Environment.CurrentDirectory : "/"));

            string selectedShell = ResolveShell(shellType, GetUserLoginShell(targetUser));
            bool isRoot = OperatingSystem.IsLinux() && geteuid() == 0;

            ProcessStartInfo psi;
            if (isRoot)
            {
                if (string.IsNullOrEmpty(targetUser) || targetUser == "root")
                {
                    _logger.Error("LinuxTerminalManager: Remote terminal refused because no non-root user session exists. Accidental root execution is blocked.");
                    throw new UnauthorizedAccessException("Remote terminal refused: no active non-root user session found. Spawning terminal as root is strictly blocked.");
                }

                // Drop privileges to active session user via runuser with safe ArgumentList
                psi = new ProcessStartInfo
                {
                    FileName = "runuser",
                    WorkingDirectory = workingDir,
                    RedirectStandardInput = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    StandardOutputEncoding = Encoding.UTF8,
                    StandardErrorEncoding = Encoding.UTF8,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                psi.ArgumentList.Add("-u");
                psi.ArgumentList.Add(targetUser);
                psi.ArgumentList.Add("--");
                psi.ArgumentList.Add(selectedShell);
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
            if (OperatingSystem.IsLinux())
            {
                psi.EnvironmentVariables["HOME"] = userHome;
                psi.EnvironmentVariables["SHELL"] = selectedShell;
                if (!string.IsNullOrEmpty(targetUser)) psi.EnvironmentVariables["USER"] = targetUser;
            }

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

            proc.EnableRaisingEvents = true;
            proc.Exited += (s, e) =>
            {
                _sessions.TryRemove(id, out _);
                OnSessionExited?.Invoke(id, effectiveOwner);
            };

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
        if (string.IsNullOrWhiteSpace(ownerDeviceId) || string.IsNullOrEmpty(sessionId) || input == null || input.Contains('\0') || input.Length > 32768)
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

        // Support Ctrl+C (0x03) signal forwarding to child process group on Linux
        if (input == "\u0003" && OperatingSystem.IsLinux())
        {
            try
            {
                kill(session.Process.Id, 2 /* SIGINT */);
            }
            catch { }
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
            // Normalize CRLF to LF for POSIX shells so trailing '\r' is not interpreted as part of the command token
            string effectiveInput = OperatingSystem.IsLinux() ? input.Replace("\r\n", "\n") : input;

            lock (session.Lock)
            {
                session.Stdin.Write(effectiveInput);
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

    private static string? GetInteractiveNonRootUser(LinuxSessionInfo sessionInfo)
    {
        if (!string.IsNullOrEmpty(sessionInfo.UserName) && sessionInfo.UserName != "root")
        {
            return sessionInfo.UserName;
        }

        if (OperatingSystem.IsLinux() && File.Exists("/etc/passwd"))
        {
            try
            {
                foreach (var line in File.ReadLines("/etc/passwd"))
                {
                    var parts = line.Split(':');
                    if (parts.Length >= 6 && uint.TryParse(parts[2], out uint uid) && uid >= 1000 && uid < 60000)
                    {
                        string user = parts[0];
                        if (user != "nobody" && Directory.Exists(parts[5]))
                        {
                            return user;
                        }
                    }
                }
            }
            catch { }
        }

        return !string.IsNullOrEmpty(Environment.UserName) && Environment.UserName != "root"
            ? Environment.UserName
            : null;
    }

    private static readonly HashSet<string> AllowedShellNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "bash", "zsh", "sh", "fish", "pwsh", "dash", "ksh"
    };

    /// <summary>Login shell from /etc/passwd for the interactive user; null when unknown.</summary>
    public static string? GetUserLoginShell(string? user)
    {
        if (string.IsNullOrEmpty(user) || !OperatingSystem.IsLinux()) return null;
        string? entry = ReadPasswdEntry(user);
        if (entry == null) return null;

        var fields = entry.Split(':');
        if (fields.Length < 7) return null;

        string shell = fields[6].Trim();
        if (shell.Length == 0 || !shell.StartsWith('/') || shell.Contains(' ') || !File.Exists(shell)) return null;
        return AllowedShellNames.Contains(Path.GetFileName(shell)) ? shell : null;
    }

    public static string? GetUserHomeDirectory(string? user)
    {
        if (string.IsNullOrEmpty(user) || !OperatingSystem.IsLinux()) return null;
        string? entry = ReadPasswdEntry(user);
        if (entry == null) return null;

        var fields = entry.Split(':');
        if (fields.Length < 6) return null;

        string home = fields[5].Trim();
        return home.StartsWith('/') && !home.Contains(' ') ? home : null;
    }

    private static string? ReadPasswdEntry(string user)
    {
        try
        {
            if (!File.Exists("/etc/passwd")) return null;
            foreach (var line in File.ReadLines("/etc/passwd"))
            {
                int idx = line.IndexOf(':');
                if (idx > 0 && string.Equals(line.Substring(0, idx), user, StringComparison.Ordinal))
                {
                    return line;
                }
            }
        }
        catch { }
        return null;
    }

    private static string? ExistingShell(string name)
    {
        foreach (var dir in new[] { "/usr/bin/", "/bin/", "/usr/local/bin/" })
        {
            string path = dir + name;
            if (File.Exists(path)) return path;
        }
        return null;
    }

    public static string ResolveShell(string requested, string? loginShell = null)
    {
        string reqLower = (requested ?? "").Trim().ToLowerInvariant();

        if (OperatingSystem.IsWindows())
        {
            return Environment.GetEnvironmentVariable("COMSPEC") ?? "cmd.exe";
        }

        bool useLogin = reqLower.Length == 0 || reqLower == "default" || reqLower == "login";
        if (useLogin && loginShell != null) return loginShell;

        if (reqLower == "pwsh" || reqLower == "powershell" || reqLower == "powershell7")
        {
            return ExistingShell("pwsh") ?? loginShell ?? ExistingShell("bash") ?? ExistingShell("sh") ?? "/bin/sh";
        }

        if (AllowedShellNames.Contains(reqLower))
        {
            return ExistingShell(reqLower) ?? loginShell ?? ExistingShell("bash") ?? ExistingShell("sh") ?? "/bin/sh";
        }

        // Unknown request: never execute it; fall back to the user's own shell.
        return loginShell ?? ExistingShell("bash") ?? ExistingShell("sh") ?? "/bin/sh";
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
