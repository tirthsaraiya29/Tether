using System;
using System.Collections.Generic;
using Tether.Shared.Logging;

namespace Tether.Tests;

public sealed class TestLogger : ITetherLogger
{
    public List<string> Messages { get; } = new();

    public void Info(string message) => Messages.Add($"[INFO] {message}");
    public void Warning(string message) => Messages.Add($"[WARN] {message}");
    public void Error(string message, Exception? ex = null) => Messages.Add($"[ERROR] {message} {ex?.Message}");
    public void Debug(string message) => Messages.Add($"[DEBUG] {message}");
}
