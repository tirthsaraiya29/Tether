using System;
using Tether.Shared.Logging;

namespace Tether.DesktopUI.Services;

public class SerilogTetherLogger : ITetherLogger
{
    public void Debug(string message) => System.Diagnostics.Debug.WriteLine($"[DEBUG] {message}");
    public void Info(string message) => System.Diagnostics.Debug.WriteLine($"[INFO] {message}");
    public void Warning(string message) => System.Diagnostics.Debug.WriteLine($"[WARN] {message}");
    public void Error(string message, Exception? ex = null) => System.Diagnostics.Debug.WriteLine($"[ERROR] {message} {ex}");
}