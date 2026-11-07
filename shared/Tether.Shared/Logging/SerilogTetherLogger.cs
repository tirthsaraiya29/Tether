using System;
using System.IO;
using Serilog;

namespace Tether.Shared.Logging
{
    public class SerilogTetherLogger : ITetherLogger
    {
        private readonly ILogger _logger;

        public SerilogTetherLogger()
        {
            var logDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Tether", "logs");
            try { Directory.CreateDirectory(logDir); } catch { }
            var logPath = Path.Combine(logDir, "tether-.log");

            _logger = new LoggerConfiguration()
                .WriteTo.File(logPath,
                              rollingInterval: RollingInterval.Day,
                              fileSizeLimitBytes: 10 * 1024 * 1024,
                              rollOnFileSizeLimit: true,
                              retainedFileCountLimit: 7)
                .WriteTo.Console()
                .CreateLogger();
        }

        private static string SanitizeLogInput(string? message)
        {
            if (string.IsNullOrEmpty(message)) return string.Empty;
            return message.Replace("\r", "").Replace("\n", " ");
        }

        public void Info(string message) => _logger.Information("{Message}", SanitizeLogInput(message));
        public void Warning(string message) => _logger.Warning("{Message}", SanitizeLogInput(message));
        public void Error(string message, Exception? ex = null)
        {
            var sanitized = SanitizeLogInput(message);
            if (ex != null) _logger.Error(ex, "{Message}", sanitized);
            else _logger.Error("{Message}", sanitized);
        }
        public void Debug(string message) => _logger.Debug("{Message}", SanitizeLogInput(message));
    }
}
