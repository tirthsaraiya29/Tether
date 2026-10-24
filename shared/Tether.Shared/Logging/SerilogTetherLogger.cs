using Serilog;

namespace Tether.Shared.Logging
{
    public class SerilogTetherLogger : ITetherLogger
    {
        private readonly ILogger _logger;

        public SerilogTetherLogger()
        {
            _logger = new LoggerConfiguration()
                .WriteTo.File(@"C:\Dev\Tether\data\logs\tether.log",
                              rollingInterval: RollingInterval.Day,
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