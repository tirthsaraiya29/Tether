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

        public void Info(string message) => _logger.Information(message);
        public void Warning(string message) => _logger.Warning(message);
        public void Error(string message, Exception? ex = null)
        {
            if (ex != null) _logger.Error(ex, message);
            else _logger.Error(message);
        }
        public void Debug(string message) => _logger.Debug(message);
    }
}