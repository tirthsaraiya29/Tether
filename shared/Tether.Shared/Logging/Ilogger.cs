namespace Tether.Shared.Logging
{
    public interface ITetherLogger
    {
        void Info(string message);
        void Warning(string message);
        void Error(string message, Exception? ex = null);
        void Debug(string message);
    }
}