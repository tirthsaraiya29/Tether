using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;

namespace Tether.DesktopUI.Updates
{
    public static class UpdateEnvironment
    {
        private static bool? _cachedIsDebug;

        /// <summary>
        /// Determines if the current program is running under a Debug configuration or development environment.
        /// When true, all update watchers, notifications, and prompts are completely deactivated.
        /// </summary>
        public static bool IsDebugOrDevEnvironment()
        {
            if (_cachedIsDebug.HasValue)
            {
                return _cachedIsDebug.Value;
            }

            // 1. Compile-time constant check
#if DEBUG
            _cachedIsDebug = true;
            return true;
#else
            // 2. Active debugger check
            if (Debugger.IsAttached)
            {
                _cachedIsDebug = true;
                return true;
            }

            // 3. Environment variables check
            string? devEnv = Environment.GetEnvironmentVariable("TETHER_DEV");
            string? debugEnv = Environment.GetEnvironmentVariable("TETHER_DEBUG");
            string? skipEnv = Environment.GetEnvironmentVariable("TETHER_SKIP_UPDATES");
            if (string.Equals(devEnv, "1", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(debugEnv, "1", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(skipEnv, "1", StringComparison.OrdinalIgnoreCase))
            {
                _cachedIsDebug = true;
                return true;
            }

            // 4. Assembly attributes check
            var entryAssembly = Assembly.GetEntryAssembly() ?? Assembly.GetExecutingAssembly();
            var debuggableAttr = entryAssembly.GetCustomAttribute<DebuggableAttribute>();
            if (debuggableAttr != null && debuggableAttr.IsJITTrackingEnabled)
            {
                _cachedIsDebug = true;
                return true;
            }

            // 5. Execution path detection (e.g., running from Visual Studio bin\Debug folder)
            try
            {
                string baseDir = AppDomain.CurrentDomain.BaseDirectory.ToLowerInvariant();
                if (baseDir.Contains(@"\bin\debug\") || 
                    baseDir.Contains(@"\bin\x64\debug\") ||
                    (baseDir.Contains(@"\apps\desktop-ui\") && !baseDir.Contains(@"\program files\")))
                {
                    _cachedIsDebug = true;
                    return true;
                }
            }
            catch
            {
                // Fall through on any permission/path error
            }

            _cachedIsDebug = false;
            return false;
#endif
        }
    }
}
