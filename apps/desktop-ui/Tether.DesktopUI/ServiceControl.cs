using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Tether.DesktopUI
{
    [SupportedOSPlatform("windows")]
    internal static class ServiceControl
    {
        private const string CommServiceName = "TetherCommService";

        private const uint SC_MANAGER_CONNECT = 0x0001;
        private const uint SERVICE_QUERY_STATUS = 0x0004;
        private const uint SERVICE_START = 0x0010;
        private const uint SERVICE_STOP = 0x0020;
        private const uint SERVICE_CONTROL_STOP = 0x00000001;
        private const uint SERVICE_STOPPED = 0x00000001;
        private const int ERROR_SERVICE_ALREADY_RUNNING = 1056;

        [StructLayout(LayoutKind.Sequential)]
        private struct SERVICE_STATUS
        {
            public uint dwServiceType;
            public uint dwCurrentState;
            public uint dwControlsAccepted;
            public uint dwWin32ExitCode;
            public uint dwServiceSpecificExitCode;
            public uint dwCheckPoint;
            public uint dwWaitHint;
        }

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr OpenSCManager(string? lpMachineName, string? lpDatabaseName, uint dwDesiredAccess);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr OpenService(IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool QueryServiceStatus(IntPtr hService, out SERVICE_STATUS lpServiceStatus);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool ControlService(IntPtr hService, uint dwControl, ref SERVICE_STATUS lpServiceStatus);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool StartService(IntPtr hService, int dwNumServiceArgs, string[]? lpServiceArgVectors);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CloseServiceHandle(IntPtr hSCObject);

        public static bool IsRunning()
        {
            IntPtr scm = OpenSCManager(null, null, SC_MANAGER_CONNECT);
            if (scm == IntPtr.Zero) return false;
            try
            {
                IntPtr svc = OpenService(scm, CommServiceName, SERVICE_QUERY_STATUS);
                if (svc == IntPtr.Zero) return false;
                try
                {
                    return QueryServiceStatus(svc, out SERVICE_STATUS status) && status.dwCurrentState != SERVICE_STOPPED;
                }
                finally { CloseServiceHandle(svc); }
            }
            finally { CloseServiceHandle(scm); }
        }

        /// <returns>0 = restarted, 1 = access denied (elevation required), 2 = other failure</returns>
        public static int Restart(Action<string> log)
        {
            IntPtr scmHandle = OpenSCManager(null, null, SC_MANAGER_CONNECT);
            if (scmHandle == IntPtr.Zero)
            {
                return TryStartStandaloneCommService(log) ? 0 : 2;
            }

            IntPtr serviceHandle = IntPtr.Zero;
            try
            {
                serviceHandle = OpenService(scmHandle, CommServiceName, SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP);
                if (serviceHandle == IntPtr.Zero)
                {
                    return Marshal.GetLastWin32Error() == 5 ? 1 : (TryStartStandaloneCommService(log) ? 0 : 2);
                }

                if (!QueryServiceStatus(serviceHandle, out SERVICE_STATUS status))
                {
                    log("Could not read the Tether service status.");
                    return 2;
                }

                if (status.dwCurrentState != SERVICE_STOPPED)
                {
                    SERVICE_STATUS stopStatus = default;
                    if (!ControlService(serviceHandle, SERVICE_CONTROL_STOP, ref stopStatus))
                    {
                        if (Marshal.GetLastWin32Error() == 5) return 1;
                        log("Could not stop the Tether service.");
                        return 2;
                    }

                    log("Stopping the Tether service…");

                    var sw = System.Diagnostics.Stopwatch.StartNew();
                    while (sw.ElapsedMilliseconds < 15000)
                    {
                        System.Threading.Thread.Sleep(400);
                        if (!QueryServiceStatus(serviceHandle, out status)) break;
                        if (status.dwCurrentState == SERVICE_STOPPED) break;
                    }

                    if (status.dwCurrentState != SERVICE_STOPPED)
                    {
                        log("The Tether service did not stop in time.");
                        return 2;
                    }
                }

                if (!StartService(serviceHandle, 0, null))
                {
                    int err = Marshal.GetLastWin32Error();
                    if (err == 5) return 1;
                    if (err != ERROR_SERVICE_ALREADY_RUNNING)
                    {
                        log("Could not start the Tether service.");
                        return 2;
                    }
                }

                log("Tether service restarted.");
                return 0;
            }
            finally
            {
                if (serviceHandle != IntPtr.Zero) CloseServiceHandle(serviceHandle);
                CloseServiceHandle(scmHandle);
            }
        }

        private static bool TryStartStandaloneCommService(Action<string> log)
        {
            try
            {
                log("Starting the Tether service directly…");
                string appDir = AppDomain.CurrentDomain.BaseDirectory;
                string serviceExePath = Path.Combine(appDir, "Tether.CommunicationService.exe");

                if (!File.Exists(serviceExePath))
                {
                    string solutionDir = Path.GetFullPath(Path.Combine(appDir, "..", "..", "..", "..", ".."));
                    string commBin = Path.Combine(solutionDir, "services", "communication-service", "Tether.CommunicationService", "bin", "Debug");
                    if (Directory.Exists(commBin))
                    {
                        var matches = Directory.GetFiles(commBin, "Tether.CommunicationService.exe", SearchOption.AllDirectories);
                        if (matches.Length > 0) serviceExePath = matches[0];
                    }
                }

                if (File.Exists(serviceExePath))
                {
                    Process.Start(new ProcessStartInfo
                    {
                        FileName = serviceExePath,
                        UseShellExecute = true,
                        CreateNoWindow = false
                    });
                    log("Tether service started.");
                    return true;
                }

                log("Could not find the Tether service program.");
                return false;
            }
            catch (Exception ex)
            {
                log($"Could not start the Tether service: {ex.Message}");
                return false;
            }
        }
    }
}
