using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using Tether.Shared.Events;
using Tether.Shared.IPC;

namespace Tether.DesktopUI
{
    public partial class App : Application
    {
        private static Mutex? _singleInstanceMutex;
        private const string MutexName = "TetherDesktopUISingleInstanceMutex";
        private const string InstancePipeName = "TetherDesktopUIInstancePipe";
        private CancellationTokenSource? _pipeCts;

        protected override void OnStartup(StartupEventArgs e)
        {
            // Intercept fatal XAML and UI Thread crashes
            this.DispatcherUnhandledException += (sender, args) =>
            {
                MessageBox.Show($"UI Crash: {args.Exception.Message}\n\n{args.Exception.InnerException?.Message}",
                                "Tether Fatal Error",
                                MessageBoxButton.OK,
                                MessageBoxImage.Error);

                args.Handled = true;
                Environment.Exit(1);
            };

            // Intercept background thread and early memory allocation crashes
            AppDomain.CurrentDomain.UnhandledException += (sender, args) =>
            {
                if (args.ExceptionObject is Exception ex)
                {
                    MessageBox.Show($"Core Crash: {ex.Message}\n\n{ex.InnerException?.Message}",
                                    "Tether Fatal Error",
                                    MessageBoxButton.OK,
                                    MessageBoxImage.Error);
                }
            };

            // Check for elevated helper commands before single instance check
            if (e.Args.Length > 0 && e.Args[0].Equals("--commit-vault-payload", StringComparison.OrdinalIgnoreCase))
            {
                if (e.Args.Length > 1)
                {
                    try
                    {
                        byte[] payload = Convert.FromHexString(e.Args[1]);
                        using var secretsKey = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Tether\CredentialProvider\Secrets", true);
                        secretsKey?.SetValue("EncryptedPassword", payload, Microsoft.Win32.RegistryValueKind.Binary);

                        using var rootKey = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Tether\CredentialProvider", true);
                        rootKey?.SetValue("VaultDaclVersion", 2, Microsoft.Win32.RegistryValueKind.DWord);
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show($"Failed writing vault secret: {ex.Message}", "Tether Vault Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    }
                }
                Environment.Exit(0);
                return;
            }

            _singleInstanceMutex = new Mutex(true, MutexName, out bool isNewInstance);

            if (!isNewInstance)
            {
                // Send arguments to running instance and exit duplicate process
                SendArgsToRunningInstance(e.Args);
                Environment.Exit(0);
                return;
            }

            // Start pipe server to receive args from secondary instances
            StartInstancePipeServer();

            base.OnStartup(e);

            // Handle initial launch arguments if any
            if (e.Args.Length > 0)
            {
                ProcessLaunchArgs(e.Args);
            }
        }

        private static void SendArgsToRunningInstance(string[] args)
        {
            try
            {
                using var client = new NamedPipeClientStream(".", InstancePipeName, PipeDirection.Out);
                client.Connect(1000);
                string json = JsonSerializer.Serialize(args);
                byte[] bytes = Encoding.UTF8.GetBytes(json);
                client.Write(bytes, 0, bytes.Length);
            }
            catch { }
        }

        private void StartInstancePipeServer()
        {
            _pipeCts = new CancellationTokenSource();
            Task.Run(async () =>
            {
                while (!_pipeCts.Token.IsCancellationRequested)
                {
                    try
                    {
                        using var server = new NamedPipeServerStream(InstancePipeName, PipeDirection.In, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
                        await server.WaitForConnectionAsync(_pipeCts.Token);

                        using var ms = new MemoryStream();
                        await server.CopyToAsync(ms, _pipeCts.Token);
                        string json = Encoding.UTF8.GetString(ms.ToArray());
                        var args = JsonSerializer.Deserialize<string[]>(json);

                        if (args != null && args.Length > 0)
                        {
                            Dispatcher.Invoke(() =>
                            {
                                ProcessLaunchArgs(args);
                                if (MainWindow != null)
                                {
                                    if (MainWindow.WindowState == WindowState.Minimized)
                                        MainWindow.WindowState = WindowState.Normal;
                                    MainWindow.Activate();
                                }
                            });
                        }
                    }
                    catch (OperationCanceledException) { break; }
                    catch { }
                }
            }, _pipeCts.Token);
        }

        public static void ProcessLaunchArgs(string[] args) => ProcessLaunchArgs(args, out _);

        public static bool ProcessLaunchArgs(string[] args, out string? errorMessage)
        {
            errorMessage = null;
            return true;
        }
    }
}
