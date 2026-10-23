using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using Tether.Shared.Logging;

namespace Tether.FileTransfer
{
    public class WindowsFilesystemIndexer
    {
        private readonly ITetherLogger _logger;
        private readonly string _dbPath;
        private const string DbName = "windows_fs.db";

        public WindowsFilesystemIndexer(ITetherLogger logger)
        {
            _logger = logger;
            string commonData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            _dbPath = Path.Combine(commonData, "Tether", DbName);
            Directory.CreateDirectory(Path.GetDirectoryName(_dbPath)!);
        }

        public async Task<string> BuildDatabaseAsync()
        {
            return await Task.Run(() =>
            {
                _logger.Info("Building Windows filesystem database...");

                if (File.Exists(_dbPath))
                {
                    try { File.Delete(_dbPath); } catch { }
                }

                using var connection = new SqliteConnection($"Data Source={_dbPath}");
                connection.Open();

                using (var cmd = connection.CreateCommand())
                {
                    cmd.CommandText = "PRAGMA journal_mode=DELETE; PRAGMA synchronous=OFF;";
                    cmd.ExecuteNonQuery();
                }

                using (var command = connection.CreateCommand())
                {
                    command.CommandText = @"
                        CREATE TABLE files (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            parent_path TEXT,
                            name TEXT,
                            path TEXT UNIQUE,
                            is_directory INTEGER,
                            size INTEGER,
                            last_modified INTEGER
                        );
                        CREATE INDEX idx_parent ON files(parent_path);
                    ";
                    command.ExecuteNonQuery();
                }

                using (var transaction = connection.BeginTransaction())
                {
                    using var insertCmd = connection.CreateCommand();
                    insertCmd.Transaction = transaction;
                    insertCmd.CommandText = "INSERT OR IGNORE INTO files (parent_path, name, path, is_directory, size, last_modified) VALUES ($parent, $name, $path, $isDir, $size, $lastMod)";

                    var parentParam = insertCmd.Parameters.Add("$parent", SqliteType.Text);
                    var nameParam = insertCmd.Parameters.Add("$name", SqliteType.Text);
                    var pathParam = insertCmd.Parameters.Add("$path", SqliteType.Text);
                    var isDirParam = insertCmd.Parameters.Add("$isDir", SqliteType.Integer);
                    var sizeParam = insertCmd.Parameters.Add("$size", SqliteType.Integer);
                    var lastModParam = insertCmd.Parameters.Add("$lastMod", SqliteType.Integer);

                    try
                    {
                        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                        ScanDirectory(insertCmd, parentParam, nameParam, pathParam, isDirParam, sizeParam, lastModParam, userProfile, "/");

                        // Add Drives
                        foreach (var drive in DriveInfo.GetDrives())
                        {
                            if (drive.IsReady && drive.RootDirectory.FullName != Path.GetPathRoot(userProfile))
                            {
                                InsertRecord(insertCmd, parentParam, nameParam, pathParam, isDirParam, sizeParam, lastModParam,
                                    "/", drive.Name, drive.RootDirectory.FullName, true, 0, 0);
                            }
                        }

                        transaction.Commit();
                    }
                    catch (Exception ex)
                    {
                        _logger.Error($"Error building Windows DB: {ex.Message}");
                        transaction.Rollback();
                    }
                }

                connection.Close();
                SqliteConnection.ClearPool(connection);

                _logger.Info($"Finished building DB. Size: {new FileInfo(_dbPath).Length} bytes");
                return _dbPath;
            });
        }

        private void ScanDirectory(
            SqliteCommand insertCmd,
            SqliteParameter parentParam,
            SqliteParameter nameParam,
            SqliteParameter pathParam,
            SqliteParameter isDirParam,
            SqliteParameter sizeParam,
            SqliteParameter lastModParam,
            string dirPath,
            string parentPath)
        {
            try
            {
                var dirInfo = new DirectoryInfo(dirPath);

                InsertRecord(insertCmd, parentParam, nameParam, pathParam, isDirParam, sizeParam, lastModParam,
                    parentPath, dirInfo.Name, dirInfo.FullName, true, 0, new DateTimeOffset(dirInfo.LastWriteTimeUtc).ToUnixTimeMilliseconds());

                // Skip scanning heavy system/temp/cache directories to ensure fast indexing
                if (dirInfo.Name.Equals("Windows", StringComparison.OrdinalIgnoreCase) ||
                    dirInfo.Name.Equals("Program Files", StringComparison.OrdinalIgnoreCase) ||
                    dirInfo.Name.Equals("Program Files (x86)", StringComparison.OrdinalIgnoreCase) ||
                    dirInfo.Name.Equals("AppData", StringComparison.OrdinalIgnoreCase) ||
                    dirInfo.Name.Equals("Application Data", StringComparison.OrdinalIgnoreCase) ||
                    dirInfo.Name.Equals("Temp", StringComparison.OrdinalIgnoreCase) ||
                    dirInfo.Name.Equals("Package Cache", StringComparison.OrdinalIgnoreCase) ||
                    dirInfo.Name.Equals("$Recycle.Bin", StringComparison.OrdinalIgnoreCase) ||
                    dirInfo.Name.Equals(".git", StringComparison.OrdinalIgnoreCase) ||
                    dirInfo.Name.Equals("node_modules", StringComparison.OrdinalIgnoreCase) ||
                    dirInfo.Name.StartsWith("."))
                {
                    return;
                }

                foreach (var dir in dirInfo.GetDirectories())
                {
                    if ((dir.Attributes & FileAttributes.Hidden) == FileAttributes.Hidden) continue;
                    ScanDirectory(insertCmd, parentParam, nameParam, pathParam, isDirParam, sizeParam, lastModParam, dir.FullName, dirInfo.FullName);
                }

                foreach (var file in dirInfo.GetFiles())
                {
                    if ((file.Attributes & FileAttributes.Hidden) == FileAttributes.Hidden) continue;
                    InsertRecord(insertCmd, parentParam, nameParam, pathParam, isDirParam, sizeParam, lastModParam,
                        dirInfo.FullName, file.Name, file.FullName, false, file.Length, new DateTimeOffset(file.LastWriteTimeUtc).ToUnixTimeMilliseconds());
                }
            }
            catch (UnauthorizedAccessException) { /* Ignore */ }
            catch (Exception ex)
            {
                _logger.Warning($"Error scanning {dirPath}: {ex.Message}");
            }
        }

        private static void InsertRecord(
            SqliteCommand command,
            SqliteParameter parentParam,
            SqliteParameter nameParam,
            SqliteParameter pathParam,
            SqliteParameter isDirParam,
            SqliteParameter sizeParam,
            SqliteParameter lastModParam,
            string parentPath,
            string name,
            string path,
            bool isDirectory,
            long size,
            long lastModified)
        {
            parentParam.Value = parentPath;
            nameParam.Value = name;
            pathParam.Value = path;
            isDirParam.Value = isDirectory ? 1 : 0;
            sizeParam.Value = size;
            lastModParam.Value = lastModified;
            command.ExecuteNonQuery();
        }
    }
}
