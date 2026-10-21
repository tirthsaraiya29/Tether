using System;
using System.Collections.Generic;
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
            _logger.Info("Building Windows filesystem database...");

            if (File.Exists(_dbPath))
            {
                File.Delete(_dbPath);
            }

            using var connection = new SqliteConnection($"Data Source={_dbPath}");
            connection.Open();

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
                try
                {
                    string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                    ScanDirectory(connection, transaction, userProfile, "/");

                    // Optionally add Drives
                    foreach (var drive in DriveInfo.GetDrives())
                    {
                        if (drive.IsReady && drive.RootDirectory.FullName != Path.GetPathRoot(userProfile))
                        {
                            InsertRecord(connection, transaction, "/", drive.Name, drive.RootDirectory.FullName, true, 0, 0);
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

            _logger.Info($"Finished building DB. Size: {new FileInfo(_dbPath).Length} bytes");
            return _dbPath;
        }

        private void ScanDirectory(SqliteConnection connection, SqliteTransaction transaction, string dirPath, string parentPath)
        {
            try
            {
                var dirInfo = new DirectoryInfo(dirPath);

                InsertRecord(connection, transaction, parentPath, dirInfo.Name, dirInfo.FullName, true, 0, new DateTimeOffset(dirInfo.LastWriteTimeUtc).ToUnixTimeMilliseconds());

                // Avoid scanning Windows or Program Files completely by default to save time
                if (dirInfo.Name.Equals("Windows", StringComparison.OrdinalIgnoreCase) ||
                    dirInfo.Name.Equals("Program Files", StringComparison.OrdinalIgnoreCase) ||
                    dirInfo.Name.Equals("Program Files (x86)", StringComparison.OrdinalIgnoreCase) ||
                    dirInfo.Name.StartsWith("."))
                {
                    return;
                }

                foreach (var dir in dirInfo.GetDirectories())
                {
                    if ((dir.Attributes & FileAttributes.Hidden) == FileAttributes.Hidden) continue;
                    ScanDirectory(connection, transaction, dir.FullName, dirInfo.FullName);
                }

                foreach (var file in dirInfo.GetFiles())
                {
                    if ((file.Attributes & FileAttributes.Hidden) == FileAttributes.Hidden) continue;
                    InsertRecord(connection, transaction, dirInfo.FullName, file.Name, file.FullName, false, file.Length, new DateTimeOffset(file.LastWriteTimeUtc).ToUnixTimeMilliseconds());
                }
            }
            catch (UnauthorizedAccessException) { /* Ignore */ }
            catch (Exception ex)
            {
                _logger.Warning($"Error scanning {dirPath}: {ex.Message}");
            }
        }

        private void InsertRecord(SqliteConnection connection, SqliteTransaction transaction, string parentPath, string name, string path, bool isDirectory, long size, long lastModified)
        {
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = "INSERT OR IGNORE INTO files (parent_path, name, path, is_directory, size, last_modified) VALUES ($parent, $name, $path, $isDir, $size, $lastMod)";
            command.Parameters.AddWithValue("$parent", parentPath);
            command.Parameters.AddWithValue("$name", name);
            command.Parameters.AddWithValue("$path", path);
            command.Parameters.AddWithValue("$isDir", isDirectory ? 1 : 0);
            command.Parameters.AddWithValue("$size", size);
            command.Parameters.AddWithValue("$lastMod", lastModified);
            command.ExecuteNonQuery();
        }
    }
}
