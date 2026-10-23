package com.tether.phone

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import android.database.sqlite.SQLiteStatement
import android.os.Environment
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import kotlinx.coroutines.yield
import java.io.File

class AndroidFilesystemIndexer(private val context: Context) {
    companion object {
        private const val TAG = "AndroidFsIndexer"
        const val DB_NAME = "android_fs.db"
        private const val DB_VERSION = 3

        private val _indexingProgressFlow = MutableStateFlow(IndexingProgress())
        val indexingProgressFlow: StateFlow<IndexingProgress> = _indexingProgressFlow.asStateFlow()
    }

    private val dbHelper = object : SQLiteOpenHelper(context, DB_NAME, null, DB_VERSION) {
        override fun onConfigure(db: SQLiteDatabase) {
            super.onConfigure(db)
            db.disableWriteAheadLogging()
        }

        override fun onCreate(db: SQLiteDatabase) {
            db.execSQL("""
                CREATE TABLE roots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT,
                    path TEXT UNIQUE,
                    root_type TEXT
                )
            """)
            db.execSQL("""
                CREATE TABLE files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    parent_path TEXT,
                    name TEXT,
                    path TEXT UNIQUE,
                    is_directory INTEGER,
                    size INTEGER,
                    last_modified INTEGER,
                    sha256 TEXT
                )
            """)
            db.execSQL("CREATE INDEX idx_parent ON files(parent_path)")
        }

        override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
            db.execSQL("DROP TABLE IF EXISTS roots")
            db.execSQL("DROP TABLE IF EXISTS files")
            onCreate(db)
        }
    }

    suspend fun buildDatabase(): File = withContext(Dispatchers.IO) {
        Log.i(TAG, "Building Android filesystem database...")
        val db = dbHelper.writableDatabase
        db.execSQL("PRAGMA synchronous = OFF")
        db.beginTransaction()
        try {
            db.execSQL("DELETE FROM roots")
            db.execSQL("DELETE FROM files")

            val roots = getStorageRoots()
            val rootStatement = db.compileStatement("INSERT OR IGNORE INTO roots (name, path, root_type) VALUES (?, ?, ?)")
            for (root in roots) {
                rootStatement.clearBindings()
                val rootName = when {
                    root.absolutePath.contains("emulated") -> "Internal Storage"
                    root.name.equals("Download", ignoreCase = true) -> "Downloads"
                    else -> "Storage (${root.name})"
                }
                rootStatement.bindString(1, rootName)
                rootStatement.bindString(2, root.absolutePath)
                rootStatement.bindString(3, "STORAGE")
                rootStatement.executeInsert()
            }

            _indexingProgressFlow.value = IndexingProgress(
                scannedFiles = 0,
                totalFilesEstimated = 0,
                currentPath = "Starting fast index...",
                isFinished = false
            )

            val fileStatement = db.compileStatement(
                "INSERT OR IGNORE INTO files (parent_path, name, path, is_directory, size, last_modified, sha256) VALUES (?, ?, ?, ?, ?, ?, ?)"
            )

            var scannedCount = 0
            for (root in roots) {
                scannedCount = scanDirectoryFast(fileStatement, root, root.absolutePath, scannedCount)
            }

            db.setTransactionSuccessful()
            _indexingProgressFlow.value = IndexingProgress(
                scannedFiles = scannedCount,
                totalFilesEstimated = scannedCount,
                currentPath = "Index complete",
                isFinished = true
            )
        } catch (e: Exception) {
            Log.e(TAG, "Error building DB: ${e.message}", e)
            _indexingProgressFlow.value = IndexingProgress(
                isFinished = true,
                errorMessage = e.message
            )
        } finally {
            db.endTransaction()
            db.close()
        }

        val dbFile = context.getDatabasePath(DB_NAME)
        Log.i(TAG, "Finished building DB. Size: ${dbFile.length()} bytes")
        return@withContext dbFile
    }

    private fun getStorageRoots(): List<File> {
        val roots = mutableListOf<File>()

        val primary = Environment.getExternalStorageDirectory()
        if (primary != null && primary.exists()) {
            roots.add(primary)
        }

        // Secondary / mounted storage dirs
        val extDirs = context.getExternalFilesDirs(null)
        if (extDirs != null) {
            for (f in extDirs) {
                if (f != null) {
                    var current = f
                    while (current.parentFile != null && current.parentFile?.name != "Android") {
                        current = current.parentFile!!
                    }
                    val mountRoot = current.parentFile ?: current
                    if (mountRoot.exists() && mountRoot.canRead() && !roots.contains(mountRoot)) {
                        roots.add(mountRoot)
                    }
                }
            }
        }

        val storageDir = File("/storage")
        if (storageDir.exists() && storageDir.isDirectory) {
            storageDir.listFiles()?.forEach { file ->
                if (file.isDirectory && file.canRead() && !file.name.equals("self", ignoreCase = true) &&
                    !file.name.equals("emulated", ignoreCase = true) && !roots.contains(file)) {
                    roots.add(file)
                }
            }
        }

        return roots
    }

    private suspend fun scanDirectoryFast(
        statement: SQLiteStatement,
        dir: File,
        parentPath: String,
        initialScanned: Int,
    ): Int {
        val files = dir.listFiles() ?: return initialScanned
        var scanned = initialScanned

        for (file in files) {
            val name = file.name
            if (name.startsWith(".") ||
                name.equals("LOST.DIR", ignoreCase = true) ||
                name.equals("Android", ignoreCase = true) ||
                name.equals("System Volume Information", ignoreCase = true)) {
                continue
            }

            val isDir = file.isDirectory
            val path = file.absolutePath
            val length = if (isDir) 0L else file.length()

            statement.clearBindings()
            statement.bindString(1, parentPath)
            statement.bindString(2, name)
            statement.bindString(3, path)
            statement.bindLong(4, if (isDir) 1L else 0L)
            statement.bindLong(5, length)
            statement.bindLong(6, file.lastModified())
            statement.bindString(7, "") // Fast scan omits SHA-256 calculation
            statement.executeInsert()

            scanned++
            if (scanned % 100 == 0) {
                _indexingProgressFlow.value = IndexingProgress(
                    scannedFiles = scanned,
                    totalFilesEstimated = scanned,
                    currentPath = name,
                    isFinished = false
                )
                yield() // Cooperatively yield execution
            }

            if (isDir) {
                scanned = scanDirectoryFast(statement, file, path, scanned)
            }
        }

        return scanned
    }
}
