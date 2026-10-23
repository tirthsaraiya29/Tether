package com.tether.phone

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import android.os.Environment
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import kotlinx.coroutines.yield
import java.io.File
import java.io.FileInputStream
import java.security.MessageDigest
import java.util.Locale

class AndroidFilesystemIndexer(private val context: Context) {
    companion object {
        private const val TAG = "AndroidFsIndexer"
        const val DB_NAME = "android_fs.db"
        private const val DB_VERSION = 2
        private const val HASH_BUFFER_SIZE = 65536 // 64 KB
        private const val MAX_HASH_SIZE_BYTES = 100 * 1024 * 1024L // Hash files up to 100MB directly

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
            db.execSQL("DROP TABLE IF EXISTS files")
            onCreate(db)
        }
    }

    suspend fun buildDatabase(): File = withContext(Dispatchers.IO) {
        Log.i(TAG, "Building Android filesystem database with SHA-256 hashes...")
        val db = dbHelper.writableDatabase
        db.beginTransaction()
        try {
            db.execSQL("DELETE FROM files")

            val roots = getStorageRoots()
            var estimatedTotal = 0
            for (root in roots) {
                estimatedTotal += countFiles(root)
            }

            _indexingProgressFlow.value = IndexingProgress(
                scannedFiles = 0,
                totalFilesEstimated = estimatedTotal,
                currentPath = "Starting index...",
                isFinished = false
            )

            var scannedCount = 0
            for (root in roots) {
                scannedCount = scanAndHashDirectory(db, root, "/", scannedCount, estimatedTotal)
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

    private fun countFiles(dir: File): Int {
        val files = dir.listFiles() ?: return 0
        var count = 0
        for (f in files) {
            if (f.name.startsWith(".")) continue
            count++
            if (f.isDirectory) {
                count += countFiles(f)
            }
        }
        return count
    }

    private suspend fun scanAndHashDirectory(
        db: SQLiteDatabase,
        dir: File,
        parentPath: String,
        initialScanned: Int,
        totalEstimate: Int
    ): Int {
        val files = dir.listFiles() ?: return initialScanned
        var scanned = initialScanned

        val statement = db.compileStatement(
            "INSERT OR IGNORE INTO files (parent_path, name, path, is_directory, size, last_modified, sha256) VALUES (?, ?, ?, ?, ?, ?, ?)"
        )

        for (file in files) {
            if (file.name.startsWith(".")) continue

            val isDir = file.isDirectory
            val path = file.absolutePath
            val length = if (isDir) 0L else file.length()
            val sha256 = if (!isDir) computeFileSha256Throttled(file) else ""

            statement.clearBindings()
            statement.bindString(1, parentPath)
            statement.bindString(2, file.name)
            statement.bindString(3, path)
            statement.bindLong(4, if (isDir) 1L else 0L)
            statement.bindLong(5, length)
            statement.bindLong(6, file.lastModified())
            statement.bindString(7, sha256)
            statement.executeInsert()

            scanned++
            if (scanned % 10 == 0 || scanned == totalEstimate) {
                _indexingProgressFlow.value = IndexingProgress(
                    scannedFiles = scanned,
                    totalFilesEstimated = maxOf(totalEstimate, scanned),
                    currentPath = file.name,
                    isFinished = false
                )
                yield() // Cooperatively release CPU execution
            }

            if (isDir) {
                scanned = scanAndHashDirectory(db, file, path, scanned, totalEstimate)
            }
        }

        return scanned
    }

    private suspend fun computeFileSha256Throttled(file: File): String {
        if (!file.exists() || !file.canRead() || file.length() == 0L) return ""
        return try {
            val digest = MessageDigest.getInstance("SHA-256")
            val buffer = ByteArray(HASH_BUFFER_SIZE)
            var bytesReadTotal = 0L
            var readCount = 0

            FileInputStream(file).use { fis ->
                while (bytesReadTotal < MAX_HASH_SIZE_BYTES) {
                    val read = fis.read(buffer)
                    if (read <= 0) break
                    digest.update(buffer, 0, read)
                    bytesReadTotal += read
                    readCount++

                    if (readCount % 16 == 0) {
                        yield() // Yield every 1MB read to prevent UI/CPU stutter
                    }
                }
            }
            digest.digest().joinToString("") { String.format(Locale.US, "%02x", it) }
        } catch (e: Exception) {
            ""
        }
    }
}
