package com.tether.phone

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import android.os.Environment
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

class AndroidFilesystemIndexer(private val context: Context) {
    companion object {
        private const val TAG = "AndroidFsIndexer"
        const val DB_NAME = "android_fs.db"
        private const val DB_VERSION = 1
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
                    last_modified INTEGER
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
        Log.i(TAG, "Building Android filesystem database...")
        val db = dbHelper.writableDatabase
        db.beginTransaction()
        try {
            db.execSQL("DELETE FROM files")
            val root = Environment.getExternalStorageDirectory()
            scanDirectory(db, root, "/")
            db.setTransactionSuccessful()
        } catch (e: Exception) {
            Log.e(TAG, "Error building DB: ${e.message}", e)
        } finally {
            db.endTransaction()
            db.close()
        }
        
        val dbFile = context.getDatabasePath(DB_NAME)
        Log.i(TAG, "Finished building DB. Size: ${dbFile.length()} bytes")
        return@withContext dbFile
    }

    private fun scanDirectory(db: SQLiteDatabase, dir: File, parentPath: String) {
        val files = dir.listFiles() ?: return
        val statement = db.compileStatement(
            "INSERT INTO files (parent_path, name, path, is_directory, size, last_modified) VALUES (?, ?, ?, ?, ?, ?)"
        )
        
        for (file in files) {
            if (file.name.startsWith(".")) continue
            
            val isDir = file.isDirectory
            val path = file.absolutePath
            
            statement.clearBindings()
            statement.bindString(1, parentPath)
            statement.bindString(2, file.name)
            statement.bindString(3, path)
            statement.bindLong(4, if (isDir) 1L else 0L)
            statement.bindLong(5, if (isDir) 0L else file.length())
            statement.bindLong(6, file.lastModified())
            statement.executeInsert()
            
            if (isDir) {
                scanDirectory(db, file, path)
            }
        }
    }
}
