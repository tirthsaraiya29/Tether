package com.tether.phone.ui

import android.database.sqlite.SQLiteDatabase
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.InsertDriveFile
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.tether.phone.TetherLanService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

data class FsNode(val name: String, val path: String, val isDir: Boolean, val size: Long)

@Composable
fun DesktopFilePicker() {
    val context = LocalContext.current
    var currentPath by remember { mutableStateOf("/") }
    var files by remember { mutableStateOf(emptyList<FsNode>()) }
    var dbExists by remember { mutableStateOf(false) }
    var isLoading by remember { mutableStateOf(false) }

    val reloadDb = {
        isLoading = true
        val dbFile = context.getDatabasePath("windows_fs.db")
        if (dbFile.exists()) {
            dbExists = true
            try {
                SQLiteDatabase.openDatabase(dbFile.absolutePath, null, SQLiteDatabase.OPEN_READONLY).use { db ->
                    val normPath = currentPath.replace('/', '\\')
                    val altPath = currentPath.replace('\\', '/')
                    db.rawQuery(
                        "SELECT name, path, is_directory, size FROM files WHERE parent_path = ? OR parent_path = ? OR REPLACE(parent_path, '/', '\\') = ? ORDER BY is_directory DESC, name ASC",
                        arrayOf(currentPath, altPath, normPath)
                    ).use { cursor ->
                        val list = mutableListOf<FsNode>()
                        while (cursor.moveToNext()) {
                            list.add(FsNode(
                                name = cursor.getString(0),
                                path = cursor.getString(1),
                                isDir = cursor.getInt(2) == 1,
                                size = cursor.getLong(3)
                            ))
                        }
                        files = list
                    }
                }
            } catch (_: Exception) { }
        } else {
            dbExists = false
        }
        isLoading = false
    }

    LaunchedEffect(currentPath) {
        withContext(Dispatchers.IO) {
            reloadDb()
        }
    }

    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text("Windows PC Files", style = MaterialTheme.typography.titleLarge)
            IconButton(onClick = {
                val service = TetherLanService.instance
                val hostIp = service?.connectedHostAddress
                if (service != null && !hostIp.isNullOrBlank()) {
                    service.fileTransferManager.requestWindowsDbSync(service.securityEngine, hostIp)
                }
            }) {
                Icon(Icons.Default.Refresh, contentDescription = "Sync PC Files")
            }
        }

        if (isLoading) {
            LinearProgressIndicator(modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp))
        }

        if (!dbExists) {
            Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Text("Auto-syncing Windows filesystem... Please wait.")
            }
        } else {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Button(onClick = { 
                    val lastSlash = maxOf(currentPath.lastIndexOf('/'), currentPath.lastIndexOf('\\'))
                    var targetPath = if (lastSlash > 0) currentPath.substring(0, lastSlash) else "/"
                    val dbFile = context.getDatabasePath("windows_fs.db")
                    if (dbFile.exists() && targetPath != "/") {
                        try {
                            val db = SQLiteDatabase.openDatabase(dbFile.absolutePath, null, SQLiteDatabase.OPEN_READONLY)
                            val normTarget = targetPath.replace('/', '\\')
                            val cursor = db.rawQuery("SELECT COUNT(1) FROM files WHERE parent_path = ? OR parent_path = ?", arrayOf(targetPath, normTarget))
                            if (cursor.moveToFirst() && cursor.getInt(0) == 0) {
                                targetPath = "/"
                            }
                            cursor.close()
                            db.close()
                        } catch (_: Exception) { }
                    }
                    currentPath = targetPath
                }, enabled = currentPath != "/") {
                    Text("Up")
                }
                Spacer(Modifier.width(8.dp))
                Text(currentPath, style = MaterialTheme.typography.bodyMedium)
            }
            Spacer(Modifier.height(8.dp))
            LazyColumn(modifier = Modifier.fillMaxSize()) {
                items(files) { file ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable {
                                if (file.isDir) {
                                    currentPath = file.path
                                } else {
                                    val service = TetherLanService.instance
                                    val hostIp = service?.connectedHostAddress
                                    if (service != null && !hostIp.isNullOrBlank()) {
                                        service.fileTransferManager.requestWindowsFileDownload(
                                            service.securityEngine,
                                            hostIp,
                                            remotePath = file.path
                                        )
                                    }
                                }
                            }
                            .padding(vertical = 12.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            imageVector = if (file.isDir) Icons.Default.Folder else Icons.Default.InsertDriveFile,
                            contentDescription = null
                        )
                        Spacer(Modifier.width(16.dp))
                        Column {
                            Text(file.name)
                            if (!file.isDir) {
                                Text("${file.size / 1024} KB • Tap to Download", style = MaterialTheme.typography.bodySmall)
                            }
                        }
                    }
                }
            }
        }
    }
}
