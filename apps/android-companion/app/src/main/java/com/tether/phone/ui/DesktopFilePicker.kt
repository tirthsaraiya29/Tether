package com.tether.phone.ui

import android.database.sqlite.SQLiteDatabase
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.InsertDriveFile
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

data class FsNode(val name: String, val path: String, val isDir: Boolean, val size: Long)

@Composable
fun DesktopFilePicker() {
    val context = LocalContext.current
    var currentPath by remember { mutableStateOf("/") }
    var files by remember { mutableStateOf(emptyList<FsNode>()) }
    var dbExists by remember { mutableStateOf(false) }

    LaunchedEffect(currentPath) {
        withContext(Dispatchers.IO) {
            val dbFile = context.getDatabasePath("windows_fs.db")
            if (dbFile.exists()) {
                dbExists = true
                val db = SQLiteDatabase.openDatabase(dbFile.absolutePath, null, SQLiteDatabase.OPEN_READONLY)
                val cursor = db.rawQuery("SELECT name, path, is_directory, size FROM files WHERE parent_path = ? ORDER BY is_directory DESC, name ASC", arrayOf(currentPath))
                val list = mutableListOf<FsNode>()
                while (cursor.moveToNext()) {
                    list.add(FsNode(
                        name = cursor.getString(0),
                        path = cursor.getString(1),
                        isDir = cursor.getInt(2) == 1,
                        size = cursor.getLong(3)
                    ))
                }
                cursor.close()
                db.close()
                withContext(Dispatchers.Main) { files = list }
            } else {
                dbExists = false
            }
        }
    }

    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        Text("Windows PC Files", style = MaterialTheme.typography.titleLarge)
        if (!dbExists) {
            Text("No Windows filesystem sync data found yet. Send a sync request from the PC.")
        } else {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Button(onClick = { 
                    val lastSlash = currentPath.lastIndexOf('/')
                    if (lastSlash > 0) {
                        currentPath = currentPath.substring(0, lastSlash)
                    } else if (currentPath != "/") {
                        currentPath = "/"
                    }
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
                                Text("${file.size / 1024} KB", style = MaterialTheme.typography.bodySmall)
                            }
                        }
                    }
                }
            }
        }
    }
}
