package com.tether.phone.ui.screens

import android.content.Intent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.InsertDriveFile
import androidx.compose.material.icons.filled.Upload
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.tether.phone.FileNode
import com.tether.phone.FileTransferClient
import com.tether.phone.ui.components.DeepSpaceCanvasVisualizer
import com.tether.phone.ui.components.ProfessionalGlassSurface
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FileTransferScreen(
    onBack: () -> Unit
) {
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()
    var currentPath by remember { mutableStateOf<String?>(null) }
    var files by remember { mutableStateOf<List<FileNode>>(emptyList()) }
    var isLoading by remember { mutableStateOf(false) }
    var errorMessage by remember { mutableStateOf<String?>(null) }
    
    var pendingDownloadFile by remember { mutableStateOf<FileNode?>(null) }
    
    var token by remember { mutableStateOf<String?>(null) }
    val service = com.tether.phone.TetherLanService.instance
    val hostIp = service?.connectedHostAddress

    val downloadLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("*/*")
    ) { uri ->
        uri?.let { destUri ->
            pendingDownloadFile?.let { fileNode ->
                coroutineScope.launch {
                    try {
                        if (hostIp == null || token == null) throw Exception("Not connected or no token")
                        isLoading = true
                        FileTransferClient.downloadFile(hostIp, fileNode.path, destUri, context, token!!)
                    } catch (e: Exception) {
                        errorMessage = e.message
                    } finally {
                        isLoading = false
                        pendingDownloadFile = null
                    }
                }
            }
        }
    }

    val uploadLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri ->
        uri?.let { sourceUri ->
            coroutineScope.launch {
                try {
                    if (hostIp == null || token == null) throw Exception("Not connected or no token")
                    isLoading = true
                    FileTransferClient.uploadFile(hostIp, sourceUri, currentPath ?: "", context, token!!)
                    // Refresh
                    files = FileTransferClient.listDirectory(hostIp, currentPath, token!!, context)
                } catch (e: Exception) {
                    errorMessage = e.message
                } finally {
                    isLoading = false
                }
            }
        }
    }

    LaunchedEffect(currentPath, token) {
        if (token != null && hostIp != null) {
            try {
                isLoading = true
                files = FileTransferClient.listDirectory(hostIp, currentPath, token!!, context)
            } catch (e: Exception) {
                errorMessage = e.message
            } finally {
                isLoading = false
            }
        }
    }

    LaunchedEffect(Unit) {
        if (service != null && hostIp != null) {
            try {
                isLoading = true
                token = service.requestFileTransferToken()
            } catch (e: Exception) {
                errorMessage = "Failed to get file transfer token: ${e.message}"
            } finally {
                isLoading = false
            }
        } else {
            errorMessage = "Not connected to a host"
        }
    }

    Box(modifier = Modifier.fillMaxSize()) {
        DeepSpaceCanvasVisualizer()
        Scaffold(
            topBar = {
                TopAppBar(
                    title = { Text(currentPath ?: "Root", maxLines = 1) },
                    navigationIcon = {
                        IconButton(onClick = {
                            if (currentPath == null) {
                                onBack()
                            } else {
                                // Simple path up
                                val segments = currentPath!!.split("/").filter { it.isNotEmpty() }
                                if (segments.size <= 1) {
                                    currentPath = null
                                } else {
                                    currentPath = segments.dropLast(1).joinToString("/")
                                }
                            }
                        }) {
                            Icon(Icons.Default.ArrowBack, contentDescription = "Back")
                        }
                    },
                    colors = TopAppBarDefaults.topAppBarColors(
                        containerColor = androidx.compose.ui.graphics.Color.Transparent
                    )
                )
            },
            floatingActionButton = {
                FloatingActionButton(onClick = {
                    uploadLauncher.launch(arrayOf("*/*"))
                }) {
                    Icon(Icons.Default.Upload, contentDescription = "Upload")
                }
            },
            containerColor = androidx.compose.ui.graphics.Color.Transparent
        ) { padding ->
            Box(modifier = Modifier.padding(padding).fillMaxSize()) {
                if (isLoading) {
                    CircularProgressIndicator(modifier = Modifier.align(Alignment.Center))
                } else if (errorMessage != null) {
                    Text(
                        text = errorMessage!!,
                        color = MaterialTheme.colorScheme.error,
                        modifier = Modifier.align(Alignment.Center).padding(16.dp)
                    )
                } else {
                    LazyColumn(modifier = Modifier.fillMaxSize()) {
                        items(files) { file ->
                            ProfessionalGlassSurface(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(horizontal = 16.dp, vertical = 8.dp)
                                    .clickable {
                                        if (file.isDirectory) {
                                            currentPath = file.path
                                        } else {
                                            pendingDownloadFile = file
                                            downloadLauncher.launch(file.name)
                                        }
                                    }
                            ) {
                                Row(
                                    modifier = Modifier.padding(16.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Icon(
                                        imageVector = if (file.isDirectory) Icons.Default.Folder else Icons.Default.InsertDriveFile,
                                        contentDescription = null,
                                        tint = MaterialTheme.colorScheme.primary
                                    )
                                    Spacer(modifier = Modifier.width(16.dp))
                                    Column {
                                        Text(file.name, fontWeight = FontWeight.Bold)
                                        if (!file.isDirectory) {
                                            Text("${file.size} bytes", style = MaterialTheme.typography.bodySmall)
                                        }
                                    }
                                    Spacer(modifier = Modifier.weight(1f))
                                    if (!file.isDirectory) {
                                        Icon(Icons.Default.Download, contentDescription = "Download")
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
