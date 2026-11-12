package com.tether.phone.ui.screens

import android.content.Intent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.tether.phone.FileNode
import com.tether.phone.FileTransferClient
import com.tether.phone.ui.components.DeepSpaceCanvasVisualizer
import com.tether.phone.ui.components.ProfessionalGlassSurface
import com.tether.phone.ui.theme.*
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class, ExperimentalFoundationApi::class)
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
    var selectedItemForAction by remember { mutableStateOf<FileNode?>(null) }
    var showActionMenu by remember { mutableStateOf(false) }

    var showRenameDialog by remember { mutableStateOf(false) }
    var renameInput by remember { mutableStateOf("") }

    var showMoveDialog by remember { mutableStateOf(false) }
    var moveDestInput by remember { mutableStateOf("") }

    var showDeleteDialog by remember { mutableStateOf(false) }
    var deletePermanent by remember { mutableStateOf(false) }

    var showNewFolderDialog by remember { mutableStateOf(false) }
    var newFolderName by remember { mutableStateOf("") }

    var isSearchActive by remember { mutableStateOf(false) }
    var searchQuery by remember { mutableStateOf("") }

    var token by remember { mutableStateOf<String?>(null) }
    val service = com.tether.phone.TetherLanService.instance
    val hostIp = service?.connectedHostAddress

    DisposableEffect(Unit) {
        service?.isHeavyTaskActive = true
        service?.currentActiveScreen = "FileTransfer"
        onDispose {
            service?.isHeavyTaskActive = false
            service?.currentActiveScreen = null
            service?.triggerFullSyncIfNeeded()
        }
    }

    fun refreshFileList() {
        if (hostIp != null) {
            coroutineScope.launch {
                try {
                    isLoading = true
                    errorMessage = null
                    if (token == null) {
                        token = service?.requestFileTransferToken()
                    }
                    val currentToken = token
                    if (currentToken == null) {
                        errorMessage = "Acquiring secure authorization..."
                        return@launch
                    }
                    try {
                        if (isSearchActive && searchQuery.isNotBlank()) {
                            files = FileTransferClient.searchFiles(
                                hostIp = hostIp,
                                path = currentPath,
                                query = searchQuery,
                                recursive = true,
                                token = currentToken,
                                context = context
                            )
                        } else {
                            files = FileTransferClient.listDirectory(hostIp, currentPath, currentToken, context)
                        }
                    } catch (e: Exception) {
                        val msg = e.message ?: ""
                        if (msg.contains("401") || msg.contains("Unauthorized", ignoreCase = true) || msg.contains("Token validation failed", ignoreCase = true)) {
                            val freshToken = service?.requestFileTransferToken()
                            if (freshToken != null) {
                                token = freshToken
                                if (isSearchActive && searchQuery.isNotBlank()) {
                                    files = FileTransferClient.searchFiles(
                                        hostIp = hostIp,
                                        path = currentPath,
                                        query = searchQuery,
                                        recursive = true,
                                        token = freshToken,
                                        context = context
                                    )
                                } else {
                                    files = FileTransferClient.listDirectory(hostIp, currentPath, freshToken, context)
                                }
                                return@launch
                            }
                        }
                        throw e
                    }
                } catch (e: Exception) {
                    errorMessage = e.message
                } finally {
                    isLoading = false
                }
            }
        }
    }

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
        contract = ActivityResultContracts.OpenMultipleDocuments()
    ) { uris ->
        if (uris.isNotEmpty()) {
            coroutineScope.launch {
                try {
                    if (hostIp == null || token == null) throw Exception("Not connected or no token")
                    isLoading = true
                    for (sourceUri in uris) {
                        FileTransferClient.uploadFile(hostIp, sourceUri, currentPath ?: "", context, token!!)
                    }
                    refreshFileList()
                } catch (e: Exception) {
                    errorMessage = e.message
                } finally {
                    isLoading = false
                }
            }
        }
    }

    LaunchedEffect(currentPath, token) {
        refreshFileList()
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
                    title = {
                        if (isSearchActive) {
                            TextField(
                                value = searchQuery,
                                onValueChange = {
                                    searchQuery = it
                                    refreshFileList()
                                },
                                placeholder = { Text("Search files & folders...", color = TextMuted) },
                                singleLine = true,
                                colors = TextFieldDefaults.colors(
                                    focusedContainerColor = Color.Transparent,
                                    unfocusedContainerColor = Color.Transparent,
                                    focusedTextColor = TextPrimary,
                                    unfocusedTextColor = TextPrimary
                                )
                            )
                        } else {
                            Text(currentPath ?: "Root Drives", maxLines = 1, color = TextPrimary)
                        }
                    },
                    navigationIcon = {
                        IconButton(onClick = {
                            if (isSearchActive) {
                                isSearchActive = false
                                searchQuery = ""
                                refreshFileList()
                            } else if (currentPath == null) {
                                onBack()
                            } else {
                                val normalized = currentPath!!.replace('\\', '/').trimEnd('/')
                                val lastSlash = normalized.lastIndexOf('/')
                                if (lastSlash <= 0 || (lastSlash == 2 && normalized.getOrNull(1) == ':')) {
                                    currentPath = null
                                } else {
                                    currentPath = normalized.substring(0, lastSlash)
                                }
                            }
                        }) {
                            Icon(Icons.Default.ArrowBack, contentDescription = "Back", tint = TextPrimary)
                        }
                    },
                    actions = {
                        IconButton(onClick = {
                            isSearchActive = !isSearchActive
                            if (!isSearchActive) {
                                searchQuery = ""
                                refreshFileList()
                            }
                        }) {
                            Icon(
                                if (isSearchActive) Icons.Default.Close else Icons.Default.Search,
                                contentDescription = "Search",
                                tint = LiquidCyan
                            )
                        }
                        IconButton(onClick = { showNewFolderDialog = true }) {
                            Icon(Icons.Default.CreateNewFolder, contentDescription = "New Folder", tint = TextPrimary)
                        }
                        IconButton(onClick = {
                            coroutineScope.launch {
                                if (hostIp != null && token != null) {
                                    try {
                                        FileTransferClient.emptyRecycleBin(hostIp, token!!, context)
                                    } catch (_: Exception) {}
                                }
                            }
                        }) {
                            Icon(Icons.Default.DeleteSweep, contentDescription = "Empty Recycle Bin", tint = AlertRed)
                        }
                    },
                    colors = TopAppBarDefaults.topAppBarColors(containerColor = Color.Transparent)
                )
            },
            floatingActionButton = {
                FloatingActionButton(
                    onClick = { uploadLauncher.launch(arrayOf("*/*")) },
                    containerColor = LiquidCyan,
                    contentColor = DeepSpace
                ) {
                    Icon(Icons.Default.Upload, contentDescription = "Upload")
                }
            },
            containerColor = Color.Transparent
        ) { padding ->
            Box(
                modifier = Modifier
                    .padding(padding)
                    .fillMaxSize()
            ) {
                if (isLoading) {
                    CircularProgressIndicator(modifier = Modifier.align(Alignment.Center), color = LiquidCyan)
                } else if (errorMessage != null) {
                    Column(
                        modifier = Modifier
                            .align(Alignment.Center)
                            .padding(24.dp),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Icon(Icons.Default.Lock, contentDescription = null, tint = MatrixGold, modifier = Modifier.size(40.dp))
                        Spacer(modifier = Modifier.height(12.dp))
                        Text(
                            text = errorMessage!!,
                            color = AlertRed,
                            style = MaterialTheme.typography.bodyMedium
                        )
                        Spacer(modifier = Modifier.height(16.dp))
                        Button(
                            onClick = {
                                coroutineScope.launch {
                                    token = service?.requestFileTransferToken()
                                    refreshFileList()
                                }
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = LiquidCyan)
                        ) {
                            Text("Re-authenticate & Refresh", color = DeepSpace, fontWeight = FontWeight.Bold)
                        }
                    }
                } else {
                    LazyColumn(modifier = Modifier.fillMaxSize()) {
                        items(files) { file ->
                            ProfessionalGlassSurface(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(horizontal = 16.dp, vertical = 6.dp)
                                    .combinedClickable(
                                        onClick = {
                                            if (file.isDirectory) {
                                                currentPath = file.path
                                            } else {
                                                pendingDownloadFile = file
                                                downloadLauncher.launch(file.name)
                                            }
                                        },
                                        onLongClick = {
                                            selectedItemForAction = file
                                            showActionMenu = true
                                        }
                                    )
                            ) {
                                Row(
                                    modifier = Modifier.padding(16.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Icon(
                                        imageVector = if (file.isDirectory) Icons.Default.Folder else Icons.Default.InsertDriveFile,
                                        contentDescription = null,
                                        tint = if (file.isDirectory) LiquidCyan else TextSecondary
                                    )
                                    Spacer(modifier = Modifier.width(16.dp))
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(file.name, fontWeight = FontWeight.Bold, color = TextPrimary, maxLines = 1)
                                        if (!file.isDirectory) {
                                            val sizeKb = file.size / 1024.0
                                            val sizeStr = if (sizeKb > 1024.0) String.format("%.2f MB", sizeKb / 1024.0) else String.format("%.1f KB", sizeKb)
                                            Text(sizeStr, style = MaterialTheme.typography.bodySmall, color = TextMuted)
                                        }
                                    }
                                    IconButton(onClick = {
                                        selectedItemForAction = file
                                        showActionMenu = true
                                    }) {
                                        Icon(Icons.Default.MoreVert, contentDescription = "Options", tint = TextMuted)
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Context Action Dialog
    if (showActionMenu && selectedItemForAction != null) {
        val target = selectedItemForAction!!
        AlertDialog(
            onDismissRequest = { showActionMenu = false },
            title = { Text(target.name, color = TextPrimary, maxLines = 1) },
            text = {
                Column {
                    if (!target.isDirectory) {
                        Surface(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable {
                                    showActionMenu = false
                                    pendingDownloadFile = target
                                    downloadLauncher.launch(target.name)
                                }
                                .padding(vertical = 10.dp),
                            color = Color.Transparent
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Default.Download, contentDescription = null, tint = IntegrityGreen)
                                Spacer(modifier = Modifier.width(12.dp))
                                Text("Download to Phone", color = TextPrimary)
                            }
                        }
                        Divider(color = GlassBorder)
                    }

                    Surface(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable {
                                showActionMenu = false
                                renameInput = target.name
                                showRenameDialog = true
                            }
                            .padding(vertical = 10.dp),
                        color = Color.Transparent
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.DriveFileRenameOutline, contentDescription = null, tint = LiquidCyan)
                            Spacer(modifier = Modifier.width(12.dp))
                            Text("Rename", color = TextPrimary)
                        }
                    }
                    Divider(color = GlassBorder)

                    Surface(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable {
                                showActionMenu = false
                                moveDestInput = target.path
                                showMoveDialog = true
                            }
                            .padding(vertical = 10.dp),
                        color = Color.Transparent
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.DriveFileMove, contentDescription = null, tint = MatrixGold)
                            Spacer(modifier = Modifier.width(12.dp))
                            Text("Move", color = TextPrimary)
                        }
                    }
                    Divider(color = GlassBorder)

                    Surface(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable {
                                showActionMenu = false
                                showDeleteDialog = true
                            }
                            .padding(vertical = 10.dp),
                        color = Color.Transparent
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.Delete, contentDescription = null, tint = AlertRed)
                            Spacer(modifier = Modifier.width(12.dp))
                            Text("Delete", color = AlertRed)
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = { showActionMenu = false }) {
                    Text("Close", color = TextSecondary)
                }
            },
            containerColor = SurfaceElevated
        )
    }

    // Rename Dialog
    if (showRenameDialog && selectedItemForAction != null) {
        val target = selectedItemForAction!!
        AlertDialog(
            onDismissRequest = { showRenameDialog = false },
            title = { Text("Rename Item", color = TextPrimary) },
            text = {
                TextField(
                    value = renameInput,
                    onValueChange = { renameInput = it },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    colors = TextFieldDefaults.colors(focusedTextColor = TextPrimary, unfocusedTextColor = TextPrimary)
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        if (hostIp != null && token != null && renameInput.isNotBlank()) {
                            coroutineScope.launch {
                                try {
                                    val ok = FileTransferClient.renameFile(hostIp, target.path, renameInput, token!!, context)
                                    if (ok) refreshFileList()
                                } catch (e: Exception) {
                                    errorMessage = e.message
                                }
                            }
                            showRenameDialog = false
                        }
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = LiquidCyan)
                ) {
                    Text("Rename", color = DeepSpace, fontWeight = FontWeight.Bold)
                }
            },
            dismissButton = {
                TextButton(onClick = { showRenameDialog = false }) { Text("Cancel", color = TextSecondary) }
            },
            containerColor = SurfaceElevated
        )
    }

    // Move Dialog
    if (showMoveDialog && selectedItemForAction != null) {
        val target = selectedItemForAction!!
        AlertDialog(
            onDismissRequest = { showMoveDialog = false },
            title = { Text("Move Item", color = TextPrimary) },
            text = {
                Column {
                    Text("Destination Path:", color = TextSecondary, style = MaterialTheme.typography.bodySmall)
                    Spacer(modifier = Modifier.height(6.dp))
                    TextField(
                        value = moveDestInput,
                        onValueChange = { moveDestInput = it },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        if (hostIp != null && token != null && moveDestInput.isNotBlank()) {
                            coroutineScope.launch {
                                try {
                                    val ok = FileTransferClient.moveFile(hostIp, target.path, moveDestInput, token!!, context)
                                    if (ok) refreshFileList()
                                } catch (e: Exception) {
                                    errorMessage = e.message
                                }
                            }
                            showMoveDialog = false
                        }
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = MatrixGold)
                ) {
                    Text("Move", color = DeepSpace, fontWeight = FontWeight.Bold)
                }
            },
            dismissButton = {
                TextButton(onClick = { showMoveDialog = false }) { Text("Cancel", color = TextSecondary) }
            },
            containerColor = SurfaceElevated
        )
    }

    // Delete Dialog
    if (showDeleteDialog && selectedItemForAction != null) {
        val target = selectedItemForAction!!
        AlertDialog(
            onDismissRequest = { showDeleteDialog = false },
            title = { Text("Delete Confirmation", color = TextPrimary) },
            text = {
                Column {
                    Text("Are you sure you want to delete '${target.name}'?", color = TextPrimary)
                    Spacer(modifier = Modifier.height(14.dp))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(
                            checked = deletePermanent,
                            onCheckedChange = { deletePermanent = it },
                            colors = CheckboxDefaults.colors(checkedColor = AlertRed)
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Permanent Delete (Bypass Recycle Bin)", color = TextSecondary, style = MaterialTheme.typography.bodySmall)
                    }
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        if (hostIp != null && token != null) {
                            coroutineScope.launch {
                                try {
                                    val ok = FileTransferClient.deleteFile(hostIp, target.path, deletePermanent, token!!, context)
                                    if (ok) refreshFileList()
                                } catch (e: Exception) {
                                    errorMessage = e.message
                                }
                            }
                            showDeleteDialog = false
                        }
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = AlertRed)
                ) {
                    Text("Delete", color = DeepSpace, fontWeight = FontWeight.Bold)
                }
            },
            dismissButton = {
                TextButton(onClick = { showDeleteDialog = false }) { Text("Cancel", color = TextSecondary) }
            },
            containerColor = SurfaceElevated
        )
    }

    // New Folder Dialog
    if (showNewFolderDialog) {
        AlertDialog(
            onDismissRequest = { showNewFolderDialog = false },
            title = { Text("Create New Directory", color = TextPrimary) },
            text = {
                TextField(
                    value = newFolderName,
                    onValueChange = { newFolderName = it },
                    placeholder = { Text("Folder name") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        if (hostIp != null && token != null && currentPath != null && newFolderName.isNotBlank()) {
                            coroutineScope.launch {
                                try {
                                    val ok = FileTransferClient.createDirectory(hostIp, currentPath!!, newFolderName, token!!, context)
                                    if (ok) refreshFileList()
                                } catch (e: Exception) {
                                    errorMessage = e.message
                                }
                            }
                            showNewFolderDialog = false
                            newFolderName = ""
                        }
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = LiquidCyan)
                ) {
                    Text("Create", color = DeepSpace, fontWeight = FontWeight.Bold)
                }
            },
            dismissButton = {
                TextButton(onClick = { showNewFolderDialog = false }) { Text("Cancel", color = TextSecondary) }
            },
            containerColor = SurfaceElevated
        )
    }
}
