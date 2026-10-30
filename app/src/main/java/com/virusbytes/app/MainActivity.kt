package com.virusbytes.app

import android.content.Context
import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.view.WindowCompat
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

private val Night = Color(0xFF030B17)
private val Panel = Color(0xFF071426)
private val Card = Color(0xFF0B1B2F)
private val Card2 = Color(0xFF10243B)
private val Card3 = Color(0xFF142D49)
private val Blue = Color(0xFF078BFF)
private val BlueDeep = Color(0xFF0759F7)
private val Cyan = Color(0xFF24C7E5)
private val Green = Color(0xFF00D5A2)
private val Muted = Color(0xFF91A8C4)
private val Ink = Color(0xFFF3F7FF)
private val Danger = Color(0xFFFF3E5D)
private val Amber = Color(0xFFFFB83F)
private val BlueGlow = Brush.horizontalGradient(listOf(Color(0xFF06A9FF), Color(0xFF075DFF)))
private val BlueWash = Brush.linearGradient(listOf(Color(0xFF0B2748), Color(0xFF071426)))
private val BorderBlue = Color(0xFF173B60)

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        WindowCompat.setDecorFitsSystemWindows(window, true)
        setContent { VirusBytesApp(this) }
    }
}

data class ScanItem(
    val name: String,
    val type: String,
    val verdict: String,
    val count: Int,
    val date: String
)

@Composable
private fun VirusBytesApp(context: Context) {
    val prefs = remember { context.getSharedPreferences("virusbytes", Context.MODE_PRIVATE) }
    var server by remember { mutableStateOf(prefs.getString("server", "http://10.0.2.2:3000") ?: "") }
    var page by remember { mutableStateOf("Splash") }
    var url by remember { mutableStateOf("") }
    var online by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var status by remember { mutableStateOf("Ready to scan") }
    var reportName by remember { mutableStateOf("") }
    var reportType by remember { mutableStateOf("FILE") }
    var verdict by remember { mutableStateOf("") }
    var stats by remember { mutableStateOf(listOf(0, 0, 0, 0)) }
    var engines by remember { mutableStateOf(emptyList<Pair<String, String>>()) }
    var history by remember { mutableStateOf(emptyList<ScanItem>()) }
    var selectedHistory by remember { mutableStateOf<ScanItem?>(null) }
    var historyFilter by remember { mutableStateOf("All") }
    var fileMode by remember { mutableStateOf("File") }
    var pickedName by remember { mutableStateOf("") }
    var scanArchives by remember { mutableStateOf(prefs.getBoolean("archives", true)) }
    var scanCompressed by remember { mutableStateOf(prefs.getBoolean("compressed", true)) }
    var scanPua by remember { mutableStateOf(prefs.getBoolean("pua", false)) }
    var notifyResults by remember { mutableStateOf(prefs.getBoolean("notifyResults", true)) }
    var notifyThreats by remember { mutableStateOf(prefs.getBoolean("notifyThreats", true)) }
    var notifyUpdates by remember { mutableStateOf(prefs.getBoolean("notifyUpdates", true)) }
    var darkMode by remember { mutableStateOf(true) }
    val scope = rememberCoroutineScope()

    LaunchedEffect(Unit) {
        val raw = org.json.JSONArray(prefs.getString("history", "[]"))
        history = (0 until raw.length()).map { i ->
            val o = raw.getJSONObject(i)
            ScanItem(o.optString("name"), o.optString("type"), o.optString("verdict"), o.optInt("count"), o.optString("date"))
        }
        delay(1500)
        page = "Home"
    }

    LaunchedEffect(server) {
        online = try {
            withContext(Dispatchers.IO) {
                getJson(server.trimEnd('/') + "/api/health").optBoolean("apiKeyConfigured")
            }
        } catch (_: Exception) { false }
    }

    fun saveHistory(item: ScanItem) {
        history = listOf(item) + history.filterNot { it.name == item.name && it.date == item.date }
        val array = org.json.JSONArray()
        history.take(50).forEach {
            array.put(JSONObject()
                .put("name", it.name)
                .put("type", it.type)
                .put("verdict", it.verdict)
                .put("count", it.count)
                .put("date", it.date))
        }
        prefs.edit().putString("history", array.toString()).apply()
    }

    suspend fun pollAnalysis(id: String, name: String, type: String) {
        page = "Result"
        busy = true
        verdict = ""
        engines = emptyList()
        stats = listOf(0, 0, 0, 0)
        reportName = name
        reportType = type
        status = "Submitted to VirusTotal. Waiting for analysis…"
        try {
            var done = false
            for (attempt in 0 until 20) {
                delay(15000)
                val response = withContext(Dispatchers.IO) {
                    getJson(server.trimEnd('/') + "/api/analyses/" + id)
                }
                val attributes = response.optJSONObject("data")?.optJSONObject("attributes") ?: JSONObject()
                if (attributes.optString("status") == "completed") {
                    val s = attributes.optJSONObject("stats") ?: JSONObject()
                    val malicious = s.optInt("malicious")
                    val suspicious = s.optInt("suspicious")
                    val harmless = s.optInt("harmless")
                    val undetected = s.optInt("undetected")
                    val total = malicious + suspicious + harmless + undetected
                    stats = listOf(total, malicious, harmless, suspicious)
                    verdict = when {
                        malicious > 0 -> "THREATS FOUND"
                        suspicious > 0 -> "REVIEW NEEDED"
                        else -> "NO DETECTIONS"
                    }
                    val resultObject = attributes.optJSONObject("results") ?: JSONObject()
                    engines = resultObject.keys().asSequence().take(100).map { key ->
                        key to (resultObject.optJSONObject(key)?.optString("category") ?: "undetected")
                    }.toList()
                    status = if (malicious + suspicious == 0) {
                        "No engines reported a threat. This does not guarantee the item is safe."
                    } else {
                        "One or more engines flagged this item. Do not open or run it."
                    }
                    saveHistory(ScanItem(
                        name, type, verdict, malicious + suspicious,
                        SimpleDateFormat("yyyy-MM-dd, HH:mm", Locale.getDefault()).format(Date())
                    ))
                    done = true
                    break
                }
                status = "Analysis is running. Checking again in 15 seconds…"
            }
            if (!done) status = "Still processing. You can check the report again later on VirusTotal."
        } catch (e: Exception) {
            status = e.message ?: "Unable to retrieve analysis."
        } finally {
            busy = false
        }
    }

    fun scanUrl() {
        val input = url.trim()
        if (!input.startsWith("https://") && !input.startsWith("http://")) {
            status = "Enter a valid HTTP or HTTPS address."
            return
        }
        scope.launch {
            busy = true
            try {
                val response = withContext(Dispatchers.IO) {
                    postJson(server.trimEnd('/') + "/api/scan/url", JSONObject().put("url", input))
                }
                val id = response.optString("analysisId")
                if (id.isBlank()) error("The server did not return an analysis ID.")
                pollAnalysis(id, input, "URL")
            } catch (e: Exception) {
                busy = false
                status = e.message ?: "URL scan failed."
            }
        }
    }

    val filePicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
        if (uri != null) scope.launch {
            busy = true
            try {
                val name = context.contentResolver.query(uri, null, null, null, null)?.use { cursor ->
                    val column = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    if (cursor.moveToFirst() && column >= 0) cursor.getString(column) else "Selected file"
                } ?: "Selected file"
                pickedName = name
                val bytes = withContext(Dispatchers.IO) {
                    context.contentResolver.openInputStream(uri)?.use { it.readBytes() }
                        ?: error("Cannot read this file.")
                }
                if (bytes.size > 32 * 1024 * 1024) error("Files must be 32 MB or smaller.")
                val id = withContext(Dispatchers.IO) {
                    upload(server.trimEnd('/'), name, bytes,
                        context.contentResolver.getType(uri) ?: "application/octet-stream")
                }
                pollAnalysis(id, name, "FILE")
            } catch (e: Exception) {
                busy = false
                status = e.message ?: "File scan failed."
            }
        }
    }

    fun chooseFile(mime: Array<String> = arrayOf("*/*")) {
        if (!busy) filePicker.launch(mime)
    }

    MaterialTheme(
        colorScheme = darkColorScheme(
            primary = Blue,
            secondary = Cyan,
            background = Night,
            surface = Card,
            onSurface = Ink
        )
    ) {
        BoxWithConstraints(
            modifier = Modifier.fillMaxSize().background(
                Brush.verticalGradient(listOf(Color(0xFF061629), Night, Color(0xFF020712)))
            ),
            contentAlignment = Alignment.TopCenter
        ) {
            val appWidth = if (maxWidth > 650.dp) 520.dp else maxWidth
            Column(
                modifier = Modifier.width(appWidth).fillMaxHeight().background(Night)
            ) {
                if (page == "Splash") {
                    SplashScreen()
                } else {
                    if (page != "Drawer") {
                        AppTopBar(
                            onMenu = { page = "Drawer" },
                            onSettings = { page = "Settings" },
                            online = online
                        )
                    }
                    Box(Modifier.weight(1f).fillMaxWidth()) {
                        when (page) {
                            "Home" -> HomeScreen(
                                busy = busy,
                                history = history,
                                onScanFile = { page = "File Scan"; fileMode = "File" },
                                onScanUrl = { page = "URL Scan" },
                                onHistory = { page = "History" },
                                onSettings = { page = "Settings" }
                            )
                            "File Scan" -> FileScanScreen(
                                busy = busy,
                                fileMode = fileMode,
                                pickedName = pickedName,
                                onBack = { page = "Home" },
                                onMode = { fileMode = it },
                                onPick = { chooseFile() },
                                onCategory = { chooseFile(it) }
                            )
                            "URL Scan" -> UrlScanScreen(
                                url = url,
                                status = status,
                                busy = busy,
                                onUrl = { url = it },
                                onBack = { page = "Home" },
                                onScan = { scanUrl() }
                            )
                            "Result" -> ResultScreen(
                                name = reportName,
                                verdict = verdict,
                                stats = stats,
                                status = status,
                                busy = busy,
                                onBack = { page = "Home" },
                                onDetails = { page = "Threat Details" },
                                onScanAgain = { page = if (reportType == "URL") "URL Scan" else "File Scan" }
                            )
                            "Threat Details" -> ThreatDetailsScreen(
                                name = reportName,
                                verdict = verdict,
                                engines = engines,
                                stats = stats,
                                onBack = { page = "Result" },
                                onScanAgain = { page = "File Scan" }
                            )
                            "History" -> HistoryScreen(
                                history = history,
                                filter = historyFilter,
                                onFilter = { historyFilter = it },
                                onBack = { page = "Home" },
                                onSelect = {
                                    selectedHistory = it
                                    reportName = it.name
                                    reportType = it.type
                                    verdict = it.verdict
                                    page = "Result"
                                }
                            )
                            "Settings" -> SettingsScreen(
                                server = server,
                                online = online,
                                scanArchives = scanArchives,
                                scanCompressed = scanCompressed,
                                scanPua = scanPua,
                                notifyResults = notifyResults,
                                notifyThreats = notifyThreats,
                                notifyUpdates = notifyUpdates,
                                onServer = { server = it; prefs.edit().putString("server", it).apply() },
                                onArchives = { scanArchives = it; prefs.edit().putBoolean("archives", it).apply() },
                                onCompressed = { scanCompressed = it; prefs.edit().putBoolean("compressed", it).apply() },
                                onPua = { scanPua = it; prefs.edit().putBoolean("pua", it).apply() },
                                onResults = { notifyResults = it; prefs.edit().putBoolean("notifyResults", it).apply() },
                                onThreats = { notifyThreats = it; prefs.edit().putBoolean("notifyThreats", it).apply() },
                                onUpdates = { notifyUpdates = it; prefs.edit().putBoolean("notifyUpdates", it).apply() }
                            )
                            "About" -> AboutScreen(onBack = { page = "Settings" })
                            "Drawer" -> DrawerScreen(
                                onClose = { page = "Home" },
                                onNavigate = { page = it }
                            )
                            else -> HomeScreen(
                                busy = busy, history = history,
                                onScanFile = { page = "File Scan" },
                                onScanUrl = { page = "URL Scan" },
                                onHistory = { page = "History" },
                                onSettings = { page = "Settings" }
                            )
                        }
                    }
                    if (page in listOf("Home", "History", "Settings")) {
                        BottomNav(selected = page, onSelect = { page = it })
                    }
                }
            }
        }
    }
}

@Composable
private fun SplashScreen() {
    Box(
        Modifier.fillMaxSize().background(
            Brush.linearGradient(listOf(Color(0xFF06162D), Color(0xFF020916), Color(0xFF030A15)))
        ),
        contentAlignment = Alignment.Center
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Box(
                Modifier.size(158.dp),
                contentAlignment = Alignment.Center
            ) {
                Icon(Icons.Default.Shield, null, tint = Blue, modifier = Modifier.size(154.dp))
                Text("V", color = Color(0xFF07152A), fontSize = 82.sp, fontWeight = FontWeight.Black)
            }
            Spacer(Modifier.height(18.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("Virus", color = Ink, fontSize = 36.sp, fontWeight = FontWeight.Bold)
                Text("Bytes", color = Blue, fontSize = 36.sp, fontWeight = FontWeight.Bold)
            }
            Text("Powered by VirusTotal", color = Muted, fontSize = 14.sp)
            Spacer(Modifier.height(54.dp))
            Text("Scan. Detect. Stay Safe.", color = Ink, fontSize = 13.sp, fontWeight = FontWeight.Medium)
            Spacer(Modifier.height(70.dp))
            Text("Built with", color = Muted, fontSize = 10.sp)
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("〉", color = Blue, fontSize = 28.sp, fontWeight = FontWeight.Bold)
                Text(" VirusTotal", color = Blue, fontSize = 14.sp, fontWeight = FontWeight.SemiBold)
            }
        }
    }
}

@Composable
private fun AppTopBar(onMenu: () -> Unit, onSettings: () -> Unit, online: Boolean) {
    Row(
        Modifier.fillMaxWidth().padding(horizontal = 18.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        IconButton(onClick = onMenu, modifier = Modifier.size(34.dp)) {
            Icon(Icons.Default.Menu, null, tint = Muted, modifier = Modifier.size(21.dp))
        }
        Icon(Icons.Default.Shield, null, tint = Blue, modifier = Modifier.size(25.dp))
        Spacer(Modifier.width(7.dp))
        Text("Virus", color = Ink, fontSize = 20.sp, fontWeight = FontWeight.Bold)
        Text("Bytes", color = Cyan, fontSize = 20.sp, fontWeight = FontWeight.Bold)
        Spacer(Modifier.weight(1f))
        Surface(color = Card, shape = CircleShape) {
            Row(
                Modifier.padding(horizontal = 10.dp, vertical = 7.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Box(Modifier.size(7.dp).background(if (online) Green else Amber, CircleShape))
                Spacer(Modifier.width(6.dp))
                Text(if (online) "Connected" else "Offline", color = Muted, fontSize = 10.sp)
            }
        }
        IconButton(onClick = onSettings, modifier = Modifier.size(38.dp)) {
            Icon(Icons.Default.Settings, null, tint = Muted, modifier = Modifier.size(20.dp))
        }
    }
}

@Composable
private fun BottomNav(selected: String, onSelect: (String) -> Unit) {
    NavigationBar(
        containerColor = Color(0xFF071426),
        tonalElevation = 0.dp,
        modifier = Modifier.border(1.dp, Color(0xFF11243A))
    ) {
        listOf(
            Triple("Home", Icons.Default.Home, "Home"),
            Triple("History", Icons.Default.History, "History"),
            Triple("Settings", Icons.Default.Settings, "Settings")
        ).forEach { item ->
            NavigationBarItem(
                selected = selected == item.first,
                onClick = { onSelect(item.first) },
                icon = { Icon(item.second, null, modifier = Modifier.size(21.dp)) },
                label = { Text(item.third, fontSize = 10.sp) },
                colors = NavigationBarItemDefaults.colors(
                    selectedIconColor = Cyan,
                    selectedTextColor = Cyan,
                    indicatorColor = Card3,
                    unselectedIconColor = Muted,
                    unselectedTextColor = Muted
                )
            )
        }
    }
}

@Composable
private fun HomeScreen(
    busy: Boolean,
    history: List<ScanItem>,
    onScanFile: () -> Unit,
    onScanUrl: () -> Unit,
    onHistory: () -> Unit,
    onSettings: () -> Unit
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 7.dp),
        verticalArrangement = Arrangement.spacedBy(13.dp)
    ) {
        item {
            RoundedCard(
                Modifier.fillMaxWidth(),
                background = Brush.linearGradient(listOf(Color(0xFF0B2340), Color(0xFF08182B)))
            ) {
                Column(Modifier.fillMaxWidth().padding(horizontal = 18.dp, vertical = 18.dp)) {
                    Eyebrow("YOUR SECURITY, IN FOCUS")
                    Spacer(Modifier.height(17.dp))
                    Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
                        Box(
                            Modifier.size(110.dp)
                                .border(2.dp, Green.copy(alpha = .75f), CircleShape)
                                .background(
                                    Brush.radialGradient(listOf(Color(0xFF075A50), Color(0xFF0B2637))),
                                    CircleShape
                                ),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(Icons.Default.VerifiedUser, null, tint = Green, modifier = Modifier.size(65.dp))
                        }
                    }
                    Spacer(Modifier.height(12.dp))
                    Text(
                        "You're protected",
                        color = Green,
                        fontSize = 22.sp,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.align(Alignment.CenterHorizontally)
                    )
                    Text(
                        "No threats found on your device",
                        color = Muted,
                        fontSize = 11.sp,
                        modifier = Modifier.align(Alignment.CenterHorizontally)
                    )
                    Spacer(Modifier.height(18.dp))
                    GradientButton(
                        text = if (busy) "Scanning…" else "Scan Now",
                        enabled = !busy,
                        modifier = Modifier.fillMaxWidth().height(48.dp),
                        onClick = onScanFile
                    )
                }
            }
        }
        item { Eyebrow("QUICK SCANS") }
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                ActionTile(
                    "Scan File", "Scan files on your device",
                    Icons.Default.InsertDriveFile, Modifier.weight(1f), onScanFile
                )
                ActionTile(
                    "Scan URL", "Check links for threats",
                    Icons.Default.Link, Modifier.weight(1f), onScanUrl
                )
            }
        }
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                ActionTile("History", "View past scans", Icons.Default.History, Modifier.weight(1f), onHistory)
                ActionTile("Settings", "App preferences", Icons.Default.Settings, Modifier.weight(1f), onSettings)
            }
        }
        item {
            RoundedCard {
                Column(Modifier.padding(15.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text("Recent activity", color = Ink, fontSize = 14.sp, fontWeight = FontWeight.Bold)
                        Spacer(Modifier.weight(1f))
                        Text("VIEW ALL", color = Cyan, fontSize = 9.sp, fontWeight = FontWeight.Bold,
                            modifier = Modifier.clickable { onHistory() })
                    }
                    Spacer(Modifier.height(9.dp))
                    if (history.isEmpty()) {
                        Text("Your scans will appear here.", color = Muted, fontSize = 11.sp)
                    } else {
                        history.take(3).forEach { HistoryRowCompact(it) }
                    }
                }
            }
        }
        item {
            Text(
                "Powered by VirusTotal · On-demand scanning",
                color = Muted,
                fontSize = 9.sp,
                modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp),
                textAlign = androidx.compose.ui.text.style.TextAlign.Center
            )
        }
    }
}

@Composable
private fun FileScanScreen(
    busy: Boolean,
    fileMode: String,
    pickedName: String,
    onBack: () -> Unit,
    onMode: (String) -> Unit,
    onPick: () -> Unit,
    onCategory: (Array<String>) -> Unit
) {
    Column(Modifier.fillMaxSize().padding(horizontal = 16.dp)) {
        ScreenTitle("Scan File", onBack)
        Row(
            Modifier.fillMaxWidth().clip(RoundedCornerShape(13.dp)).background(Panel).padding(4.dp)
        ) {
            listOf("File", "Apps").forEach { mode ->
                Box(
                    Modifier.weight(1f).clip(RoundedCornerShape(10.dp))
                        .background(if (fileMode == mode) BlueWash else Color.Transparent)
                        .clickable { onMode(mode) }.padding(vertical = 11.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Text(mode, color = if (fileMode == mode) Cyan else Muted, fontSize = 12.sp,
                        fontWeight = if (fileMode == mode) FontWeight.Bold else FontWeight.Normal)
                }
            }
        }
        Spacer(Modifier.height(18.dp))
        if (fileMode == "File") {
            Column(
                Modifier.fillMaxWidth().weight(1f),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Box(
                    Modifier.fillMaxWidth().weight(1f)
                        .border(1.dp, Blue.copy(alpha = .7f), RoundedCornerShape(18.dp))
                        .background(Panel, RoundedCornerShape(18.dp))
                        .clickable { onPick() },
                    contentAlignment = Alignment.Center
                ) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Icon(Icons.Default.InsertDriveFile, null, tint = Color(0xFF83AEEB), modifier = Modifier.size(54.dp))
                        Spacer(Modifier.height(12.dp))
                        Text(if (pickedName.isBlank()) "Tap to select a file" else pickedName,
                            color = Ink, fontSize = 13.sp, fontWeight = FontWeight.SemiBold,
                            maxLines = 1, overflow = TextOverflow.Ellipsis)
                        Text("or browse your files", color = Muted, fontSize = 10.sp)
                        Text("Maximum file size: 32 MB", color = Muted, fontSize = 9.sp)
                    }
                }
                Spacer(Modifier.height(15.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(9.dp)) {
                    CategoryTile("Photos", Icons.Default.Image, Modifier.weight(1f)) {
                        onCategory(arrayOf("image/*"))
                    }
                    CategoryTile("Videos", Icons.Default.VideoLibrary, Modifier.weight(1f)) {
                        onCategory(arrayOf("video/*"))
                    }
                    CategoryTile("Documents", Icons.Default.Description, Modifier.weight(1f)) {
                        onCategory(arrayOf("application/pdf", "text/*", "application/msword", "application/vnd.openxmlformats-officedocument.*"))
                    }
                }
                Spacer(Modifier.height(9.dp))
                CategoryTile("Other", Icons.Default.FolderOpen, Modifier.width(112.dp)) {
                    onCategory(arrayOf("*/*"))
                }
                Spacer(Modifier.height(17.dp))
                GradientButton(
                    "Select File", enabled = !busy,
                    modifier = Modifier.fillMaxWidth().height(48.dp), onClick = onPick
                )
            }
        } else {
            Column(
                Modifier.fillMaxWidth().weight(1f),
                verticalArrangement = Arrangement.Center,
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Icon(Icons.Default.Apps, null, tint = Blue, modifier = Modifier.size(58.dp))
                Spacer(Modifier.height(12.dp))
                Text("Scan an app package", color = Ink, fontSize = 18.sp, fontWeight = FontWeight.Bold)
                Spacer(Modifier.height(6.dp))
                Text(
                    "Choose an APK file from your device storage. Installed-app scanning is not available yet.",
                    color = Muted, fontSize = 11.sp, textAlign = androidx.compose.ui.text.style.TextAlign.Center
                )
                Spacer(Modifier.height(20.dp))
                GradientButton("Choose APK", modifier = Modifier.fillMaxWidth().height(48.dp), onClick = onPick)
            }
        }
        Spacer(Modifier.height(12.dp))
    }
}

@Composable
private fun UrlScanScreen(
    url: String,
    status: String,
    busy: Boolean,
    onUrl: (String) -> Unit,
    onBack: () -> Unit,
    onScan: () -> Unit
) {
    Column(Modifier.fillMaxSize().padding(horizontal = 16.dp)) {
        ScreenTitle("Scan URL", onBack)
        Text("Check a link before you visit", color = Ink, fontSize = 19.sp, fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(15.dp))
        OutlinedTextField(
            value = url,
            onValueChange = onUrl,
            modifier = Modifier.fillMaxWidth(),
            placeholder = { Text("Enter URL (e.g. https://example.com)", fontSize = 11.sp, color = Muted) },
            leadingIcon = { Icon(Icons.Default.Link, null, tint = Cyan) },
            singleLine = true,
            shape = RoundedCornerShape(13.dp),
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = Blue,
                unfocusedBorderColor = BorderBlue,
                focusedContainerColor = Card,
                unfocusedContainerColor = Card,
                cursorColor = Cyan,
                focusedTextColor = Ink,
                unfocusedTextColor = Ink
            )
        )
        Spacer(Modifier.height(13.dp))
        GradientButton(
            if (busy) "Scanning…" else "Scan URL",
            enabled = !busy,
            modifier = Modifier.fillMaxWidth().height(48.dp),
            onClick = onScan
        )
        Spacer(Modifier.height(18.dp))
        Text("Quick scan examples", color = Ink, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
        Spacer(Modifier.height(10.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            ExamplePill("Phishing", Modifier.weight(1f)) { onUrl("https://example.com") }
            ExamplePill("Malware", Modifier.weight(1f)) { onUrl("https://www.eicar.org") }
        }
        Spacer(Modifier.height(8.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            ExamplePill("Suspicious", Modifier.weight(1f)) { onUrl("https://suspicious-site.example") }
            ExamplePill("Reputation", Modifier.weight(1f)) { onUrl("https://google.com") }
        }
        Spacer(Modifier.weight(1f))
        Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Box(Modifier.size(116.dp), contentAlignment = Alignment.Center) {
                    Icon(Icons.Default.Language, null, tint = Blue, modifier = Modifier.size(98.dp))
                    Icon(Icons.Default.Shield, null, tint = Cyan, modifier = Modifier.size(44.dp).offset(27.dp, 20.dp))
                }
                Text("Check if a website is safe", color = Muted, fontSize = 11.sp)
                Text("before you visit it.", color = Muted, fontSize = 11.sp)
            }
        }
        if (status != "Ready to scan" && status.isNotBlank()) {
            Spacer(Modifier.height(8.dp))
            Text(status, color = Muted, fontSize = 10.sp)
        }
        Spacer(Modifier.height(18.dp))
    }
}

@Composable
private fun ResultScreen(
    name: String,
    verdict: String,
    stats: List<Int>,
    status: String,
    busy: Boolean,
    onBack: () -> Unit,
    onDetails: () -> Unit,
    onScanAgain: () -> Unit
) {
    val isThreat = verdict == "THREATS FOUND"
    val isSuspicious = verdict == "REVIEW NEEDED"
    LazyColumn(
        Modifier.fillMaxSize(),
        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 6.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item { ScreenTitle("Scan Results", onBack) }
        item {
            RoundedCard(Modifier.fillMaxWidth()) {
                Column(Modifier.fillMaxWidth().padding(17.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                    Box(
                        Modifier.size(78.dp)
                            .border(2.dp, (if (isThreat) Danger else if (isSuspicious) Amber else Green).copy(alpha = .8f), CircleShape)
                            .background((if (isThreat) Danger else if (isSuspicious) Amber else Green).copy(alpha = .08f), CircleShape),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            if (isThreat) Icons.Default.BugReport else Icons.Default.VerifiedUser,
                            null,
                            tint = if (isThreat) Danger else if (isSuspicious) Amber else Green,
                            modifier = Modifier.size(43.dp)
                        )
                    }
                    Spacer(Modifier.height(10.dp))
                    Text(
                        when {
                            busy && verdict.isBlank() -> "Analysis in progress"
                            isThreat -> "Threat detected!"
                            isSuspicious -> "Review recommended"
                            else -> "No threats found"
                        },
                        color = if (isThreat) Danger else if (isSuspicious) Amber else Green,
                        fontSize = 18.sp, fontWeight = FontWeight.Bold
                    )
                    Text(if (busy) "Analysis running" else "1/1 item analyzed", color = Muted, fontSize = 10.sp)
                    Spacer(Modifier.height(12.dp))
                    Text(name, color = Ink, fontSize = 12.sp, fontWeight = FontWeight.SemiBold,
                        maxLines = 1, overflow = TextOverflow.Ellipsis)
                    Text(if (isThreat) "Malicious detections: ${stats.getOrElse(1) { 0 }}" else "Powered by VirusTotal engines",
                        color = Muted, fontSize = 10.sp)
                    if (verdict.isNotBlank()) {
                        Spacer(Modifier.height(9.dp))
                        StatusPill(if (isThreat) "Malicious" else if (isSuspicious) "Suspicious" else "Clean",
                            if (isThreat) Danger else if (isSuspicious) Amber else Green)
                    }
                    if (busy) {
                        Spacer(Modifier.height(12.dp))
                        CircularProgressIndicator(color = Cyan, modifier = Modifier.size(26.dp), strokeWidth = 2.dp)
                    }
                    Spacer(Modifier.height(9.dp))
                    Text(status, color = Muted, fontSize = 10.sp,
                        textAlign = androidx.compose.ui.text.style.TextAlign.Center)
                }
            }
        }
        if (stats.any { it > 0 }) {
            item {
                RoundedCard {
                    Column(Modifier.padding(15.dp)) {
                        Text("Scan Summary", color = Ink, fontSize = 14.sp, fontWeight = FontWeight.Bold)
                        Spacer(Modifier.height(10.dp))
                        SummaryLine("Total engines", stats.getOrElse(0) { 0 }, Cyan)
                        SummaryLine("Detected", stats.getOrElse(1) { 0 }, Danger)
                        SummaryLine("Clean", stats.getOrElse(2) { 0 }, Green)
                        SummaryLine("Suspicious", stats.getOrElse(3) { 0 }, Amber)
                    }
                }
            }
        }
        item {
            GradientButton(
                "View Details",
                enabled = verdict.isNotBlank() && !busy,
                modifier = Modifier.fillMaxWidth().height(45.dp),
                onClick = onDetails,
                danger = isThreat
            )
        }
        item {
            OutlinedActionButton("Scan Again", Modifier.fillMaxWidth().height(44.dp), onScanAgain)
        }
        item { Spacer(Modifier.height(4.dp)) }
    }
}

@Composable
private fun ThreatDetailsScreen(
    name: String,
    verdict: String,
    engines: List<Pair<String, String>>,
    stats: List<Int>,
    onBack: () -> Unit,
    onScanAgain: () -> Unit
) {
    LazyColumn(
        Modifier.fillMaxSize(),
        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 6.dp),
        verticalArrangement = Arrangement.spacedBy(11.dp)
    ) {
        item { ScreenTitle("Threat Details", onBack) }
        item {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(Modifier.size(48.dp).background(Danger.copy(alpha = .12f), CircleShape), contentAlignment = Alignment.Center) {
                    Icon(Icons.Default.BugReport, null, tint = Danger, modifier = Modifier.size(27.dp))
                }
                Spacer(Modifier.width(11.dp))
                Column(Modifier.weight(1f)) {
                    Text(verdict.ifBlank { "Analysis pending" }, color = Ink, fontSize = 14.sp, fontWeight = FontWeight.Bold)
                    Text(name, color = Muted, fontSize = 10.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
                StatusPill(if (verdict == "THREATS FOUND") "Malicious" else "Reviewed",
                    if (verdict == "THREATS FOUND") Danger else Amber)
            }
        }
        item {
            RoundedCard {
                Column(Modifier.padding(14.dp)) {
                    Text("File Information", color = Ink, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                    Spacer(Modifier.height(9.dp))
                    InfoLine("Name", name)
                    InfoLine("Type", if (name.contains(".")) name.substringAfterLast(".").uppercase(Locale.getDefault()) else "URL")
                    InfoLine("Status", verdict.ifBlank { "Pending" })
                    InfoLine("Detections", stats.getOrElse(1) { 0 }.toString() + " / " + stats.getOrElse(0) { 0 })
                }
            }
        }
        item { Text("DETECTION ENGINES", color = Muted, fontSize = 10.sp, fontWeight = FontWeight.Bold) }
        if (engines.isEmpty()) {
            item {
                RoundedCard { Text("Engine-level results will appear when the analysis completes.", color = Muted, fontSize = 11.sp, modifier = Modifier.padding(14.dp)) }
            }
        } else {
            items(engines) { engine ->
                Row(
                    Modifier.fillMaxWidth().background(Card, RoundedCornerShape(12.dp)).padding(12.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Box(Modifier.size(26.dp).background(Card3, CircleShape), contentAlignment = Alignment.Center) {
                        Text(engine.first.take(1).uppercase(), color = Cyan, fontSize = 11.sp, fontWeight = FontWeight.Bold)
                    }
                    Spacer(Modifier.width(9.dp))
                    Text(engine.first, color = Ink, fontSize = 11.sp, modifier = Modifier.weight(1f),
                        maxLines = 1, overflow = TextOverflow.Ellipsis)
                    Text(engine.second.replaceFirstChar { it.uppercase() },
                        color = when (engine.second.lowercase()) {
                            "malicious" -> Danger
                            "suspicious" -> Amber
                            "harmless" -> Green
                            else -> Muted
                        }, fontSize = 10.sp, fontWeight = FontWeight.SemiBold)
                }
            }
        }
        item { OutlinedActionButton("Scan Again", Modifier.fillMaxWidth().height(44.dp), onScanAgain) }
    }
}

@Composable
private fun HistoryScreen(
    history: List<ScanItem>,
    filter: String,
    onFilter: (String) -> Unit,
    onBack: () -> Unit,
    onSelect: (ScanItem) -> Unit
) {
    val shown = history.filter {
        filter == "All" || (filter == "Files" && it.type != "URL") || (filter == "URLs" && it.type == "URL")
    }
    Column(Modifier.fillMaxSize()) {
        ScreenTitle("Scan History", onBack)
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 16.dp).clip(RoundedCornerShape(12.dp)).background(Panel).padding(4.dp)
        ) {
            listOf("All", "Files", "URLs").forEach { option ->
                Box(
                    Modifier.weight(1f).clip(RoundedCornerShape(9.dp))
                        .background(if (filter == option) Blue else Color.Transparent)
                        .clickable { onFilter(option) }.padding(vertical = 9.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Text(option, color = if (filter == option) Ink else Muted, fontSize = 11.sp)
                }
            }
        }
        if (shown.isEmpty()) {
            Column(Modifier.fillMaxSize(), horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center) {
                Icon(Icons.Default.History, null, tint = Muted, modifier = Modifier.size(45.dp))
                Spacer(Modifier.height(10.dp))
                Text("No scans yet", color = Ink, fontWeight = FontWeight.SemiBold)
                Text("Your reports will show here.", color = Muted, fontSize = 11.sp)
            }
        } else {
            LazyColumn(
                Modifier.fillMaxSize(),
                contentPadding = PaddingValues(16.dp),
                verticalArrangement = Arrangement.spacedBy(9.dp)
            ) {
                items(shown) { item ->
                    HistoryCard(item) { onSelect(item) }
                }
            }
        }
    }
}

@Composable
private fun SettingsScreen(
    server: String,
    online: Boolean,
    scanArchives: Boolean,
    scanCompressed: Boolean,
    scanPua: Boolean,
    notifyResults: Boolean,
    notifyThreats: Boolean,
    notifyUpdates: Boolean,
    onServer: (String) -> Unit,
    onArchives: (Boolean) -> Unit,
    onCompressed: (Boolean) -> Unit,
    onPua: (Boolean) -> Unit,
    onResults: (Boolean) -> Unit,
    onThreats: (Boolean) -> Unit,
    onUpdates: (Boolean) -> Unit
) {
    LazyColumn(
        Modifier.fillMaxSize(),
        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 7.dp),
        verticalArrangement = Arrangement.spacedBy(11.dp)
    ) {
        item { Text("Settings", color = Ink, fontSize = 22.sp, fontWeight = FontWeight.Bold) }
        item { Eyebrow("VIRUSTOTAL API") }
        item {
            RoundedCard {
                Column(Modifier.padding(14.dp)) {
                    Text("API Key", color = Ink, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                    Spacer(Modifier.height(5.dp))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text("••••••••••••••••••••••••", color = Muted, fontSize = 11.sp, modifier = Modifier.weight(1f))
                        StatusPill(if (online) "Connected" else "Offline", if (online) Green else Amber)
                    }
                    Spacer(Modifier.height(11.dp))
                    Text("Server URL", color = Muted, fontSize = 10.sp)
                    Spacer(Modifier.height(5.dp))
                    OutlinedTextField(
                        value = server,
                        onValueChange = onServer,
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                        textStyle = androidx.compose.ui.text.TextStyle(color = Ink, fontSize = 11.sp),
                        shape = RoundedCornerShape(10.dp),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = Blue,
                            unfocusedBorderColor = BorderBlue,
                            focusedContainerColor = Panel,
                            unfocusedContainerColor = Panel,
                            cursorColor = Cyan
                        )
                    )
                    Text("Emulator default: http://10.0.2.2:3000", color = Muted, fontSize = 9.sp)
                }
            }
        }
        item { Eyebrow("SCAN SETTINGS") }
        item {
            RoundedCard {
                Column(Modifier.padding(horizontal = 14.dp, vertical = 6.dp)) {
                    SettingSwitch("Scan archives", scanArchives, onArchives)
                    SettingSwitch("Scan compressed files", scanCompressed, onCompressed)
                    SettingSwitch("Potentially unwanted apps", scanPua, onPua)
                    Divider(color = BorderBlue.copy(alpha = .6f))
                    Row(Modifier.fillMaxWidth().padding(vertical = 11.dp), verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text("Real-time protection", color = Muted, fontSize = 11.sp)
                            Text("Requires Android accessibility permission and background service", color = Muted, fontSize = 9.sp)
                        }
                        Text("Not available", color = Muted, fontSize = 9.sp)
                    }
                }
            }
        }
        item { Eyebrow("NOTIFICATIONS") }
        item {
            RoundedCard {
                Column(Modifier.padding(horizontal = 14.dp, vertical = 6.dp)) {
                    SettingSwitch("Scan results", notifyResults, onResults)
                    SettingSwitch("Threat alerts", notifyThreats, onThreats)
                    SettingSwitch("Update notifications", notifyUpdates, onUpdates)
                }
            }
        }
        item { Eyebrow("APPEARANCE") }
        item {
            RoundedCard {
                Column(Modifier.padding(14.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text("Dark mode", color = Ink, fontSize = 11.sp, modifier = Modifier.weight(1f))
                        Text("On", color = Cyan, fontSize = 10.sp)
                    }
                    Spacer(Modifier.height(8.dp))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text("Language", color = Ink, fontSize = 11.sp, modifier = Modifier.weight(1f))
                        Text("English  ›", color = Muted, fontSize = 10.sp)
                    }
                }
            }
        }
        item {
            Text(
                "Settings marked as unavailable are display preferences only; VirusBytes currently performs on-demand scans.",
                color = Muted, fontSize = 9.sp, modifier = Modifier.padding(bottom = 10.dp)
            )
        }
    }
}

@Composable
private fun AboutScreen(onBack: () -> Unit) {
    Column(
        Modifier.fillMaxSize().padding(20.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        ScreenTitle("About", onBack)
        Spacer(Modifier.height(28.dp))
        Icon(Icons.Default.Shield, null, tint = Blue, modifier = Modifier.size(75.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Virus", color = Ink, fontSize = 25.sp, fontWeight = FontWeight.Bold)
            Text("Bytes", color = Cyan, fontSize = 25.sp, fontWeight = FontWeight.Bold)
        }
        Text("v1.0.0", color = Muted, fontSize = 10.sp)
        Spacer(Modifier.height(16.dp))
        Text("Powered by VirusTotal", color = Blue, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
        Spacer(Modifier.height(10.dp))
        Text(
            "VirusBytes uses the VirusTotal API to scan files, URLs and malware indicators from multiple security engines.",
            color = Muted, fontSize = 11.sp,
            textAlign = androidx.compose.ui.text.style.TextAlign.Center
        )
        Spacer(Modifier.height(22.dp))
        RoundedCard {
            Column(Modifier.padding(15.dp)) {
                AboutRow("〉", "VirusTotal", "Threat intelligence platform", Blue)
                AboutRow("▣", "Android", "Mobile application", Green)
                AboutRow("✦", "Open Source", "Built for a safer internet", Danger)
            }
        }
        Spacer(Modifier.weight(1f))
        Text("© 2026 VirusBytes. All rights reserved.", color = Muted, fontSize = 9.sp)
    }
}

@Composable
private fun DrawerScreen(onClose: () -> Unit, onNavigate: (String) -> Unit) {
    Column(Modifier.fillMaxSize().background(Night).padding(18.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Default.Shield, null, tint = Blue, modifier = Modifier.size(28.dp))
            Spacer(Modifier.width(8.dp))
            Text("Virus", color = Ink, fontSize = 20.sp, fontWeight = FontWeight.Bold)
            Text("Bytes", color = Cyan, fontSize = 20.sp, fontWeight = FontWeight.Bold)
            Spacer(Modifier.weight(1f))
            IconButton(onClick = onClose) { Icon(Icons.Default.Close, null, tint = Muted) }
        }
        Spacer(Modifier.height(28.dp))
        listOf(
            Triple("Home", Icons.Default.Home, "Home"),
            Triple("Scan File", Icons.Default.InsertDriveFile, "File Scan"),
            Triple("Scan URL", Icons.Default.Link, "URL Scan"),
            Triple("History", Icons.Default.History, "History"),
            Triple("Settings", Icons.Default.Settings, "Settings"),
            Triple("About", Icons.Default.Info, "About")
        ).forEach { item ->
            Row(
                Modifier.fillMaxWidth().clip(RoundedCornerShape(12.dp))
                    .background(if (item.third == "Home") Card2 else Color.Transparent)
                    .clickable { onNavigate(item.third) }.padding(14.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(item.second, null, tint = if (item.third == "Home") Blue else Muted)
                Spacer(Modifier.width(14.dp))
                Text(item.first, color = Ink, fontSize = 13.sp, fontWeight = FontWeight.Medium)
            }
        }
        Spacer(Modifier.weight(1f))
        RoundedCard(Modifier.fillMaxWidth(), background = BlueWash) {
            Row(Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.Shield, null, tint = Blue, modifier = Modifier.size(30.dp))
                Spacer(Modifier.width(10.dp))
                Column {
                    Text("Stay safe.", color = Ink, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                    Text("Stay informed.", color = Ink, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                    Text("Powered by VirusTotal", color = Muted, fontSize = 9.sp)
                }
            }
        }
    }
}

@Composable
private fun ScreenTitle(title: String, onBack: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().padding(top = 4.dp, bottom = 13.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        IconButton(onClick = onBack, modifier = Modifier.size(36.dp)) {
            Icon(Icons.Default.ArrowBack, null, tint = Ink, modifier = Modifier.size(21.dp))
        }
        Spacer(Modifier.width(7.dp))
        Text(title, color = Ink, fontSize = 17.sp, fontWeight = FontWeight.Bold)
    }
}

@Composable
private fun Eyebrow(text: String) {
    Text(text, color = Cyan, fontSize = 9.sp, fontWeight = FontWeight.Bold, letterSpacing = 1.3.sp)
}

@Composable
private fun RoundedCard(
    modifier: Modifier = Modifier.fillMaxWidth(),
    background: Brush = Brush.verticalGradient(listOf(Card2, Card)),
    content: @Composable ColumnScope.() -> Unit
) {
    Column(
        modifier.clip(RoundedCornerShape(17.dp))
            .background(background)
            .border(1.dp, Color(0xFF102B49), RoundedCornerShape(17.dp)),
        content = content
    )
}

@Composable
private fun GradientButton(
    text: String,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    danger: Boolean = false,
    onClick: () -> Unit
) {
    val brush = if (danger) {
        Brush.horizontalGradient(listOf(Color(0xFFFF4661), Color(0xFFE91D47)))
    } else BlueGlow
    Box(
        modifier.clip(RoundedCornerShape(13.dp))
            .background(if (enabled) brush else Card3)
            .clickable(enabled = enabled, onClick = onClick),
        contentAlignment = Alignment.Center
    ) {
        Text(text, color = Color.White, fontSize = 12.sp, fontWeight = FontWeight.Bold)
    }
}

@Composable
private fun OutlinedActionButton(text: String, modifier: Modifier = Modifier, onClick: () -> Unit) {
    Box(
        modifier.border(1.dp, Blue, RoundedCornerShape(13.dp))
            .clip(RoundedCornerShape(13.dp))
            .clickable { onClick() },
        contentAlignment = Alignment.Center
    ) {
        Text(text, color = Cyan, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
    }
}

@Composable
private fun ActionTile(
    title: String,
    subtitle: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    modifier: Modifier = Modifier,
    onClick: () -> Unit
) {
    RoundedCard(modifier.clickable { onClick() }) {
        Column(Modifier.fillMaxWidth().padding(13.dp)) {
            Box(Modifier.size(33.dp).background(Blue.copy(alpha = .13f), RoundedCornerShape(10.dp)),
                contentAlignment = Alignment.Center) {
                Icon(icon, null, tint = Blue, modifier = Modifier.size(21.dp))
            }
            Spacer(Modifier.height(9.dp))
            Text(title, color = Ink, fontSize = 12.sp, fontWeight = FontWeight.Bold)
            Text(subtitle, color = Muted, fontSize = 9.sp, lineHeight = 12.sp, maxLines = 2)
        }
    }
}

@Composable
private fun CategoryTile(
    title: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    modifier: Modifier = Modifier,
    onClick: () -> Unit
) {
    Column(
        modifier.clip(RoundedCornerShape(13.dp)).background(Card).clickable { onClick() }
            .border(1.dp, BorderBlue, RoundedCornerShape(13.dp)).padding(vertical = 13.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Icon(icon, null, tint = Color(0xFF9BCBFF), modifier = Modifier.size(21.dp))
        Spacer(Modifier.height(6.dp))
        Text(title, color = Muted, fontSize = 9.sp)
    }
}

@Composable
private fun ExamplePill(text: String, modifier: Modifier = Modifier, onClick: () -> Unit) {
    Box(
        modifier.clip(CircleShape).background(Card2).clickable { onClick() }
            .padding(horizontal = 10.dp, vertical = 10.dp),
        contentAlignment = Alignment.Center
    ) {
        Text(text, color = Muted, fontSize = 10.sp)
    }
}

@Composable
private fun StatusPill(text: String, color: Color) {
    Row(
        Modifier.clip(CircleShape).background(color.copy(alpha = .14f))
            .padding(horizontal = 9.dp, vertical = 5.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(Modifier.size(6.dp).background(color, CircleShape))
        Spacer(Modifier.width(5.dp))
        Text(text, color = color, fontSize = 9.sp, fontWeight = FontWeight.Bold)
    }
}

@Composable
private fun SummaryLine(label: String, value: Int, color: Color) {
    Row(Modifier.fillMaxWidth().padding(vertical = 5.dp), verticalAlignment = Alignment.CenterVertically) {
        Box(Modifier.size(7.dp).background(color, CircleShape))
        Spacer(Modifier.width(8.dp))
        Text(label, color = Muted, fontSize = 11.sp, modifier = Modifier.weight(1f))
        Text(value.toString(), color = if (color == Danger) Danger else Ink, fontSize = 11.sp, fontWeight = FontWeight.Bold)
    }
}

@Composable
private fun InfoLine(label: String, value: String) {
    Row(Modifier.fillMaxWidth().padding(vertical = 5.dp), verticalAlignment = Alignment.Top) {
        Text(label, color = Muted, fontSize = 10.sp, modifier = Modifier.width(74.dp))
        Text(value, color = Ink, fontSize = 10.sp, modifier = Modifier.weight(1f), maxLines = 2, overflow = TextOverflow.Ellipsis)
    }
}

@Composable
private fun HistoryRowCompact(item: ScanItem) {
    Row(Modifier.fillMaxWidth().padding(vertical = 5.dp), verticalAlignment = Alignment.CenterVertically) {
        Icon(if (item.type == "URL") Icons.Default.Link else Icons.Default.InsertDriveFile,
            null, tint = if (item.verdict == "THREATS FOUND") Danger else Cyan, modifier = Modifier.size(18.dp))
        Spacer(Modifier.width(8.dp))
        Column(Modifier.weight(1f)) {
            Text(item.name, color = Ink, fontSize = 10.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(item.date, color = Muted, fontSize = 8.sp)
        }
        Text(item.verdict, color = if (item.verdict == "THREATS FOUND") Danger else Green, fontSize = 8.sp)
    }
}

@Composable
private fun HistoryCard(item: ScanItem, onClick: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().clip(RoundedCornerShape(13.dp)).background(Card)
            .border(1.dp, Color(0xFF102943), RoundedCornerShape(13.dp))
            .clickable { onClick() }.padding(12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(Modifier.size(38.dp).background(
            (if (item.verdict == "THREATS FOUND") Danger else if (item.verdict == "REVIEW NEEDED") Amber else Green).copy(alpha = .13f),
            CircleShape
        ), contentAlignment = Alignment.Center) {
            Icon(if (item.type == "URL") Icons.Default.Link else Icons.Default.InsertDriveFile, null,
                tint = if (item.verdict == "THREATS FOUND") Danger else if (item.verdict == "REVIEW NEEDED") Amber else Green)
        }
        Spacer(Modifier.width(10.dp))
        Column(Modifier.weight(1f)) {
            Text(item.name, color = Ink, fontSize = 11.sp, fontWeight = FontWeight.SemiBold,
                maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(item.date + " · " + item.type, color = Muted, fontSize = 9.sp)
            Spacer(Modifier.height(3.dp))
            StatusPill(
                if (item.verdict == "THREATS FOUND") "Malicious" else if (item.verdict == "REVIEW NEEDED") "Suspicious" else "Clean",
                if (item.verdict == "THREATS FOUND") Danger else if (item.verdict == "REVIEW NEEDED") Amber else Green
            )
        }
        Icon(Icons.Default.ChevronRight, null, tint = Muted)
    }
}

@Composable
private fun SettingSwitch(label: String, checked: Boolean, onChecked: (Boolean) -> Unit) {
    Row(Modifier.fillMaxWidth().padding(vertical = 7.dp), verticalAlignment = Alignment.CenterVertically) {
        Text(label, color = Ink, fontSize = 11.sp, modifier = Modifier.weight(1f))
        Switch(
            checked = checked,
            onCheckedChange = onChecked,
            modifier = Modifier.height(29.dp),
            colors = SwitchDefaults.colors(
                checkedThumbColor = Color.White,
                checkedTrackColor = Blue,
                uncheckedThumbColor = Muted,
                uncheckedTrackColor = Card3
            )
        )
    }
}

@Composable
private fun AboutRow(symbol: String, title: String, subtitle: String, color: Color) {
    Row(Modifier.fillMaxWidth().padding(vertical = 9.dp), verticalAlignment = Alignment.CenterVertically) {
        Text(symbol, color = color, fontSize = 23.sp, fontWeight = FontWeight.Bold, modifier = Modifier.width(34.dp))
        Column {
            Text(title, color = Ink, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
            Text(subtitle, color = Muted, fontSize = 9.sp)
        }
    }
}

private fun getJson(address: String): JSONObject = httpRequest(address, null)

private fun postJson(address: String, body: JSONObject): JSONObject =
    httpRequest(address, body.toString().toByteArray())

private fun httpRequest(address: String, body: ByteArray?): JSONObject {
    val connection = URL(address).openConnection() as HttpURLConnection
    connection.connectTimeout = 15000
    connection.readTimeout = 25000
    if (body != null) {
        connection.requestMethod = "POST"
        connection.doOutput = true
        connection.setRequestProperty("Content-Type", "application/json")
        connection.outputStream.use { it.write(body) }
    }
    return try {
        val code = connection.responseCode
        val stream = if (code in 200..299) connection.inputStream else connection.errorStream
        val json = JSONObject(stream.bufferedReader().use { it.readText() })
        if (code !in 200..299) error(json.optString("error", "Server error ($code)"))
        json
    } finally {
        connection.disconnect()
    }
}

private fun upload(address: String, name: String, bytes: ByteArray, mime: String): String {
    val boundary = "VirusBytesBoundary" + System.currentTimeMillis()
    val connection = URL(address + "/api/scan/file").openConnection() as HttpURLConnection
    connection.requestMethod = "POST"
    connection.connectTimeout = 30000
    connection.readTimeout = 60000
    connection.doOutput = true
    connection.setRequestProperty("Content-Type", "multipart/form-data; boundary=" + boundary)
    val safeName = name.replace("\\", "_").replace("\"", "_").replace("\r", "_").replace("\n", "_")
    connection.outputStream.use { output ->
        output.write(("--" + boundary + "\r\n").toByteArray())
        output.write(("Content-Disposition: form-data; name=\"file\"; filename=\"" + safeName + "\"\r\n").toByteArray())
        output.write(("Content-Type: " + mime + "\r\n\r\n").toByteArray())
        output.write(bytes)
        output.write(("\r\n--" + boundary + "--\r\n").toByteArray())
    }
    return try {
        val code = connection.responseCode
        val stream = if (code in 200..299) connection.inputStream else connection.errorStream
        val json = JSONObject(stream.bufferedReader().use { it.readText() })
        if (code !in 200..299) error(json.optString("error", "Server error ($code)"))
        json.optString("analysisId").takeIf { it.isNotBlank() } ?: error("No analysis ID returned.")
    } finally {
        connection.disconnect()
    }
}
