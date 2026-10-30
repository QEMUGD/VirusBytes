package com.virusbytes.app

import android.content.Context
import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import androidx.activity.ComponentActivity
import androidx.core.view.WindowCompat
import androidx.activity.compose.setContent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
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

private val Night = Color(0xFF050D19)
private val Card = Color(0xFF0D1A2B)
private val Card2 = Color(0xFF142943)
private val Blue = Color(0xFF168BFF)
private val Cyan = Color(0xFF26C6DA)
private val Green = Color(0xFF00D6A0)
private val Muted = Color(0xFF8BA2BD)
private val Ink = Color(0xFFF2F7FF)
private val Danger = Color(0xFFFF4567)

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        WindowCompat.setDecorFitsSystemWindows(window, true)
        setContent { VirusBytesApp(this) }
    }
}

data class ScanItem(val name: String, val type: String, val verdict: String, val count: Int, val date: String)

@Composable
private fun VirusBytesApp(context: Context) {
    val prefs = remember { context.getSharedPreferences("virusbytes", Context.MODE_PRIVATE) }
    var server by remember { mutableStateOf(prefs.getString("server", "http://10.0.2.2:3000") ?: "") }
    var tab by remember { mutableStateOf("Home") }
    var url by remember { mutableStateOf("") }
    var online by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var status by remember { mutableStateOf("Ready to scan") }
    var reportName by remember { mutableStateOf("") }
    var verdict by remember { mutableStateOf("") }
    var stats by remember { mutableStateOf(listOf(0, 0, 0, 0)) }
    var engines by remember { mutableStateOf(emptyList<Pair<String, String>>()) }
    var history by remember { mutableStateOf(emptyList<ScanItem>()) }
    val scope = rememberCoroutineScope()

    fun saveHistory(item: ScanItem) {
        history = listOf(item) + history
        val array = org.json.JSONArray()
        history.take(30).forEach { array.put(JSONObject().put("name", it.name).put("type", it.type).put("verdict", it.verdict).put("count", it.count).put("date", it.date)) }
        prefs.edit().putString("history", array.toString()).apply()
    }

    fun poll(id: String, name: String, type: String) {
        scope.launch {
            tab = "Result"
            busy = true
            verdict = ""
            reportName = name
            status = "Submitted to VirusTotal. Waiting for analysis…"
            try {
                var done = false
                for (attempt in 0 until 20) {
                    delay(15_000)
                    val response = withContext(Dispatchers.IO) { getJson(server.trimEnd('/') + "/api/analyses/" + id) }
                    val attributes = response.optJSONObject("data")?.optJSONObject("attributes") ?: JSONObject()
                    if (attributes.optString("status") == "completed") {
                        val s = attributes.optJSONObject("stats") ?: JSONObject()
                        val bad = s.optInt("malicious")
                        val suspicious = s.optInt("suspicious")
                        val undetected = s.optInt("undetected")
                        stats = listOf(bad, suspicious, undetected, bad + suspicious + undetected + s.optInt("harmless"))
                        verdict = when { bad > 0 -> "THREATS FOUND"; suspicious > 0 -> "REVIEW NEEDED"; else -> "NO DETECTIONS" }
                        val resultObject = attributes.optJSONObject("results") ?: JSONObject()
                        engines = resultObject.keys().asSequence().take(80).map { key -> key to (resultObject.optJSONObject(key)?.optString("category") ?: "undetected") }.toList()
                        status = if (bad + suspicious == 0) "No engines reported a threat. This does not guarantee the item is safe." else "One or more engines flagged this item. Do not open or run it."
                        saveHistory(ScanItem(name, type, verdict, bad + suspicious, SimpleDateFormat("MMM d, HH:mm", Locale.getDefault()).format(Date())))
                        done = true
                        break
                    }
                    status = "Analysis is running. Checking again in 15 seconds…"
                }
                if (!done) status = "Still processing. You can check the report again later on VirusTotal."
            } catch (e: Exception) { status = e.message ?: "Unable to retrieve analysis." }
            finally { busy = false }
        }
    }

    fun scanUrl() {
        val input = url.trim()
        if (!input.startsWith("https://") && !input.startsWith("http://")) { status = "Enter a valid HTTP or HTTPS address."; return }
        scope.launch {
            busy = true
            try {
                val response = withContext(Dispatchers.IO) { postJson(server.trimEnd('/') + "/api/scan/url", JSONObject().put("url", input)) }
                val id = response.optString("analysisId")
                if (id.isBlank()) error("The server did not return an analysis ID.")
                poll(id, input, "URL")
            } catch (e: Exception) { status = e.message ?: "URL scan failed." }
            finally { busy = false }
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
                val bytes = withContext(Dispatchers.IO) { context.contentResolver.openInputStream(uri)?.use { it.readBytes() } ?: error("Cannot read this file.") }
                if (bytes.size > 32 * 1024 * 1024) error("Files must be 32 MB or smaller.")
                val id = withContext(Dispatchers.IO) { upload(server.trimEnd('/'), name, bytes, context.contentResolver.getType(uri) ?: "application/octet-stream") }
                poll(id, name, "FILE")
            } catch (e: Exception) { status = e.message ?: "File scan failed." }
            finally { busy = false }
        }
    }

    LaunchedEffect(server) {
        online = try { withContext(Dispatchers.IO) { getJson(server.trimEnd('/') + "/api/health").optBoolean("apiKeyConfigured") } } catch (_: Exception) { false }
    }
    LaunchedEffect(Unit) {
        val raw = org.json.JSONArray(prefs.getString("history", "[]"))
        history = (0 until raw.length()).map { i ->
            val o = raw.getJSONObject(i)
            ScanItem(o.optString("name"), o.optString("type"), o.optString("verdict"), o.optInt("count"), o.optString("date"))
        }
    }

    MaterialTheme(colorScheme = darkColorScheme(primary = Blue, background = Night, surface = Card, onSurface = Ink)) {
        Scaffold(containerColor = Night, bottomBar = {
            NavigationBar(containerColor = Color(0xFF091525)) {
                listOf("Home", "History", "Settings").forEach { item ->
                    NavigationBarItem(selected = tab == item, onClick = { tab = item }, icon = {
                        Icon(when (item) { "Home" -> Icons.Default.Home; "History" -> Icons.Default.History; else -> Icons.Default.Settings }, null)
                    }, label = { Text(item, fontSize = 11.sp) }, colors = NavigationBarItemDefaults.colors(selectedIconColor = Cyan, selectedTextColor = Cyan, indicatorColor = Card2, unselectedIconColor = Muted, unselectedTextColor = Muted))
                }
            }
        }) { padding ->
            Column(Modifier.fillMaxSize().background(Night).padding(padding)) {
                Row(Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 16.dp), verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.Shield, null, tint = Cyan, modifier = Modifier.size(30.dp))
                    Spacer(Modifier.width(9.dp))
                    Text("Virus", color = Ink, fontSize = 22.sp, fontWeight = FontWeight.Bold)
                    Text("Bytes", color = Cyan, fontSize = 22.sp, fontWeight = FontWeight.Bold)
                    Spacer(Modifier.weight(1f))
                    Surface(color = Card, shape = CircleShape) {
                        Row(Modifier.padding(horizontal = 10.dp, vertical = 7.dp), verticalAlignment = Alignment.CenterVertically) {
                            Box(Modifier.size(7.dp).background(if (online) Green else Color(0xFFFFC15A), CircleShape))
                            Spacer(Modifier.width(7.dp))
                            Text(if (online) "Connected" else "Offline", color = Muted, fontSize = 10.sp)
                        }
                    }
                }
                when (tab) {
                    "Home" -> LazyColumn(contentPadding = PaddingValues(horizontal = 18.dp, vertical = 8.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
                        item {
                            Surface(color = Card, shape = RoundedCornerShape(24.dp)) {
                                Column(Modifier.fillMaxWidth().padding(22.dp)) {
                                    Text("YOUR SECURITY, IN FOCUS", color = Cyan, fontSize = 10.sp, fontWeight = FontWeight.Bold, letterSpacing = 1.4.sp)
                                    Spacer(Modifier.height(18.dp))
                                    Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
                                        Box(Modifier.size(126.dp).border(2.dp, Green.copy(alpha = .6f), CircleShape).background(Green.copy(alpha = .07f), CircleShape), contentAlignment = Alignment.Center) {
                                            Icon(Icons.Default.Shield, null, tint = Green, modifier = Modifier.size(72.dp))
                                        }
                                    }
                                    Spacer(Modifier.height(14.dp))
                                    Text("You're protected", color = Green, fontSize = 22.sp, fontWeight = FontWeight.Bold, modifier = Modifier.align(Alignment.CenterHorizontally))
                                    Text("On-demand checks powered by VirusTotal", color = Muted, fontSize = 12.sp, modifier = Modifier.align(Alignment.CenterHorizontally))
                                    Spacer(Modifier.height(18.dp))
                                    Button(onClick = { filePicker.launch(arrayOf("*/*")) }, enabled = !busy, modifier = Modifier.fillMaxWidth().height(52.dp), shape = RoundedCornerShape(14.dp)) { Text("Scan a file now", fontWeight = FontWeight.Bold) }
                                }
                            }
                        }
                        item { Text("QUICK SCANS", color = Muted, fontSize = 10.sp, fontWeight = FontWeight.Bold, letterSpacing = 1.4.sp) }
                        item { Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                            Tile("Scan File", "Check a file", Icons.Default.InsertDriveFile, Modifier.weight(1f)) { filePicker.launch(arrayOf("*/*")) }
                            Tile("Scan URL", "Inspect a link", Icons.Default.Link, Modifier.weight(1f)) { tab = "URL Scan" }
                        } }
                        item { Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                            Tile("Scan History", "Past reports", Icons.Default.History, Modifier.weight(1f)) { tab = "History" }
                            Tile("Settings", "App preferences", Icons.Default.Settings, Modifier.weight(1f)) { tab = "Settings" }
                        } }
                        item {
                            Surface(color = Card, shape = RoundedCornerShape(16.dp)) {
                                Column(Modifier.padding(16.dp)) {
                                    Text("Recent activity", color = Ink, fontWeight = FontWeight.Bold)
                                    Spacer(Modifier.height(10.dp))
                                    if (history.isEmpty()) Text("Your scans will appear here.", color = Muted, fontSize = 12.sp)
                                    else history.take(3).forEach { HistoryRow(it) }
                                }
                            }
                        }
                    }
                    "URL Scan" -> Column(Modifier.fillMaxSize().padding(20.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
                        BackTitle("Scan URL") { tab = "Home" }
                        Text("Check a link before you visit", color = Ink, fontSize = 21.sp, fontWeight = FontWeight.Bold)
                        OutlinedTextField(url, { url = it }, modifier = Modifier.fillMaxWidth(), label = { Text("Website URL") }, placeholder = { Text("https://example.com") }, singleLine = true, shape = RoundedCornerShape(14.dp))
                        Button(onClick = { scanUrl() }, enabled = !busy, modifier = Modifier.fillMaxWidth().height(52.dp)) { Text(if (busy) "Scanning…" else "Scan URL") }
                        Text("Only HTTP and HTTPS links are supported. Public submissions may be shared by VirusTotal.", color = Muted, fontSize = 11.sp)
                        if (status.isNotBlank()) Text(status, color = Muted, fontSize = 12.sp)
                    }
                    "Result" -> LazyColumn(contentPadding = PaddingValues(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        item { BackTitle("Scan Results") { tab = "Home" } }
                        item {
                            Surface(color = Card, shape = RoundedCornerShape(20.dp)) {
                                Column(Modifier.fillMaxWidth().padding(20.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                                    Icon(if (verdict == "THREATS FOUND") Icons.Default.GppBad else Icons.Default.VerifiedUser, null, tint = if (verdict == "THREATS FOUND") Danger else Green, modifier = Modifier.size(58.dp))
                                    Text(if (verdict.isBlank()) "Analysis in progress" else verdict, color = if (verdict == "THREATS FOUND") Danger else Green, fontWeight = FontWeight.Bold, fontSize = 19.sp)
                                    Text(reportName, color = Muted, fontSize = 11.sp, maxLines = 2, overflow = TextOverflow.Ellipsis)
                                    Spacer(Modifier.height(12.dp))
                                    if (busy) CircularProgressIndicator(color = Cyan)
                                    Text(status, color = Muted, fontSize = 12.sp)
                                }
                            }
                        }
                        if (stats.any { it > 0 }) item {
                            Row(horizontalArrangement = Arrangement.spacedBy(7.dp)) {
                                listOf("Malicious", "Suspicious", "Undetected", "Engines").forEachIndexed { index, label ->
                                    Surface(Modifier.weight(1f), color = Card, shape = RoundedCornerShape(11.dp)) {
                                        Column(Modifier.padding(9.dp)) { Text(stats[index].toString(), color = if (index == 0 && stats[index] > 0) Danger else Ink, fontWeight = FontWeight.Bold, fontSize = 18.sp); Text(label, color = Muted, fontSize = 9.sp) }
                                    }
                                }
                            }
                        }
                        if (engines.isNotEmpty()) item { Text("ENGINE VERDICTS", color = Muted, fontWeight = FontWeight.Bold, fontSize = 10.sp) }
                        items(engines) { row ->
                            Row(Modifier.fillMaxWidth().background(Card, RoundedCornerShape(10.dp)).padding(12.dp), horizontalArrangement = Arrangement.SpaceBetween) {
                                Text(row.first, color = Ink, fontSize = 12.sp)
                                Text(row.second, color = if (row.second == "malicious") Danger else if (row.second == "suspicious") Color(0xFFFFC15A) else Green, fontSize = 11.sp)
                            }
                        }
                    }
                    "History" -> LazyColumn(contentPadding = PaddingValues(20.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        item { Text("Scan History", color = Ink, fontSize = 22.sp, fontWeight = FontWeight.Bold) }
                        if (history.isEmpty()) item { Text("No scans yet. Your reports will show here.", color = Muted) }
                        items(history) { HistoryRow(it) }
                    }
                    else -> Column(Modifier.fillMaxSize().padding(20.dp), verticalArrangement = Arrangement.spacedBy(15.dp)) {
                        Text("Settings", color = Ink, fontSize = 22.sp, fontWeight = FontWeight.Bold)
                        Text("SERVER CONNECTION", color = Cyan, fontSize = 10.sp, fontWeight = FontWeight.Bold)
                        OutlinedTextField(server, { server = it; prefs.edit().putString("server", it).apply() }, modifier = Modifier.fillMaxWidth(), label = { Text("VirusBytes server URL") }, placeholder = { Text("http://192.168.1.10:3000") }, singleLine = true)
                        Text("Emulator default: http://10.0.2.2:3000. On a real phone, enter your computer's LAN IP and use the same Wi-Fi.", color = Muted, fontSize = 11.sp)
                        Text("ABOUT VIRUSBYTES", color = Cyan, fontSize = 10.sp, fontWeight = FontWeight.Bold)
                        Text("VirusBytes is an on-demand scanner. It does not provide real-time protection, quarantine, or malware removal.", color = Muted, fontSize = 12.sp)
                    }
                }
            }
        }
    }
}

@Composable
private fun Tile(title: String, subtitle: String, icon: androidx.compose.ui.graphics.vector.ImageVector, modifier: Modifier, action: () -> Unit) {
    Surface(modifier.clickable { action() }, color = Card, shape = RoundedCornerShape(16.dp)) {
        Column(Modifier.padding(15.dp)) {
            Icon(icon, null, tint = Cyan, modifier = Modifier.size(25.dp))
            Spacer(Modifier.height(11.dp))
            Text(title, color = Ink, fontWeight = FontWeight.Bold, fontSize = 13.sp)
            Text(subtitle, color = Muted, fontSize = 10.sp)
        }
    }
}

@Composable
private fun BackTitle(title: String, back: () -> Unit) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        IconButton(onClick = back) { Icon(Icons.Default.ArrowBack, null, tint = Ink) }
        Text(title, color = Ink, fontSize = 19.sp, fontWeight = FontWeight.Bold)
    }
}

@Composable
private fun HistoryRow(item: ScanItem) {
    Row(Modifier.fillMaxWidth().background(Card, RoundedCornerShape(12.dp)).padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
        Icon(if (item.type == "URL") Icons.Default.Link else Icons.Default.InsertDriveFile, null, tint = Cyan)
        Spacer(Modifier.width(10.dp))
        Column(Modifier.weight(1f)) {
            Text(item.name, color = Ink, fontSize = 12.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(item.date, color = Muted, fontSize = 10.sp)
        }
        Text(item.verdict, color = if (item.verdict == "THREATS FOUND") Danger else Green, fontSize = 9.sp, fontWeight = FontWeight.Bold)
    }
}

private fun getJson(address: String): JSONObject = httpRequest(address, null)

private fun postJson(address: String, body: JSONObject): JSONObject = httpRequest(address, body.toString().toByteArray())

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
    } finally { connection.disconnect() }
}

private fun upload(address: String, name: String, bytes: ByteArray, mime: String): String {
    val boundary = "VirusBytesBoundary" + System.currentTimeMillis()
    val connection = URL(address + "/api/scan/file").openConnection() as HttpURLConnection
    connection.requestMethod = "POST"
    connection.connectTimeout = 30000
    connection.readTimeout = 60000
    connection.doOutput = true
    connection.setRequestProperty("Content-Type", "multipart/form-data; boundary=" + boundary)
    connection.outputStream.use { output ->
        output.write(("--" + boundary + "\r\n").toByteArray())
        output.write("Content-Disposition: form-data; name=\"file\"; filename=\"upload.bin\"\r\n".toByteArray())
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
    } finally { connection.disconnect() }
}
