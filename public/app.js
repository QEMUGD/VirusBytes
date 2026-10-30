const $ = (selector) => document.querySelector(selector);
const scanForm = $("#scanForm");
const fileInput = $("#fileInput");
const dropzone = $("#dropzone");
const consent = $("#consent");
const scanButton = $("#scanButton");
const urlInput = $("#urlInput");
const fileTab = $("#fileTab");
const urlTab = $("#urlTab");
const filePanel = $("#filePanel");
const urlPanel = $("#urlPanel");
const resultsSection = $("#resultsSection");
const HISTORY_KEY = "virusbytes.scan-history.v1";
const MAX_FILE_SIZE = 32 * 1024 * 1024;

let mode = "file";
let selectedFile = null;
let activePollController = null;
let toastTimer = null;

function getHistory() {
  try {
    const value = JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
    return Array.isArray(value) ? value.slice(0, 30) : [];
  } catch {
    return [];
  }
}

function saveHistory(items) {
  try {
    localStorage.setItem(HISTORY_KEY, JSON.stringify(items.slice(0, 30)));
  } catch {
    showToast("Browser storage is unavailable; this scan will not be saved.");
  }
  renderHistory();
}

function showToast(message) {
  const toast = $("#toast");
  toast.textContent = message;
  toast.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove("show"), 3200);
}

function setMode(nextMode) {
  mode = nextMode;
  const isFile = mode === "file";
  filePanel.hidden = !isFile;
  urlPanel.hidden = isFile;
  fileTab.classList.toggle("active", isFile);
  urlTab.classList.toggle("active", !isFile);
  fileTab.setAttribute("aria-selected", String(isFile));
  urlTab.setAttribute("aria-selected", String(!isFile));
  updateSubmitState();
}

function updateSubmitState() {
  const ready = consent.checked && (mode === "file" ? Boolean(selectedFile) : Boolean(urlInput.value.trim()));
  scanButton.disabled = !ready;
}

function chooseFile(file) {
  if (!file) return;
  if (file.size > MAX_FILE_SIZE) {
    selectedFile = null;
    fileInput.value = "";
    $("#dropTitle").textContent = "Drop your file here";
    $("#dropSubtitle").innerHTML = 'or <b>browse files</b> from your device';
    showToast("Files must be 32 MB or smaller.");
    updateSubmitState();
    return;
  }
  selectedFile = file;
  $("#dropTitle").textContent = file.name;
  $("#dropSubtitle").textContent = formatBytes(file.size) + " · Ready to submit";
  updateSubmitState();
}

function formatBytes(bytes) {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / (1024 * 1024)).toFixed(2) + " MB";
}

function setBusy(busy) {
  scanButton.disabled = busy || !consent.checked || (mode === "file" ? !selectedFile : !urlInput.value.trim());
  scanButton.innerHTML = busy ? 'Submitting <span class="spinner">◌</span>' : 'Scan now <span>→</span>';
  scanButton.setAttribute("aria-busy", String(busy));
}

function showPending(name) {
  resultsSection.hidden = false;
  $("#resultSymbol").textContent = "◌";
  $("#resultState").textContent = "Analysis submitted";
  $("#resultName").textContent = name;
  $("#resultBadge").textContent = "IN PROGRESS";
  $("#resultBadge").className = "result-badge pending";
  $("#progressFill").style.width = "26%";
  $("#resultMessage").textContent = "VirusTotal is processing your submission. This may take a little time.";
  $("#resultStats").hidden = true;
  $("#engineResults").hidden = true;
  resultsSection.scrollIntoView({ behavior: "smooth", block: "start" });
}

function safeDate(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Just now" : date.toLocaleString();
}

function addHistory(entry) {
  const current = getHistory().filter((item) => item.id !== entry.id);
  current.unshift(entry);
  saveHistory(current);
}

function renderHistory() {
  const list = $("#historyList");
  const items = getHistory();
  $("#checksCount").textContent = String(items.length);

  if (!items.length) {
    list.innerHTML = '<div class="empty-history"><span class="empty-history-icon">◷</span><strong>No scans yet</strong><span>Your recent file and URL checks will appear here.</span></div>';
    return;
  }

  list.replaceChildren();
  for (const item of items.slice(0, 8)) {
    const row = document.createElement("div");
    row.className = "history-row";

    const itemCell = document.createElement("div");
    itemCell.className = "history-item";
    const icon = document.createElement("span");
    icon.className = "history-file-icon";
    icon.textContent = item.type === "URL" ? "↗" : "▤";
    const name = document.createElement("span");
    name.className = "history-file-name";
    name.textContent = item.name || "Unknown item";
    name.title = item.name || "";
    itemCell.append(icon, name);

    const date = document.createElement("span");
    date.className = "history-date";
    date.textContent = safeDate(item.date);

    const detections = document.createElement("span");
    detections.textContent = item.detections == null ? "—" : String(item.detections);

    const status = document.createElement("span");
    status.className = "history-status" + (item.status === "THREATS FOUND" ? " alert" : item.status === "PENDING" ? " pending" : "");
    status.textContent = item.status || "PENDING";

    row.append(itemCell, date, detections, status);
    list.append(row);
  }
}

function renderVerdict(analysis, name, type) {
  const attributes = analysis?.attributes || {};
  const stats = attributes.stats || {};
  const malicious = Number(stats.malicious || 0);
  const suspicious = Number(stats.suspicious || 0);
  const undetected = Number(stats.undetected || 0);
  const harmless = Number(stats.harmless || 0);
  const total = Object.values(stats).reduce((sum, value) => sum + (Number(value) || 0), 0);
  const hits = malicious + suspicious;
  const isDanger = malicious > 0;
  const isWarning = !isDanger && suspicious > 0;
  const isClean = hits === 0;

  $("#resultSymbol").textContent = isDanger ? "!" : isWarning ? "⚠" : "✓";
  $("#resultSymbol").style.color = isDanger ? "#ff9da6" : isWarning ? "#f4ca7c" : "#83e8b6";
  $("#resultSymbol").style.background = isDanger ? "#4a252c" : isWarning ? "#493a21" : "#173b30";
  $("#resultState").textContent = isDanger ? "Malicious detections reported" : isWarning ? "Suspicious activity reported" : "No detections reported";
  $("#resultName").textContent = name;
  $("#resultBadge").textContent = isDanger ? "THREATS FOUND" : isWarning ? "REVIEW NEEDED" : "NO DETECTIONS";
  $("#resultBadge").className = "result-badge " + (isDanger ? "danger" : isWarning ? "warning" : "clean");
  $("#progressFill").style.width = "100%";
  $("#resultMessage").textContent = isClean
    ? "No engines marked this submission as malicious or suspicious. This is not a guarantee that it is safe."
    : "One or more engines raised a flag. Treat this item with caution and review the individual engine verdicts.";
  $("#resultStats").hidden = false;
  $("#maliciousCount").textContent = String(malicious);
  $("#suspiciousCount").textContent = String(suspicious);
  $("#undetectedCount").textContent = String(undetected);
  $("#totalCount").textContent = String(total || (malicious + suspicious + undetected + harmless));

  const results = attributes.results || {};
  const engineList = $("#engineList");
  engineList.replaceChildren();
  const entries = Object.entries(results).slice(0, 80);
  for (const [engine, result] of entries) {
    const row = document.createElement("div");
    row.className = "engine-row";
    const engineName = document.createElement("span");
    engineName.textContent = engine;
    const verdict = document.createElement("span");
    const category = String(result?.category || "undetected").toLowerCase();
    const label = result?.result || category;
    verdict.textContent = label;
    verdict.className = "verdict " + (category === "malicious" ? "bad" : category === "suspicious" ? "suspicious" : category === "harmless" ? "clean" : "neutral");
    row.append(engineName, verdict);
    engineList.append(row);
  }
  $("#engineCount").textContent = entries.length + " engines shown";
  $("#engineResults").hidden = entries.length === 0;

  addHistory({
    id: activeAnalysisId || String(Date.now()),
    name,
    type,
    date: new Date().toISOString(),
    detections: hits,
    status: isDanger ? "THREATS FOUND" : isWarning ? "REVIEW NEEDED" : "NO DETECTIONS"
  });
}

let activeAnalysisId = null;

async function pollAnalysis(id, name, type) {
  activePollController = new AbortController();
  const started = Date.now();
  let attempt = 0;

  while (Date.now() - started < 120000) {
    attempt += 1;
    try {
      const response = await fetch("/api/analyses/" + encodeURIComponent(id), {
        signal: activePollController.signal,
        headers: { "accept": "application/json" }
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error || "Unable to retrieve the analysis.");
      const analysis = payload.data;
      const attributes = analysis?.attributes || {};
      const status = attributes.status;

      if (status === "completed") {
        renderVerdict(analysis, name, type);
        return;
      }

      const progress = Math.min(88, 28 + attempt * 5);
      $("#progressFill").style.width = progress + "%";
      $("#resultMessage").textContent = "Analysis is still running. Checking again…";
    } catch (error) {
      if (error.name === "AbortError") return;
      $("#resultMessage").textContent = error.message || "Could not check the analysis status.";
      return;
    }

    await new Promise((resolve) => setTimeout(resolve, 3500));
  }

  $("#resultState").textContent = "Analysis is taking longer than expected";
  $("#resultBadge").textContent = "STILL PROCESSING";
  $("#resultBadge").className = "result-badge pending";
  $("#resultMessage").textContent = "You can check this item again later from VirusTotal. No final verdict was received in this session.";
  addHistory({
    id,
    name,
    type,
    date: new Date().toISOString(),
    detections: null,
    status: "PENDING"
  });
}

async function submitScan(event) {
  event.preventDefault();
  if (!consent.checked) {
    showToast("Please confirm that you understand the submission terms.");
    return;
  }

  const isFile = mode === "file";
  if (isFile && !selectedFile) return;

  let url = "";
  if (!isFile) {
    url = urlInput.value.trim();
    try {
      const parsed = new URL(url);
      if (!["http:", "https:"].includes(parsed.protocol)) throw new Error();
    } catch {
      showToast("Enter a valid HTTP or HTTPS URL.");
      return;
    }
  }

  if (activePollController) activePollController.abort();
  setBusy(true);
  const displayName = isFile ? selectedFile.name : url;
  const type = isFile ? "FILE" : "URL";
  showPending(displayName);

  try {
    let response;
    if (isFile) {
      const body = new FormData();
      body.append("file", selectedFile);
      response = await fetch("/api/scan/file", { method: "POST", body });
    } else {
      response = await fetch("/api/scan/url", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ url })
      });
    }

    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || "The scan could not be submitted.");
    if (!payload.analysisId) throw new Error("VirusTotal did not return an analysis ID.");

    activeAnalysisId = payload.analysisId;
    $("#resultName").textContent = displayName;
    addHistory({
      id: payload.analysisId,
      name: displayName,
      type,
      date: new Date().toISOString(),
      detections: null,
      status: "PENDING"
    });
    pollAnalysis(payload.analysisId, displayName, type);
  } catch (error) {
    $("#resultState").textContent = "Could not start the scan";
    $("#resultBadge").textContent = "SUBMISSION FAILED";
    $("#resultBadge").className = "result-badge danger";
    $("#resultMessage").textContent = error.message || "Something went wrong.";
    $("#progressFill").style.width = "0%";
    showToast(error.message || "Scan failed.");
  } finally {
    setBusy(false);
  }
}

async function checkHealth() {
  try {
    const response = await fetch("/api/health", { headers: { "accept": "application/json" } });
    const data = await response.json();
    if (!response.ok) throw new Error("Server unavailable");
    const configured = Boolean(data.apiKeyConfigured);
    $("#scannerStatus").textContent = configured ? "Ready" : "Setup needed";
    $("#statusFoot").textContent = configured ? "VirusTotal API connected" : "Add your API key to .env";
    $("#sidebarStatus").textContent = configured ? "Connected" : "Not configured";
    $("#statusDot").style.background = configured ? "#62dda5" : "#e8b65d";
    if (!configured) showToast("Add VT_API_KEY to your server .env file to enable scanning.");
  } catch {
    $("#scannerStatus").textContent = "Unavailable";
    $("#statusFoot").textContent = "Could not reach the app server";
    $("#sidebarStatus").textContent = "Offline";
    $("#statusDot").style.background = "#e58a8a";
  }
}

fileTab.addEventListener("click", () => setMode("file"));
urlTab.addEventListener("click", () => setMode("url"));
fileInput.addEventListener("change", () => chooseFile(fileInput.files?.[0]));
consent.addEventListener("change", updateSubmitState);
urlInput.addEventListener("input", updateSubmitState);
scanForm.addEventListener("submit", submitScan);

for (const eventName of ["dragenter", "dragover"]) {
  dropzone.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropzone.classList.add("dragover");
  });
}
for (const eventName of ["dragleave", "drop"]) {
  dropzone.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropzone.classList.remove("dragover");
  });
}
dropzone.addEventListener("drop", (event) => {
  const file = event.dataTransfer?.files?.[0];
  if (file) chooseFile(file);
});

$("#dismissResults").addEventListener("click", () => {
  resultsSection.hidden = true;
});
$("#clearHistory").addEventListener("click", () => {
  saveHistory([]);
  showToast("Scan history cleared from this browser.");
});

document.querySelectorAll("[data-nav]").forEach((link) => {
  link.addEventListener("click", () => {
    document.querySelectorAll("[data-nav]").forEach((item) => item.classList.remove("active"));
    link.classList.add("active");
  });
});

renderHistory();
checkHealth();
