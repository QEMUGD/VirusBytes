import "dotenv/config";
import express from "express";
import helmet from "helmet";
import multer from "multer";
import rateLimit from "express-rate-limit";

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const VT_API_KEY = process.env.VT_API_KEY;

app.disable("x-powered-by");
app.use(helmet());
app.use(express.json({ limit: "32kb" }));
app.use(express.static("public", { extensions: ["html"] }));

const scanLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 4,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: "The scan limit has been reached. Please wait a minute before trying again." }
});

const pollLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 120,
  standardHeaders: "draft-7",
  legacyHeaders: false
});

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 32 * 1024 * 1024, files: 1 }
});

function requireApiKey(_req, res, next) {
  if (!VT_API_KEY) {
    return res.status(503).json({
      error: "The VirusTotal API key is not configured. Add VT_API_KEY to your server .env file."
    });
  }
  next();
}

async function parseVirusTotalResponse(response) {
  const text = await response.text();
  let payload = {};
  try {
    payload = text ? JSON.parse(text) : {};
  } catch {
    payload = { error: { message: "VirusTotal returned an unreadable response." } };
  }

  if (!response.ok) {
    const message = payload?.error?.message || "VirusTotal could not process this request.";
    const status = response.status === 429 ? 429 : response.status === 401 || response.status === 403 ? 502 : 502;
    const error = new Error(message);
    error.status = status;
    throw error;
  }
  return payload;
}

app.get("/api/health", (_req, res) => {
  res.json({
    ok: true,
    provider: "VirusTotal",
    apiKeyConfigured: Boolean(VT_API_KEY)
  });
});

app.post("/api/scan/file", scanLimiter, requireApiKey, upload.single("file"), async (req, res, next) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: "Choose a file to scan." });
    }

    const body = new FormData();
    body.append("file", new Blob([req.file.buffer], { type: req.file.mimetype || "application/octet-stream" }), req.file.originalname);

    const response = await fetch("https://www.virustotal.com/api/v3/files", {
      method: "POST",
      headers: { "x-apikey": VT_API_KEY },
      body
    });

    const payload = await parseVirusTotalResponse(response);
    res.status(202).json({
      analysisId: payload?.data?.id,
      fileName: req.file.originalname,
      message: "File submitted to VirusTotal."
    });
  } catch (error) {
    next(error);
  }
});

app.post("/api/scan/url", scanLimiter, requireApiKey, async (req, res, next) => {
  try {
    const input = typeof req.body?.url === "string" ? req.body.url.trim() : "";
    if (!input || input.length > 2048) {
      return res.status(400).json({ error: "Enter a valid URL (maximum 2,048 characters)." });
    }

    let parsed;
    try {
      parsed = new URL(input);
    } catch {
      return res.status(400).json({ error: "That URL does not look valid." });
    }
    if (!["http:", "https:"].includes(parsed.protocol)) {
      return res.status(400).json({ error: "Only HTTP and HTTPS URLs can be submitted." });
    }

    const body = new URLSearchParams({ url: parsed.toString() });
    const response = await fetch("https://www.virustotal.com/api/v3/urls", {
      method: "POST",
      headers: {
        "x-apikey": VT_API_KEY,
        "content-type": "application/x-www-form-urlencoded"
      },
      body
    });

    const payload = await parseVirusTotalResponse(response);
    res.status(202).json({
      analysisId: payload?.data?.id,
      message: "URL submitted to VirusTotal."
    });
  } catch (error) {
    next(error);
  }
});

app.get("/api/analyses/:id", pollLimiter, requireApiKey, async (req, res, next) => {
  try {
    const id = req.params.id;
    if (!/^[A-Za-z0-9_-]{8,220}$/.test(id)) {
      return res.status(400).json({ error: "Invalid analysis identifier." });
    }

    const response = await fetch(
      `https://www.virustotal.com/api/v3/analyses/${encodeURIComponent(id)}`,
      { headers: { "x-apikey": VT_API_KEY } }
    );
    const payload = await parseVirusTotalResponse(response);
    res.json({ data: payload.data });
  } catch (error) {
    next(error);
  }
});

app.use((error, _req, res, _next) => {
  if (error instanceof multer.MulterError) {
    const message = error.code === "LIMIT_FILE_SIZE"
      ? "That file is larger than 32 MB. This version supports files up to 32 MB."
      : "The upload could not be accepted.";
    return res.status(400).json({ error: message });
  }

  const status = Number(error.status) || 500;
  if (status === 429) {
    return res.status(429).json({ error: "VirusTotal's rate limit was reached. Please wait before scanning again." });
  }
  if (status >= 500) {
    console.error("VirusBytes request failed:", error.message);
  }
  res.status(status).json({
    error: status === 500 ? "Something went wrong while contacting VirusTotal." : error.message
  });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`VirusBytes is running at http://localhost:${PORT}`);
});
