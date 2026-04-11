const DEFAULT_API = "https://threatwatch-ai.nusabyte.cloud";
const LEGACY_API_URLS = new Set([
  "http://localhost:8100",
  "http://127.0.0.1:8100",
  "https://threatwatch-ai-api.up.railway.app",
]);
const DISPLAY_SCRIPT = "message_display_script.js";
const MAX_TEXT_LENGTH = 4000;

let registeredScript = null;

async function ensureDisplayScriptRegistered() {
  if (registeredScript) return registeredScript;

  registeredScript = await messenger.messageDisplayScripts.register({
    js: [{ file: DISPLAY_SCRIPT }],
    runAt: "document_idle",
  });

  return registeredScript;
}

async function scanDisplayedMessage(tab, message) {
  await ensureDisplayScriptRegistered();

  if (!tab || !message || !message.id) return;

  try {
    const full = await messenger.messages.getFull(message.id, {
      decodeContent: true,
      decodeHeaders: true,
    });

    const payload = buildScanPayload(message, full);
    const result = await fetchScanResult(payload);

    await messenger.tabs.sendMessage(tab.id, {
      type: "threatwatch:scan-result",
      payload: result,
    });
  } catch (error) {
    await safeSend(tab.id, {
      type: "threatwatch:scan-result",
      payload: {
        verdict: "error",
        risk_percent: 0,
        reasons: [String(error.message || error)],
      },
    });
  }
}

function buildScanPayload(message, full) {
  const subject = normalize(message.subject || "");
  const author = normalize(message.author || "");
  const bodyText = collectMessageText(full).slice(0, MAX_TEXT_LENGTH);

  const combined = [
    author ? `From: ${author}` : "",
    subject ? `Subject: ${subject}` : "",
    bodyText,
  ]
    .filter(Boolean)
    .join("\n\n");

  return {
    text: combined,
    channel: "email",
    url: extractFirstUrl(combined),
  };
}

function collectMessageText(part) {
  if (!part) return "";

  const current = [];
  const contentType = (part.contentType || "").toLowerCase();

  if (typeof part.body === "string") {
    if (contentType.includes("text/plain")) {
      current.push(part.body);
    } else if (contentType.includes("text/html")) {
      current.push(stripHtml(part.body));
    }
  }

  if (Array.isArray(part.parts)) {
    for (const child of part.parts) {
      const text = collectMessageText(child);
      if (text) current.push(text);
    }
  }

  return normalize(current.join("\n\n"));
}

function stripHtml(html) {
  return String(html || "")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/gi, " ");
}

function normalize(value) {
  return String(value || "")
    .replace(/\s+/g, " ")
    .trim();
}

function extractFirstUrl(text) {
  const match = String(text || "").match(/https?:\/\/[^\s"'<>]+/i);
  return match ? match[0].slice(0, 2048) : null;
}

function normalizeApiBaseUrl(value) {
  const normalized = String(value || DEFAULT_API).trim().replace(/\/$/, "");
  return LEGACY_API_URLS.has(normalized) ? DEFAULT_API : normalized;
}

async function fetchScanResult(payload) {
  const settings = await getExtensionSettings();
  const endpoint = settings.scanMode === "ai" ? "/api/v1/scan/ai" : "/api/v1/scan";
  const body = {
    text: payload.text,
    channel: payload.channel,
    url: payload.url,
  };
  if (settings.scanMode === "ai") {
    body.include_explanation = true;
  }

  const response = await fetch(`${settings.apiBaseUrl}${endpoint}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    throw new Error(`ThreatWatch API returned ${response.status}`);
  }

  return response.json();
}

async function getExtensionSettings() {
  try {
    const result = await messenger.storage.local.get(["threatwatchApiUrl", "threatwatchScanMode"]);
    return {
      apiBaseUrl: normalizeApiBaseUrl(result.threatwatchApiUrl),
      scanMode: result.threatwatchScanMode === "ai" ? "ai" : "standard",
    };
  } catch (error) {
    return {
      apiBaseUrl: DEFAULT_API,
      scanMode: "standard",
    };
  }
}

async function safeSend(tabId, message) {
  try {
    await messenger.tabs.sendMessage(tabId, message);
  } catch (error) {
    // Registered display scripts only attach to newly opened messages after startup.
  }
}

messenger.runtime.onStartup.addListener(ensureDisplayScriptRegistered);
messenger.runtime.onInstalled.addListener(ensureDisplayScriptRegistered);

messenger.messageDisplay.onMessageDisplayed.addListener((tab, message) => {
  scanDisplayedMessage(tab, message);
});

ensureDisplayScriptRegistered();
