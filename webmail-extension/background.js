const DEFAULT_API = "https://threatwatch-ai.nusabyte.cloud";
const LEGACY_API_URLS = new Set([
  "http://localhost:8100",
  "http://127.0.0.1:8100",
  "https://threatwatch-ai-api.up.railway.app",
]);

let latestResult = null;

function normalizeApiBaseUrl(value) {
  const normalized = String(value || DEFAULT_API).trim().replace(/\/$/, "");
  return LEGACY_API_URLS.has(normalized) ? DEFAULT_API : normalized;
}

function getBadgeState(result) {
  const verdict = result && result.verdict ? result.verdict : "";
  if (verdict === "safe") return { text: "SAFE", color: "#166534" };
  if (verdict === "suspicious") return { text: "RISK", color: "#92400e" };
  if (verdict === "scam") return { text: "SCAM", color: "#991b1b" };
  if (verdict === "scanning") return { text: "...", color: "#1d4ed8" };
  if (verdict === "error") return { text: "ERR", color: "#374151" };
  return { text: "", color: "#2563eb" };
}

async function updateActionBadge(result) {
  const badge = getBadgeState(result);
  await chrome.action.setBadgeBackgroundColor({ color: badge.color });
  await chrome.action.setBadgeText({ text: badge.text });
}

async function persistLatestResult(result) {
  latestResult = result || null;
  await chrome.storage.local.set({ threatwatchLatestResult: latestResult });
  await updateActionBadge(latestResult);
}

async function clearLatestResult() {
  latestResult = null;
  await chrome.storage.local.remove("threatwatchLatestResult");
  await updateActionBadge(null);
}

async function getExtensionSettings() {
  try {
    const result = await chrome.storage.local.get(["threatwatchApiUrl", "threatwatchScanMode"]);
    return {
      apiBaseUrl: normalizeApiBaseUrl(result.threatwatchApiUrl || DEFAULT_API),
      scanMode: result.threatwatchScanMode === "ai" ? "ai" : "standard",
    };
  } catch (error) {
    return {
      apiBaseUrl: DEFAULT_API,
      scanMode: "standard",
    };
  }
}

async function fetchScanResult(payload) {
  const settings = await getExtensionSettings();
  const endpoint = settings.scanMode === "ai" ? "/api/v1/scan/ai" : "/api/v1/scan";
  const body = {
    text: payload.text,
    channel: payload.channel || "email",
    url: payload.url || null,
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
    throw new Error(`API returned ${response.status}`);
  }

  return response.json();
}

chrome.runtime.onInstalled.addListener(() => {
  chrome.action.setBadgeText({ text: "" });
});

chrome.runtime.onStartup?.addListener(async () => {
  const stored = await chrome.storage.local.get("threatwatchLatestResult");
  latestResult = stored.threatwatchLatestResult || null;
  await updateActionBadge(latestResult);
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message) return false;

  if (message.type === "threatwatch:scan-email") {
    fetchScanResult(message.payload || {})
      .then((result) => sendResponse({ ok: true, result }))
      .catch(async (error) => {
        const settings = await getExtensionSettings();
        sendResponse({
          ok: false,
          error: String(error && error.message ? error.message : error),
          apiBaseUrl: settings.apiBaseUrl,
        });
      });
    return true;
  }

  if (!message.action) return false;

  if (message.action === "setLatestResult") {
    persistLatestResult(message.result)
      .then(() => sendResponse({ ok: true }))
      .catch((error) => sendResponse({ ok: false, error: String(error.message || error) }));
    return true;
  }

  if (message.action === "clearLatestResult") {
    clearLatestResult()
      .then(() => sendResponse({ ok: true }))
      .catch((error) => sendResponse({ ok: false, error: String(error.message || error) }));
    return true;
  }

  if (message.action === "getLatestResult") {
    (async () => {
      if (latestResult) {
        sendResponse({ ok: true, result: latestResult });
        return;
      }
      const stored = await chrome.storage.local.get("threatwatchLatestResult");
      latestResult = stored.threatwatchLatestResult || null;
      sendResponse({ ok: true, result: latestResult });
    })().catch((error) => sendResponse({ ok: false, error: String(error.message || error) }));
    return true;
  }

  return false;
});
