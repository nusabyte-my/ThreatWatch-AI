const DEFAULT_API = "http://localhost:8100";

function normalizeApiBaseUrl(value) {
  return String(value || DEFAULT_API).trim().replace(/\/$/, "");
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

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || message.type !== "threatwatch:scan-email") {
    return false;
  }

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
});
