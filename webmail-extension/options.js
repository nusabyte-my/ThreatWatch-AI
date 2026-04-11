const DEFAULT_API = "https://threatwatch-ai.nusabyte.cloud";
const LEGACY_API_URLS = new Set([
  "http://localhost:8100",
  "http://127.0.0.1:8100",
  "https://threatwatch-ai-api.up.railway.app",
]);

function normalizeApiBaseUrl(value) {
  const normalized = String(value || DEFAULT_API).trim().replace(/\/$/, "");
  return LEGACY_API_URLS.has(normalized) ? DEFAULT_API : normalized;
}

async function restore() {
  const result = await chrome.storage.local.get(["threatwatchApiUrl", "threatwatchScanMode"]);
  document.getElementById("apiUrl").value = normalizeApiBaseUrl(result.threatwatchApiUrl);
  document.getElementById("scanMode").value = result.threatwatchScanMode === "ai" ? "ai" : "standard";
}

async function save() {
  const input = document.getElementById("apiUrl");
  const scanMode = document.getElementById("scanMode").value === "ai" ? "ai" : "standard";
  const status = document.getElementById("status");
  const value = normalizeApiBaseUrl(input.value);

  await chrome.storage.local.set({
    threatwatchApiUrl: value,
    threatwatchScanMode: scanMode,
  });
  status.textContent = `Saved: ${value} (${scanMode})`;
  window.setTimeout(() => {
    status.textContent = "";
  }, 2500);
}

document.getElementById("saveBtn").addEventListener("click", save);
restore();
