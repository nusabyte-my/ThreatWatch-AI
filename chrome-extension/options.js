const DEFAULT_API = "https://threatwatch-ai.nusabyte.cloud";

async function restore() {
  const result = await chrome.storage.local.get(["threatwatchApiUrl", "threatwatchScanMode"]);
  document.getElementById("apiUrl").value = result.threatwatchApiUrl || DEFAULT_API;
  document.getElementById("scanMode").value = result.threatwatchScanMode === "ai" ? "ai" : "standard";
}

async function save() {
  const input = document.getElementById("apiUrl");
  const scanMode = document.getElementById("scanMode").value === "ai" ? "ai" : "standard";
  const status = document.getElementById("status");
  const value = (input.value || DEFAULT_API).trim().replace(/\/$/, "");

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
