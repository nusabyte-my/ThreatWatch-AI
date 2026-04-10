const resultCard = document.getElementById("result");

const THEMES = {
  safe: { label: "SAFE", background: "#dcfce7", border: "#86efac", color: "#166534" },
  suspicious: { label: "SUSPICIOUS", background: "#fef3c7", border: "#fcd34d", color: "#92400e" },
  scam: { label: "SCAM", background: "#fde8e8", border: "#fca5a5", color: "#991b1b" },
  scanning: { label: "SCANNING", background: "#dbeafe", border: "#93c5fd", color: "#1d4ed8" },
  error: { label: "UNAVAILABLE", background: "#f3f4f6", border: "#d1d5db", color: "#374151" },
  ready: { label: "READY", background: "#ffffff", border: "#d1d5db", color: "#111827" },
};

let refreshTimer = null;
let lastVisibleResult = null;

function renderResult(result) {
  const verdict = result && result.verdict ? result.verdict : "ready";
  lastVisibleResult = result;
  const theme = THEMES[verdict] || THEMES.ready;
  const reasons = Array.isArray(result?.reasons) ? result.reasons.slice(0, 3).join(" • ") : "";
  const explanation = result?.agent?.explanation || "";
  const risk = typeof result?.risk_percent === "number" ? `${result.risk_percent}% risk` : "";
  const subject = result?.meta?.subject || "";
  const surface = result?.meta?.surface ? result.meta.surface.toUpperCase() : "";
  const scannedAt = result?.meta?.scanned_at ? formatTime(result.meta.scanned_at) : "";
  const summary = reasons || explanation || getFallbackMessage(verdict);
  const details = [
    surface ? `Surface: ${surface}` : "",
    subject ? `Message: ${subject}` : "",
    scannedAt ? `Scanned: ${scannedAt}` : "",
  ]
    .filter(Boolean)
    .join("\n");

  resultCard.style.background = theme.background;
  resultCard.style.border = `1px solid ${theme.border}`;
  resultCard.style.color = theme.color;
  resultCard.innerHTML = `
    <div class="row">
      <div class="label">ThreatWatch AI: ${theme.label}</div>
      <div class="risk">${risk}</div>
    </div>
    <div class="meta">${escapeHtml(summary)}</div>
    ${details ? `<div class="meta" style="margin-top:6px;opacity:0.82;">${escapeHtml(details)}</div>` : ""}
  `;
}

function escapeHtml(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function getFallbackMessage(verdict) {
  if (verdict === "safe") return "No major threat indicators detected.";
  if (verdict === "suspicious") return "Potential risk detected. Review carefully.";
  if (verdict === "scam") return "High-confidence threat detected.";
  if (verdict === "scanning") return "Scanning the current webmail message...";
  if (verdict === "error") return "ThreatWatch could not complete the scan.";
  return "Open a Gmail or Outlook message to see the latest result here.";
}

function formatTime(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

async function refreshLatestResult() {
  try {
    const stored = await chrome.storage.local.get("threatwatchLatestResult");
    if (stored.threatwatchLatestResult) {
      renderResult(stored.threatwatchLatestResult);
      return;
    }
    if (!lastVisibleResult) {
      renderResult({ verdict: "ready" });
    }
  } catch (error) {
    renderResult({ verdict: "error", reasons: [String(error.message || error)] });
  }
}

chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName !== "local" || !changes.threatwatchLatestResult) return;
  if (changes.threatwatchLatestResult.newValue) {
    renderResult(changes.threatwatchLatestResult.newValue);
    return;
  }
  if (!lastVisibleResult) {
    renderResult({ verdict: "ready" });
  }
});

refreshLatestResult();
refreshTimer = window.setInterval(refreshLatestResult, 1500);
window.addEventListener("unload", () => {
  if (refreshTimer) {
    window.clearInterval(refreshTimer);
  }
});
