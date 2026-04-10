const mainBody   = document.getElementById("mainBody");
const ftStatus   = document.getElementById("ftStatus");
const dashLink   = document.getElementById("dashLink");
const scanNowBtn = document.getElementById("scanNowBtn");

const DASH_URL = "https://threatwatch-ai.nusabyte.cloud";

dashLink.href = DASH_URL;

// ── Helpers ────────────────────────────────────────────────────
function esc(v) {
  return String(v || "")
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

function fmtTime(v) {
  const d = new Date(v);
  if (Number.isNaN(d.getTime())) return "";
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function pct(v) {
  if (v === undefined || v === null) return "—";
  return `${Math.round(Number(v) * 100)}%`;
}

function verdictClass(v) {
  return { safe: "v-safe", suspicious: "v-suspicious", scam: "v-scam", scanning: "v-scanning" }[v] || "v-error";
}

function verdictLabel(v) {
  return { safe: "Safe", suspicious: "Suspicious", scam: "Scam / Phishing", scanning: "Scanning…", error: "Error", ready: "Ready" }[v] || (v || "Unknown");
}

function riskClass(pct) {
  if (pct >= 70) return "risk-high";
  if (pct >= 40) return "risk-med";
  return "risk-low";
}

function recClass(verdict) {
  if (verdict === "scam") return "rec-danger";
  if (verdict === "suspicious") return "rec-warn";
  if (verdict === "safe") return "rec-safe";
  return "";
}

function defaultExplain(verdict) {
  if (verdict === "safe") return "No threat indicators were detected in this email. The content, sender, and links appear legitimate.";
  if (verdict === "suspicious") return "Some elements of this email match known phishing or scam patterns. Review before clicking any links or sharing information.";
  if (verdict === "scam") return "This email contains strong indicators of a phishing attempt or scam. Do not click links, download attachments, or reply with personal information.";
  if (verdict === "scanning") return "Analysing email content with ML + rule engine…";
  return "ThreatWatch could not complete the scan. Check the extension options to verify the API endpoint.";
}

function defaultRec(verdict) {
  if (verdict === "safe") return "No action required. You may proceed normally.";
  if (verdict === "suspicious") return "Proceed with caution. Do not click unfamiliar links. Verify the sender through a trusted channel if unsure.";
  if (verdict === "scam") return "Do not interact with this email. Mark as spam and report to your IT team or email provider. Do not share credentials or payment details.";
  return "";
}

// ── Render ────────────────────────────────────────────────────
function renderResult(result) {
  if (!result || result.verdict === "ready" || !result.verdict) {
    mainBody.innerHTML = `<div class="empty"><strong>No scan result yet</strong>Open a Gmail message — ThreatWatch will scan it automatically.</div>`;
    ftStatus.textContent = "Waiting for Gmail…";
    return;
  }

  const v           = result.verdict || "error";
  const risk        = typeof result.risk_percent === "number" ? result.risk_percent : 0;
  const mlScore     = result.ml_score;
  const ruleScore   = result.rule_score;
  const reasons     = Array.isArray(result.reasons) ? result.reasons.filter(Boolean) : [];
  const tokens      = Array.isArray(result.highlighted_tokens) ? result.highlighted_tokens.filter(Boolean) : [];
  const agent       = result.agent || {};
  const explanation = agent.explanation || defaultExplain(v);
  const rec         = agent.user_action || defaultRec(v);
  const mode        = agent.pipeline_mode || result.scan_mode || (v === "scanning" ? "…" : "standard");
  const subject     = result.meta?.subject || "";
  const scannedAt   = result.meta?.scanned_at ? fmtTime(result.meta.scanned_at) : "";
  const confidence  = agent.confidence || result.confidence || "";

  // Flags from reasons + rule_flags
  const allFlags = [...new Set([
    ...(reasons),
    ...(Array.isArray(result.rule_flags) ? result.rule_flags : [])
  ])].slice(0, 8);

  let html = `
    <div class="verdict-card" style="border-color:${v === "scam" ? "#fca5a5" : v === "suspicious" ? "#fcd34d" : v === "safe" ? "#86efac" : "#e2e8f0"}">
      <div class="verdict-row">
        <span class="verdict-pill ${verdictClass(v)}">${esc(verdictLabel(v))}</span>
        <span class="risk-badge ${riskClass(risk)}">${risk}% risk</span>
      </div>`;

  // Score breakdown
  if (mlScore !== undefined || ruleScore !== undefined) {
    html += `<div class="scores">
      <div class="score-pill"><div class="slabel">ML score</div><div class="sval">${pct(mlScore)}</div></div>
      <div class="score-pill"><div class="slabel">Rule score</div><div class="sval">${pct(ruleScore)}</div></div>
      <div class="score-pill"><div class="slabel">Mode</div><div class="sval" style="font-size:11px">${esc(mode)}</div></div>
    </div>`;
  }

  html += `</div>`;

  // Explanation
  html += `<div>
    <div class="sec-label">Why ${esc(verdictLabel(v))}?</div>
    <div class="explain">${esc(explanation)}</div>
  </div>`;

  // Flags / triggered signals
  if (allFlags.length) {
    html += `<div>
      <div class="sec-label">Triggered signals</div>
      <div class="flags">${allFlags.map(f =>
        `<span class="flag">${esc(String(f).replace(/_/g, " "))}</span>`
      ).join("")}</div>
    </div>`;
  }

  // Suspicious tokens
  if (tokens.length) {
    html += `<div>
      <div class="sec-label">Suspicious tokens</div>
      <div class="tokens">${tokens.slice(0, 10).map(t => `<span class="token">${esc(t)}</span>`).join("")}</div>
    </div>`;
  }

  // Recommendation
  if (rec) {
    html += `<div>
      <div class="sec-label">Recommended action</div>
      <div class="rec ${recClass(v)}">${esc(rec)}</div>
    </div>`;
  }

  // Meta
  const metaParts = [];
  if (subject) metaParts.push(`<strong>Subject:</strong> ${esc(subject)}`);
  if (confidence) metaParts.push(`<strong>Confidence:</strong> ${esc(confidence)}`);
  if (scannedAt) metaParts.push(`<strong>Scanned:</strong> ${esc(scannedAt)}`);
  if (metaParts.length) {
    html += `<div class="meta">${metaParts.join(" &nbsp;·&nbsp; ")}</div>`;
  }

  mainBody.innerHTML = html;
  ftStatus.textContent = scannedAt ? `Last scan: ${scannedAt}` : (v === "scanning" ? "Scanning…" : "Scan complete");
}

// ── Scan now button ───────────────────────────────────────────
scanNowBtn.addEventListener("click", async () => {
  scanNowBtn.disabled = true;
  scanNowBtn.textContent = "Scanning…";
  ftStatus.textContent = "Requesting scan…";
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.id) throw new Error("No active tab");
    chrome.tabs.sendMessage(tab.id, { action: "scanNow" }, (resp) => {
      if (chrome.runtime.lastError) {
        ftStatus.textContent = "Could not reach content script — open a Gmail message first.";
      } else if (resp && resp.result) {
        renderResult(resp.result);
      }
    });
  } catch (e) {
    ftStatus.textContent = `Error: ${e.message}`;
  } finally {
    setTimeout(() => {
      scanNowBtn.disabled = false;
      scanNowBtn.textContent = "Scan now";
    }, 1500);
  }
});

// ── Live updates from storage ─────────────────────────────────
chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local" || !changes.threatwatchLatestResult) return;
  if (changes.threatwatchLatestResult.newValue) {
    renderResult(changes.threatwatchLatestResult.newValue);
  }
});

// ── Initial load ──────────────────────────────────────────────
(async () => {
  try {
    const stored = await chrome.storage.local.get("threatwatchLatestResult");
    renderResult(stored.threatwatchLatestResult || { verdict: "ready" });
  } catch (e) {
    renderResult({ verdict: "error", reasons: [String(e.message || e)] });
  }
})();
