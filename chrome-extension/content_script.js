(function () {
  const DEFAULT_API = "http://localhost:8100";
  const BADGE_ID = "threatwatch-gmail-badge";
  const SCAN_DEBOUNCE_MS = 1200;
  const MAX_TEXT_LENGTH = 4000;

  let lastFingerprint = "";
  let scanTimer = null;
  let apiBaseUrl = DEFAULT_API;
  let scanMode = "standard";

  async function start() {
    const settings = await getExtensionSettings();
    apiBaseUrl = settings.apiBaseUrl;
    scanMode = settings.scanMode;
    observePage();
    scheduleScan();
  }

  function observePage() {
    const observer = new MutationObserver(() => scheduleScan());
    observer.observe(document.body, {
      childList: true,
      subtree: true,
      characterData: true,
    });

    window.addEventListener("hashchange", scheduleScan);
    document.addEventListener("click", scheduleScan, true);
  }

  function scheduleScan() {
    window.clearTimeout(scanTimer);
    scanTimer = window.setTimeout(scanCurrentEmail, SCAN_DEBOUNCE_MS);
  }

  async function scanCurrentEmail() {
    const email = extractEmailContext();
    if (!email) {
      removeBadge();
      return;
    }

    const fingerprint = JSON.stringify(email);
    if (fingerprint === lastFingerprint) return;
    lastFingerprint = fingerprint;

    renderBadge({
      verdict: "scanning",
      risk_percent: 0,
      reasons: ["Scanning current Gmail message..."],
    });

    try {
      const endpoint = scanMode === "ai" ? "/api/v1/scan/ai" : "/api/v1/scan";
      const payload = {
        text: email.text,
        channel: "email",
        url: email.firstUrl,
      };
      if (scanMode === "ai") {
        payload.include_explanation = true;
      }

      const response = await fetch(`${apiBaseUrl}${endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        throw new Error(`API returned ${response.status}`);
      }

      const result = await response.json();
      renderBadge(result);
    } catch (error) {
      renderBadge({
        verdict: "error",
        risk_percent: 0,
        reasons: [String(error.message || error)],
      });
    }
  }

  function extractEmailContext() {
    const subjectNode = document.querySelector("h2[data-thread-perm-id]");
    const bodyNodes = Array.from(document.querySelectorAll("div.a3s.aiL"));

    if (!subjectNode || !bodyNodes.length) {
      return null;
    }

    const subject = normalizeText(subjectNode.textContent);
    const body = normalizeText(
      bodyNodes
        .map((node) => node.innerText || node.textContent || "")
        .join("\n\n")
    ).slice(0, MAX_TEXT_LENGTH);

    if (!subject && !body) {
      return null;
    }

    const combined = [subject ? `Subject: ${subject}` : "", body]
      .filter(Boolean)
      .join("\n\n");

    return {
      text: combined,
      firstUrl: extractFirstUrl(combined),
    };
  }

  function extractFirstUrl(text) {
    const match = text.match(/https?:\/\/[^\s"'<>]+/i);
    return match ? match[0].slice(0, 2048) : null;
  }

  function normalizeText(value) {
    return String(value || "")
      .replace(/\s+/g, " ")
      .trim();
  }

  function renderBadge(result) {
    const anchor = document.querySelector("h2[data-thread-perm-id]") || document.querySelector("div[role='main']");
    if (!anchor) return;

    let badge = document.getElementById(BADGE_ID);
    if (!badge) {
      badge = document.createElement("div");
      badge.id = BADGE_ID;
      badge.style.margin = "8px 0 12px";
      badge.style.padding = "10px 12px";
      badge.style.borderRadius = "10px";
      badge.style.fontFamily = "Arial, sans-serif";
      badge.style.fontSize = "13px";
      badge.style.lineHeight = "1.4";
      badge.style.boxShadow = "0 1px 3px rgba(0,0,0,0.12)";
      anchor.insertAdjacentElement("afterend", badge);
    }

    const theme = getTheme(result.verdict);
    const reasons = Array.isArray(result.reasons) ? result.reasons.slice(0, 3) : [];
    const explanation = result.agent && result.agent.explanation ? result.agent.explanation : "";
    const risk = typeof result.risk_percent === "number" ? `${result.risk_percent}% risk` : "";

    badge.style.background = theme.background;
    badge.style.border = `1px solid ${theme.border}`;
    badge.style.color = theme.color;
    badge.innerHTML = `
      <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;">
        <strong style="font-size:13px;">ThreatWatch AI: ${theme.label}</strong>
        <span style="font-size:12px;opacity:0.85;">${risk}</span>
      </div>
      <div style="margin-top:4px;font-size:12px;opacity:0.92;">
        ${reasons.length ? escapeHtml(reasons.join(" • ")) : escapeHtml(theme.description)}
      </div>
      ${explanation ? `<div style="margin-top:6px;font-size:12px;opacity:0.88;">${escapeHtml(explanation)}</div>` : ""}
    `;
  }

  function getTheme(verdict) {
    if (verdict === "scam") {
      return {
        label: "SCAM",
        description: "High-confidence threat detected.",
        background: "#fde8e8",
        border: "#fca5a5",
        color: "#991b1b",
      };
    }
    if (verdict === "suspicious") {
      return {
        label: "SUSPICIOUS",
        description: "Potential risk detected. Review carefully.",
        background: "#fef3c7",
        border: "#fcd34d",
        color: "#92400e",
      };
    }
    if (verdict === "safe") {
      return {
        label: "SAFE",
        description: "No major threat indicators detected.",
        background: "#dcfce7",
        border: "#86efac",
        color: "#166534",
      };
    }
    if (verdict === "scanning") {
      return {
        label: "SCANNING",
        description: "Analyzing current message...",
        background: "#dbeafe",
        border: "#93c5fd",
        color: "#1d4ed8",
      };
    }
    return {
      label: "UNAVAILABLE",
      description: "ThreatWatch API could not be reached.",
      background: "#f3f4f6",
      border: "#d1d5db",
      color: "#374151",
    };
  }

  function removeBadge() {
    const badge = document.getElementById(BADGE_ID);
    if (badge) badge.remove();
    lastFingerprint = "";
  }

  function escapeHtml(value) {
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  async function getExtensionSettings() {
    try {
      const result = await chrome.storage.local.get(["threatwatchApiUrl", "threatwatchScanMode"]);
      const configured = String(result.threatwatchApiUrl || "").trim();
      return {
        apiBaseUrl: (configured || DEFAULT_API).replace(/\/$/, ""),
        scanMode: result.threatwatchScanMode === "ai" ? "ai" : "standard",
      };
    } catch (error) {
      return {
        apiBaseUrl: DEFAULT_API,
        scanMode: "standard",
      };
    }
  }

  start();
})();
