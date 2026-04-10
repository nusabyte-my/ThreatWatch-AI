(function () {
  const BADGE_ID = "threatwatch-outlook-badge";
  const SCAN_DEBOUNCE_MS = 1200;
  const MAX_TEXT_LENGTH = 4000;

  let lastFingerprint = "";
  let scanTimer = null;

  function getExtensionRuntime() {
    const runtime =
      (globalThis.chrome && globalThis.chrome.runtime) ||
      (globalThis.browser && globalThis.browser.runtime) ||
      null;
    return runtime && typeof runtime.sendMessage === "function" ? runtime : null;
  }

  async function sendRuntimeMessage(message) {
    const runtime = getExtensionRuntime();
    if (!runtime) {
      throw new Error("Extension runtime unavailable. Reload the extension and the webmail tab.");
    }
    return runtime.sendMessage(message);
  }

  async function start() {
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
      await clearLatestResult();
      return;
    }

    const fingerprint = JSON.stringify(email);
    if (fingerprint === lastFingerprint) return;
    lastFingerprint = fingerprint;

    const scanningResult = {
      verdict: "scanning",
      risk_percent: 0,
      reasons: ["Scanning current Outlook message..."],
      meta: buildScanMeta(email),
    };
    renderBadge(scanningResult);
    await persistLatestResult(scanningResult);

    try {
      const response = await sendRuntimeMessage({
        type: "threatwatch:scan-email",
        payload: {
          text: email.text,
          channel: "email",
          url: email.firstUrl,
        },
      });

      if (!response || !response.ok) {
        throw new Error(response && response.error ? response.error : "Failed to fetch");
      }

      const result = {
        ...(response.result || {}),
        meta: buildScanMeta(email),
      };
      renderBadge(result);
      await persistLatestResult(result);
    } catch (error) {
      const result = {
        verdict: "error",
        risk_percent: 0,
        reasons: [String(error.message || error)],
        meta: buildScanMeta(email),
      };
      renderBadge(result);
      await persistLatestResult(result);
    }
  }

  function extractEmailContext() {
    const subjectNode =
      document.querySelector("[role='heading'][aria-level='2']") ||
      document.querySelector("div[aria-label*='Subject']");
    const bodyNode =
      document.querySelector("[aria-label='Message body']") ||
      document.querySelector("[data-app-section='MailReadCompose'] div[role='document']") ||
      document.querySelector("div[role='document']");

    if (!subjectNode || !bodyNode) return null;

    const subject = normalizeText(subjectNode.textContent);
    const body = normalizeText(bodyNode.innerText || bodyNode.textContent || "").slice(0, MAX_TEXT_LENGTH);

    if (!subject && !body) return null;

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

  function buildScanMeta(email) {
    const subjectLine = email && email.text
      ? email.text.split("\n")[0].replace(/^Subject:\s*/, "").trim()
      : "";

    return {
      surface: "outlook",
      subject: subjectLine || "Unknown subject",
      scanned_at: new Date().toISOString(),
      thread_key: `${window.location.pathname || ""}::${window.location.hash || ""}::${subjectLine || ""}`,
    };
  }

  function renderBadge(result) {
    const anchor =
      document.querySelector("[role='heading'][aria-level='2']") ||
      document.querySelector("div[aria-label*='Subject']") ||
      document.querySelector("div[role='main']");
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
        <span style="font-size:12px;opacity:0.85;">${escapeHtml(risk)}</span>
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

  async function persistLatestResult(result) {
    try {
      await sendRuntimeMessage({ action: "setLatestResult", result });
    } catch (error) {
      // Ignore background sync failures.
    }
  }

  async function clearLatestResult() {
    try {
      await sendRuntimeMessage({ action: "clearLatestResult" });
    } catch (error) {
      // Ignore background sync failures.
    }
  }

  start();
})();
