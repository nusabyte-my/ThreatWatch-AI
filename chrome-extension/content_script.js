(function () {
  const DEFAULT_API = "http://localhost:8100";
  const INLINE_RESULT_ID = "threatwatch-inline-result";
  const SCAN_DEBOUNCE_MS = 1200;
  const CLICK_SCAN_DELAY_MS = 350;
  const RESYNC_INTERVAL_MS = 1000;
  const MAX_TEXT_LENGTH = 4000;

  let lastFingerprint = "";
  let scanTimer = null;
  let apiBaseUrl = DEFAULT_API;
  let scanMode = "standard";
  let lastRenderedResult = null;
  let lastThreadKey = "";
  let lastSeenLocation = "";
  let lastSeenSubject = "";

  async function start() {
    const settings = await getExtensionSettings();
    apiBaseUrl = settings.apiBaseUrl;
    scanMode = settings.scanMode;
    observePage();
    installStorageListener();
    window.setInterval(() => {
      if (checkForThreadChange()) {
        scheduleImmediateScan(150);
        return;
      }
      scheduleScan();
    }, RESYNC_INTERVAL_MS);
    scheduleScan();
  }

  function observePage() {
    const observer = new MutationObserver(() => scheduleScan());
    observer.observe(document.body, {
      childList: true,
      subtree: true,
      characterData: true,
    });

    window.addEventListener("hashchange", () => {
      invalidateScanCache();
      scheduleImmediateScan();
    });
    window.addEventListener("focus", scheduleScan);
    document.addEventListener("visibilitychange", scheduleScan);
    document.addEventListener("click", handleDocumentClick, true);
  }

  function installStorageListener() {
    if (!chrome.storage || !chrome.storage.onChanged) return;
    chrome.storage.onChanged.addListener((changes, areaName) => {
      if (areaName !== "local") return;
      if (changes.threatwatchApiUrl) {
        apiBaseUrl = String(changes.threatwatchApiUrl.newValue || DEFAULT_API).trim().replace(/\/$/, "");
      }
      if (changes.threatwatchScanMode) {
        scanMode = changes.threatwatchScanMode.newValue === "ai" ? "ai" : "standard";
      }
      invalidateScanCache();
      scheduleScan();
    });
  }

  function scheduleScan() {
    window.clearTimeout(scanTimer);
    scanTimer = window.setTimeout(scanCurrentEmail, SCAN_DEBOUNCE_MS);
  }

  function scheduleImmediateScan(delayMs = CLICK_SCAN_DELAY_MS) {
    window.clearTimeout(scanTimer);
    scanTimer = window.setTimeout(triggerImmediateScan, delayMs);
  }

  function invalidateScanCache() {
    lastFingerprint = "";
    lastThreadKey = "";
  }

  function triggerImmediateScan() {
    window.clearTimeout(scanTimer);
    invalidateScanCache();
    lastRenderedResult = {
      verdict: "scanning",
      risk_percent: 0,
      reasons: ["Scanning current Gmail message..."],
      meta: buildScanMeta(),
    };
    renderInlineResult(lastRenderedResult);
    persistLatestResult(lastRenderedResult);
    return scanCurrentEmail();
  }

  async function scanCurrentEmail() {
    const email = extractEmailContext();
    if (!email) {
      lastFingerprint = "";
      lastThreadKey = "";
      return {
        verdict: "error",
        risk_percent: 0,
        reasons: ["No open Gmail message detected."],
      };
    }

    const threadKey = getCurrentThreadKey();
    const fingerprint = JSON.stringify(email);
    if (fingerprint === lastFingerprint && threadKey === lastThreadKey && lastRenderedResult) {
      return lastRenderedResult;
    }
    lastFingerprint = fingerprint;
    lastThreadKey = threadKey;
    lastRenderedResult = {
      verdict: "scanning",
      risk_percent: 0,
      reasons: ["Scanning current Gmail message..."],
      meta: buildScanMeta(email),
    };
    renderInlineResult(lastRenderedResult);
    await persistLatestResult(lastRenderedResult);

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
      lastRenderedResult = {
        ...result,
        meta: buildScanMeta(email),
      };
      renderInlineResult(lastRenderedResult);
      await persistLatestResult(lastRenderedResult);
      return lastRenderedResult;
    } catch (error) {
      const errorResult = {
        verdict: "error",
        risk_percent: 0,
        reasons: [String(error.message || error)],
        meta: buildScanMeta(email),
      };
      lastRenderedResult = errorResult;
      renderInlineResult(errorResult);
      await persistLatestResult(errorResult);
      return errorResult;
    }
  }

  function extractEmailContext() {
    const subjectNode = findSubjectNode();
    const bodyNodes = Array.from(document.querySelectorAll("div.a3s.aiL, div.a3s"));

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

  function buildScanMeta(email) {
    const subjectLine = email && email.text
      ? email.text.split("\n")[0].replace(/^Subject:\s*/, "").trim()
      : normalizeText(findSubjectNode()?.textContent || "");

    return {
      subject: subjectLine || "Unknown subject",
      scanned_at: new Date().toISOString(),
      thread_key: getCurrentThreadKey(),
    };
  }

  function renderInlineResult(result) {
    const anchor = findInlineAnchor();
    if (!anchor) return;

    let panel = document.getElementById(INLINE_RESULT_ID);
    if (!panel) {
      panel = document.createElement("div");
      panel.id = INLINE_RESULT_ID;
      panel.style.cssText = [
        "margin:10px 0 8px",
        "border-radius:12px",
        "font-family:-apple-system,'Segoe UI',Arial,sans-serif",
        "font-size:13px",
        "line-height:1.45",
        "box-shadow:0 2px 8px rgba(0,0,0,0.10)",
        "overflow:hidden",
      ].join(";");
    }

    if (!panel.parentElement || panel.previousElementSibling !== anchor) {
      anchor.insertAdjacentElement("afterend", panel);
    }

    const v       = result?.verdict || "error";
    const theme   = getTheme(v);
    const risk    = typeof result?.risk_percent === "number" ? result.risk_percent : null;
    const mlScore = result?.ml_score;
    const ruleScore = result?.rule_score;
    const agent   = result?.agent || {};
    const reasons = Array.isArray(result?.reasons) ? result.reasons.filter(Boolean) : [];
    const tokens  = Array.isArray(result?.highlighted_tokens) ? result.highlighted_tokens.filter(Boolean) : [];
    const ruleFlags = Array.isArray(result?.rule_flags) ? result.rule_flags.filter(Boolean) : [];
    const allFlags  = [...new Set([...reasons, ...ruleFlags])].slice(0, 6);
    const explanation = agent.explanation || getDefaultExplain(v);
    const rec     = agent.user_action || getDefaultRec(v);
    const mode    = agent.pipeline_mode || result?.scan_mode || "";
    const confidence = agent.confidence || "";

    const pct = (n) => n !== undefined && n !== null ? `${Math.round(Number(n) * 100)}%` : "—";

    let scoreHtml = "";
    if (mlScore !== undefined || ruleScore !== undefined) {
      scoreHtml = `
        <div style="display:flex;gap:6px;margin:6px 0 0">
          <div style="flex:1;padding:4px 6px;border-radius:6px;background:rgba(0,0,0,.04);text-align:center">
            <div style="font-size:10px;opacity:.65;text-transform:uppercase;letter-spacing:.06em">ML</div>
            <div style="font-weight:700;font-size:12px;margin-top:1px">${pct(mlScore)}</div>
          </div>
          <div style="flex:1;padding:4px 6px;border-radius:6px;background:rgba(0,0,0,.04);text-align:center">
            <div style="font-size:10px;opacity:.65;text-transform:uppercase;letter-spacing:.06em">Rules</div>
            <div style="font-weight:700;font-size:12px;margin-top:1px">${pct(ruleScore)}</div>
          </div>
          ${risk !== null ? `<div style="flex:1;padding:4px 6px;border-radius:6px;background:rgba(0,0,0,.04);text-align:center">
            <div style="font-size:10px;opacity:.65;text-transform:uppercase;letter-spacing:.06em">Risk</div>
            <div style="font-weight:700;font-size:12px;margin-top:1px">${risk}%</div>
          </div>` : ""}
          ${mode ? `<div style="flex:1;padding:4px 6px;border-radius:6px;background:rgba(0,0,0,.04);text-align:center">
            <div style="font-size:10px;opacity:.65;text-transform:uppercase;letter-spacing:.06em">Mode</div>
            <div style="font-weight:600;font-size:10px;margin-top:2px">${escapeHtml(mode)}</div>
          </div>` : ""}
        </div>`;
    }

    let flagsHtml = "";
    if (allFlags.length && v !== "scanning" && v !== "error") {
      flagsHtml = `
        <div style="margin-top:7px">
          <div style="font-size:10px;text-transform:uppercase;letter-spacing:.07em;opacity:.55;margin-bottom:4px;font-weight:700">Triggered signals</div>
          <div style="display:flex;flex-wrap:wrap;gap:4px">
            ${allFlags.map(f => `<span style="padding:2px 7px;border-radius:5px;font-size:11px;font-weight:500;background:rgba(0,0,0,.06);opacity:.9">${escapeHtml(String(f).replace(/_/g, " "))}</span>`).join("")}
          </div>
        </div>`;
    }

    let tokensHtml = "";
    if (tokens.length && v !== "scanning" && v !== "safe") {
      tokensHtml = `
        <div style="margin-top:6px">
          <div style="font-size:10px;text-transform:uppercase;letter-spacing:.07em;opacity:.55;margin-bottom:4px;font-weight:700">Suspicious indicators</div>
          <div style="display:flex;flex-wrap:wrap;gap:3px">
            ${tokens.slice(0, 8).map(t => `<code style="padding:1px 5px;border-radius:4px;font-size:10px;background:rgba(0,0,0,.06)">${escapeHtml(t)}</code>`).join("")}
          </div>
        </div>`;
    }

    let recHtml = "";
    if (rec && v !== "scanning" && v !== "error") {
      recHtml = `
        <div style="margin-top:7px;padding:6px 9px;border-radius:7px;background:rgba(0,0,0,.06);font-size:12px;line-height:1.45">
          <span style="font-weight:700;font-size:10px;text-transform:uppercase;letter-spacing:.07em;opacity:.6;display:block;margin-bottom:2px">Recommended action</span>
          ${escapeHtml(rec)}
        </div>`;
    }

    panel.style.background = theme.background;
    panel.style.border = `1px solid ${theme.border}`;
    panel.style.color = theme.color;
    panel.innerHTML = `
      <div style="padding:10px 13px">
        <div style="display:flex;align-items:center;justify-content:space-between;gap:8px">
          <strong style="font-size:13px;letter-spacing:-.01em">
            🛡 ThreatWatch AI &nbsp;<span style="font-weight:800">${escapeHtml(theme.label)}</span>
          </strong>
          ${risk !== null ? `<span style="font-size:12px;font-weight:600;opacity:.8">${risk}% risk</span>` : ""}
        </div>

        ${explanation && v !== "scanning" ? `
          <div style="margin-top:6px;font-size:12px;line-height:1.5;opacity:.9">${escapeHtml(explanation)}</div>` : ""}

        ${v === "scanning" ? `
          <div style="margin-top:5px;font-size:12px;opacity:.8">Analysing content with ML engine and rule patterns…</div>` : ""}

        ${scoreHtml}
        ${flagsHtml}
        ${tokensHtml}
        ${recHtml}

        ${confidence ? `<div style="margin-top:5px;font-size:10px;opacity:.5">Confidence: ${escapeHtml(confidence)}</div>` : ""}
      </div>`;
  }

  function getDefaultExplain(verdict) {
    if (verdict === "safe") return "No threat indicators were detected. The content, sender, and any links appear legitimate based on ML analysis and rule matching.";
    if (verdict === "suspicious") return "Some elements of this email match patterns associated with phishing or scams. Exercise caution before clicking links or sharing information.";
    if (verdict === "scam") return "This email contains strong indicators of a phishing attempt or scam — such as urgent language, spoofed sender, or suspicious links. Do not interact with it.";
    if (verdict === "scanning") return "";
    return "The scan could not be completed. Verify the extension options and API connectivity.";
  }

  function getDefaultRec(verdict) {
    if (verdict === "safe") return "No action required.";
    if (verdict === "suspicious") return "Do not click links or download attachments without verifying the sender through a trusted channel.";
    if (verdict === "scam") return "Do not reply, click any links, or provide personal information. Mark as spam and report to your IT/security team.";
    return "";
  }

  function getSummaryText(result) {
    const reasons = Array.isArray(result?.reasons) ? result.reasons.filter(Boolean) : [];
    const explanation = result?.agent?.explanation || "";
    if (explanation) return explanation;
    if (reasons.length) return reasons.slice(0, 2).join(" • ");
    return getDefaultExplain(result?.verdict || "error");
  }

  function getTheme(verdict) {
    if (verdict === "scam") {
      return { label: "SCAM", background: "#fde8e8", border: "#fca5a5", color: "#991b1b" };
    }
    if (verdict === "suspicious") {
      return { label: "SUSPICIOUS", background: "#fef3c7", border: "#fcd34d", color: "#92400e" };
    }
    if (verdict === "safe") {
      return { label: "SAFE", background: "#dcfce7", border: "#86efac", color: "#166534" };
    }
    if (verdict === "scanning") {
      return { label: "SCANNING", background: "#dbeafe", border: "#93c5fd", color: "#1d4ed8" };
    }
    return { label: "UNAVAILABLE", background: "#f3f4f6", border: "#d1d5db", color: "#374151" };
  }

  function findInlineAnchor() {
    return (
      document.querySelector("h3.iw, .gD") ||
      findSubjectNode() ||
      document.querySelector("div[role='main']")
    );
  }

  function escapeHtml(value) {
    return String(value || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/\"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  async function persistLatestResult(result) {
    try {
      await chrome.storage.local.set({ threatwatchLatestResult: result });
    } catch (error) {
      // Ignore storage failures in content script.
    }
    try {
      await chrome.runtime.sendMessage({ action: "setLatestResult", result });
    } catch (error) {
      // Ignore messaging failures in content script.
    }
  }

  function handleDocumentClick(event) {
    const target = event.target;
    if (!(target instanceof Element)) {
      scheduleScan();
      return;
    }

    const openedThread =
      target.closest("tr[role='row']") ||
      target.closest("[data-legacy-thread-id]") ||
      target.closest("[data-thread-id]") ||
      target.closest("h2[data-thread-perm-id]") ||
      target.closest("h2.hP");

    if (openedThread) {
      invalidateScanCache();
      scheduleImmediateScan();
      return;
    }

    scheduleScan();
  }

  function getCurrentThreadKey() {
    const subjectNode = findSubjectNode();
    if (subjectNode) {
      const permId = subjectNode.getAttribute("data-thread-perm-id");
      const legacyId = subjectNode.getAttribute("data-legacy-thread-id");
      if (permId || legacyId) {
        return `${permId || ""}|${legacyId || ""}`;
      }
    }
    return window.location.hash || window.location.href;
  }

  function findSubjectNode() {
    return (
      document.querySelector("h2[data-thread-perm-id]") ||
      document.querySelector("h2.hP") ||
      document.querySelector("div[role='main'] h2")
    );
  }

  function findPrimaryAnchor() {
    return findSubjectNode() || document.querySelector("div[role='main']");
  }

  function checkForThreadChange() {
    const currentLocation = window.location.href;
    const currentSubject = normalizeText(findSubjectNode()?.textContent || "");
    if (currentLocation !== lastSeenLocation || currentSubject !== lastSeenSubject) {
      lastSeenLocation = currentLocation;
      lastSeenSubject = currentSubject;
      invalidateScanCache();
      return true;
    }
    return false;
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

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (!message || !message.action) {
      return false;
    }

    if (message.action === "scanNow") {
      triggerImmediateScan()
        .then((result) => sendResponse({ ok: true, result }))
        .catch((error) => {
          sendResponse({
            ok: false,
            result: {
              verdict: "error",
              risk_percent: 0,
              reasons: [String(error.message || error)],
            },
          });
        });
      return true;
    }

    if (message.action === "getLatestResult") {
      sendResponse({ ok: true, result: lastRenderedResult });
      return false;
    }

    return false;
  });

  start();
})();
