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
      panel.style.margin = "10px 0 6px";
      panel.style.padding = "10px 12px";
      panel.style.borderRadius = "10px";
      panel.style.fontFamily = "Arial, sans-serif";
      panel.style.fontSize = "13px";
      panel.style.lineHeight = "1.35";
      panel.style.boxShadow = "0 1px 2px rgba(0,0,0,0.10)";
    }

    if (!panel.parentElement || panel.previousElementSibling !== anchor) {
      anchor.insertAdjacentElement("afterend", panel);
    }

    const theme = getTheme(result?.verdict);
    const risk = typeof result?.risk_percent === "number" ? `${result.risk_percent}% risk` : "";
    const summary = getSummaryText(result);

    panel.style.background = theme.background;
    panel.style.border = `1px solid ${theme.border}`;
    panel.style.color = theme.color;
    panel.innerHTML = `
      <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;">
        <strong style="font-size:13px;">ThreatWatch AI: ${theme.label}</strong>
        <span style="font-size:12px;opacity:0.85;">${escapeHtml(risk)}</span>
      </div>
      <div style="margin-top:4px;font-size:12px;opacity:0.92;">${escapeHtml(summary)}</div>
    `;
  }

  function getSummaryText(result) {
    const reasons = Array.isArray(result?.reasons) ? result.reasons.filter(Boolean) : [];
    const explanation = result?.agent?.explanation || "";
    if (reasons.length) return reasons.slice(0, 2).join(" • ");
    if (explanation) return explanation;
    if (result?.verdict === "safe") return "No major threat indicators detected.";
    if (result?.verdict === "suspicious") return "Potential risk detected. Review carefully.";
    if (result?.verdict === "scam") return "High-confidence threat detected.";
    if (result?.verdict === "scanning") return "Scanning current Gmail message...";
    return "ThreatWatch could not complete the scan.";
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
