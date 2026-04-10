(function () {
  const INLINE_RESULT_ID = "threatwatch-inline-result";
  const SCAN_DEBOUNCE_MS = 1200;
  const CLICK_SCAN_DELAY_MS = 350;
  const RESYNC_INTERVAL_MS = 1000;
  const MAX_TEXT_LENGTH = 4000;

  let lastFingerprint = "";
  let scanTimer = null;
  let lastRenderedResult = null;
  let lastThreadKey = "";
  let lastSeenLocation = "";
  let lastSeenSubject = "";

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
      await clearLatestResult();
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
      lastRenderedResult = result;
      renderInlineResult(result);
      await persistLatestResult(result);
      return result;
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
      surface: "gmail",
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
    if (verdict === "safe") {
      return { label: "SAFE", background: "#dcfce7", border: "#86efac", color: "#166534" };
    }
    if (verdict === "suspicious") {
      return { label: "SUSPICIOUS", background: "#fef3c7", border: "#fcd34d", color: "#92400e" };
    }
    if (verdict === "scam") {
      return { label: "SCAM", background: "#fde8e8", border: "#fca5a5", color: "#991b1b" };
    }
    if (verdict === "scanning") {
      return { label: "SCANNING", background: "#dbeafe", border: "#93c5fd", color: "#1d4ed8" };
    }
    return { label: "UNAVAILABLE", background: "#f3f4f6", border: "#d1d5db", color: "#374151" };
  }

  function handleDocumentClick(event) {
    const target = event.target;
    if (!(target instanceof Element)) return;
    if (target.closest("tr[role='row'], div[role='main'], [data-legacy-thread-id], [data-thread-id]")) {
      scheduleImmediateScan();
    }
  }

  function getCurrentThreadKey() {
    const threadNode = document.querySelector("[data-legacy-thread-id], [data-thread-id]");
    if (threadNode) {
      return (
        threadNode.getAttribute("data-legacy-thread-id") ||
        threadNode.getAttribute("data-thread-id") ||
        ""
      );
    }
    const subject = normalizeText(findSubjectNode()?.textContent || "");
    const location = window.location.hash || window.location.pathname || "";
    return `${location}::${subject}`;
  }

  function checkForThreadChange() {
    const location = window.location.hash || window.location.pathname || "";
    const subject = normalizeText(findSubjectNode()?.textContent || "");
    const changed = location !== lastSeenLocation || subject !== lastSeenSubject;
    lastSeenLocation = location;
    lastSeenSubject = subject;
    if (changed) {
      invalidateScanCache();
    }
    return changed;
  }

  function findSubjectNode() {
    return document.querySelector("h2.hP") || document.querySelector("h2[data-thread-perm-id]");
  }

  function findInlineAnchor() {
    return findSubjectNode() || document.querySelector("div.ii.gt");
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
