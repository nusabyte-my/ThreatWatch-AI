let latestResult = null;

function getBadgeState(result) {
  const verdict = result && result.verdict ? result.verdict : "";
  if (verdict === "safe") return { text: "SAFE", color: "#166534" };
  if (verdict === "suspicious") return { text: "RISK", color: "#92400e" };
  if (verdict === "scam") return { text: "SCAM", color: "#991b1b" };
  if (verdict === "scanning") return { text: "...", color: "#1d4ed8" };
  if (verdict === "error") return { text: "ERR", color: "#374151" };
  return { text: "", color: "#2563eb" };
}

async function updateActionBadge(result) {
  const badge = getBadgeState(result);
  await chrome.action.setBadgeBackgroundColor({ color: badge.color });
  await chrome.action.setBadgeText({ text: badge.text });
}

async function persistLatestResult(result) {
  latestResult = result || null;
  await chrome.storage.local.set({ threatwatchLatestResult: latestResult });
  await updateActionBadge(latestResult);
}

async function clearLatestResult() {
  latestResult = null;
  await chrome.storage.local.remove("threatwatchLatestResult");
  await updateActionBadge(null);
}

chrome.runtime.onInstalled.addListener(() => {
  chrome.action.setBadgeText({ text: "" });
});

chrome.runtime.onStartup?.addListener(async () => {
  const stored = await chrome.storage.local.get("threatwatchLatestResult");
  latestResult = stored.threatwatchLatestResult || null;
  await updateActionBadge(latestResult);
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || !message.action) return false;

  if (message.action === "setLatestResult") {
    persistLatestResult(message.result)
      .then(() => sendResponse({ ok: true }))
      .catch((error) => sendResponse({ ok: false, error: String(error.message || error) }));
    return true;
  }

  if (message.action === "clearLatestResult") {
    clearLatestResult()
      .then(() => sendResponse({ ok: true }))
      .catch((error) => sendResponse({ ok: false, error: String(error.message || error) }));
    return true;
  }

  if (message.action === "getLatestResult") {
    (async () => {
      if (latestResult) {
        sendResponse({ ok: true, result: latestResult });
        return;
      }
      const stored = await chrome.storage.local.get("threatwatchLatestResult");
      latestResult = stored.threatwatchLatestResult || null;
      sendResponse({ ok: true, result: latestResult });
    })().catch((error) => sendResponse({ ok: false, error: String(error.message || error) }));
    return true;
  }

  return false;
});
