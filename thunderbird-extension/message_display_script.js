(function () {
  const BANNER_ID = "threatwatch-thunderbird-banner";

  messenger.runtime.onMessage.addListener((message) => {
    if (!message || message.type !== "threatwatch:scan-result") return;
    renderBanner(message.payload || {});
  });

  function renderBanner(result) {
    const root = document.body;
    if (!root) return;

    let banner = document.getElementById(BANNER_ID);
    if (!banner) {
      banner = document.createElement("div");
      banner.id = BANNER_ID;
      banner.style.margin = "0 0 12px";
      banner.style.padding = "10px 12px";
      banner.style.borderRadius = "10px";
      banner.style.fontFamily = "Arial, sans-serif";
      banner.style.fontSize = "13px";
      banner.style.lineHeight = "1.45";
      banner.style.position = "sticky";
      banner.style.top = "0";
      banner.style.zIndex = "9999";
      banner.style.boxShadow = "0 1px 3px rgba(0,0,0,0.12)";
      root.prepend(banner);
    }

    const theme = getTheme(result.verdict);
    const reasons = Array.isArray(result.reasons) ? result.reasons.slice(0, 3) : [];
    const explanation = result.agent && result.agent.explanation ? result.agent.explanation : "";
    const risk = typeof result.risk_percent === "number" ? `${result.risk_percent}% risk` : "";

    banner.style.background = theme.background;
    banner.style.border = `1px solid ${theme.border}`;
    banner.style.color = theme.color;
    banner.innerHTML = `
      <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;">
        <strong>ThreatWatch AI: ${theme.label}</strong>
        <span style="font-size:12px;opacity:0.85;">${risk}</span>
      </div>
      <div style="margin-top:4px;font-size:12px;opacity:0.92;">
        ${escapeHtml(reasons.length ? reasons.join(" • ") : theme.description)}
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
    return {
      label: "UNAVAILABLE",
      description: "ThreatWatch API could not be reached.",
      background: "#f3f4f6",
      border: "#d1d5db",
      color: "#374151",
    };
  }

  function escapeHtml(value) {
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }
})();
