/**
 * AI Shield — Gmail Content Script (shield.js)
 */

let API_BASE = "http://localhost:8000";
const HEALTH_CHECK_INTERVAL = 30000; // 30 seconds
const MUTATION_DEBOUNCE_MS = 500;
const POLL_INTERVAL_MS = 3000;

let serverOnline = false;
let debounceTimer = null;
let pollTimer = null;

// ─── Initialization ──────────────────────────────────────────────────────────

async function init() {
  const data = await chrome.storage.sync.get({ apiBaseUrl: "http://localhost:8000" });
  API_BASE = data.apiBaseUrl;

  checkServerHealth();
  setInterval(checkServerHealth, HEALTH_CHECK_INTERVAL);

  setupMutationObserver();
  setupFallbackPolling();

  chrome.runtime.onMessage.addListener(handleMessage);
  console.log("[AI Shield] Content script initialized. API:", API_BASE);
}

// ─── Server Health Monitoring ────────────────────────────────────────────────

async function checkServerHealth() {
  try {
    const response = await fetch(`${API_BASE}/api/health`, {
      method: "GET",
      signal: AbortSignal.timeout(5000),
    });

    if (response.ok) {
      if (!serverOnline) {
        serverOnline = true;
        hideOfflineBanner();
        console.log("[AI Shield] Server connected.");
      }
    } else {
      handleServerOffline();
    }
  } catch (e) {
    handleServerOffline();
  }
}

function handleServerOffline() {
  if (serverOnline || !document.querySelector(".ai-shield-offline-banner")) {
    serverOnline = false;
    showOfflineBanner();
    console.log("[AI Shield] Server offline.");
  }
}

// ─── Offline Banner ──────────────────────────────────────────────────────────

function showOfflineBanner() {
  if (document.querySelector(".ai-shield-offline-banner")) return;

  const banner = document.createElement("div");
  banner.className = "ai-shield-offline-banner";
  banner.innerHTML = `
    <div class="ai-shield-offline-content">
      <span class="ai-shield-offline-icon">⚠️</span>
      <span class="ai-shield-offline-text">
        <strong>AI Shield server is unreachable.</strong>
        Check your API Base URL in the extension settings.
      </span>
      <button class="ai-shield-offline-dismiss" onclick="this.parentElement.parentElement.remove()">✕</button>
    </div>
  `;
  document.body.prepend(banner);
}

function hideOfflineBanner() {
  const banner = document.querySelector(".ai-shield-offline-banner");
  if (banner) banner.remove();
}

// ─── Gmail DOM Observation ───────────────────────────────────────────────────

function setupMutationObserver() {
  const observer = new MutationObserver(() => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      checkForNewEmails();
    }, MUTATION_DEBOUNCE_MS);
  });
  observer.observe(document.body, { childList: true, subtree: true });
}

function setupFallbackPolling() {
  pollTimer = setInterval(() => {
    checkForNewEmails();
  }, POLL_INTERVAL_MS);
}

function checkForNewEmails() {
  if (!serverOnline) return;

  const emailBodies = document.querySelectorAll(".a3s.aiL");
  emailBodies.forEach((emailBody) => {
    if (emailBody.dataset.aiShieldScanned === "true") return;
    emailBody.dataset.aiShieldScanned = "true";

    const text = emailBody.innerText || emailBody.textContent || "";
    if (text.trim().length > 20) {
      autoScanEmail(text, emailBody);
    }
  });
}

// ─── Auto-Scanning ───────────────────────────────────────────────────────────

async function autoScanEmail(text, emailElement) {
  if (!serverOnline) return;

  try {
    const response = await fetch(`${API_BASE}/api/scan-email`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: text.substring(0, 50000) }),
    });

    if (!response.ok) return;

    const result = await response.json();

    if (result.is_ai_generated) {
      showWarning(result, emailElement);
    } else {
      showSafeBadge(emailElement);
    }
  } catch (e) {
    console.log("[AI Shield] Auto-scan failed:", e.message);
  }
}

// ─── Warning Overlay ─────────────────────────────────────────────────────────

function showWarning(result, emailElement) {
  const existing = emailElement.parentElement?.querySelector(".ai-shield-warning");
  if (existing) existing.remove();

  const warning = document.createElement("div");
  warning.className = "ai-shield-warning";

  const isHigh = result.threat_level === "high";
  warning.classList.add(isHigh ? "ai-shield-warning-high" : "ai-shield-warning-medium");

  warning.innerHTML = `
    <div class="ai-shield-warning-header">
      <span class="ai-shield-warning-icon">${isHigh ? "🚨" : "⚠️"}</span>
      <span class="ai-shield-warning-title">
        ${isHigh ? "AI Phishing Detected!" : "Suspicious Email Detected"}
      </span>
      <span class="ai-shield-warning-confidence">${result.confidence}% confidence</span>
    </div>
    <div class="ai-shield-warning-body">
      <p>${isHigh
        ? "This email has strong signs of being AI-generated phishing. Do NOT click any links or share personal information."
        : "This email has some suspicious patterns. Be cautious before taking any action."
      }</p>
    </div>
    <div class="ai-shield-warning-actions">
      <button class="ai-shield-btn ai-shield-btn-dismiss" data-action="dismiss">Dismiss</button>
    </div>
  `;

  emailElement.parentElement?.insertBefore(warning, emailElement);

  warning.querySelector('[data-action="dismiss"]').addEventListener("click", () => {
    warning.remove();
  });
}

function showSafeBadge(emailElement) {
  if (emailElement.parentElement?.querySelector(".ai-shield-safe-badge")) return;
  const badge = document.createElement("div");
  badge.className = "ai-shield-safe-badge";
  badge.innerHTML = `<span class="ai-shield-safe-icon">🛡️</span><span class="ai-shield-safe-text">AI Shield: Scanned ✅</span>`;
  emailElement.parentElement?.insertBefore(badge, emailElement);
}

function hideWarning() {
  document.querySelectorAll(".ai-shield-warning").forEach((w) => w.remove());
}

// ─── Message Handler (from popup) ────────────────────────────────────────────

function handleMessage(message, sender, sendResponse) {
  if (message.action === "getEmailText") {
    const emailBodies = document.querySelectorAll(".a3s.aiL");
    let text = "";
    emailBodies.forEach((body) => { text += (body.innerText || body.textContent || "") + "\n"; });
    sendResponse({ text: text.trim() });
    return true;
  }

  if (message.action === "showScanResult") {
    const emailBodies = document.querySelectorAll(".a3s.aiL");
    if (emailBodies.length > 0 && message.result) {
      if (message.result.is_ai_generated) {
        showWarning(message.result, emailBodies[0]);
      } else {
        showSafeBadge(emailBodies[0]);
      }
    }
    sendResponse({ ok: true });
    return true;
  }
}

// Listen for config changes
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "sync" && changes.apiBaseUrl) {
    API_BASE = changes.apiBaseUrl.newValue;
    console.log("[AI Shield] API URL updated:", API_BASE);
    checkServerHealth();
  }
});

init();
