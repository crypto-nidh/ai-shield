/**
 * AI Shield — Extension Popup Controller
 */

let API_BASE = "http://localhost:8000";
const DEFAULT_API_URL = "http://localhost:8000";

// ─── DOM Elements ────────────────────────────────────────────────────────────
const statusDot = document.getElementById("statusDot");
const statusLabel = document.getElementById("statusLabel");
const statusDetail = document.getElementById("statusDetail");
const scanBtn = document.getElementById("scanBtn");
const lastResult = document.getElementById("lastResult");
const settingsBtn = document.getElementById("settingsBtn");

settingsBtn.addEventListener("click", () => {
  if (chrome.runtime.openOptionsPage) {
    chrome.runtime.openOptionsPage();
  } else {
    window.open(chrome.runtime.getURL('options.html'));
  }
});

// ─── Server Status ───────────────────────────────────────────────────────────

async function checkServerStatus() {
  const data = await chrome.storage.sync.get({ apiBaseUrl: DEFAULT_API_URL });
  API_BASE = data.apiBaseUrl;

  statusDetail.textContent = `Connecting to ${new URL(API_BASE).hostname}`;

  let isColdStart = false;
  const timeoutId = setTimeout(() => {
    isColdStart = true;
    setStatus("checking", "Warming up...", "This can take ~30s on Render free tier");
  }, 3000);

  try {
    const response = await fetch(`${API_BASE}/api/health`, {
      method: "GET",
    });

    clearTimeout(timeoutId);

    if (response.ok) {
      const respData = await response.json();
      setStatus("connected", "Server Connected", `v${respData.version} • Model: ${respData.model_loaded ? "Ready" : "Not loaded"}`);
      scanBtn.disabled = false;
    } else {
      setStatus("disconnected", "Server Error", `HTTP ${response.status}`);
      scanBtn.disabled = true;
    }
  } catch (e) {
    clearTimeout(timeoutId);
    setStatus("disconnected", "Server Offline", "Check API Base URL in Settings");
    scanBtn.disabled = true;
  }
}

function setStatus(state, label, detail) {
  statusDot.className = `status-dot ${state}`;
  statusLabel.textContent = label;
  statusDetail.textContent = detail;
}

// ─── Email Scanning ──────────────────────────────────────────────────────────

scanBtn.addEventListener("click", async () => {
  scanBtn.disabled = true;
  scanBtn.textContent = "🔍 Scanning...";

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    if (!tab || !tab.url.includes("mail.google.com")) {
      showResult("warning", "⚠️ Please open a Gmail email first.");
      return;
    }

    const response = await chrome.tabs.sendMessage(tab.id, { action: "getEmailText" });

    if (!response || !response.text) {
      showResult("warning", "⚠️ Could not read email content. Make sure an email is open.");
      return;
    }

    let isColdStart = false;
    const timeoutId = setTimeout(() => {
      isColdStart = true;
      scanBtn.textContent = "⏳ Warming up server (~30s)...";
    }, 3000);

    const apiResponse = await fetch(`${API_BASE}/api/scan-email`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ text: response.text }),
    });

    clearTimeout(timeoutId);

    if (apiResponse.status === 429) {
      showResult("warning", "⏳ Too many scans. Please wait a moment.");
      return;
    }

    if (!apiResponse.ok) {
      showResult("danger", `❌ Scan failed: HTTP ${apiResponse.status}`);
      return;
    }

    const result = await apiResponse.json();

    // Send result back to content script for overlay
    await chrome.tabs.sendMessage(tab.id, {
      action: "showScanResult",
      result: result,
    });

    // Update popup display
    if (result.is_ai_generated) {
      if (result.threat_level === "high") {
        showResult("danger", `🚨 HIGH RISK — AI phishing detected (${result.confidence}%)`);
      } else {
        showResult("warning", `⚠️ Suspicious — ${result.confidence}% confidence`);
      }
    } else {
      showResult("safe", `✅ Safe — This email looks legitimate (${result.confidence}% risk)`);
    }
  } catch (e) {
    showResult("warning", `❌ Scan failed: ${e.message}`);
  } finally {
    scanBtn.disabled = false;
    scanBtn.textContent = "🔍 Scan Current Email";
  }
});

function showResult(type, message) {
  lastResult.className = `last-result ${type}`;
  lastResult.textContent = message;
}

// ─── Initialize ──────────────────────────────────────────────────────────────

async function init() {
  await checkServerStatus();
}

init();
