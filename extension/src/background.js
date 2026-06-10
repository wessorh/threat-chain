// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

// ============================================================
// ThreatAttest Shield — Background Service Worker
// Handles: download interception, webRequest IP/domain checks,
//          threat popups, badge updates, notifications
// ============================================================

import {
  checkFileSHA256, checkURL, checkIPv4, checkDomain,
  sha256Bytes, normalizeURL, normalizeDomain, parseIPv4, isReservedIPv4,
  extractDomain, setNodeURL, getNodeURL,
  SEVERITY, STATUS, ARTIFACT_TYPE, THREAT_CATEGORIES, categoryLabel, categoryIcon, cacheClear,
  // DNS Identity badge
  resolveIdentity, getIdentityBadge, prefetchIdentities, IdentityStatus,
} from "./api.js";

// ============================================================
// State
// ============================================================

// Pending download decisions: downloadId → { resolve, reject }
const pendingDownloads = new Map();

// Pending navigation decisions: tabId → { resolve, url }
const pendingNavigations = new Map();

// Blocked hosts this session (user clicked "Block")
const blockedHosts = new Set();

// Allowed hosts this session (user clicked "Allow Once")
const allowedOnce = new Set();

// Per-tab threat info for popup display
const tabThreats = new Map();

// Settings defaults
let settings = {
  nodeURL:              "http://localhost:1317",
  checkDownloads:       true,
  checkDomains:         true,
  checkIPs:             true,
  blockOnCritical:      true,   // auto-block CRITICAL severity
  blockOnHigh:          false,  // auto-block HIGH severity
  minSeverityAlert:     2,      // 0=all, 1=INFO+, 2=LOW+, 3=MED+, 4=HIGH+, 5=CRIT only
  showNotifications:    true,
  whitelistDomains:     [],     // user-defined always-allow list
  whitelistIPs:         [],
};

// ============================================================
// Initialisation
// ============================================================

async function loadSettings() {
  const stored = await chrome.storage.local.get("threatattestSettings");
  if (stored.threatattestSettings) {
    settings = { ...settings, ...stored.threatattestSettings };
  }
  setNodeURL(settings.nodeURL);
}

async function saveSettings(patch) {
  settings = { ...settings, ...patch };
  await chrome.storage.local.set({ threatattestSettings: settings });
  setNodeURL(settings.nodeURL);
  cacheClear();
}

// Run on install / startup
chrome.runtime.onInstalled.addListener(async () => {
  await loadSettings();
  setBadge("ON", "#22c55e");
  console.log("[ThreatAttest] Extension installed, node:", settings.nodeURL);
});

chrome.runtime.onStartup.addListener(async () => {
  await loadSettings();
  setBadge("ON", "#22c55e");
});

// ============================================================
// Badge helpers
// ============================================================

function setBadge(text, color) {
  chrome.action.setBadgeText({ text });
  chrome.action.setBadgeBackgroundColor({ color });
}

function setTabBadge(tabId, text, color) {
  chrome.action.setBadgeText({ text, tabId });
  chrome.action.setBadgeBackgroundColor({ color, tabId });
}

// ============================================================
// Message bus (from popup / options / content scripts)
// ============================================================

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    await loadSettings();

    switch (msg.type) {

      // Popup/options fetches current settings
      case "GET_SETTINGS":
        sendResponse({ settings });
        break;

      // Options page saves new settings
      case "SAVE_SETTINGS":
        await saveSettings(msg.settings);
        sendResponse({ ok: true });
        break;

      // Popup asks for threats on the current tab
      case "GET_TAB_THREATS": {
        const threats = tabThreats.get(msg.tabId) || [];
        sendResponse({ threats });
        break;
      }

      // User decision from threat popup: BLOCK / ALLOW / SNOOZE
      case "THREAT_DECISION": {
        handleThreatDecision(msg);
        sendResponse({ ok: true });
        break;
      }

      // Content script reports IPs resolved on a page
      case "PAGE_IPS": {
        if (settings.checkIPs) {
          for (const ip of msg.ips) {
            await checkAndReportIPv4(ip, msg.tabId, msg.url);
          }
        }
        sendResponse({ ok: true });
        break;
      }

      // Manual re-check request from popup
      case "RECHECK_TAB": {
        const tab = await chrome.tabs.get(msg.tabId).catch(() => null);
        if (tab && tab.url) {
          await checkNavigationURL(tab.url, msg.tabId);
        }
        sendResponse({ ok: true });
        break;
      }

      // Clear session block/allow lists
      case "CLEAR_SESSION": {
        blockedHosts.clear();
        allowedOnce.clear();
        tabThreats.clear();
        cacheClear();
        setBadge("ON", "#22c55e");
        sendResponse({ ok: true });
        break;
      }

      case "GET_NODE_STATUS": {
        try {
          const res = await fetch(`${settings.nodeURL}/cosmos/base/tendermint/v1beta1/node_info`, {
            signal: AbortSignal.timeout(4000),
          });
          sendResponse({ online: res.ok });
        } catch {
          sendResponse({ online: false });
        }
        break;
      }

      // Popup requests the identity badge for the current tab's domain
      case "GET_IDENTITY_BADGE": {
        const badge = await getIdentityBadge(msg.domain || "").catch(() => null);
        sendResponse({ badge });
        break;
      }

      // Popup or content script prefetches identities for a list of domains
      case "PREFETCH_IDENTITIES":
        prefetchIdentities(msg.domains || []);
        sendResponse({ ok: true });
        break;

      // Popup queries raw identity record
      case "GET_IDENTITY_RECORD": {
        const record = await resolveIdentity(msg.domain || "").catch(() => null);
        sendResponse({ record });
        break;
      }

      default:
        sendResponse({ error: "unknown message type" });
    }
  })();
  return true; // keep channel open for async
});

// ============================================================
// Download Interception
// ============================================================

chrome.downloads.onCreated.addListener(async (downloadItem) => {
  if (!settings.checkDownloads) return;

  // We need the file content to hash it — wait for completion
  // Store the download item so onChanged can pick it up
  pendingDownloads.set(downloadItem.id, { item: downloadItem, checked: false });
});

chrome.downloads.onChanged.addListener(async (delta) => {
  if (!settings.checkDownloads) return;
  if (!delta.state) return;

  const entry = pendingDownloads.get(delta.id);
  if (!entry || entry.checked) return;

  // Only proceed when download completes
  if (delta.state.current !== "complete") return;
  entry.checked = true;

  // Get full download info
  const results = await chrome.downloads.search({ id: delta.id });
  const dl = results[0];
  if (!dl || !dl.filename) return;

  console.log("[ThreatAttest] Download completed:", dl.filename);

  // Use the download URL as a URL check immediately
  if (dl.url && settings.checkDomains) {
    const urlResult = await checkURL(dl.url).catch(() => null);
    if (urlResult && urlResult.isMalicious) {
      await handleDownloadThreat(dl, urlResult, "url");
      return;
    }
    // Also check the download domain as a DOMAIN artifact
    try {
      const dlHost = new URL(dl.url).hostname;
      const normDom = normalizeDomain(dlHost);
      if (normDom) {
        const domResult = await checkDomain(normDom).catch(() => null);
        if (domResult && domResult.isMalicious) {
          await handleDownloadThreat(dl, domResult, "domain");
          return;
        }
      }
    } catch { /* ignore parse errors */ }
  }

  // Hash the file via fetch (works for local file:// paths via downloads API)
  try {
    const sha256 = await hashDownloadedFile(dl);
    if (!sha256) return;

    console.log("[ThreatAttest] File SHA-256:", sha256);
    const result = await checkFileSHA256(sha256);
    if (!result) return;

    if (result.isMalicious) {
      await handleDownloadThreat(dl, result, "file");
    } else {
      // Store clean result for popup display
      recordTabThreat(null, {
        type: "FILE",
        subject: dl.filename.split("/").pop() || dl.filename.split("\\").pop(),
        sha256,
        isMalicious: false,
        trustScore: result.trustScore,
        attestation: result.attestation,
        downloadId: dl.id,
      });
    }
  } catch (err) {
    console.warn("[ThreatAttest] File hash error:", err.message);
  }

  pendingDownloads.delete(delta.id);
});

async function hashDownloadedFile(dl) {
  // Try to read via fetch with the file's local path (Blob URL approach)
  // In MV3, we can't directly read local files from background.
  // Instead we use the downloads API's finalUrl and the known SHA-256 if
  // the server provides it via ETag or Content-MD5.
  // Fallback: inject a content script to read and hash the blob.
  //
  // Best available approach in MV3: use a content script in the tab that
  // triggered the download to fetch+hash the download URL.
  //
  // For now: attempt to fetch the original URL and hash response body.
  // This re-fetches the file (acceptable for small files, ~5MB limit).
  try {
    const response = await fetch(dl.url, {
      method: "GET",
      signal: AbortSignal.timeout(15000),
    });
    if (!response.ok) return null;

    // Only hash files up to 50MB
    const contentLength = response.headers.get("content-length");
    if (contentLength && parseInt(contentLength) > 50 * 1024 * 1024) {
      console.warn("[ThreatAttest] File too large to hash:", contentLength);
      return null;
    }

    const buffer = await response.arrayBuffer();
    return sha256Bytes(new Uint8Array(buffer));
  } catch (err) {
    console.warn("[ThreatAttest] Could not hash download:", err.message);
    return null;
  }
}

async function handleDownloadThreat(dl, result, checkType) {
  const filename = dl.filename.split("/").pop() || dl.filename.split("\\").pop() || "file";
  const sev = result.attestation ? result.attestation.severity : 5;
  const sevInfo = SEVERITY[sev] || SEVERITY[5];

  console.warn(`[ThreatAttest] THREAT in download: ${filename} — ${sevInfo.label}`);

  // Auto-block CRITICAL / HIGH if configured
  if ((sev === 5 && settings.blockOnCritical) || (sev === 4 && settings.blockOnHigh)) {
    await chrome.downloads.cancel(dl.id).catch(() => {});
    await chrome.downloads.erase({ id: dl.id }).catch(() => {});
    showNotification(
      "⛔ Download Blocked",
      `${sevInfo.emoji} ${sevInfo.label} threat detected in: ${filename}`,
      "warning"
    );
    recordTabThreat(null, {
      type: "FILE",
      subject: filename,
      isMalicious: true,
      autoBlocked: true,
      result,
      downloadId: dl.id,
    });
    return;
  }

  // Show decision popup
  showDownloadDecisionPopup(dl, result, filename, sevInfo);
}

function showDownloadDecisionPopup(dl, result, filename, sevInfo) {
  const attest = result.attestation;
  const notifId = `download_${dl.id}_${Date.now()}`;

  // Store pending decision
  pendingDownloads.set(`decision_${dl.id}`, { dl, result });

  // Open decision popup window
  chrome.windows.create({
    url: chrome.runtime.getURL("threat-popup.html") +
      `?type=DOWNLOAD&id=${dl.id}&notifId=${encodeURIComponent(notifId)}` +
      `&filename=${encodeURIComponent(filename)}` +
      `&severity=${attest ? attest.severity : 5}` +
      `&trustScore=${result.trustScore}` +
      `&categories=${encodeURIComponent(JSON.stringify(attest ? attest.threat_categories || [] : []))}` +
      `&attester=${encodeURIComponent(attest ? attest.attester || "" : "")}` +
      `&description=${encodeURIComponent(attest ? (attest.description || "") : "")}` +
      `&attestId=${encodeURIComponent(attest ? attest.id || "" : "")}`,
    type: "popup",
    width: 540,
    height: 480,
    focused: true,
  });
}

// ============================================================
// URL / Domain / IP checking on navigation
// ============================================================

chrome.webRequest.onBeforeRequest.addListener(
  async (details) => {
    if (!settings.checkDomains && !settings.checkIPs) return {};
    if (details.type !== "main_frame" && details.type !== "sub_frame") return {};

    try {
      const u = new URL(details.url);
      const hostname = u.hostname.toLowerCase();

      // Skip chrome:// / extension pages
      if (!hostname || u.protocol === "chrome-extension:" || u.protocol === "chrome:") return {};

      // Check whitelist
      if (settings.whitelistDomains.some(d => hostname === d || hostname.endsWith("." + d))) {
        return {};
      }

      // Skip if already allowed this session
      if (allowedOnce.has(hostname)) return {};

      // Check if blocked this session
      if (blockedHosts.has(hostname)) {
        return { cancel: true };
      }

      // Run checks asynchronously — don't block the request here
      // (blocking requires synchronous return which isn't possible with async chain queries)
      // Instead we check and show a warning banner after the fact for domains.
      // For IP-based requests we CAN block via declarativeNetRequest.
      checkNavigationURL(details.url, details.tabId);

    } catch { /* ignore parse errors */ }
    return {};
  },
  { urls: ["http://*/*", "https://*/*"] },
  ["blocking"]
);

async function checkNavigationURL(rawURL, tabId) {
  if (!rawURL || rawURL.startsWith("chrome")) return;
  try {
    const u = new URL(rawURL);
    const hostname = u.hostname.toLowerCase();

    // Check domain/URL
    if (settings.checkDomains) {
      // 1. Check the full URL (URL artifact type)
      const urlResult = await checkURL(rawURL).catch(() => null);
      if (urlResult && urlResult.isMalicious) {
        await handleNavigationThreat(rawURL, hostname, urlResult, "URL", tabId);
        return;
      }

      // 2. Check the bare domain against DOMAIN artifact type
      //    This catches adware/malvertising/phishing-site attestations on the whole domain.
      const normDom = normalizeDomain(hostname);
      if (normDom) {
        const domResult = await checkDomain(normDom).catch(() => null);
        if (domResult && domResult.isMalicious) {
          await handleNavigationThreat(rawURL, normDom, domResult, "DOMAIN", tabId);
          return;
        }
      }

      // 3. Fallback: check hostname as a URL (catches URL-typed attestations on the root)
      const hostResult = await checkURL(`${u.protocol}//${hostname}/`).catch(() => null);
      if (hostResult && hostResult.isMalicious) {
        await handleNavigationThreat(rawURL, hostname, hostResult, "HOST_URL", tabId);
        return;
      }
    }

    // Check if hostname is an IPv4 address
    if (settings.checkIPs) {
      const ip = parseIPv4(hostname);
      if (ip && !isReservedIPv4(ip)) {
        const ipResult = await checkIPv4(ip).catch(() => null);
        if (ipResult && ipResult.isMalicious) {
          await handleNavigationThreat(rawURL, ip, ipResult, "IPV4", tabId);
        }
      }
    }

    // Prefetch DNS identity badge for the navigated domain (fire-and-forget).
    // The result is cached so the popup can display it instantly.
    if (settings.checkDomains && hostname) {
      const normDom = normalizeDomain(hostname);
      if (normDom) {
        resolveIdentity(normDom).then(record => {
          if (record) {
            // Notify the popup/tab that an identity badge is available
            chrome.tabs.sendMessage(tabId, {
              type: 'IDENTITY_BADGE_AVAILABLE',
              domain: normDom,
              status: record.status,
              name:   record.name || null,
              tier:   record.attester_tier || 0,
            }).catch(() => {}); // Tab may not be listening yet
          }
        }).catch(() => {});
      }
    }

  } catch (err) {
    console.warn("[ThreatAttest] checkNavigationURL error:", err.message);
  }
}

async function checkAndReportIPv4(ip, tabId, pageURL) {
  if (!ip || isReservedIPv4(ip)) return;
  if (settings.whitelistIPs.includes(ip)) return;
  if (allowedOnce.has(ip)) return;

  const result = await checkIPv4(ip).catch(() => null);
  if (!result || !result.isMalicious) return;

  await handleNavigationThreat(pageURL, ip, result, "IPV4", tabId);
}

async function handleNavigationThreat(rawURL, subject, result, checkType, tabId) {
  const sev = result.attestation ? result.attestation.severity : 4;
  const sevInfo = SEVERITY[sev] || SEVERITY[4];
  const attest = result.attestation;

  console.warn(`[ThreatAttest] THREAT: ${checkType} ${subject} — ${sevInfo.label}`);

  // Record for popup
  recordTabThreat(tabId, {
    type: checkType,
    subject,
    isMalicious: true,
    result,
    url: rawURL,
    timestamp: Date.now(),
  });

  // Update badge
  if (sev >= 4) {
    setTabBadge(tabId, "!!!", "#ef4444");
  } else if (sev === 3) {
    setTabBadge(tabId, "!", "#f59e0b");
  } else {
    setTabBadge(tabId, "?", "#3b82f6");
  }

  // Only show popup for severity >= minSeverityAlert
  if (sev < settings.minSeverityAlert) {
    showNotification(
      `${sevInfo.emoji} ThreatAttest: ${sevInfo.label}`,
      `${checkType}: ${subject.slice(0, 80)}`,
      "basic"
    );
    return;
  }

  // Inject warning overlay into the tab
  if (tabId && tabId > 0) {
    await injectThreatOverlay(tabId, {
      type: checkType,
      subject,
      severity: sev,
      sevLabel: sevInfo.label,
      sevColor: sevInfo.color,
      trustScore: result.trustScore,
      categories: attest ? (attest.threat_categories || []) : [],
      attester: attest ? (attest.attester || "") : "",
      description: attest ? (attest.description || "") : "",
      attestId: attest ? (attest.id || "") : "",
      url: rawURL,
    });
  }
}

// ============================================================
// Threat overlay injection into page
// ============================================================

async function injectThreatOverlay(tabId, threat) {
  try {
    await chrome.scripting.executeScript({
      target: { tabId },
      func: showThreatOverlayInPage,
      args: [threat],
    });
  } catch (err) {
    console.warn("[ThreatAttest] Could not inject overlay:", err.message);
    // Fallback to notification
    showNotification(
      `⚠️ ThreatAttest: ${threat.sevLabel}`,
      `${threat.type}: ${threat.subject.slice(0, 100)}`,
      "warning"
    );
  }
}

// This function runs IN the page context (injected via scripting API)
function showThreatOverlayInPage(threat) {
  // Avoid duplicate overlays
  if (document.getElementById("threatattest-overlay")) return;

  const COLORS = {
    CRITICAL: { bg: "#7f1d1d", border: "#ef4444", badge: "#ef4444" },
    HIGH:     { bg: "#7c2d12", border: "#f97316", badge: "#f97316" },
    MEDIUM:   { bg: "#78350f", border: "#f59e0b", badge: "#f59e0b" },
    LOW:      { bg: "#14532d", border: "#22c55e", badge: "#22c55e" },
    INFO:     { bg: "#1e3a5f", border: "#3b82f6", badge: "#3b82f6" },
  };
  const c = COLORS[threat.sevLabel] || COLORS["HIGH"];
  const cats = (threat.categories || []).join(", ") || "—";

  const overlay = document.createElement("div");
  overlay.id = "threatattest-overlay";
  overlay.style.cssText = `
    position: fixed; top: 0; left: 0; right: 0; z-index: 2147483647;
    background: ${c.bg}; border-bottom: 3px solid ${c.border};
    color: #fff; font-family: -apple-system, system-ui, sans-serif;
    font-size: 14px; padding: 0; box-shadow: 0 4px 24px rgba(0,0,0,0.5);
    animation: ta-slide-in 0.3s ease-out;
  `;

  const style = document.createElement("style");
  style.textContent = `
    @keyframes ta-slide-in { from { transform: translateY(-100%); } to { transform: translateY(0); } }
    #threatattest-overlay button { cursor: pointer; border: none; border-radius: 6px; padding: 6px 14px; font-size: 13px; font-weight: 600; }
    #threatattest-overlay .ta-block-btn  { background: #ef4444; color: #fff; }
    #threatattest-overlay .ta-allow-btn  { background: #374151; color: #e5e7eb; }
    #threatattest-overlay .ta-detail-btn { background: transparent; color: #93c5fd; text-decoration: underline; border: none; padding: 0; font-size: 12px; }
    #threatattest-overlay .ta-close-btn  { background: transparent; color: #9ca3af; font-size: 18px; border: none; padding: 2px 8px; float: right; }
  `;
  document.head.appendChild(style);

  overlay.innerHTML = `
    <div style="max-width:900px; margin:0 auto; padding:10px 16px; display:flex; align-items:center; gap:12px; flex-wrap:wrap;">
      <span style="background:${c.badge}; color:#fff; font-weight:700; font-size:11px; padding:2px 8px; border-radius:4px; letter-spacing:1px; white-space:nowrap;">
        ${threat.sevLabel}
      </span>
      <span style="font-weight:600; flex:1; min-width:180px;">
        ⚠️ ThreatAttest: <strong>${threat.type}</strong> threat detected
      </span>
      <span style="color:#d1d5db; font-size:12px; max-width:300px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${threat.subject}">
        ${threat.subject.length > 60 ? threat.subject.slice(0,57)+"…" : threat.subject}
      </span>
      <span style="color:#9ca3af; font-size:12px;">
        Trust Score: <strong>${threat.trustScore}</strong>
        &nbsp;|&nbsp; Categories: <strong>${cats}</strong>
      </span>
      <div style="display:flex; gap:8px; align-items:center; flex-shrink:0;">
        <button class="ta-block-btn"  id="ta-block">🚫 Block Site</button>
        <button class="ta-allow-btn"  id="ta-allow">✅ Allow Once</button>
        <button class="ta-detail-btn" id="ta-detail">View attestation ↗</button>
        <button class="ta-close-btn"  id="ta-close">✕</button>
      </div>
    </div>
    <div style="background:rgba(0,0,0,0.2); padding:4px 16px; font-size:11px; color:#9ca3af;">
      Attester: ${threat.attester || "unknown"} &nbsp;|&nbsp; ID: ${threat.attestId || "—"} &nbsp;|&nbsp;
      ${threat.description ? threat.description.slice(0,120) + (threat.description.length>120?"…":"") : "No description"}
    </div>
  `;

  document.body.prepend(overlay);

  // Button handlers
  document.getElementById("ta-close").onclick = () => overlay.remove();

  document.getElementById("ta-block").onclick = () => {
    overlay.remove();
    chrome.runtime.sendMessage({
      type: "THREAT_DECISION",
      decision: "BLOCK",
      subject: threat.subject,
      subjectType: threat.type,
      url: threat.url,
    });
    // Redirect to blocked page
    document.body.innerHTML = `
      <div style="display:flex;flex-direction:column;align-items:center;justify-content:center;height:100vh;background:#0f172a;color:#f1f5f9;font-family:system-ui,sans-serif;text-align:center;gap:16px;">
        <div style="font-size:72px;">🛡️</div>
        <h1 style="font-size:28px;font-weight:700;color:#ef4444;">Site Blocked by ThreatAttest</h1>
        <p style="color:#94a3b8;max-width:480px;">This ${threat.type.toLowerCase()} has been attested as a <strong style="color:${c.badge}">${threat.sevLabel}</strong> threat on the blockchain.</p>
        <p style="color:#64748b;font-size:13px;">Subject: ${threat.subject}</p>
        <button onclick="history.back()" style="margin-top:8px;padding:10px 24px;background:#1e40af;color:#fff;border:none;border-radius:8px;font-size:15px;cursor:pointer;">← Go Back</button>
      </div>`;
  };

  document.getElementById("ta-allow").onclick = () => {
    overlay.remove();
    chrome.runtime.sendMessage({
      type: "THREAT_DECISION",
      decision: "ALLOW_ONCE",
      subject: threat.subject,
      subjectType: threat.type,
      url: threat.url,
    });
  };

  document.getElementById("ta-detail").onclick = () => {
    chrome.runtime.sendMessage({
      type: "THREAT_DECISION",
      decision: "VIEW_DETAIL",
      attestId: threat.attestId,
      subject: threat.subject,
    });
  };
}

// ============================================================
// Threat decision handler
// ============================================================

function handleThreatDecision(msg) {
  switch (msg.decision) {
    case "BLOCK":
      if (msg.subject) blockedHosts.add(msg.subject);
      // Cancel download if applicable
      if (msg.downloadId) {
        chrome.downloads.cancel(msg.downloadId).catch(() => {});
        chrome.downloads.erase({ id: msg.downloadId }).catch(() => {});
      }
      break;

    case "ALLOW_ONCE":
      if (msg.subject) allowedOnce.add(msg.subject);
      // Resume download if applicable
      if (msg.downloadId) {
        // Download is already saved, no action needed
      }
      break;

    case "ALLOW_ALWAYS":
      if (msg.subject && msg.subjectType === "DOMAIN") {
        settings.whitelistDomains.push(msg.subject);
        saveSettings({ whitelistDomains: settings.whitelistDomains });
      } else if (msg.subject && msg.subjectType === "IPV4") {
        settings.whitelistIPs.push(msg.subject);
        saveSettings({ whitelistIPs: settings.whitelistIPs });
      }
      break;

    case "VIEW_DETAIL":
      if (msg.attestId) {
        chrome.tabs.create({
          url: `${settings.nodeURL}/threatattest/attestation/v1/attestation/${msg.attestId}`
        });
      }
      break;
  }
}

// ============================================================
// Per-tab threat record
// ============================================================

function recordTabThreat(tabId, threat) {
  if (!tabId) return;
  const existing = tabThreats.get(tabId) || [];
  existing.unshift({ ...threat, timestamp: Date.now() });
  // Keep last 20 per tab
  tabThreats.set(tabId, existing.slice(0, 20));
}

// Clean up tab threats when tab is closed
chrome.tabs.onRemoved.addListener((tabId) => {
  tabThreats.delete(tabId);
});

// Clean up tab threats when tab navigates away
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === "loading") {
    tabThreats.delete(tabId);
    // Reset badge
    chrome.action.setBadgeText({ text: "", tabId }).catch(() => {});
  }
});

// ============================================================
// Notifications
// ============================================================

function showNotification(title, message, type = "basic") {
  if (!settings.showNotifications) return;
  const id = `ta_notif_${Date.now()}`;
  chrome.notifications.create(id, {
    type: "basic",
    iconUrl: "../icons/icon48.png",
    title,
    message,
    priority: type === "warning" ? 2 : 1,
  });
  // Auto-clear after 8s
  setTimeout(() => chrome.notifications.clear(id).catch(() => {}), 8000);
}

// ============================================================
// Periodic chain connectivity check
// ============================================================

chrome.alarms.create("nodeHealthCheck", { periodInMinutes: 2 });
chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name !== "nodeHealthCheck") return;
  await loadSettings();
  try {
    const res = await fetch(
      `${settings.nodeURL}/cosmos/base/tendermint/v1beta1/node_info`,
      { signal: AbortSignal.timeout(4000) }
    );
    if (res.ok) {
      setBadge("ON", "#22c55e");
    } else {
      setBadge("!", "#f59e0b");
    }
  } catch {
    setBadge("OFF", "#6b7280");
  }
});
