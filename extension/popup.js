// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

// ============================================================
// ThreatAttest Shield — Popup Script
// ============================================================

const SEVERITY_LABELS = ["UNSPECIFIED","INFO","LOW","MEDIUM","HIGH","CRITICAL"];
const SEVERITY_COLORS = ["#6b7280","#3b82f6","#22c55e","#f59e0b","#f97316","#ef4444"];
const SEVERITY_BADGE  = ["badge-unknown","badge-info","badge-low","badge-medium","badge-high","badge-critical"];
const SEVERITY_EMOJI  = ["❓","ℹ️","🟢","🟡","🟠","🔴"];

let currentTabId   = null;
let currentTabURL  = null;
let sessionChecks  = 0;
let sessionThreats = 0;
let sessionBlocked = 0;

// ============================================================
// Init
// ============================================================
document.addEventListener("DOMContentLoaded", async () => {
  // Get current tab
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  currentTabId  = tab?.id  ?? null;
  currentTabURL = tab?.url ?? "";

  renderCurrentURL(currentTabURL);
  await checkNodeStatus();
  await loadThreats();
  await updatePageStatus();
  loadStats();
  loadIdentityBadge();

  // Button handlers
  document.getElementById("btn-recheck").addEventListener("click", async () => {
    document.getElementById("page-status-badge").className = "page-status-badge badge-unknown";
    document.getElementById("page-status-badge").textContent = "CHECKING…";
    await chrome.runtime.sendMessage({ type: "RECHECK_TAB", tabId: currentTabId });
    setTimeout(loadThreats, 2000);
  });

  document.getElementById("btn-options").addEventListener("click", () => {
    chrome.runtime.openOptionsPage();
  });

  document.getElementById("btn-clear").addEventListener("click", async () => {
    await chrome.runtime.sendMessage({ type: "CLEAR_SESSION" });
    sessionChecks = sessionThreats = sessionBlocked = 0;
    await chrome.storage.local.set({ taStats: { checks: 0, threats: 0, blocked: 0 } });
    renderThreats([]);
    updateStatsUI();
  });

  document.getElementById("btn-check-manual").addEventListener("click", () => {
    openManualCheck();
  });
});

// ============================================================
// Node status
// ============================================================
async function checkNodeStatus() {
  const dot  = document.getElementById("node-dot");
  const text = document.getElementById("node-status-text");
  const urlEl = document.getElementById("node-url-short");

  const { settings } = await chrome.runtime.sendMessage({ type: "GET_SETTINGS" });
  const nodeURL = settings?.nodeURL ?? "http://localhost:1317";
  try {
    const u = new URL(nodeURL);
    urlEl.textContent = u.host;
  } catch { urlEl.textContent = nodeURL.slice(0, 30); }

  try {
    const { online } = await chrome.runtime.sendMessage({ type: "GET_NODE_STATUS" });
    if (online) {
      dot.className  = "status-dot";
      text.textContent = "Node online";
    } else {
      dot.className  = "status-dot warn";
      text.textContent = "Node unreachable";
    }
  } catch {
    dot.className  = "status-dot offline";
    text.textContent = "Cannot connect";
  }
}

// ============================================================
// Current URL display
// ============================================================
function renderCurrentURL(url) {
  const el = document.getElementById("current-url");
  if (!url || url.startsWith("chrome")) {
    el.textContent = "Browser internal page";
  } else {
    try {
      const u = new URL(url);
      el.textContent = u.hostname + u.pathname.slice(0, 40);
      el.title = url;
    } catch {
      el.textContent = url.slice(0, 60);
    }
  }
}

// ============================================================
// Update page status badge based on worst threat severity
// ============================================================
async function updatePageStatus() {
  const badge = document.getElementById("page-status-badge");
  const text  = document.getElementById("page-status-text");

  const { threats } = await chrome.runtime.sendMessage({ type: "GET_TAB_THREATS", tabId: currentTabId });

  if (!threats || threats.length === 0) {
    badge.className = "page-status-badge badge-clean";
    badge.textContent = "CLEAN";
    text.textContent = "No threats detected";
    return;
  }

  const malicious = threats.filter(t => t.isMalicious);
  if (malicious.length === 0) {
    badge.className = "page-status-badge badge-clean";
    badge.textContent = "CLEAN";
    text.textContent = "No active threats";
    return;
  }

  // Find worst severity
  let maxSev = 0;
  for (const t of malicious) {
    const sev = t.result?.attestation?.severity ?? 0;
    if (sev > maxSev) maxSev = sev;
  }

  badge.className = `page-status-badge ${SEVERITY_BADGE[maxSev]}`;
  badge.textContent = SEVERITY_LABELS[maxSev];
  text.textContent = `${malicious.length} active threat${malicious.length > 1 ? "s" : ""}`;
}

// ============================================================
// Threat list rendering
// ============================================================
async function loadThreats() {
  if (!currentTabId) return;
  const { threats } = await chrome.runtime.sendMessage({ type: "GET_TAB_THREATS", tabId: currentTabId });
  renderThreats(threats || []);
  await updatePageStatus();
}

function renderThreats(threats) {
  const list  = document.getElementById("threats-list");
  const count = document.getElementById("threat-count");

  count.textContent = threats.length;

  if (threats.length === 0) {
    list.innerHTML = `
      <div class="no-threats">
        <div class="big">✅</div>
        <div>No threats detected</div>
        <div style="font-size:11px;margin-top:4px;">on this page</div>
      </div>`;
    return;
  }

  list.innerHTML = threats.map((t, i) => {
    const sev   = t.result?.attestation?.severity ?? (t.isMalicious ? 4 : 0);
    const emoji = SEVERITY_EMOJI[sev] || "❓";
    const label = SEVERITY_LABELS[sev] || "UNKNOWN";
    const color = SEVERITY_COLORS[sev] || "#6b7280";
    const subject = t.subject || t.url || "—";
    const shortSubject = subject.length > 45 ? subject.slice(0, 42) + "…" : subject;
    const cats  = (t.result?.attestation?.threat_categories || []).slice(0, 2).join(", ") || "";
    const ts    = t.result?.trustScore ?? 0;
    const ago   = t.timestamp ? timeAgo(t.timestamp) : "";
    const typeIcon = { FILE: "📄", URL: "🌐", DOMAIN: "🌐", IPV4: "📡" }[t.type] || "🔍";

    return `
      <div class="threat-item" data-index="${i}">
        <div class="threat-icon">${t.isMalicious ? emoji : "✅"}</div>
        <div class="threat-info">
          <div class="threat-type">${typeIcon} ${t.type || "CHECK"}</div>
          <div class="threat-subject" title="${subject}">${shortSubject}</div>
          <div class="threat-meta">
            ${cats ? `${cats} &nbsp;•&nbsp;` : ""}
            Trust: <strong>${ts}</strong>
            ${ago ? `&nbsp;•&nbsp; ${ago}` : ""}
          </div>
        </div>
        ${t.isMalicious ? `
          <div class="threat-sev" style="background:${color}22;color:${color};border:1px solid ${color}44">
            ${label}
          </div>` : `
          <div class="threat-sev" style="background:#14532d22;color:#86efac;border:1px solid #14532d">
            CLEAN
          </div>`}
      </div>`;
  }).join("");

  // Click to expand detail
  list.querySelectorAll(".threat-item").forEach(el => {
    el.addEventListener("click", () => {
      const idx = parseInt(el.dataset.index);
      showThreatDetail(threats[idx]);
    });
  });
}

// ============================================================
// Threat detail modal
// ============================================================
function showThreatDetail(threat) {
  if (!threat) return;
  const attest = threat.result?.attestation;
  if (!attest) return;

  const sev   = attest.severity ?? 4;
  const color = SEVERITY_COLORS[sev];
  const label = SEVERITY_LABELS[sev];
  const emoji = SEVERITY_EMOJI[sev];

  const modal = document.createElement("div");
  modal.style.cssText = `
    position: fixed; inset: 0; z-index: 1000;
    background: rgba(0,0,0,0.7); display: flex;
    align-items: center; justify-content: center;
    padding: 12px;
  `;

  modal.innerHTML = `
    <div style="background:#1e293b;border:1px solid #334155;border-radius:12px;
      padding:16px;max-width:360px;width:100%;max-height:480px;overflow-y:auto;
      box-shadow:0 20px 60px rgba(0,0,0,0.5);">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px;">
        <span style="font-size:24px;">${emoji}</span>
        <div>
          <div style="font-weight:700;font-size:15px;color:${color}">${label} Threat</div>
          <div style="font-size:11px;color:#94a3b8;">${(threat.type || "").toUpperCase()} attestation</div>
        </div>
        <button id="modal-close" style="margin-left:auto;background:none;border:none;color:#94a3b8;font-size:20px;cursor:pointer;">✕</button>
      </div>
      ${row("Subject",   truncate(threat.subject, 60))}
      ${row("Severity",  `<span style="color:${color};font-weight:700;">${label}</span>`)}
      ${row("TLP",       tlpLabel(attest.tlp))}
      ${row("Trust Score", `${threat.result?.trustScore ?? 0} / 1000`)}
      ${row("Confidence", `${attest.confidence ?? 0}%`)}
      ${row("Status",    attest.status_str || statusLabel(attest.status))}
      ${row("Attester",  truncate(attest.attester || "—", 42))}
      ${row("Published", attest.published_at ? new Date(attest.published_at * 1000).toLocaleString() : "—")}
      ${row("Expires",   attest.expires_at   ? new Date(attest.expires_at   * 1000).toLocaleString() : "—")}
      ${row("Endorsements", `${attest.endorsement_count ?? 0}`)}
      ${row("Disputes",     `${attest.dispute_count ?? 0}`)}
      ${attest.threat_categories?.length ? row("Categories", attest.threat_categories.join(", ")) : ""}
      ${attest.mitre_attack_ids?.length  ? row("MITRE ATT&CK", attest.mitre_attack_ids.join(", ")) : ""}
      ${attest.tags?.length              ? row("Tags", attest.tags.join(", ")) : ""}
      ${attest.description               ? row("Description", truncate(attest.description, 120)) : ""}
      ${row("Attestation ID", truncate(attest.id || "—", 52))}
      <div style="display:flex;gap:8px;margin-top:14px;flex-wrap:wrap;">
        <button id="modal-block"  style="${btnStyle("#ef4444")}">🚫 Block Host</button>
        <button id="modal-allow"  style="${btnStyle("#374151")}">✅ Allow Once</button>
        <button id="modal-chain"  style="${btnStyle("#1e40af")}">🔗 View on Chain</button>
      </div>
    </div>`;

  document.body.appendChild(modal);

  modal.querySelector("#modal-close").onclick = () => modal.remove();
  modal.onclick = (e) => { if (e.target === modal) modal.remove(); };

  modal.querySelector("#modal-block").onclick = () => {
    chrome.runtime.sendMessage({
      type: "THREAT_DECISION", decision: "BLOCK",
      subject: threat.subject, subjectType: threat.type,
    });
    modal.remove();
  };

  modal.querySelector("#modal-allow").onclick = () => {
    chrome.runtime.sendMessage({
      type: "THREAT_DECISION", decision: "ALLOW_ONCE",
      subject: threat.subject, subjectType: threat.type,
    });
    modal.remove();
  };

  modal.querySelector("#modal-chain").onclick = () => {
    chrome.runtime.sendMessage({
      type: "THREAT_DECISION", decision: "VIEW_DETAIL",
      attestId: attest.id, subject: threat.subject,
    });
    modal.remove();
  };
}

function row(label, value) {
  return `
    <div style="display:flex;justify-content:space-between;padding:4px 0;
      border-bottom:1px solid #1e293b;font-size:12px;gap:8px;">
      <span style="color:#94a3b8;white-space:nowrap;">${label}</span>
      <span style="color:#f1f5f9;text-align:right;word-break:break-all;">${value}</span>
    </div>`;
}

function btnStyle(bg) {
  return `background:${bg};color:#fff;border:none;border-radius:6px;padding:7px 12px;
    font-size:12px;font-weight:600;cursor:pointer;flex:1;min-width:80px;`;
}

function truncate(str, n) {
  if (!str) return "—";
  return str.length > n ? str.slice(0, n - 1) + "…" : str;
}

function statusLabel(s) {
  return ["UNSPECIFIED","ACTIVE","EXPIRED","REVOKED","DISPUTED","SUPERSEDED"][s] || "UNKNOWN";
}

function tlpLabel(t) {
  const labels = ["UNSPECIFIED","WHITE","GREEN","AMBER","RED"];
  const colors = ["#6b7280","#f9fafb","#22c55e","#f59e0b","#ef4444"];
  const l = labels[t] || "—";
  const c = colors[t] || "#6b7280";
  return `<span style="color:${c};font-weight:700;">${l}</span>`;
}

function timeAgo(ts) {
  const diff = Date.now() - ts;
  if (diff < 60000)  return "just now";
  if (diff < 3600000) return `${Math.floor(diff/60000)}m ago`;
  return `${Math.floor(diff/3600000)}h ago`;
}

// ============================================================
// Manual check dialog
// ============================================================
function openManualCheck() {
  const modal = document.createElement("div");
  modal.style.cssText = `
    position:fixed;inset:0;z-index:1000;
    background:rgba(0,0,0,0.7);display:flex;
    align-items:center;justify-content:center;padding:12px;`;

  modal.innerHTML = `
    <div style="background:#1e293b;border:1px solid #334155;border-radius:12px;
      padding:16px;max-width:360px;width:100%;">
      <div style="font-weight:700;font-size:14px;margin-bottom:12px;">🔍 Manual Check</div>
      <div style="margin-bottom:8px;">
        <label style="font-size:11px;color:#94a3b8;display:block;margin-bottom:4px;">
          URL, IPv4 address, or file SHA-256 hash
        </label>
        <input id="manual-input" type="text" placeholder="https://example.com  or  8.8.8.8  or  abc123…"
          style="width:100%;background:#0f172a;border:1px solid #334155;color:#f1f5f9;
          border-radius:6px;padding:8px 10px;font-size:12px;outline:none;"/>
      </div>
      <div id="manual-result" style="min-height:40px;font-size:12px;"></div>
      <div style="display:flex;gap:8px;margin-top:12px;">
        <button id="manual-check-btn" style="${btnStyle("#3b82f6")}">Check</button>
        <button id="manual-close-btn" style="${btnStyle("#374151")}">Cancel</button>
      </div>
    </div>`;

  document.body.appendChild(modal);

  const input   = modal.querySelector("#manual-input");
  const resultEl = modal.querySelector("#manual-result");

  modal.querySelector("#manual-close-btn").onclick = () => modal.remove();
  modal.onclick = (e) => { if (e.target === modal) modal.remove(); };

  modal.querySelector("#manual-check-btn").onclick = async () => {
    const val = input.value.trim();
    if (!val) return;

    resultEl.innerHTML = `<span class="spinner"></span>Querying chain…`;

    // Determine type
    const isIPv4  = /^\d{1,3}(\.\d{1,3}){3}$/.test(val);
    const isSHA256 = /^[a-f0-9]{64}$/i.test(val);
    const isURL   = val.startsWith("http://") || val.startsWith("https://");

    const { settings } = await chrome.runtime.sendMessage({ type: "GET_SETTINGS" });
    const nodeURL = settings?.nodeURL ?? "http://localhost:1317";

    try {
      let endpoint, label;
      if (isIPv4) {
        endpoint = `${nodeURL}/threatattest/attestation/v1/is-malicious-ipv4?ipv4=${encodeURIComponent(val)}`;
        label = `IPv4 ${val}`;
      } else if (isSHA256) {
        endpoint = `${nodeURL}/threatattest/attestation/v1/is-malicious?artifact_sha256=${encodeURIComponent(val)}`;
        label = `SHA-256 ${val.slice(0,16)}…`;
      } else if (isURL) {
        endpoint = `${nodeURL}/threatattest/attestation/v1/is-malicious-url?url=${encodeURIComponent(val)}`;
        label = new URL(val).hostname;
      } else {
        // Try as domain → build URL
        endpoint = `${nodeURL}/threatattest/attestation/v1/is-malicious-url?url=${encodeURIComponent("https://" + val + "/")}`;
        label = val;
      }

      const res  = await fetch(endpoint, { signal: AbortSignal.timeout(8000) });
      const data = await res.json();

      if (data.is_malicious) {
        const sev   = data.attestation?.severity ?? 4;
        const color = SEVERITY_COLORS[sev];
        const label2 = SEVERITY_LABELS[sev];
        resultEl.innerHTML = `
          <div style="background:#7f1d1d22;border:1px solid ${color}44;border-radius:6px;padding:8px;">
            <div style="color:${color};font-weight:700;font-size:13px;">⚠️ THREAT DETECTED — ${label2}</div>
            <div style="color:#94a3b8;margin-top:4px;">${label}</div>
            <div style="color:#94a3b8;margin-top:2px;font-size:11px;">
              Trust Score: ${data.trust_score ?? 0} &nbsp;|&nbsp;
              ${(data.attestation?.threat_categories || []).slice(0,2).join(", ")}
            </div>
          </div>`;
      } else {
        resultEl.innerHTML = `
          <div style="background:#14532d22;border:1px solid #22c55e44;border-radius:6px;padding:8px;">
            <div style="color:#86efac;font-weight:700;">✅ Not found in threat database</div>
            <div style="color:#94a3b8;margin-top:4px;font-size:11px;">${label}</div>
          </div>`;
      }
    } catch (err) {
      resultEl.innerHTML = `
        <div style="color:#f87171;">
          ⚠️ Query failed: ${err.message.slice(0, 80)}<br>
          <span style="font-size:11px;color:#94a3b8;">Is the ThreatAttest node running?</span>
        </div>`;
    }
  };

  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") modal.querySelector("#manual-check-btn").click();
  });
  setTimeout(() => input.focus(), 50);
}

// ============================================================
// Stats
// ============================================================
async function loadStats() {
  const stored = await chrome.storage.local.get("taStats");
  if (stored.taStats) {
    sessionChecks  = stored.taStats.checks  || 0;
    sessionThreats = stored.taStats.threats || 0;
    sessionBlocked = stored.taStats.blocked || 0;
  }
  updateStatsUI();
}

function updateStatsUI() {
  document.getElementById("stat-checks").textContent  = sessionChecks;
  document.getElementById("stat-threats").textContent = sessionThreats;
  document.getElementById("stat-blocked").textContent = sessionBlocked;
}

// ============================================================
// DNS Identity Badge
// ============================================================

const TIER_LABELS  = ['Anonymous', 'Staked', 'DNS Bound', 'Expert'];
const TIER_CLASSES = ['tier-0', 'tier-1', 'tier-2', 'tier-3'];
const TIER_ICONS   = ['👤', '🔒', '🌐', '⭐'];
const TIER_MULTS   = ['0.25x', '0.50x', '1.00x', '2.00x'];

/**
 * Load and render the DNS identity badge for the current tab's domain.
 * Sends GET_IDENTITY_BADGE message to the background service worker.
 */
async function loadIdentityBadge() {
  if (!currentTabURL) return;

  let hostname = '';
  try {
    hostname = new URL(currentTabURL).hostname.toLowerCase();
  } catch { return; }

  if (!hostname || hostname === 'newtab' || currentTabURL.startsWith('chrome')) return;

  // Show the identity section while loading
  const section = document.getElementById('identity-section');
  if (section) section.style.display = '';

  try {
    const resp = await chrome.runtime.sendMessage({
      type:   'GET_IDENTITY_BADGE',
      domain: hostname,
    });

    if (resp && resp.badge) {
      renderIdentityBadge(resp.badge);
    } else {
      renderNoIdentity(hostname);
    }
  } catch (err) {
    console.warn('[ThreatAttest Popup] Identity badge error:', err);
    renderNoIdentity(hostname);
  }
}

/**
 * Render an IdentityBadge object into the popup UI.
 * @param {Object} badge
 */
function renderIdentityBadge(badge) {
  const section   = document.getElementById('identity-section');
  const badgeEl   = document.getElementById('identity-badge');
  const iconEl    = document.getElementById('identity-icon');
  const labelEl   = document.getElementById('identity-label');
  const metaEl    = document.getElementById('identity-meta');
  const tierEl    = document.getElementById('identity-tier');
  const toggleBtn = document.getElementById('identity-details-toggle');

  if (!section || !badgeEl) return;
  section.style.display = '';

  // Update badge container class
  badgeEl.className = `identity-badge ${badge.badgeClass || 'badge-no-identity'}`;
  badgeEl.title     = badge.tooltip || '';

  iconEl.textContent  = badge.badgeIcon  || '❔';
  labelEl.textContent = badge.badgeLabel || 'No Identity';

  if (badge.found && badge.record) {
    const r    = badge.record;
    const tier = typeof r.attester_tier === 'number' ? r.attester_tier : 0;

    // Meta line
    const meta = [];
    if (r.domain)  meta.push(r.domain);
    if (r.expires_at) meta.push(`Expires ${formatTs(r.expires_at)}`);
    metaEl.textContent = meta.join(' · ');

    // Tier badge
    tierEl.className   = `identity-tier ${TIER_CLASSES[tier] || 'tier-0'}`;
    tierEl.textContent = `${TIER_ICONS[tier] || '👤'} ${TIER_LABELS[tier] || 'Anon'} ${TIER_MULTS[tier] || '0.25x'}`;

    // Details panel
    setDetailField('id-detail-domain',      r.domain || '—');
    setDetailField('id-detail-addr',        r.cosmos_addr ? r.cosmos_addr.slice(0,16) + '…' : '—');
    setDetailField('id-detail-selector',    r.selector || '—');
    setDetailField('id-detail-score',       r.trust_score !== undefined ? `${r.trust_score} RS` : '—');
    setDetailField('id-detail-expires',     r.expires_at ? formatTs(r.expires_at) : '—');
    setDetailField('id-detail-attestation', r.attestation_id ? r.attestation_id.slice(0,12) + '…' : '—');

    // Show toggle button
    if (toggleBtn) {
      toggleBtn.style.display = '';
      toggleBtn.onclick = () => {
        const details = document.getElementById('identity-details');
        if (details) {
          const visible = details.classList.toggle('visible');
          toggleBtn.textContent = visible ? 'Hide details ▲' : 'Show details ▼';
        }
      };
    }
  } else {
    metaEl.textContent = 'No DNS identity registered for this domain';
    tierEl.className   = 'identity-tier tier-0';
    tierEl.textContent = '👤 Anon 0.25x';
    if (toggleBtn) toggleBtn.style.display = 'none';
  }
}

/**
 * Render a "no identity" state for a hostname.
 * @param {string} hostname
 */
function renderNoIdentity(hostname) {
  const badgeEl = document.getElementById('identity-badge');
  const labelEl = document.getElementById('identity-label');
  const metaEl  = document.getElementById('identity-meta');
  const tierEl  = document.getElementById('identity-tier');
  const toggle  = document.getElementById('identity-details-toggle');

  if (badgeEl) badgeEl.className = 'identity-badge badge-no-identity';
  if (labelEl) labelEl.textContent = 'No Identity';
  if (metaEl)  metaEl.textContent  = `No DNS identity registered for ${hostname}`;
  if (tierEl)  { tierEl.className = 'identity-tier tier-0'; tierEl.textContent = '👤 Anon 0.25x'; }
  if (toggle)  toggle.style.display = 'none';
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function setDetailField(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

function formatTs(unix) {
  if (!unix) return 'unknown';
  const d = new Date(unix * 1000);
  return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}
