// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

// ============================================================
// ThreatAttest Chain API Client
// Queries the Cosmos SDK REST (LCD) endpoint for attestation data
// ============================================================

const DEFAULT_NODE_URL = "http://localhost:1317";

// Severity levels matching on-chain enums
export const SEVERITY = {
  0: { label: "UNSPECIFIED", color: "#6b7280", emoji: "❓" },
  1: { label: "INFO",        color: "#3b82f6", emoji: "ℹ️" },
  2: { label: "LOW",         color: "#22c55e", emoji: "🟢" },
  3: { label: "MEDIUM",      color: "#f59e0b", emoji: "🟡" },
  4: { label: "HIGH",        color: "#f97316", emoji: "🟠" },
  5: { label: "CRITICAL",    color: "#ef4444", emoji: "🔴" },
};

// Attestation status labels
export const STATUS = {
  0: "UNSPECIFIED",
  1: "ACTIVE",
  2: "EXPIRED",
  3: "REVOKED",
  4: "DISPUTED",
  5: "SUPERSEDED",
};

// Artifact types
export const ARTIFACT_TYPE = {
  0: "UNSPECIFIED",
  1: "FILE",
  2: "URL",
  3: "IPV4",
  4: "DOMAIN",
};

// Threat category metadata — label, icon, permitted artifact types, default severity hint
export const THREAT_CATEGORIES = {
  // Original categories (unconstrained — valid for any artifact type)
  "TATST:MALWARE":       { label: "Malware",        icon: "\u{1F9A0}", artifacts: null },
  "TATST:PHISHING":      { label: "Phishing",       icon: "\u{1F3A3}", artifacts: null },
  "TATST:C2":            { label: "C2",              icon: "\u{1F4E1}", artifacts: null },
  "TATST:CRYPTOMINER":   { label: "Cryptominer",    icon: "\u26CF\uFE0F", artifacts: null },
  "TATST:RANSOMWARE":    { label: "Ransomware",     icon: "\u{1F512}", artifacts: null },
  "TATST:EXPLOIT":       { label: "Exploit",        icon: "\u{1F4A5}", artifacts: null },
  "TATST:SCANNER":       { label: "Scanner",        icon: "\u{1F50D}", artifacts: null },
  "TATST:SPAM":          { label: "Spam",           icon: "\u{1F4E7}", artifacts: null },
  "TATST:BOTNET":        { label: "Botnet",         icon: "\u{1F916}", artifacts: null },
  "TATST:INFOSTEALER":   { label: "Infostealer",    icon: "\u{1F575}\uFE0F", artifacts: null },
  "TATST:DROPPER":       { label: "Dropper",        icon: "\u{1F4E6}", artifacts: null },
  "TATST:BACKDOOR":      { label: "Backdoor",       icon: "\u{1F6AA}", artifacts: null },
  // PUA — Potentially Unwanted Application (FILE artifacts only)
  "TATST:PUA":           { label: "PUA",            icon: "\u26A0\uFE0F", artifacts: ["FILE"],         severity: 2 },
  // Phishing URL / phishing site (URL and DOMAIN artifacts)
  "TATST:PHISHING_URL":  { label: "Phishing URL",  icon: "\u{1F3A3}", artifacts: ["URL","DOMAIN"],    severity: 4 },
  "TATST:PHISHING_SITE": { label: "Phishing Site", icon: "\u{1F3A3}", artifacts: ["URL","DOMAIN"],    severity: 4 },
  // Advertising abuse — adware / malvertising (URL and DOMAIN artifacts)
  "TATST:ADWARE":        { label: "Adware",         icon: "\u{1F4E2}", artifacts: ["URL","DOMAIN"],    severity: 2 },
  "TATST:MALVERTISING":  { label: "Malvertising",   icon: "\u{1F3AF}", artifacts: ["URL","DOMAIN"],    severity: 3 },
};

/** Returns the human-readable label for a threat category code. */
export function categoryLabel(code) {
  return THREAT_CATEGORIES[code]?.label ?? code;
}

/** Returns the emoji icon for a threat category code. */
export function categoryIcon(code) {
  return THREAT_CATEGORIES[code]?.icon ?? "\u26A0\uFE0F";
}

// TLP traffic light protocol labels
export const TLP = {
  0: { label: "UNSPECIFIED", color: "#6b7280" },
  1: { label: "WHITE",       color: "#f9fafb" },
  2: { label: "GREEN",       color: "#22c55e" },
  3: { label: "AMBER",       color: "#f59e0b" },
  4: { label: "RED",         color: "#ef4444" },
};

// ============================================================
// SHA-256 utilities (Web Crypto API)
// ============================================================

/**
 * Compute SHA-256 of arbitrary bytes (ArrayBuffer or Uint8Array).
 * Returns lowercase hex string.
 */
export async function sha256Bytes(buffer) {
  const hashBuf = await crypto.subtle.digest("SHA-256", buffer);
  return Array.from(new Uint8Array(hashBuf))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Compute SHA-256 of a UTF-8 string.
 */
export async function sha256String(str) {
  const enc = new TextEncoder().encode(str);
  return sha256Bytes(enc);
}

/**
 * Normalize a URL for attestation lookup (mirrors Go NormalizeURL logic):
 * - lowercase scheme + host
 * - remove default ports (80 for http, 443 for https)
 * - sort query parameters
 * - strip fragment
 * - strip trailing slash from path if path is "/"
 */
export function normalizeURL(rawURL) {
  try {
    const u = new URL(rawURL.trim());
    u.hash = "";  // strip fragment

    // Lowercase scheme and host
    const scheme = u.protocol.replace(":", "").toLowerCase();
    const host   = u.hostname.toLowerCase();

    // Remove default ports
    let port = u.port;
    if ((scheme === "http"  && port === "80")  ||
        (scheme === "https" && port === "443")) {
      port = "";
    }

    // Sort query params
    u.searchParams.sort();

    // Reconstruct
    const portPart = port ? `:${port}` : "";
    const path     = u.pathname === "/" ? "/" : u.pathname.replace(/\/+$/, "");
    const query    = u.search;  // already sorted

    return `${scheme}://${host}${portPart}${path}${query}`;
  } catch {
    return null;
  }
}

/**
 * Extract registrable domain from a hostname.
 * e.g. "sub.evil.com" → "evil.com"
 * Falls back to the full hostname if parsing fails.
 */
export function extractDomain(hostname) {
  const parts = hostname.split(".");
  if (parts.length >= 2) {
    return parts.slice(-2).join(".");
  }
  return hostname;
}

// ============================================================
// REST Query Functions
// ============================================================

let _nodeURL = DEFAULT_NODE_URL;

export function setNodeURL(url) {
  _nodeURL = url.replace(/\/$/, "");
}

export function getNodeURL() {
  return _nodeURL;
}

/**
 * Core fetch wrapper with timeout and error normalization.
 */
async function apiGet(path, timeoutMs = 8000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(`${_nodeURL}${path}`, {
      signal: controller.signal,
      headers: { "Accept": "application/json" },
    });
    clearTimeout(timer);
    if (!res.ok) {
      const txt = await res.text().catch(() => "");
      throw new Error(`HTTP ${res.status}: ${txt.slice(0, 200)}`);
    }
    return await res.json();
  } catch (err) {
    clearTimeout(timer);
    throw err;
  }
}

/**
 * Query: is-malicious by raw SHA-256 hex
 * GET /threatattest/attestation/v1/is-malicious?artifact_sha256={hex}
 */
export async function isMaliciousBySHA256(artifactSHA256) {
  const data = await apiGet(
    `/threatattest/attestation/v1/is-malicious?artifact_sha256=${encodeURIComponent(artifactSHA256)}`
  );
  return {
    isMalicious:  data.is_malicious  ?? false,
    attestation:  data.attestation   ?? null,
    trustScore:   data.trust_score   ?? 0,
  };
}

/**
 * Query: is-malicious by raw URL string
 * GET /threatattest/attestation/v1/is-malicious-url?url={url}
 */
export async function isMaliciousByURL(rawURL) {
  const norm = normalizeURL(rawURL);
  if (!norm) return null;
  const data = await apiGet(
    `/threatattest/attestation/v1/is-malicious-url?url=${encodeURIComponent(norm)}`
  );
  return {
    isMalicious: data.is_malicious ?? false,
    attestation: data.attestation  ?? null,
    trustScore:  data.trust_score  ?? 0,
    queriedURL:  norm,
  };
}

/**
 * Query: is-malicious by IPv4 address string
 * GET /threatattest/attestation/v1/is-malicious-ipv4?ipv4={ip}
 */
export async function isMaliciousByIPv4(ipv4) {
  const data = await apiGet(
    `/threatattest/attestation/v1/is-malicious-ipv4?ipv4=${encodeURIComponent(ipv4)}`
  );
  return {
    isMalicious: data.is_malicious ?? false,
    attestation: data.attestation  ?? null,
    trustScore:  data.trust_score  ?? 0,
    queriedIP:   ipv4,
  };
}

/**
 * Query: list all attestations for an artifact SHA-256
 * GET /threatattest/attestation/v1/list-by-artifact?artifact_sha256={hex}
 */
export async function listByArtifact(artifactSHA256) {
  const data = await apiGet(
    `/threatattest/attestation/v1/list-by-artifact?artifact_sha256=${encodeURIComponent(artifactSHA256)}`
  );
  return data.attestations ?? [];
}

/**
 * Query: get a single attestation by ID
 * GET /threatattest/attestation/v1/attestation/{id}
 */
export async function getAttestation(attestationID) {
  const data = await apiGet(
    `/threatattest/attestation/v1/attestation/${encodeURIComponent(attestationID)}`
  );
  return data.attestation ?? null;
}

/**
 * Query: node status / connectivity check
 * GET /cosmos/base/tendermint/v1beta1/node_info
 */
export async function getNodeInfo() {
  return apiGet("/cosmos/base/tendermint/v1beta1/node_info", 5000);
}

// ============================================================
// Result cache (in-memory, per session)
// ============================================================

const _cache = new Map();
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

export function cacheGet(key) {
  const entry = _cache.get(key);
  if (!entry) return null;
  if (Date.now() - entry.ts > CACHE_TTL_MS) {
    _cache.delete(key);
    return null;
  }
  return entry.value;
}

export function cacheSet(key, value) {
  _cache.set(key, { value, ts: Date.now() });
}

export function cacheClear() {
  _cache.clear();
}

// ============================================================
// High-level check functions (with cache)
// ============================================================

/**
 * Check a downloaded file by its SHA-256 hash.
 * Returns { isMalicious, attestation, trustScore } or null on error.
 */
export async function checkFileSHA256(sha256hex) {
  const key = `file:${sha256hex}`;
  const cached = cacheGet(key);
  if (cached !== null) return cached;

  try {
    const result = await isMaliciousBySHA256(sha256hex);
    cacheSet(key, result);
    return result;
  } catch (err) {
    console.warn("[ThreatAttest] checkFileSHA256 error:", err.message);
    return null;
  }
}

/**
 * Check a URL (normalized) against the chain.
 */
export async function checkURL(rawURL) {
  const norm = normalizeURL(rawURL);
  if (!norm) return null;
  const key = `url:${norm}`;
  const cached = cacheGet(key);
  if (cached !== null) return cached;

  try {
    const result = await isMaliciousByURL(rawURL);
    cacheSet(key, result);
    return result;
  } catch (err) {
    console.warn("[ThreatAttest] checkURL error:", err.message);
    return null;
  }
}

/**
 * Check an IPv4 address against the chain.
 */
export async function checkIPv4(ip) {
  if (isReservedIPv4(ip)) return null;
  const key = `ipv4:${ip}`;
  const cached = cacheGet(key);
  if (cached !== null) return cached;

  try {
    const result = await isMaliciousByIPv4(ip);
    cacheSet(key, result);
    return result;
  } catch (err) {
    console.warn("[ThreatAttest] checkIPv4 error:", err.message);
    return null;
  }
}

/**
 * Normalize a bare domain name for chain lookup:
 *   - lowercase, strip leading www., strip port, strip scheme and path if present.
 * Returns null if the domain looks invalid (< 2 labels, reserved TLD, etc.).
 */
export function normalizeDomain(domain) {
  if (!domain || typeof domain !== "string") return null;
  let d = domain.trim().toLowerCase();
  // strip scheme
  const schemeIdx = d.indexOf("://");
  if (schemeIdx !== -1) d = d.slice(schemeIdx + 3);
  // strip path / query / fragment
  const pathIdx = d.search(/[/?#]/);
  if (pathIdx !== -1) d = d.slice(0, pathIdx);
  // strip port
  const portIdx = d.lastIndexOf(":");
  if (portIdx !== -1 && !d.slice(portIdx + 1).includes(".")) {
    d = d.slice(0, portIdx);
  }
  // strip www.
  if (d.startsWith("www.")) d = d.slice(4);
  // Must have at least 2 labels
  const labels = d.split(".");
  if (labels.length < 2 || labels.some(l => l.length === 0)) return null;
  return d;
}

/**
 * checkDomain queries the chain for attestations against a bare domain name.
 * The artifact SHA-256 is SHA-256(normalizedDomain).
 * Returns the same result shape as checkURL / checkFileSHA256, or null if clean.
 */
export async function checkDomain(rawDomain) {
  const norm = normalizeDomain(rawDomain);
  if (!norm) return null;
  const key = `domain:${norm}`;
  const cached = cacheGet(key);
  if (cached !== null) return cached;

  try {
    // Compute SHA-256 of the normalized domain using Web Crypto
    const encoder = new TextEncoder();
    const data = encoder.encode(norm);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const domainSHA256 = hashArray.map(b => b.toString(16).padStart(2, "0")).join("");

    const result = await isMaliciousBySHA256(domainSHA256);
    cacheSet(key, result);
    return result;
  } catch (err) {
    console.warn("[ThreatAttest] checkDomain error:", err.message);
    return null;
  }
}

// ============================================================
// IPv4 reserved range detection (mirrors Go IsReservedIPv4)
// ============================================================

const RESERVED_CIDRS = [
  ["0.0.0.0",     8],
  ["10.0.0.0",    8],
  ["100.64.0.0", 10],
  ["127.0.0.0",   8],
  ["169.254.0.0",16],
  ["172.16.0.0", 12],
  ["192.0.0.0",  24],
  ["192.168.0.0",16],
  ["198.18.0.0", 15],
  ["198.51.100.0",24],
  ["203.0.113.0", 24],
  ["224.0.0.0",   4],
  ["240.0.0.0",   4],
  ["255.255.255.255", 32],
];

function ipToInt(ip) {
  return ip.split(".").reduce((acc, octet) => (acc << 8) | parseInt(octet, 10), 0) >>> 0;
}

export function isReservedIPv4(ip) {
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return true;
  const ipInt = ipToInt(ip);
  for (const [base, prefix] of RESERVED_CIDRS) {
    const mask   = prefix === 32 ? 0xffffffff : (~(0xffffffff >>> prefix)) >>> 0;
    const baseInt = ipToInt(base);
    if ((ipInt & mask) === (baseInt & mask)) return true;
  }
  return false;
}

/**
 * Parse IPv4 from a hostname string (returns null if not a plain IPv4).
 */
export function parseIPv4(hostname) {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) return hostname;
  return null;
}

// ============================================================
// DNS Identity — re-exports from dns_identity.js
// Import directly from dns_identity.js or use these convenience re-exports.
// ============================================================
export {
  resolveIdentity,
  hasActiveIdentity,
  prefetchIdentities,
  invalidateIdentityCache,
  clearIdentityCache,
  buildIdentityBadge,
  getIdentityBadge,
  parseIdentityFlags,
  IdentityStatus,
  ComplianceTiers,
  IdentityFlags,
} from './dns_identity.js';
