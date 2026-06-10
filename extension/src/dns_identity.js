// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

/**
 * dns_identity.js — ThreatAttest DNS Identity Badge resolution
 *
 * Resolves and caches DNS identity records for domains, providing identity
 * badge data for display in the browser extension popup.
 *
 * Identity records are fetched from the ThreatAttest chain via the REST API
 * (same endpoint used for attestation lookups) and cached in memory with a
 * configurable TTL.
 *
 * @module dns_identity
 */

import { API_BASE_URL, normalizeDomain } from './api.js';

// ── Cache ────────────────────────────────────────────────────────────────────

/** In-memory identity record cache. Key: normalized domain, Value: CacheEntry */
const identityCache = new Map();

/** TTL for positive (found) cache entries: 5 minutes */
const CACHE_TTL_FOUND_MS = 5 * 60 * 1000;

/** TTL for negative (not found) cache entries: 2 minutes */
const CACHE_TTL_NOT_FOUND_MS = 2 * 60 * 1000;

/**
 * @typedef {Object} CacheEntry
 * @property {IdentityRecord|null} record  - null means "not found" (negative cache)
 * @property {number}             fetchedAt - Date.now() when cached
 * @property {number}             ttlMs      - milliseconds until expiry
 */

// ── Types ────────────────────────────────────────────────────────────────────

/**
 * @typedef {Object} IdentityRecord
 * @property {string}  identity_id        - SHA-256 identity ID (hex)
 * @property {string}  cosmos_addr        - Cosmos bech32 address
 * @property {string}  domain             - Normalized domain name
 * @property {string}  selector           - Active DNS selector
 * @property {string}  public_key_hex     - Compressed secp256k1 pubkey (hex)
 * @property {string}  [name]             - Human-readable identity name
 * @property {string}  [uri]              - Identity URI
 * @property {number}  [flags]            - IdentityFlag bitmask
 * @property {string}  status             - PENDING|ACTIVE|EXPIRED|REVOKED|DNS_REMOVED|SUPERSEDED
 * @property {number}  registered_at      - Unix timestamp
 * @property {number}  expires_at         - Unix timestamp
 * @property {number}  [last_verified_at] - Unix timestamp
 * @property {string}  [attestation_id]   - Cross-referenced TATST:IDENTITY attestation ID
 * @property {number}  [trust_score]      - Reputation score (RS)
 * @property {number}  [attester_tier]    - 0=ANON, 1=STAKED, 2=DNS_BOUND, 3=EXPERT
 */

/**
 * @typedef {Object} IdentityBadge
 * @property {boolean}         found         - true if a live identity record exists
 * @property {IdentityRecord|null} record    - the record (null if not found)
 * @property {string}          badgeClass    - CSS class for badge styling
 * @property {string}          badgeLabel    - Short display label
 * @property {string}          badgeIcon     - Emoji icon
 * @property {string}          tooltip       - Full tooltip text
 * @property {boolean}         isVerified    - true if status === ACTIVE
 * @property {boolean}         isExpired     - true if status === EXPIRED
 * @property {boolean}         isRevoked     - true if status is terminal
 * @property {string}          tierLabel     - Compliance tier label
 * @property {string}          tierMultiplier - e.g. "1.00x"
 */

// ── Constants ─────────────────────────────────────────────────────────────────

/** Identity status values */
export const IdentityStatus = {
  PENDING:     'PENDING',
  ACTIVE:      'ACTIVE',
  EXPIRED:     'EXPIRED',
  REVOKED:     'REVOKED',
  DNS_REMOVED: 'DNS_REMOVED',
  SUPERSEDED:  'SUPERSEDED',
};

/** Compliance tier definitions */
export const ComplianceTiers = {
  0: { label: 'Anonymous',  multiplier: '0.25x', icon: '👤',  class: 'tier-anon'   },
  1: { label: 'Staked',     multiplier: '0.50x', icon: '🔒',  class: 'tier-staked' },
  2: { label: 'DNS Bound',  multiplier: '1.00x', icon: '🌐',  class: 'tier-dns'    },
  3: { label: 'Expert',     multiplier: '2.00x', icon: '⭐',  class: 'tier-expert' },
};

/** IdentityFlag bitmask values */
export const IdentityFlags = {
  EXPERT:        1 << 0,
  ORGANIZATION:  1 << 1,
  GOVERNMENT:    1 << 2,
  SECURITY_FIRM: 1 << 3,
  AUTOMATED:     1 << 4,
  MULTISIG:      1 << 5,
};

// ── Core API ──────────────────────────────────────────────────────────────────

/**
 * Fetch a DNS identity record for a domain from the ThreatAttest chain.
 * Results are cached to avoid hammering the API.
 *
 * @param {string} domain - Raw domain name (will be normalized)
 * @returns {Promise<IdentityRecord|null>} The record, or null if not found
 */
export async function resolveIdentity(domain) {
  let normalized;
  try {
    normalized = normalizeDomain(domain);
  } catch {
    return null;
  }
  if (!normalized) return null;

  // Check cache first
  const cached = identityCache.get(normalized);
  if (cached && (Date.now() - cached.fetchedAt) < cached.ttlMs) {
    return cached.record;
  }

  try {
    const url = `${API_BASE_URL}/identity/domain/${encodeURIComponent(normalized)}`;
    const resp = await fetch(url, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
      signal: AbortSignal.timeout(5000),
    });

    if (resp.status === 404) {
      // Negative cache entry
      identityCache.set(normalized, {
        record: null,
        fetchedAt: Date.now(),
        ttlMs: CACHE_TTL_NOT_FOUND_MS,
      });
      return null;
    }

    if (!resp.ok) {
      console.warn(`[ThreatAttest] Identity lookup failed for ${normalized}: HTTP ${resp.status}`);
      return null;
    }

    const data = await resp.json();
    const record = data.record || data || null;

    identityCache.set(normalized, {
      record,
      fetchedAt: Date.now(),
      ttlMs: CACHE_TTL_FOUND_MS,
    });

    return record;
  } catch (err) {
    console.warn(`[ThreatAttest] Identity fetch error for ${normalized}:`, err);
    return null;
  }
}

/**
 * Check if a domain has a valid (ACTIVE) identity record.
 *
 * @param {string} domain
 * @returns {Promise<boolean>}
 */
export async function hasActiveIdentity(domain) {
  const record = await resolveIdentity(domain);
  return record !== null && record.status === IdentityStatus.ACTIVE;
}

/**
 * Prefetch identity records for a list of domains (fire-and-forget).
 * Useful for preloading identities for domains seen during navigation.
 *
 * @param {string[]} domains
 */
export function prefetchIdentities(domains) {
  for (const domain of domains) {
    resolveIdentity(domain).catch(() => {});
  }
}

/**
 * Invalidate the cache entry for a domain (force re-fetch on next lookup).
 *
 * @param {string} domain
 */
export function invalidateIdentityCache(domain) {
  try {
    const normalized = normalizeDomain(domain);
    if (normalized) identityCache.delete(normalized);
  } catch {}
}

/**
 * Clear the entire identity cache.
 */
export function clearIdentityCache() {
  identityCache.clear();
}

// ── Badge construction ────────────────────────────────────────────────────────

/**
 * Build a complete IdentityBadge from an IdentityRecord (or null).
 *
 * @param {IdentityRecord|null} record
 * @returns {IdentityBadge}
 */
export function buildIdentityBadge(record) {
  if (!record) {
    return {
      found:          false,
      record:         null,
      badgeClass:     'badge-no-identity',
      badgeLabel:     'No Identity',
      badgeIcon:      '❔',
      tooltip:        'No DNS identity registered for this domain.',
      isVerified:     false,
      isExpired:      false,
      isRevoked:      false,
      tierLabel:      'Anonymous',
      tierMultiplier: '0.25x',
    };
  }

  const status = record.status || IdentityStatus.UNKNOWN;
  const tier   = typeof record.attester_tier === 'number' ? record.attester_tier : 0;
  const tierDef = ComplianceTiers[tier] || ComplianceTiers[0];

  const isActive  = status === IdentityStatus.ACTIVE;
  const isExpired = status === IdentityStatus.EXPIRED;
  const isRevoked = status === IdentityStatus.REVOKED ||
                    status === IdentityStatus.SUPERSEDED;
  const isDNSRemoved = status === IdentityStatus.DNS_REMOVED;
  const isPending = status === IdentityStatus.PENDING;

  let badgeClass, badgeLabel, badgeIcon, tooltip;

  if (isActive) {
    badgeClass = `badge-identity-active tier-${tier}`;
    badgeLabel = record.name ? `✓ ${record.name}` : '✓ Verified Identity';
    badgeIcon  = tierDef.icon;
    tooltip    = buildActiveTooltip(record, tierDef);
  } else if (isPending) {
    badgeClass = 'badge-identity-pending';
    badgeLabel = '⏳ Identity Pending';
    badgeIcon  = '⏳';
    tooltip    = `Identity for ${record.domain} is pending DNS verification.`;
  } else if (isExpired) {
    badgeClass = 'badge-identity-expired';
    badgeLabel = '⚠️ Identity Expired';
    badgeIcon  = '⚠️';
    tooltip    = `Identity for ${record.domain} has expired. Last verified: ${formatTimestamp(record.last_verified_at)}.`;
  } else if (isRevoked) {
    badgeClass = 'badge-identity-revoked';
    badgeLabel = '🚫 Identity Revoked';
    badgeIcon  = '🚫';
    tooltip    = `Identity for ${record.domain} has been revoked.`;
  } else if (isDNSRemoved) {
    badgeClass = 'badge-identity-dns-removed';
    badgeLabel = '⛔ DNS Removed';
    badgeIcon  = '⛔';
    tooltip    = `Identity for ${record.domain}: DNS records no longer resolve.`;
  } else {
    badgeClass = 'badge-identity-unknown';
    badgeLabel = `Identity (${status})`;
    badgeIcon  = '❓';
    tooltip    = `Identity status: ${status}`;
  }

  return {
    found:          true,
    record,
    badgeClass,
    badgeLabel,
    badgeIcon,
    tooltip,
    isVerified:     isActive,
    isExpired,
    isRevoked,
    tierLabel:      tierDef.label,
    tierMultiplier: tierDef.multiplier,
  };
}

/**
 * Resolve and build an identity badge for a domain in one call.
 *
 * @param {string} domain
 * @returns {Promise<IdentityBadge>}
 */
export async function getIdentityBadge(domain) {
  const record = await resolveIdentity(domain);
  return buildIdentityBadge(record);
}

// ── Flag helpers ──────────────────────────────────────────────────────────────

/**
 * Returns an array of human-readable flag labels for a flags bitmask.
 *
 * @param {number} flags
 * @returns {string[]}
 */
export function parseIdentityFlags(flags) {
  const labels = [];
  if (!flags) return labels;
  if (flags & IdentityFlags.EXPERT)        labels.push('Expert');
  if (flags & IdentityFlags.ORGANIZATION)  labels.push('Organization');
  if (flags & IdentityFlags.GOVERNMENT)    labels.push('Government');
  if (flags & IdentityFlags.SECURITY_FIRM) labels.push('Security Firm');
  if (flags & IdentityFlags.AUTOMATED)     labels.push('Automated');
  if (flags & IdentityFlags.MULTISIG)      labels.push('Multisig');
  return labels;
}

// ── Internal helpers ──────────────────────────────────────────────────────────

function buildActiveTooltip(record, tierDef) {
  const parts = [`✓ Verified DNS Identity`];
  if (record.name)   parts.push(`Name: ${record.name}`);
  parts.push(`Domain: ${record.domain}`);
  parts.push(`Cosmos: ${record.cosmos_addr ? record.cosmos_addr.slice(0, 12) + '…' : 'unknown'}`);
  parts.push(`Tier: ${tierDef.label} (${tierDef.multiplier} weight)`);
  if (record.trust_score !== undefined) parts.push(`Trust Score: ${record.trust_score} RS`);
  if (record.expires_at) parts.push(`Expires: ${formatTimestamp(record.expires_at)}`);
  const flagLabels = parseIdentityFlags(record.flags);
  if (flagLabels.length) parts.push(`Flags: ${flagLabels.join(', ')}`);
  return parts.join('\n');
}

function formatTimestamp(unix) {
  if (!unix) return 'unknown';
  return new Date(unix * 1000).toLocaleDateString();
}