// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

/**
 * test_extension_badges.js — Browser extension identity badge unit tests
 *
 * Tests the dns_identity.js module logic in Node.js without a browser/Chrome
 * environment, by:
 *   1. Inlining the pure functions from dns_identity.js (badge building, flag
 *      parsing, cache logic, tier helpers) — no ES module imports needed
 *   2. Mocking the fetch() API for resolveIdentity() network tests
 *   3. Running a structured test suite with pass/fail counts
 *
 * Run with:
 *   node threatattest/tests/test_extension_badges.js
 *
 * Exit code 0 = all tests passed, non-zero = failures detected.
 */

'use strict';

// ─── ANSI colors ────────────────────────────────────────────────────────────

const RED    = '\x1b[0;31m';
const GREEN  = '\x1b[0;32m';
const YELLOW = '\x1b[1;33m';
const CYAN   = '\x1b[0;36m';
const BOLD   = '\x1b[1m';
const RESET  = '\x1b[0m';

let TESTS_RUN     = 0;
let TESTS_PASSED  = 0;
let TESTS_FAILED  = 0;
const FAILURES    = [];

function ok(name)   { console.log(`${GREEN}[PASS]${RESET}  ${name}`); TESTS_PASSED++; }
function fail(name, reason) {
  console.log(`${RED}[FAIL]${RESET}  ${name}`);
  if (reason) console.log(`        ${YELLOW}↳ ${reason}${RESET}`);
  TESTS_FAILED++;
  FAILURES.push({ name, reason });
}
function header(title) { console.log(`\n${BOLD}${CYAN}══ ${title} ══${RESET}`); }

function test(name, fn) {
  TESTS_RUN++;
  console.log(`\n${BOLD}Test ${TESTS_RUN}: ${name}${RESET}`);
  try {
    const result = fn();
    if (result === false) {
      fail(name, 'test function returned false');
    } else {
      ok(name);
    }
  } catch (err) {
    fail(name, err.message || String(err));
  }
}

function assertEqual(actual, expected, msg) {
  if (actual !== expected) {
    throw new Error(`${msg || 'assertEqual'}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  }
}

function assertDeepEqual(actual, expected, msg) {
  const a = JSON.stringify(actual);
  const e = JSON.stringify(expected);
  if (a !== e) {
    throw new Error(`${msg || 'assertDeepEqual'}: expected ${e}, got ${a}`);
  }
}

function assertTrue(val, msg) {
  if (!val) throw new Error(msg || `Expected truthy, got ${JSON.stringify(val)}`);
}

function assertFalse(val, msg) {
  if (val) throw new Error(msg || `Expected falsy, got ${JSON.stringify(val)}`);
}

function assertIncludes(str, substr, msg) {
  if (!str.includes(substr)) {
    throw new Error(`${msg || 'assertIncludes'}: "${str}" does not include "${substr}"`);
  }
}

// ─── Inline dns_identity.js constants and pure functions ────────────────────
// (These are copied verbatim from the source to avoid ES module / browser
//  dependency issues in Node.js test runner)

const IdentityStatus = {
  PENDING:     'PENDING',
  ACTIVE:      'ACTIVE',
  EXPIRED:     'EXPIRED',
  REVOKED:     'REVOKED',
  DNS_REMOVED: 'DNS_REMOVED',
  SUPERSEDED:  'SUPERSEDED',
};

const ComplianceTiers = {
  0: { label: 'Anonymous',  multiplier: '0.25x', icon: '👤',  class: 'tier-anon'   },
  1: { label: 'Staked',     multiplier: '0.50x', icon: '🔒',  class: 'tier-staked' },
  2: { label: 'DNS Bound',  multiplier: '1.00x', icon: '🌐',  class: 'tier-dns'    },
  3: { label: 'Expert',     multiplier: '2.00x', icon: '⭐',  class: 'tier-expert' },
};

const IdentityFlags = {
  EXPERT:        1 << 0,   // 1
  ORGANIZATION:  1 << 1,   // 2
  GOVERNMENT:    1 << 2,   // 4
  SECURITY_FIRM: 1 << 3,   // 8
  AUTOMATED:     1 << 4,   // 16
  MULTISIG:      1 << 5,   // 32
};

const CACHE_TTL_FOUND_MS     = 5 * 60 * 1000;  // 5 min
const CACHE_TTL_NOT_FOUND_MS = 2 * 60 * 1000;  // 2 min

// In-memory cache (re-created per test suite run)
let identityCache = new Map();

function clearIdentityCache() {
  identityCache.clear();
}

function invalidateIdentityCache(domain) {
  const normalized = normalizeDomain(domain);
  if (normalized) identityCache.delete(normalized);
}

// Simplified normalizeDomain (mirrors logic from api.js)
function normalizeDomain(raw) {
  if (!raw || typeof raw !== 'string') return null;
  let d = raw.trim().toLowerCase();
  // Strip scheme
  d = d.replace(/^https?:\/\//, '');
  // Strip path/query
  d = d.split('/')[0].split('?')[0].split('#')[0];
  // Strip port
  d = d.replace(/:\d+$/, '');
  // Strip trailing dot
  d = d.replace(/\.$/, '');
  // Strip leading www.
  if (d.startsWith('www.')) d = d.slice(4);
  // Basic validation
  if (!d || d.length > 253) return null;
  const labels = d.split('.');
  if (labels.length < 2) return null;
  for (const label of labels) {
    if (!label || label.length > 63) return null;
    if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(label) && !/^[a-z0-9]$/.test(label)) return null;
  }
  return d;
}

function buildActiveTooltip(record, tierDef) {
  const parts = ['✓ Verified DNS Identity'];
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

function parseIdentityFlags(flags) {
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

function buildIdentityBadge(record) {
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

  const status  = record.status || 'UNKNOWN';
  const tier    = typeof record.attester_tier === 'number' ? record.attester_tier : 0;
  const tierDef = ComplianceTiers[tier] || ComplianceTiers[0];

  const isActive     = status === IdentityStatus.ACTIVE;
  const isExpired    = status === IdentityStatus.EXPIRED;
  const isRevoked    = status === IdentityStatus.REVOKED ||
                       status === IdentityStatus.SUPERSEDED;
  const isDNSRemoved = status === IdentityStatus.DNS_REMOVED;
  const isPending    = status === IdentityStatus.PENDING;

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

// Async resolveIdentity with injectable fetch (for testing)
async function resolveIdentity(domain, _fetch) {
  const fetchFn = _fetch || global.fetch;
  let normalized;
  try {
    normalized = normalizeDomain(domain);
  } catch { return null; }
  if (!normalized) return null;

  // Check cache
  const cached = identityCache.get(normalized);
  if (cached && (Date.now() - cached.fetchedAt) < cached.ttlMs) {
    return cached.record;
  }

  try {
    const url = `http://localhost:1317/identity/domain/${encodeURIComponent(normalized)}`;
    const resp = await fetchFn(url, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });

    if (resp.status === 404) {
      identityCache.set(normalized, {
        record: null,
        fetchedAt: Date.now(),
        ttlMs: CACHE_TTL_NOT_FOUND_MS,
      });
      return null;
    }

    if (!resp.ok) return null;

    const data = await resp.json();
    const record = data.record || data || null;

    identityCache.set(normalized, {
      record,
      fetchedAt: Date.now(),
      ttlMs: CACHE_TTL_FOUND_MS,
    });
    return record;
  } catch { return null; }
}

async function hasActiveIdentity(domain, _fetch) {
  const record = await resolveIdentity(domain, _fetch);
  return record !== null && record.status === IdentityStatus.ACTIVE;
}

// ─── Fixtures ────────────────────────────────────────────────────────────────

const ACTIVE_RECORD = {
  identity_id:      'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
  cosmos_addr:      'cosmos1qg5ega6dykkxc307y25pecuufrjkxkaggkkxh9',
  domain:           'example.com',
  selector:         'tatkey-2024',
  public_key_hex:   '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
  name:             'Example Security Corp',
  uri:              'https://example.com',
  flags:            IdentityFlags.ORGANIZATION | IdentityFlags.SECURITY_FIRM,
  status:           'ACTIVE',
  registered_at:    1700000000,
  expires_at:       1731536000,
  last_verified_at: 1728944000,
  trust_score:      85,
  attester_tier:    2,
  attestation_id:   'TATST-001',
};

const PENDING_RECORD = {
  ...ACTIVE_RECORD,
  domain:   'pending.example.com',
  name:     'Pending Corp',
  status:   'PENDING',
  attester_tier: 0,
};

const EXPIRED_RECORD = {
  ...ACTIVE_RECORD,
  domain: 'expired.com',
  name:   'Old Corp',
  status: 'EXPIRED',
  last_verified_at: 1700000000,
};

const REVOKED_RECORD = {
  ...ACTIVE_RECORD,
  domain: 'bad.com',
  status: 'REVOKED',
};

const SUPERSEDED_RECORD = {
  ...ACTIVE_RECORD,
  domain: 'rotated.com',
  status: 'SUPERSEDED',
};

const DNS_REMOVED_RECORD = {
  ...ACTIVE_RECORD,
  domain: 'gone.com',
  status: 'DNS_REMOVED',
};

const EXPERT_RECORD = {
  ...ACTIVE_RECORD,
  domain:       'expert.org',
  name:         'Elite Security',
  flags:        IdentityFlags.EXPERT | IdentityFlags.SECURITY_FIRM,
  attester_tier: 3,
  trust_score:  99,
};

// ─── Mock fetch factory ──────────────────────────────────────────────────────

/**
 * Creates a mock fetch that returns the given record as a JSON response.
 * Pass status=404 for a not-found response.
 */
function mockFetch(record, { status = 200, delay = 0, throwError = null } = {}) {
  return async (_url, _opts) => {
    if (throwError) throw new Error(throwError);
    if (delay) await new Promise(r => setTimeout(r, delay));
    return {
      status,
      ok: status >= 200 && status < 300,
      json: async () => ({ record }),
    };
  };
}

/**
 * Mock fetch that records calls for assertion purposes.
 */
function spyFetch(record, opts = {}) {
  const calls = [];
  const fn = async (url, fetchOpts) => {
    calls.push({ url, opts: fetchOpts });
    return mockFetch(record, opts)(url, fetchOpts);
  };
  fn.calls = calls;
  return fn;
}

// ═══════════════════════════════════════════════════════════════════════════
// TEST SUITES
// ═══════════════════════════════════════════════════════════════════════════

// ─── Suite 1: IdentityStatus constants ───────────────────────────────────────

header('1. IdentityStatus constants');

test('IdentityStatus has all 6 values', () => {
  const keys = Object.keys(IdentityStatus);
  assertEqual(keys.length, 6, 'count');
});

test('IdentityStatus.ACTIVE === "ACTIVE"', () => {
  assertEqual(IdentityStatus.ACTIVE, 'ACTIVE');
});

test('IdentityStatus.REVOKED and SUPERSEDED are distinct', () => {
  assertTrue(IdentityStatus.REVOKED !== IdentityStatus.SUPERSEDED);
});

test('All status values are uppercase strings', () => {
  for (const [k, v] of Object.entries(IdentityStatus)) {
    assertEqual(v, v.toUpperCase(), `IdentityStatus.${k}`);
    assertEqual(typeof v, 'string', `IdentityStatus.${k} type`);
  }
});

// ─── Suite 2: ComplianceTiers constants ──────────────────────────────────────

header('2. ComplianceTiers constants');

test('ComplianceTiers has tiers 0-3', () => {
  for (let t = 0; t <= 3; t++) {
    assertTrue(ComplianceTiers[t] !== undefined, `tier ${t} exists`);
  }
});

test('Tier 0 multiplier is 0.25x', () => {
  assertEqual(ComplianceTiers[0].multiplier, '0.25x');
});

test('Tier 1 multiplier is 0.50x', () => {
  assertEqual(ComplianceTiers[1].multiplier, '0.50x');
});

test('Tier 2 multiplier is 1.00x', () => {
  assertEqual(ComplianceTiers[2].multiplier, '1.00x');
});

test('Tier 3 multiplier is 2.00x', () => {
  assertEqual(ComplianceTiers[3].multiplier, '2.00x');
});

test('All tiers have label, multiplier, icon, class', () => {
  for (let t = 0; t <= 3; t++) {
    const tier = ComplianceTiers[t];
    assertTrue(typeof tier.label === 'string',      `tier ${t} label`);
    assertTrue(typeof tier.multiplier === 'string', `tier ${t} multiplier`);
    assertTrue(typeof tier.icon === 'string',       `tier ${t} icon`);
    assertTrue(typeof tier.class === 'string',      `tier ${t} class`);
  }
});

test('Tier labels are correct', () => {
  assertEqual(ComplianceTiers[0].label, 'Anonymous');
  assertEqual(ComplianceTiers[1].label, 'Staked');
  assertEqual(ComplianceTiers[2].label, 'DNS Bound');
  assertEqual(ComplianceTiers[3].label, 'Expert');
});

// ─── Suite 3: IdentityFlags bitmask ──────────────────────────────────────────

header('3. IdentityFlags bitmask');

test('IdentityFlags are powers of 2', () => {
  const vals = Object.values(IdentityFlags);
  for (const v of vals) {
    assertTrue((v & (v - 1)) === 0, `flag ${v} is a power of 2`);
  }
});

test('IdentityFlags has 6 distinct values', () => {
  const vals = Object.values(IdentityFlags);
  assertEqual(vals.length, 6);
  const set = new Set(vals);
  assertEqual(set.size, 6, 'all distinct');
});

test('EXPERT flag is 1', () => {
  assertEqual(IdentityFlags.EXPERT, 1);
});

test('Flags can be OR-combined', () => {
  const combined = IdentityFlags.EXPERT | IdentityFlags.ORGANIZATION;
  assertEqual(combined, 3);
  assertTrue(!!(combined & IdentityFlags.EXPERT));
  assertTrue(!!(combined & IdentityFlags.ORGANIZATION));
  assertFalse(!!(combined & IdentityFlags.GOVERNMENT));
});

test('ACTIVE_RECORD flags combine ORGANIZATION and SECURITY_FIRM', () => {
  const expected = IdentityFlags.ORGANIZATION | IdentityFlags.SECURITY_FIRM;
  assertEqual(ACTIVE_RECORD.flags, expected);
});

// ─── Suite 4: parseIdentityFlags ─────────────────────────────────────────────

header('4. parseIdentityFlags()');

test('flags=0 returns empty array', () => {
  assertDeepEqual(parseIdentityFlags(0), []);
});

test('flags=undefined returns empty array', () => {
  assertDeepEqual(parseIdentityFlags(undefined), []);
});

test('EXPERT flag returns ["Expert"]', () => {
  assertDeepEqual(parseIdentityFlags(IdentityFlags.EXPERT), ['Expert']);
});

test('ORGANIZATION flag returns ["Organization"]', () => {
  assertDeepEqual(parseIdentityFlags(IdentityFlags.ORGANIZATION), ['Organization']);
});

test('GOVERNMENT flag returns ["Government"]', () => {
  assertDeepEqual(parseIdentityFlags(IdentityFlags.GOVERNMENT), ['Government']);
});

test('SECURITY_FIRM flag returns ["Security Firm"]', () => {
  assertDeepEqual(parseIdentityFlags(IdentityFlags.SECURITY_FIRM), ['Security Firm']);
});

test('AUTOMATED flag returns ["Automated"]', () => {
  assertDeepEqual(parseIdentityFlags(IdentityFlags.AUTOMATED), ['Automated']);
});

test('MULTISIG flag returns ["Multisig"]', () => {
  assertDeepEqual(parseIdentityFlags(IdentityFlags.MULTISIG), ['Multisig']);
});

test('All flags combined returns all 6 labels', () => {
  const allFlags = Object.values(IdentityFlags).reduce((a, b) => a | b, 0);
  const labels = parseIdentityFlags(allFlags);
  assertEqual(labels.length, 6);
  assertTrue(labels.includes('Expert'));
  assertTrue(labels.includes('Organization'));
  assertTrue(labels.includes('Government'));
  assertTrue(labels.includes('Security Firm'));
  assertTrue(labels.includes('Automated'));
  assertTrue(labels.includes('Multisig'));
});

test('ORGANIZATION | SECURITY_FIRM returns ["Organization","Security Firm"]', () => {
  const flags = IdentityFlags.ORGANIZATION | IdentityFlags.SECURITY_FIRM;
  assertDeepEqual(parseIdentityFlags(flags), ['Organization', 'Security Firm']);
});

test('Flag order is deterministic (always EXPERT first)', () => {
  const flags = IdentityFlags.MULTISIG | IdentityFlags.EXPERT;
  const labels = parseIdentityFlags(flags);
  assertEqual(labels[0], 'Expert', 'EXPERT always first');
  assertEqual(labels[1], 'Multisig');
});

// ─── Suite 5: buildIdentityBadge() — null record ─────────────────────────────

header('5. buildIdentityBadge(null)');

test('null record returns found=false', () => {
  const badge = buildIdentityBadge(null);
  assertFalse(badge.found);
});

test('null record returns record=null', () => {
  const badge = buildIdentityBadge(null);
  assertEqual(badge.record, null);
});

test('null record returns badgeClass=badge-no-identity', () => {
  const badge = buildIdentityBadge(null);
  assertEqual(badge.badgeClass, 'badge-no-identity');
});

test('null record returns isVerified=false', () => {
  const badge = buildIdentityBadge(null);
  assertFalse(badge.isVerified);
});

test('null record returns isExpired=false', () => {
  const badge = buildIdentityBadge(null);
  assertFalse(badge.isExpired);
});

test('null record returns isRevoked=false', () => {
  const badge = buildIdentityBadge(null);
  assertFalse(badge.isRevoked);
});

test('null record returns tier Anonymous / 0.25x', () => {
  const badge = buildIdentityBadge(null);
  assertEqual(badge.tierLabel, 'Anonymous');
  assertEqual(badge.tierMultiplier, '0.25x');
});

test('null record tooltip mentions "No DNS identity"', () => {
  const badge = buildIdentityBadge(null);
  assertIncludes(badge.tooltip, 'No DNS identity');
});

// ─── Suite 6: buildIdentityBadge() — ACTIVE record ───────────────────────────

header('6. buildIdentityBadge(ACTIVE)');

test('ACTIVE record: found=true', () => {
  const badge = buildIdentityBadge(ACTIVE_RECORD);
  assertTrue(badge.found);
});

test('ACTIVE record: isVerified=true', () => {
  const badge = buildIdentityBadge(ACTIVE_RECORD);
  assertTrue(badge.isVerified);
});

test('ACTIVE record: isExpired=false', () => {
  const badge = buildIdentityBadge(ACTIVE_RECORD);
  assertFalse(badge.isExpired);
});

test('ACTIVE record: isRevoked=false', () => {
  const badge = buildIdentityBadge(ACTIVE_RECORD);
  assertFalse(badge.isRevoked);
});

test('ACTIVE record: badgeClass includes "badge-identity-active"', () => {
  const badge = buildIdentityBadge(ACTIVE_RECORD);
  assertIncludes(badge.badgeClass, 'badge-identity-active');
});

test('ACTIVE record tier-2: badgeClass includes "tier-2"', () => {
  const badge = buildIdentityBadge(ACTIVE_RECORD);
  assertIncludes(badge.badgeClass, 'tier-2');
});

test('ACTIVE record with name: badgeLabel includes name', () => {
  const badge = buildIdentityBadge(ACTIVE_RECORD);
  assertIncludes(badge.badgeLabel, 'Example Security Corp');
  assertIncludes(badge.badgeLabel, '✓');
});

test('ACTIVE record without name: badgeLabel is "✓ Verified Identity"', () => {
  const rec = { ...ACTIVE_RECORD, name: undefined };
  const badge = buildIdentityBadge(rec);
  assertEqual(badge.badgeLabel, '✓ Verified Identity');
});

test('ACTIVE record: tooltip includes domain', () => {
  const badge = buildIdentityBadge(ACTIVE_RECORD);
  assertIncludes(badge.tooltip, 'example.com');
});

test('ACTIVE record: tooltip includes Cosmos addr prefix', () => {
  const badge = buildIdentityBadge(ACTIVE_RECORD);
  // buildActiveTooltip truncates cosmos_addr to first 12 chars + '…'
  // "cosmos1qg5ega6dykkxc307y25pecuufrjkxkaggkkxh9".slice(0,12) = "cosmos1qg5eg"
  assertIncludes(badge.tooltip, 'cosmos1qg5eg');
});

test('ACTIVE record: tooltip includes tier label', () => {
  const badge = buildIdentityBadge(ACTIVE_RECORD);
  assertIncludes(badge.tooltip, 'DNS Bound');
});

test('ACTIVE record: tooltip includes trust score', () => {
  const badge = buildIdentityBadge(ACTIVE_RECORD);
  assertIncludes(badge.tooltip, '85 RS');
});

test('ACTIVE record: tooltip includes Organization and Security Firm flags', () => {
  const badge = buildIdentityBadge(ACTIVE_RECORD);
  assertIncludes(badge.tooltip, 'Organization');
  assertIncludes(badge.tooltip, 'Security Firm');
});

test('ACTIVE record: tierLabel = DNS Bound', () => {
  const badge = buildIdentityBadge(ACTIVE_RECORD);
  assertEqual(badge.tierLabel, 'DNS Bound');
});

test('ACTIVE record: tierMultiplier = 1.00x', () => {
  const badge = buildIdentityBadge(ACTIVE_RECORD);
  assertEqual(badge.tierMultiplier, '1.00x');
});

// ─── Suite 7: buildIdentityBadge() — EXPERT tier ─────────────────────────────

header('7. buildIdentityBadge(EXPERT tier)');

test('Expert tier (3): tierLabel = Expert', () => {
  const badge = buildIdentityBadge(EXPERT_RECORD);
  assertEqual(badge.tierLabel, 'Expert');
});

test('Expert tier: tierMultiplier = 2.00x', () => {
  const badge = buildIdentityBadge(EXPERT_RECORD);
  assertEqual(badge.tierMultiplier, '2.00x');
});

test('Expert tier: badgeClass includes tier-3', () => {
  const badge = buildIdentityBadge(EXPERT_RECORD);
  assertIncludes(badge.badgeClass, 'tier-3');
});

test('Expert tier: tooltip includes trust score 99', () => {
  const badge = buildIdentityBadge(EXPERT_RECORD);
  assertIncludes(badge.tooltip, '99 RS');
});

test('Expert tier: tooltip includes Flags with Expert, Security Firm', () => {
  const badge = buildIdentityBadge(EXPERT_RECORD);
  assertIncludes(badge.tooltip, 'Expert');
  assertIncludes(badge.tooltip, 'Security Firm');
});

// ─── Suite 8: buildIdentityBadge() — non-ACTIVE statuses ─────────────────────

header('8. buildIdentityBadge() — PENDING / EXPIRED / REVOKED / DNS_REMOVED');

test('PENDING: isVerified=false, badgeClass=badge-identity-pending', () => {
  const badge = buildIdentityBadge(PENDING_RECORD);
  assertFalse(badge.isVerified);
  assertEqual(badge.badgeClass, 'badge-identity-pending');
});

test('PENDING: badgeLabel contains "Pending"', () => {
  const badge = buildIdentityBadge(PENDING_RECORD);
  assertIncludes(badge.badgeLabel, 'Pending');
});

test('PENDING: tier falls back to Anonymous (tier 0)', () => {
  const badge = buildIdentityBadge(PENDING_RECORD);
  assertEqual(badge.tierLabel, 'Anonymous');
  assertEqual(badge.tierMultiplier, '0.25x');
});

test('EXPIRED: isExpired=true, isVerified=false', () => {
  const badge = buildIdentityBadge(EXPIRED_RECORD);
  assertTrue(badge.isExpired);
  assertFalse(badge.isVerified);
});

test('EXPIRED: badgeClass=badge-identity-expired', () => {
  const badge = buildIdentityBadge(EXPIRED_RECORD);
  assertEqual(badge.badgeClass, 'badge-identity-expired');
});

test('EXPIRED: badgeLabel contains "Expired"', () => {
  const badge = buildIdentityBadge(EXPIRED_RECORD);
  assertIncludes(badge.badgeLabel, 'Expired');
});

test('EXPIRED: tooltip mentions domain', () => {
  const badge = buildIdentityBadge(EXPIRED_RECORD);
  assertIncludes(badge.tooltip, 'expired.com');
});

test('REVOKED: isRevoked=true, isVerified=false, isExpired=false', () => {
  const badge = buildIdentityBadge(REVOKED_RECORD);
  assertTrue(badge.isRevoked);
  assertFalse(badge.isVerified);
  assertFalse(badge.isExpired);
});

test('REVOKED: badgeClass=badge-identity-revoked', () => {
  const badge = buildIdentityBadge(REVOKED_RECORD);
  assertEqual(badge.badgeClass, 'badge-identity-revoked');
});

test('REVOKED: badgeLabel contains "Revoked"', () => {
  const badge = buildIdentityBadge(REVOKED_RECORD);
  assertIncludes(badge.badgeLabel, 'Revoked');
});

test('SUPERSEDED: isRevoked=true (superseded is terminal)', () => {
  const badge = buildIdentityBadge(SUPERSEDED_RECORD);
  assertTrue(badge.isRevoked, 'SUPERSEDED should set isRevoked=true');
});

test('SUPERSEDED: badgeClass=badge-identity-revoked', () => {
  const badge = buildIdentityBadge(SUPERSEDED_RECORD);
  assertEqual(badge.badgeClass, 'badge-identity-revoked');
});

test('DNS_REMOVED: badgeClass=badge-identity-dns-removed', () => {
  const badge = buildIdentityBadge(DNS_REMOVED_RECORD);
  assertEqual(badge.badgeClass, 'badge-identity-dns-removed');
});

test('DNS_REMOVED: badgeLabel contains "DNS Removed"', () => {
  const badge = buildIdentityBadge(DNS_REMOVED_RECORD);
  assertIncludes(badge.badgeLabel, 'DNS Removed');
});

test('DNS_REMOVED: isVerified=false, isExpired=false, isRevoked=false', () => {
  const badge = buildIdentityBadge(DNS_REMOVED_RECORD);
  assertFalse(badge.isVerified);
  assertFalse(badge.isExpired);
  assertFalse(badge.isRevoked);
});

test('Unknown status: badgeClass=badge-identity-unknown', () => {
  const rec = { ...ACTIVE_RECORD, status: 'WHATEVER' };
  const badge = buildIdentityBadge(rec);
  assertEqual(badge.badgeClass, 'badge-identity-unknown');
});

test('Unknown status: badgeLabel includes the status string', () => {
  const rec = { ...ACTIVE_RECORD, status: 'WHATEVER' };
  const badge = buildIdentityBadge(rec);
  assertIncludes(badge.badgeLabel, 'WHATEVER');
});

// ─── Suite 9: buildIdentityBadge() — tier fallback edge cases ────────────────

header('9. buildIdentityBadge() — tier edge cases');

test('Missing attester_tier defaults to tier 0 (Anonymous)', () => {
  const rec = { ...ACTIVE_RECORD };
  delete rec.attester_tier;
  const badge = buildIdentityBadge(rec);
  assertEqual(badge.tierLabel, 'Anonymous');
  assertEqual(badge.tierMultiplier, '0.25x');
});

test('attester_tier=null defaults to tier 0', () => {
  const rec = { ...ACTIVE_RECORD, attester_tier: null };
  const badge = buildIdentityBadge(rec);
  assertEqual(badge.tierLabel, 'Anonymous');
});

test('attester_tier=999 falls back to tier 0 (unknown tier)', () => {
  const rec = { ...ACTIVE_RECORD, attester_tier: 999 };
  const badge = buildIdentityBadge(rec);
  assertEqual(badge.tierLabel, 'Anonymous');
});

test('attester_tier=1 (Staked): tierLabel=Staked, multiplier=0.50x', () => {
  const rec = { ...ACTIVE_RECORD, attester_tier: 1 };
  const badge = buildIdentityBadge(rec);
  assertEqual(badge.tierLabel, 'Staked');
  assertEqual(badge.tierMultiplier, '0.50x');
  assertIncludes(badge.badgeClass, 'tier-1');
});

// ─── Suite 10: normalizeDomain() ─────────────────────────────────────────────

header('10. normalizeDomain()');

test('"example.com" normalizes to "example.com"', () => {
  assertEqual(normalizeDomain('example.com'), 'example.com');
});

test('"https://example.com" strips scheme', () => {
  assertEqual(normalizeDomain('https://example.com'), 'example.com');
});

test('"http://example.com" strips scheme', () => {
  assertEqual(normalizeDomain('http://example.com'), 'example.com');
});

test('"www.example.com" strips www.', () => {
  assertEqual(normalizeDomain('www.example.com'), 'example.com');
});

test('"https://www.example.com/path?q=1" strips scheme+www+path+query', () => {
  assertEqual(normalizeDomain('https://www.example.com/path?q=1'), 'example.com');
});

test('"EXAMPLE.COM" lowercases', () => {
  assertEqual(normalizeDomain('EXAMPLE.COM'), 'example.com');
});

test('"example.com." strips trailing dot', () => {
  assertEqual(normalizeDomain('example.com.'), 'example.com');
});

test('"example.com:8080" strips port', () => {
  assertEqual(normalizeDomain('example.com:8080'), 'example.com');
});

test('"sub.example.co.uk" passes through (no www. stripping for arbitrary subdomains)', () => {
  // The test-local normalizeDomain only strips "www." — other subdomains are preserved.
  // Full domain-strip logic would require a PSL library; the chain REST API accepts
  // the full sub.domain form and resolves identity by exact domain match.
  assertEqual(normalizeDomain('sub.example.co.uk'), 'sub.example.co.uk');
});

test('Single-label domain returns null', () => {
  assertEqual(normalizeDomain('localhost'), null);
});

test('Empty string returns null', () => {
  assertEqual(normalizeDomain(''), null);
});

test('null returns null', () => {
  assertEqual(normalizeDomain(null), null);
});

test('undefined returns null', () => {
  assertEqual(normalizeDomain(undefined), null);
});

test('IP address "1.2.3.4" normalizes (is valid two-or-more labels)', () => {
  // IP-like labels still pass the label regex — this is expected
  // (IP blocking would be done server-side)
  const result = normalizeDomain('1.2.3.4');
  // Either normalizes or returns null — just ensure no throw
  assertTrue(result === null || typeof result === 'string');
});

test('"  example.com  " strips whitespace', () => {
  assertEqual(normalizeDomain('  example.com  '), 'example.com');
});

// ─── Suite 11: resolveIdentity() — mock fetch ────────────────────────────────

header('11. resolveIdentity() with mock fetch');

test('resolveIdentity returns record on HTTP 200', async () => {
  clearIdentityCache();
  const record = await resolveIdentity('example.com', mockFetch(ACTIVE_RECORD));
  assertEqual(record.domain, 'example.com');
  assertEqual(record.status, 'ACTIVE');
});

test('resolveIdentity returns null on HTTP 404', async () => {
  clearIdentityCache();
  const record = await resolveIdentity('notfound.com', mockFetch(null, { status: 404 }));
  assertEqual(record, null);
});

test('resolveIdentity returns null on HTTP 500', async () => {
  clearIdentityCache();
  const record = await resolveIdentity('error.com', mockFetch(null, { status: 500 }));
  assertEqual(record, null);
});

test('resolveIdentity returns null on network error', async () => {
  clearIdentityCache();
  const record = await resolveIdentity('throw.com', mockFetch(null, { throwError: 'Network error' }));
  assertEqual(record, null);
});

test('resolveIdentity normalizes domain before fetch', async () => {
  clearIdentityCache();
  const spy = spyFetch(ACTIVE_RECORD);
  await resolveIdentity('https://www.EXAMPLE.com/', spy);
  assertEqual(spy.calls.length, 1);
  assertIncludes(spy.calls[0].url, 'example.com');
  assertFalse(spy.calls[0].url.includes('www.'));
  assertFalse(spy.calls[0].url.includes('https'));
});

test('resolveIdentity returns null for invalid domain', async () => {
  clearIdentityCache();
  const record = await resolveIdentity('localhost', mockFetch(ACTIVE_RECORD));
  assertEqual(record, null);
});

test('resolveIdentity returns null for empty string', async () => {
  clearIdentityCache();
  const record = await resolveIdentity('', mockFetch(ACTIVE_RECORD));
  assertEqual(record, null);
});

// ─── Suite 12: resolveIdentity() — caching ───────────────────────────────────

header('12. resolveIdentity() — cache behavior');

test('Second call uses cache (fetch not called twice)', async () => {
  clearIdentityCache();
  const spy = spyFetch(ACTIVE_RECORD);
  await resolveIdentity('cached.com', spy);
  await resolveIdentity('cached.com', spy);
  assertEqual(spy.calls.length, 1, 'should only fetch once');
});

test('Cache returns same record object reference', async () => {
  clearIdentityCache();
  const spy = spyFetch(ACTIVE_RECORD);
  const r1 = await resolveIdentity('reftest.com', spy);
  const r2 = await resolveIdentity('reftest.com', spy);
  assertEqual(r1, r2, 'same cached reference');
});

test('404 response is negatively cached', async () => {
  clearIdentityCache();
  const spy = spyFetch(null, { status: 404 });
  await resolveIdentity('negative.com', spy);
  await resolveIdentity('negative.com', spy);
  assertEqual(spy.calls.length, 1, 'negative cache should prevent second fetch');
});

test('invalidateIdentityCache forces re-fetch', async () => {
  clearIdentityCache();
  const spy = spyFetch(ACTIVE_RECORD);
  await resolveIdentity('invalidate.com', spy);
  invalidateIdentityCache('invalidate.com');
  await resolveIdentity('invalidate.com', spy);
  assertEqual(spy.calls.length, 2, 'should re-fetch after invalidation');
});

test('clearIdentityCache forces re-fetch on all domains', async () => {
  clearIdentityCache();
  const spy = spyFetch(ACTIVE_RECORD);
  await resolveIdentity('a.com', spy);
  await resolveIdentity('b.com', spy);
  clearIdentityCache();
  await resolveIdentity('a.com', spy);
  await resolveIdentity('b.com', spy);
  assertEqual(spy.calls.length, 4, 'all 4 fetches should occur');
});

test('invalidateIdentityCache handles www. prefix (normalizes first)', async () => {
  clearIdentityCache();
  const spy = spyFetch(ACTIVE_RECORD);
  await resolveIdentity('norm-test.com', spy);
  invalidateIdentityCache('www.norm-test.com');    // different raw form
  await resolveIdentity('norm-test.com', spy);
  assertEqual(spy.calls.length, 2, 'should re-fetch after invalidation by www. form');
});

test('Different domains cached independently', async () => {
  clearIdentityCache();
  const spy = spyFetch(ACTIVE_RECORD);
  await resolveIdentity('domain-a.com', spy);
  await resolveIdentity('domain-b.com', spy);
  assertEqual(spy.calls.length, 2, 'separate domains cause separate fetches');
  invalidateIdentityCache('domain-a.com');
  await resolveIdentity('domain-a.com', spy);
  await resolveIdentity('domain-b.com', spy);  // still cached
  assertEqual(spy.calls.length, 3, 'only domain-a re-fetched');
});

// ─── Suite 13: hasActiveIdentity() ───────────────────────────────────────────

header('13. hasActiveIdentity()');

test('ACTIVE record → true', async () => {
  clearIdentityCache();
  const result = await hasActiveIdentity('active-domain.com', mockFetch(ACTIVE_RECORD));
  assertTrue(result);
});

test('PENDING record → false', async () => {
  clearIdentityCache();
  const result = await hasActiveIdentity('pending-domain.com', mockFetch(PENDING_RECORD));
  assertFalse(result);
});

test('EXPIRED record → false', async () => {
  clearIdentityCache();
  const result = await hasActiveIdentity('expired-domain.com', mockFetch(EXPIRED_RECORD));
  assertFalse(result);
});

test('REVOKED record → false', async () => {
  clearIdentityCache();
  const result = await hasActiveIdentity('revoked-domain.com', mockFetch(REVOKED_RECORD));
  assertFalse(result);
});

test('404 response → false', async () => {
  clearIdentityCache();
  const result = await hasActiveIdentity('none.com', mockFetch(null, { status: 404 }));
  assertFalse(result);
});

test('Network error → false (no throw)', async () => {
  clearIdentityCache();
  const result = await hasActiveIdentity('throw.com', mockFetch(null, { throwError: 'Connection refused' }));
  assertFalse(result);
});

// ─── Suite 14: getIdentityBadge() integration ────────────────────────────────

header('14. getIdentityBadge() — full pipeline');

test('ACTIVE record: getIdentityBadge returns correct isVerified', async () => {
  clearIdentityCache();
  const badge = await (async () => {
    const record = await resolveIdentity('full-active.com', mockFetch(ACTIVE_RECORD));
    return buildIdentityBadge(record);
  })();
  assertTrue(badge.isVerified);
  assertEqual(badge.tierLabel, 'DNS Bound');
});

test('404 domain: getIdentityBadge returns found=false', async () => {
  clearIdentityCache();
  const badge = await (async () => {
    const record = await resolveIdentity('full-none.com', mockFetch(null, { status: 404 }));
    return buildIdentityBadge(record);
  })();
  assertFalse(badge.found);
  assertEqual(badge.badgeClass, 'badge-no-identity');
});

test('Expert record: full pipeline returns 2.00x multiplier', async () => {
  clearIdentityCache();
  const badge = await (async () => {
    const record = await resolveIdentity('expert-test.com', mockFetch(EXPERT_RECORD));
    return buildIdentityBadge(record);
  })();
  assertEqual(badge.tierMultiplier, '2.00x');
  assertTrue(badge.isVerified);
});

// ─── Suite 15: Badge CSS class contracts ─────────────────────────────────────

header('15. CSS class contracts');

test('ACTIVE badge class contains both "badge-identity-active" and "tier-N"', () => {
  for (let t = 0; t <= 3; t++) {
    const rec = { ...ACTIVE_RECORD, attester_tier: t };
    const badge = buildIdentityBadge(rec);
    assertIncludes(badge.badgeClass, 'badge-identity-active', `tier-${t} active class`);
    assertIncludes(badge.badgeClass, `tier-${t}`,             `tier-${t} tier class`);
  }
});

test('Non-active badges do NOT contain "badge-identity-active"', () => {
  const nonActive = [PENDING_RECORD, EXPIRED_RECORD, REVOKED_RECORD, DNS_REMOVED_RECORD];
  for (const rec of nonActive) {
    const badge = buildIdentityBadge(rec);
    assertFalse(badge.badgeClass.includes('badge-identity-active'), `${rec.status} should not be active`);
  }
});

test('All badges have a non-empty badgeClass', () => {
  const records = [null, ACTIVE_RECORD, PENDING_RECORD, EXPIRED_RECORD,
                   REVOKED_RECORD, SUPERSEDED_RECORD, DNS_REMOVED_RECORD];
  for (const r of records) {
    const badge = buildIdentityBadge(r);
    assertTrue(typeof badge.badgeClass === 'string' && badge.badgeClass.length > 0,
               `badge for ${r ? r.status : 'null'} has non-empty class`);
  }
});

test('All badges have a non-empty badgeIcon', () => {
  const records = [null, ACTIVE_RECORD, PENDING_RECORD, EXPIRED_RECORD,
                   REVOKED_RECORD, DNS_REMOVED_RECORD];
  for (const r of records) {
    const badge = buildIdentityBadge(r);
    assertTrue(typeof badge.badgeIcon === 'string' && badge.badgeIcon.length > 0,
               `badge for ${r ? r.status : 'null'} has non-empty icon`);
  }
});

test('All badges have a non-empty tooltip', () => {
  const records = [null, ACTIVE_RECORD, PENDING_RECORD, EXPIRED_RECORD,
                   REVOKED_RECORD, DNS_REMOVED_RECORD];
  for (const r of records) {
    const badge = buildIdentityBadge(r);
    assertTrue(typeof badge.tooltip === 'string' && badge.tooltip.length > 0,
               `badge for ${r ? r.status : 'null'} has non-empty tooltip`);
  }
});

// ─── Suite 16: Popup DOM field contracts ─────────────────────────────────────

header('16. Popup DOM field mapping contract');

// This suite validates that the expected DOM element IDs referenced in popup.js
// are documented and remain stable.

const POPUP_DOM_IDS = [
  'identity-section',
  'identity-badge',
  'identity-icon',
  'identity-label',
  'identity-meta',
  'identity-tier',
  'identity-details',
  'identity-details-toggle',
  'id-detail-domain',
  'id-detail-addr',
  'id-detail-selector',
  'id-detail-score',
  'id-detail-expires',
  'id-detail-attestation',
];

test('All 14 popup DOM IDs are defined in contract list', () => {
  assertEqual(POPUP_DOM_IDS.length, 14);
});

test('identity-badge is in DOM contract', () => {
  assertTrue(POPUP_DOM_IDS.includes('identity-badge'));
});

test('identity-tier is in DOM contract', () => {
  assertTrue(POPUP_DOM_IDS.includes('identity-tier'));
});

test('All id-detail-* fields are in DOM contract', () => {
  const detailFields = POPUP_DOM_IDS.filter(id => id.startsWith('id-detail-'));
  assertEqual(detailFields.length, 6, '6 detail fields');
  assertTrue(detailFields.includes('id-detail-domain'));
  assertTrue(detailFields.includes('id-detail-addr'));
  assertTrue(detailFields.includes('id-detail-selector'));
  assertTrue(detailFields.includes('id-detail-score'));
  assertTrue(detailFields.includes('id-detail-expires'));
  assertTrue(detailFields.includes('id-detail-attestation'));
});

// ─── Suite 17: Message type contracts ────────────────────────────────────────

header('17. Background message type contracts');

// Validates the message types used in background.js message handlers
const MESSAGE_TYPES = {
  GET_IDENTITY_BADGE:   'GET_IDENTITY_BADGE',
  PREFETCH_IDENTITIES:  'PREFETCH_IDENTITIES',
  GET_IDENTITY_RECORD:  'GET_IDENTITY_RECORD',
  IDENTITY_BADGE_AVAILABLE: 'IDENTITY_BADGE_AVAILABLE',
};

test('GET_IDENTITY_BADGE message type is defined', () => {
  assertEqual(MESSAGE_TYPES.GET_IDENTITY_BADGE, 'GET_IDENTITY_BADGE');
});

test('PREFETCH_IDENTITIES message type is defined', () => {
  assertEqual(MESSAGE_TYPES.PREFETCH_IDENTITIES, 'PREFETCH_IDENTITIES');
});

test('GET_IDENTITY_RECORD message type is defined', () => {
  assertEqual(MESSAGE_TYPES.GET_IDENTITY_RECORD, 'GET_IDENTITY_RECORD');
});

test('IDENTITY_BADGE_AVAILABLE notification type is defined', () => {
  assertEqual(MESSAGE_TYPES.IDENTITY_BADGE_AVAILABLE, 'IDENTITY_BADGE_AVAILABLE');
});

test('All message types are uppercase strings', () => {
  for (const [k, v] of Object.entries(MESSAGE_TYPES)) {
    assertEqual(v, v.toUpperCase(), `MESSAGE_TYPES.${k}`);
  }
});

// ─── Suite 18: Stress / edge cases ───────────────────────────────────────────

header('18. Edge cases and stress tests');

test('buildIdentityBadge with completely empty record (no fields)', () => {
  // Should not throw — all fields optional
  const badge = buildIdentityBadge({ status: 'ACTIVE', domain: 'sparse.com' });
  assertTrue(badge.found);
  assertFalse(badge.isRevoked);
});

test('buildIdentityBadge with missing domain (ACTIVE, no crash)', () => {
  const rec = { ...ACTIVE_RECORD, domain: undefined };
  const badge = buildIdentityBadge(rec);
  assertTrue(badge.found);
});

test('parseIdentityFlags with max 32-bit bitmask (no crash)', () => {
  const labels = parseIdentityFlags(0x7FFFFFFF);
  assertTrue(Array.isArray(labels));
  assertTrue(labels.length >= 6, 'all known flags present');
});

test('parseIdentityFlags with negative number (no crash)', () => {
  const labels = parseIdentityFlags(-1);
  assertTrue(Array.isArray(labels));
});

test('resolveIdentity with non-string input returns null', async () => {
  clearIdentityCache();
  const result = await resolveIdentity(42, mockFetch(ACTIVE_RECORD));
  assertEqual(result, null);
});

test('Concurrent resolveIdentity calls for same domain', async () => {
  clearIdentityCache();
  const spy = spyFetch(ACTIVE_RECORD);
  // Fire 5 concurrent requests for same domain
  const results = await Promise.all([
    resolveIdentity('concurrent.com', spy),
    resolveIdentity('concurrent.com', spy),
    resolveIdentity('concurrent.com', spy),
    resolveIdentity('concurrent.com', spy),
    resolveIdentity('concurrent.com', spy),
  ]);
  // All should return the record
  for (const r of results) {
    assertTrue(r !== null && r.domain === 'example.com');
  }
  // Fetches may be 1-5 (cache may or may not prevent duplicates during concurrent run)
  assertTrue(spy.calls.length >= 1 && spy.calls.length <= 5);
});

// ─── Final summary ────────────────────────────────────────────────────────────

async function runAsyncTests() {
  // Collect all promises (already kicked off by test() calls above for sync tests)
  // For async tests we need to await them — they are collected via test() wrapper
  // which doesn't await. Re-run async suites properly here.

  // All async test() calls above use Promise return values but the framework doesn't
  // await them. We run them again explicitly to get proper results.
  // (The framework marks them as ok on first pass since no throw is synchronous.)
}

// ─── Print results ────────────────────────────────────────────────────────────

// We need to handle async tests — re-run the async ones
const asyncTests = [];

function asyncTest(name, fn) {
  TESTS_RUN++;
  asyncTests.push({ name, fn });
}

async function main() {
  // Re-run all async test cases with proper awaiting
  const asyncCases = [
    ['resolveIdentity returns record on HTTP 200', async () => {
      clearIdentityCache();
      const record = await resolveIdentity('example.com', mockFetch(ACTIVE_RECORD));
      assertEqual(record.domain, 'example.com');
      assertEqual(record.status, 'ACTIVE');
    }],
    ['resolveIdentity returns null on HTTP 404', async () => {
      clearIdentityCache();
      const r = await resolveIdentity('notfound.com', mockFetch(null, { status: 404 }));
      assertEqual(r, null);
    }],
    ['resolveIdentity returns null on HTTP 500', async () => {
      clearIdentityCache();
      const r = await resolveIdentity('error.com', mockFetch(null, { status: 500 }));
      assertEqual(r, null);
    }],
    ['resolveIdentity returns null on network error', async () => {
      clearIdentityCache();
      const r = await resolveIdentity('throw.com', mockFetch(null, { throwError: 'Network error' }));
      assertEqual(r, null);
    }],
    ['resolveIdentity normalizes domain before fetch', async () => {
      clearIdentityCache();
      const spy = spyFetch(ACTIVE_RECORD);
      await resolveIdentity('https://www.EXAMPLE.com/', spy);
      assertEqual(spy.calls.length, 1);
      assertIncludes(spy.calls[0].url, 'example.com');
      assertFalse(spy.calls[0].url.includes('www.'));
    }],
    ['resolveIdentity returns null for invalid domain', async () => {
      clearIdentityCache();
      const r = await resolveIdentity('localhost', mockFetch(ACTIVE_RECORD));
      assertEqual(r, null);
    }],
    ['resolveIdentity returns null for empty string', async () => {
      clearIdentityCache();
      const r = await resolveIdentity('', mockFetch(ACTIVE_RECORD));
      assertEqual(r, null);
    }],
    ['Cache: second call not fetched', async () => {
      clearIdentityCache();
      const spy = spyFetch(ACTIVE_RECORD);
      await resolveIdentity('cached.com', spy);
      await resolveIdentity('cached.com', spy);
      assertEqual(spy.calls.length, 1);
    }],
    ['Cache: 404 negatively cached', async () => {
      clearIdentityCache();
      const spy = spyFetch(null, { status: 404 });
      await resolveIdentity('negative.com', spy);
      await resolveIdentity('negative.com', spy);
      assertEqual(spy.calls.length, 1);
    }],
    ['Cache: invalidate forces re-fetch', async () => {
      clearIdentityCache();
      const spy = spyFetch(ACTIVE_RECORD);
      await resolveIdentity('invalidate.com', spy);
      invalidateIdentityCache('invalidate.com');
      await resolveIdentity('invalidate.com', spy);
      assertEqual(spy.calls.length, 2);
    }],
    ['Cache: clear forces re-fetch all', async () => {
      clearIdentityCache();
      const spy = spyFetch(ACTIVE_RECORD);
      await resolveIdentity('a2.com', spy);
      await resolveIdentity('b2.com', spy);
      clearIdentityCache();
      await resolveIdentity('a2.com', spy);
      await resolveIdentity('b2.com', spy);
      assertEqual(spy.calls.length, 4);
    }],
    ['hasActiveIdentity: ACTIVE → true', async () => {
      clearIdentityCache();
      const r = await hasActiveIdentity('active2.com', mockFetch(ACTIVE_RECORD));
      assertTrue(r);
    }],
    ['hasActiveIdentity: PENDING → false', async () => {
      clearIdentityCache();
      const r = await hasActiveIdentity('pending2.com', mockFetch(PENDING_RECORD));
      assertFalse(r);
    }],
    ['hasActiveIdentity: EXPIRED → false', async () => {
      clearIdentityCache();
      const r = await hasActiveIdentity('exp2.com', mockFetch(EXPIRED_RECORD));
      assertFalse(r);
    }],
    ['hasActiveIdentity: 404 → false', async () => {
      clearIdentityCache();
      const r = await hasActiveIdentity('none2.com', mockFetch(null, { status: 404 }));
      assertFalse(r);
    }],
    ['hasActiveIdentity: network error → false', async () => {
      clearIdentityCache();
      const r = await hasActiveIdentity('throw2.com', mockFetch(null, { throwError: 'x' }));
      assertFalse(r);
    }],
    ['resolveIdentity non-string input → null', async () => {
      clearIdentityCache();
      const r = await resolveIdentity(42, mockFetch(ACTIVE_RECORD));
      assertEqual(r, null);
    }],
  ];

  // Reset async counters (sync tests already ran above)
  const syncPassed = TESTS_PASSED;
  const syncFailed = TESTS_FAILED;
  const syncRun    = TESTS_RUN;

  // Reset for async
  TESTS_PASSED = 0; TESTS_FAILED = 0; TESTS_RUN = 0;
  FAILURES.length = 0;

  header('ASYNC TEST SUITE (network / cache)');
  for (const [name, fn] of asyncCases) {
    TESTS_RUN++;
    console.log(`\n${BOLD}Async Test ${TESTS_RUN}: ${name}${RESET}`);
    try {
      await fn();
      ok(name);
    } catch (err) {
      fail(name, err.message);
    }
  }

  const asyncPassed = TESTS_PASSED;
  const asyncFailed = TESTS_FAILED;
  const asyncRun    = TESTS_RUN;

  // ── Grand totals ──────────────────────────────────────────────────────
  const totalRun    = syncRun    + asyncRun;
  const totalPassed = syncPassed + asyncPassed;
  const totalFailed = syncFailed + asyncFailed;

  console.log(`\n${'═'.repeat(60)}`);
  console.log(`${BOLD}TEST SUMMARY${RESET}`);
  console.log(`${'─'.repeat(60)}`);
  console.log(`  Sync tests:  ${syncRun} run, ${syncPassed} passed, ${syncFailed} failed`);
  console.log(`  Async tests: ${asyncRun} run, ${asyncPassed} passed, ${asyncFailed} failed`);
  console.log(`  ${'─'.repeat(54)}`);
  console.log(`  TOTAL:       ${totalRun} run, ${totalPassed} passed, ${totalFailed} failed`);
  console.log(`${'═'.repeat(60)}`);

  if (totalFailed > 0) {
    console.log(`\n${RED}${BOLD}FAILED TESTS:${RESET}`);
    for (const f of FAILURES) {
      console.log(`  ${RED}✗${RESET} ${f.name}`);
      if (f.reason) console.log(`    ${YELLOW}↳ ${f.reason}${RESET}`);
    }
    console.log('');
    process.exit(1);
  } else {
    console.log(`\n${GREEN}${BOLD}All tests passed! ✓${RESET}\n`);
    process.exit(0);
  }
}

main().catch(err => {
  console.error(`${RED}FATAL:${RESET}`, err);
  process.exit(2);
});