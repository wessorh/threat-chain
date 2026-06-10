# ThreatAttest Test Suite

This directory contains the integration and unit test suite for the ThreatAttest protocol implementation. The tests cover the `x/identity` Cosmos SDK module, the `x/attestation` attester-domain extension, the compliance tier enforcement system, and the browser extension identity badge module.

---

## Test Files

| File | Language | Runtime Required | What It Tests |
|------|----------|-----------------|---------------|
| `test_identity_module.sh` | Bash + embedded Go | Go 1.21+ | Full `x/identity` module: message validation, lifecycle transitions, CLI structure, genesis, DNS proof computation |
| `test_attester_domain.sh` | Bash + embedded Go | Go 1.21+ | `attester_domain`/`attester_selector` fields on `MsgPublishAttestation`; tier-scaled confidence math |
| `test_compliance_tiers.sh` | Bash + embedded Go | Go 1.21+ | Compliance tier multipliers, `WeightedConfidence`, `TierRequirementsMet`, category enforcement policy |
| `test_extension_badges.js` | Node.js | Node.js 18+ | Browser extension `dns_identity.js` pure functions, badge building, cache behavior, mock-fetch async flows |

---

## Quick Start

### Run all tests

```bash
cd threatattest

# Shell / Go tests (no running node required)
bash tests/test_identity_module.sh
bash tests/test_attester_domain.sh
bash tests/test_compliance_tiers.sh

# Node.js extension tests
node tests/test_extension_badges.js
```

### Run against a live chain node

Set the `BINARY` and `NODE` environment variables before running shell tests:

```bash
export BINARY=./build/threatattestd
export NODE=http://localhost:26657
bash tests/test_identity_module.sh
```

If `BINARY` is not set, shell tests fall back to structural/offline checks only (no node required).

---

## Test Descriptions

### `test_identity_module.sh`

Tests the `x/identity` Cosmos SDK module end-to-end, covering:

**Message Validation**
- `MsgRegisterIdentity` — domain normalization, selector validation, pubkey hex length, proof signature presence, TTL range, timestamp skew (±5 min), optional name/URI
- `MsgRotateIdentityKey` — dual-signature fields, selector change requirements
- `MsgRevokeIdentity` — reason string, authority check
- `MsgRenewIdentity` — evidence bundle structure, domain consistency

**Lifecycle Transitions**
- `PENDING → ACTIVE` on successful DNS verification
- `ACTIVE → EXPIRED` on TTL expiry (EndBlocker sweep)
- `ACTIVE → REVOKED` via `MsgRevokeIdentity`
- `ACTIVE → DNS_REMOVED` when TAT TXT records disappear
- `ACTIVE → SUPERSEDED` on key rotation

**CLI Structure**
- `tx identity register-identity` — all required flags present
- `tx identity rotate-identity-key` — rotation flags present
- `tx identity revoke-identity` — reason flag
- `tx identity renew-identity` — evidence-file flag
- `query identity identity` — address query
- `query identity identity-by-domain` — domain query
- `query identity trust-score` — RS output
- `query identity tier` — tier + multiplier output
- `query identity params` — governance parameters
- `query identity verify-domain-proof` — local off-chain proof computation

**Domain Proof Computation**
- SHA-256 pre-image: `tatkey-domain-proof|domain|selector|cosmosAddr|registeredAt`
- Identity ID: SHA-256(`addr|domain|registeredAt`)
- TAT key FQDN: `{selector}._tatkey.{domain}.`
- TAT proof FQDN: `{selector}._tatproof.{domain}.`
- TAT active selector FQDN: `_tatactive.{domain}.`

**DNSSEC Validation**
- Algorithm allow-list (RSASHA1/5 blocked)
- TAT TXT record format: `v=TAT1 cosmos=... pubkey=... ts=...`
- Evidence bundle freshness check (1h max)

**KV Store Key Prefixes**
- All 7 prefixes (0x00–0x05, 0x10) verified in `keys.go`

**Genesis**
- Default state has empty records slice, valid params
- `InitGenesis`/`ExportGenesis` round-trip

---

### `test_attester_domain.sh`

Tests the `attester_domain`/`attester_selector` extension to `x/attestation`:

**Field Presence**
- `AttesterDomain` and `AttesterSelector` fields exist on `AttestationRecord`
- `AttestationRecord.AttesterTier` (int32) field present
- `MsgPublishAttestation` carries `attester_domain`/`attester_selector`
- Fields are `omitempty` (absent if empty)

**CLI Flags**
- `--attester-domain` flag registered on `publish-attestation` command
- `--attester-selector` flag registered on `publish-attestation` command
- Both flags are optional (no error when omitted)

**Mutual Requirement Validation**
- `attester_domain` present without `attester_selector` → `ErrInvalidAttesterDomain`
- `attester_selector` present without `attester_domain` → `ErrInvalidAttesterDomain`
- Both present together → passes validation
- Both absent → passes validation

**Domain Normalization**
- `https://www.example.com` normalizes to `example.com` before validation
- `EXAMPLE.COM` lowercased
- Trailing dot stripped
- Selector length validated ≤ 63 chars

**Tier-Scaled Confidence Math (embedded Go)**
- Tier 0 (Anonymous): raw × 1/4 — e.g. confidence 80 → 20
- Tier 1 (Staked): raw × 2/4 — e.g. confidence 80 → 40
- Tier 2 (DNS Bound): raw × 4/4 — e.g. confidence 80 → 80
- Tier 3 (Expert): raw × 8/4 — e.g. confidence 80 → 160 → clamped to 100
- Clamping: result always ≤ 100
- Zero input always yields 0 output regardless of tier

**Integration (requires live node)**
- Publish attestation with domain+selector, verify record fields
- Verify `attester_tier` stored in record matches chain identity lookup

---

### `test_compliance_tiers.sh`

Tests the compliance tier enforcement system in `x/identity/types/compliance.go` and `x/identity/keeper/compliance.go`:

**Tier Multiplier Correctness (embedded Go)**

| Tier | Label | Expected Numerator | Multiplier |
|------|-------|-------------------|------------|
| 0    | Anonymous | 1 | 0.25× |
| 1    | Staked    | 2 | 0.50× |
| 2    | DNS Bound | 4 | 1.00× |
| 3    | Expert    | 8 | 2.00× |

**WeightedConfidence**
- Tier 0, raw 80 → 20
- Tier 1, raw 80 → 40
- Tier 2, raw 80 → 80
- Tier 3, raw 80 → 100 (clamped, raw result would be 160)
- Tier 3, raw 50 → 100 (clamped)
- Tier 0, raw 0 → 0
- Tier 2, raw 100 → 100

**TierRequirementsMet**
- Exact match: tier 2 meets requirement 2 → true
- Exceeds: tier 3 meets requirement 2 → true
- Below: tier 1 does not meet requirement 2 → false
- All tiers meet requirement 0 → true
- No tier meets requirement 4 (out of range) → false

**CategoryMinimumTiers**
- `malware` category: requires tier 1 (Staked)
- `phishing` category: requires tier 1
- `exploit` category: requires tier 2 (DNS Bound)
- `apt` category: requires tier 3 (Expert)
- `unknown` category: requires tier 0 (no restriction)

**String Representations**
- `ComplianceTier.String()` returns the tier label name

**CLI Tier Queries (requires live node)**
- `query identity tier {address}` returns tier + multiplier
- `query identity params` shows governance parameters

---

### `test_extension_badges.js`

Tests the browser extension `dns_identity.js` module in Node.js using inline copies of the pure functions and a mock `fetch` implementation:

**Constants Validation**
- `IdentityStatus` — 6 values, all uppercase strings
- `ComplianceTiers` — tiers 0–3, correct multipliers, labels, icons, CSS classes
- `IdentityFlags` — 6 bitmask values, all powers of 2, distinct

**`parseIdentityFlags()`**
- Zero/undefined → empty array
- Each individual flag → single-element array
- Combined flags → multiple labels, deterministic order (EXPERT first)
- All-flags combined → all 6 labels

**`buildIdentityBadge(null)`**
- `found=false`, `record=null`
- `badgeClass='badge-no-identity'`
- `isVerified=false`, `isExpired=false`, `isRevoked=false`
- Tier defaults to Anonymous / 0.25×

**`buildIdentityBadge(ACTIVE)`**
- `found=true`, `isVerified=true`
- `badgeClass` contains `badge-identity-active` and `tier-N`
- `badgeLabel` contains `✓` and identity name
- Tooltip contains domain, addr prefix, tier label, trust score, flags

**`buildIdentityBadge()` — all non-ACTIVE statuses**
- PENDING → `badge-identity-pending`, `isVerified=false`
- EXPIRED → `badge-identity-expired`, `isExpired=true`
- REVOKED → `badge-identity-revoked`, `isRevoked=true`
- SUPERSEDED → `badge-identity-revoked` (treated as terminal/revoked)
- DNS_REMOVED → `badge-identity-dns-removed`
- Unknown status → `badge-identity-unknown`, status string in label

**Tier edge cases**
- Missing/null `attester_tier` → defaults to Anonymous
- `attester_tier=999` → falls back to Anonymous (unknown tier)
- Tiers 0–3 produce correct label + multiplier + CSS class

**`normalizeDomain()`**
- Strips `https://`, `http://`, `www.`, port, trailing dot, path, query
- Lowercases
- Returns `null` for empty, single-label, `null`, `undefined`

**`resolveIdentity()` with mock fetch**
- HTTP 200 → returns record
- HTTP 404 → returns `null`
- HTTP 500 → returns `null`
- Network error → returns `null` (no throw)
- Normalizes domain before constructing fetch URL
- Invalid domain → returns `null` without fetching

**Cache behavior**
- Positive cache (5 min TTL): second call not fetched
- Negative cache (2 min TTL): 404 responses cached
- `invalidateIdentityCache(domain)` forces re-fetch
- `clearIdentityCache()` clears all entries
- Domains cached independently
- `invalidateIdentityCache` normalizes domain (accepts `www.` prefix)

**`hasActiveIdentity()`**
- ACTIVE record → `true`
- PENDING/EXPIRED/REVOKED records → `false`
- 404 / network error → `false`

**CSS class contracts**
- Active badges always have both `badge-identity-active` and `tier-N`
- Non-active badges never have `badge-identity-active`
- All badges (including `null`) have non-empty `badgeClass`, `badgeIcon`, `tooltip`

**DOM / message contracts**
- 14 popup DOM element IDs documented (stable contract)
- 4 background message types documented

**Edge cases**
- Empty record (no fields) → no crash
- `parseIdentityFlags` with `0x7FFFFFFF` or `-1` → no crash
- Non-string domain input to `resolveIdentity` → `null`
- 5 concurrent `resolveIdentity` calls for same domain → all return record

**Total: 151 tests (134 sync + 17 async)**

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `BINARY` | `threatattestd` | Path to the `threatattestd` binary |
| `NODE` | `http://localhost:26657` | Tendermint RPC endpoint |
| `REST` | `http://localhost:1317` | Cosmos REST API endpoint |
| `CHAIN_ID` | `threatattest-1` | Chain ID for tx signing |
| `KEYRING` | `test` | Keyring backend |

---

## Test Infrastructure

### Shell test framework

All `.sh` test scripts share the same lightweight framework:

```bash
TESTS_RUN=0; TESTS_PASSED=0; TESTS_FAILED=0

ok()     { echo "[PASS] $*"; ((TESTS_PASSED++)); }
fail()   { echo "[FAIL] $*"; ((TESTS_FAILED++)); }
run_test() { ... }  # runs a function, catches non-zero exit
```

Each test function uses standard Bash exit codes: `return 0` = pass, `return 1` = fail.

### Node.js test framework

`test_extension_badges.js` uses a minimal inline framework with:

- `test(name, fn)` — sync tests
- Async tests collected and awaited in `main()`
- `assertEqual`, `assertDeepEqual`, `assertTrue`, `assertFalse`, `assertIncludes` helpers
- `mockFetch(record, opts)` — injectable fetch mock
- `spyFetch(record, opts)` — fetch mock that records call URLs for assertion
- Exit code 0 on all pass, non-zero on any failure

### Embedded Go programs

The shell scripts embed self-contained Go programs in heredocs (written to `mktemp` files) to test pure logic without a running chain node:

```bash
GOTEST=$(mktemp /tmp/test_XXXXX.go)
cat > "$GOTEST" << 'GOEOF'
package main
// ... mirror types + logic from source ...
GOEOF
go run "$GOTEST"
```

This approach validates mathematical correctness of tier multipliers, confidence scaling, bitmask operations, and key encoding without requiring a compiled binary or running node.

---

## Adding New Tests

### Shell tests

1. Create a new `.sh` file following the pattern in existing test scripts
2. Source the framework header (copy from any existing script)
3. Add test functions returning 0/1
4. Call `run_test "Test name" test_function_name`
5. Print summary with `print_summary` at the end

### Node.js tests

1. Add `test('name', () => { ... })` blocks (sync) to `test_extension_badges.js`
2. Add async cases to the `asyncCases` array in `main()`
3. Use `assertEqual`, `assertTrue`, `assertIncludes` for assertions
4. Use `mockFetch`/`spyFetch` for network mocking
5. Call `clearIdentityCache()` at the start of each cache-sensitive test

---

## Coverage Map

```
x/identity/types/
  keys.go          ← test_identity_module.sh  (key prefix constants)
  types.go         ← test_identity_module.sh  (DNSIdentityRecord, ComputeIdentityID,
                                               DomainProofPayload, NormalizeDomain)
  params.go        ← test_identity_module.sh  (DefaultParams, Validate)
  errors.go        ← test_identity_module.sh  (error code presence)
  msgs.go          ← test_identity_module.sh  (ValidateBasic for all 4 messages)
  compliance.go    ← test_compliance_tiers.sh (TierMultiplierNumerator, WeightedConfidence,
                                               TierRequirementsMet, DefaultTierEnforcementPolicy)

x/identity/keeper/
  keeper.go        ← test_identity_module.sh  (CRUD, pending/expiry queue)
  identity.go      ← test_identity_module.sh  (RegisterIdentity, RevokeIdentity, etc.)
  dns_verify.go    ← test_identity_module.sh  (ValidateEvidenceBundle structure)
  trust_score.go   ← test_identity_module.sh  (trust score adjustments)
  compliance.go    ← test_compliance_tiers.sh (ScaleConfidence, EnforceMinTier, TierBreakdown)

x/identity/
  module.go        ← test_identity_module.sh  (AppModule interface compliance)
  genesis.go       ← test_identity_module.sh  (InitGenesis/ExportGenesis)

x/identity/cli/
  tx.go            ← test_identity_module.sh  (CLI flag registration)
  query.go         ← test_identity_module.sh  (CLI query subcommands)

x/attestation/types/types.go  ← test_attester_domain.sh (AttesterDomain/Selector/Tier fields)
x/attestation/msgs/msgs.go    ← test_attester_domain.sh (MsgPublishAttestation fields)
x/attestation/keeper/
  msg_server.go    ← test_attester_domain.sh  (tier lookup + confidence scaling)

threatattest-extension/src/
  dns_identity.js  ← test_extension_badges.js (all exported functions + cache)
  background.js    ← test_extension_badges.js (message type contracts)
  popup.js         ← test_extension_badges.js (DOM ID contracts)
```

---

## Known Limitations

**Stub implementations** — Several functions are structural stubs pending production wiring:

| Function | File | Notes |
|----------|------|-------|
| `ValidateDNSSECChain()` | `keeper/dns_verify.go` | Requires live DNSSEC resolver library |
| `verifySecp256k1Sig()` | `keeper/identity.go` | Requires secp256k1 signature verification library |
| `identityTier()` | `attestation/keeper/msg_server.go` | Requires `x/identity` keeper injection |

Tests exercise the *structural interface* of these stubs. Full cryptographic validation requires integration with a live chain node and real DNS infrastructure.

**Browser extension tests** — `test_extension_badges.js` tests pure JS logic only. End-to-end popup rendering tests require a real Chrome extension environment (e.g. Puppeteer + Chrome with extension loaded) and are outside the scope of this suite.

**Chain integration tests** — Shell tests that require a live node are guarded by `BINARY` / `NODE` checks and are skipped automatically in offline environments.