#!/usr/bin/env node
// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.
/**
 * scripts/validate.js — Validate extension manifest and source file integrity
 *
 * Checks:
 *  1. manifest.json is valid JSON with required MV3 fields
 *  2. All files referenced in manifest actually exist
 *  3. Required source files are present
 *  4. No obvious syntax errors in JS files (via node --check)
 *  5. Extension version matches package.json version
 *
 * Usage:
 *   node scripts/validate.js             # validate source tree
 *   node scripts/validate.js --dist      # validate dist/ build output
 */

'use strict';

const fs           = require('fs');
const path         = require('path');
const { execSync } = require('child_process');

const ROOT     = path.resolve(__dirname, '..');
const IS_DIST  = process.argv.includes('--dist');
const BASE     = IS_DIST ? path.join(ROOT, 'dist') : ROOT;

const green  = s => `\x1b[32m${s}\x1b[0m`;
const red    = s => `\x1b[31m${s}\x1b[0m`;
const yellow = s => `\x1b[33m${s}\x1b[0m`;
const cyan   = s => `\x1b[36m${s}\x1b[0m`;
const bold   = s => `\x1b[1m${s}\x1b[0m`;

let errors   = 0;
let warnings = 0;

function pass(msg)  { console.log(`  ${green('✓')} ${msg}`); }
function fail(msg)  { console.log(`  ${red('✗')} ${msg}`); errors++; }
function warn(msg)  { console.log(`  ${yellow('⚠')} ${msg}`); warnings++; }
function check(msg) { console.log(`\n${bold(cyan('─'))} ${msg}`); }

// ─── 1. manifest.json exists and parses ──────────────────────────────────────
check('manifest.json');

const manifestPath = path.join(BASE, 'manifest.json');
if (!fs.existsSync(manifestPath)) {
  fail(`manifest.json not found at ${manifestPath}`);
  process.exit(1);
}

let manifest;
try {
  manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  pass('manifest.json is valid JSON');
} catch (e) {
  fail(`manifest.json parse error: ${e.message}`);
  process.exit(1);
}

// Required MV3 fields
const requiredFields = ['manifest_version', 'name', 'version', 'description'];
for (const field of requiredFields) {
  if (manifest[field] !== undefined && manifest[field] !== '') {
    pass(`manifest.${field} = ${JSON.stringify(manifest[field])}`);
  } else {
    fail(`manifest.${field} is missing or empty`);
  }
}

// Must be MV3
if (manifest.manifest_version === 3) {
  pass('manifest_version = 3 (MV3)');
} else {
  fail(`manifest_version = ${manifest.manifest_version} (expected 3)`);
}

// Must have background service worker
if (manifest.background?.service_worker) {
  pass(`background.service_worker = ${manifest.background.service_worker}`);
} else {
  fail('background.service_worker is missing (required for MV3)');
}

// ─── 2. Files referenced in manifest exist ────────────────────────────────────
check('Manifest-referenced files');

function checkFile(filePath, context) {
  const full = path.join(BASE, filePath);
  if (fs.existsSync(full)) {
    pass(`${filePath}  (${context})`);
  } else {
    fail(`${filePath} not found  (${context})`);
  }
}

// Service worker
if (manifest.background?.service_worker) {
  checkFile(manifest.background.service_worker, 'background.service_worker');
}

// Action popup + icons
if (manifest.action?.default_popup) {
  checkFile(manifest.action.default_popup, 'action.default_popup');
}
if (manifest.action?.default_icon) {
  for (const [size, p] of Object.entries(manifest.action.default_icon)) {
    checkFile(p, `action.default_icon[${size}]`);
  }
}

// Content scripts
for (const cs of (manifest.content_scripts || [])) {
  for (const js of (cs.js || [])) {
    checkFile(js, 'content_scripts.js');
  }
  for (const css of (cs.css || [])) {
    checkFile(css, 'content_scripts.css');
  }
}

// Options page
if (manifest.options_page) {
  checkFile(manifest.options_page, 'options_page');
}

// Web accessible resources
for (const war of (manifest.web_accessible_resources || [])) {
  for (const r of (war.resources || [])) {
    if (!r.includes('*')) {
      checkFile(r, 'web_accessible_resources');
    }
  }
}

// Top-level icons
if (manifest.icons) {
  for (const [size, p] of Object.entries(manifest.icons)) {
    checkFile(p, `icons[${size}]`);
  }
}

// ─── 3. Required source files ────────────────────────────────────────────────
check('Required source files');

const requiredSources = [
  'src/api.js',
  'src/background.js',
  'src/content.js',
  'src/dns_identity.js',
  'popup.html',
  'popup.js',
  'options.html',
];

for (const src of requiredSources) {
  const full = path.join(BASE, src);
  if (fs.existsSync(full)) {
    pass(src);
  } else {
    fail(`${src} missing`);
  }
}

// ─── 4. JS syntax check ──────────────────────────────────────────────────────
check('JS syntax (node --check)');

const jsFiles = [
  'src/api.js',
  'src/background.js',
  'src/content.js',
  'src/dns_identity.js',
  'popup.js',
];

for (const jsFile of jsFiles) {
  const full = path.join(BASE, jsFile);
  if (!fs.existsSync(full)) {
    warn(`Skipping syntax check (not found): ${jsFile}`);
    continue;
  }

  try {
    // node --check is syntax-only, no execution
    execSync(`node --check "${full}"`, { stdio: 'pipe' });
    pass(`${jsFile} — syntax OK`);
  } catch (err) {
    fail(`${jsFile} — syntax error: ${err.stderr?.toString()?.trim() || err.message}`);
  }
}

// ─── 5. Version consistency ────────────────────────────────────────────────
check('Version consistency');

let pkgVersion = null;
const pkgPath = path.join(ROOT, 'package.json');
if (fs.existsSync(pkgPath)) {
  try {
    pkgVersion = JSON.parse(fs.readFileSync(pkgPath, 'utf8')).version;
  } catch { /* ignore */ }
}

if (pkgVersion && manifest.version) {
  if (pkgVersion === manifest.version) {
    pass(`package.json version === manifest.json version (${pkgVersion})`);
  } else {
    warn(`Version mismatch: package.json=${pkgVersion}, manifest.json=${manifest.version}`);
  }
} else {
  warn('Could not compare versions (one or both missing)');
}

// ─── 6. dns_identity.js exports check ────────────────────────────────────────
check('dns_identity.js exports');

const dnsIdPath = path.join(BASE, 'src/dns_identity.js');
if (fs.existsSync(dnsIdPath)) {
  const src = fs.readFileSync(dnsIdPath, 'utf8');
  const requiredExports = [
    'resolveIdentity',
    'hasActiveIdentity',
    'prefetchIdentities',
    'invalidateIdentityCache',
    'clearIdentityCache',
    'buildIdentityBadge',
    'getIdentityBadge',
    'parseIdentityFlags',
    'IdentityStatus',
    'ComplianceTiers',
    'IdentityFlags',
  ];
  for (const exp of requiredExports) {
    if (src.includes(`export`) && src.includes(exp)) {
      pass(`export: ${exp}`);
    } else {
      warn(`export may be missing: ${exp}`);
    }
  }
} else {
  warn('dns_identity.js not found — skipping export check');
}

// ─── Summary ─────────────────────────────────────────────────────────────────
console.log('');
console.log('═'.repeat(50));
console.log(`  Errors   : ${errors > 0 ? red(errors) : green(errors)}`);
console.log(`  Warnings : ${warnings > 0 ? yellow(warnings) : green(warnings)}`);
console.log('═'.repeat(50));
console.log('');

if (errors > 0) {
  console.log(red(`✗ Validation FAILED (${errors} error${errors !== 1 ? 's' : ''})`));
  process.exit(1);
} else if (warnings > 0) {
  console.log(yellow(`⚠ Validation passed with ${warnings} warning${warnings !== 1 ? 's' : ''}`));
} else {
  console.log(green('✓ Validation passed'));
}
console.log('');