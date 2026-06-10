#!/usr/bin/env node
// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.
/**
 * scripts/pack.js — Package the built extension into a .zip for distribution
 *
 * Must be run after scripts/build.js (requires dist/ to exist).
 *
 * Usage:
 *   node scripts/pack.js           # → build/threatattest-shield-<version>.zip
 *   node scripts/pack.js --dev     # → build/threatattest-shield-<version>-dev.zip
 *
 * The resulting zip is suitable for:
 *   - Chrome Web Store submission (production)
 *   - Manual load-unpacked in Chrome/Edge (either mode)
 *   - Firefox Add-ons submission (production)
 */

'use strict';

const fs          = require('fs');
const path        = require('path');
const { execSync } = require('child_process');

const ROOT    = path.resolve(__dirname, '..');
const DIST    = path.join(ROOT, 'dist');
const BUILD   = path.join(ROOT, 'build');
const IS_DEV  = process.argv.includes('--dev');

const green  = s => `\x1b[32m${s}\x1b[0m`;
const cyan   = s => `\x1b[36m${s}\x1b[0m`;
const yellow = s => `\x1b[33m${s}\x1b[0m`;
const bold   = s => `\x1b[1m${s}\x1b[0m`;
const red    = s => `\x1b[31m${s}\x1b[0m`;

// ─── Validate dist exists ────────────────────────────────────────────────────
if (!fs.existsSync(DIST)) {
  console.error(red('ERROR: dist/ not found — run: node scripts/build.js first'));
  process.exit(1);
}

// ─── Read version ────────────────────────────────────────────────────────────
let version = '0.0.0';
try {
  const vf = JSON.parse(fs.readFileSync(path.join(DIST, 'version.json'), 'utf8'));
  version = vf.version || version;
} catch {
  try {
    const mf = JSON.parse(fs.readFileSync(path.join(DIST, 'manifest.json'), 'utf8'));
    version = mf.version || version;
  } catch { /* keep default */ }
}

const suffix   = IS_DEV ? `-dev` : '';
const zipName  = `threatattest-shield-${version}${suffix}.zip`;
const zipPath  = path.join(BUILD, zipName);

console.log('');
console.log(bold(cyan('ThreatAttest Shield Extension Pack')));
console.log(`  Version : ${version}`);
console.log(`  Mode    : ${IS_DEV ? yellow('development') : green('production')}`);
console.log(`  Output  : ${zipPath}`);
console.log('');

// ─── Create build dir ────────────────────────────────────────────────────────
fs.mkdirSync(BUILD, { recursive: true });

// Remove existing zip if present
if (fs.existsSync(zipPath)) {
  fs.rmSync(zipPath);
}

// ─── Create zip ──────────────────────────────────────────────────────────────
// We use the system zip command (available on Linux/macOS).
// On Windows you would use PowerShell Compress-Archive or a Node zip library.
try {
  execSync(`zip -r "${zipPath}" .`, { cwd: DIST, stdio: 'pipe' });
} catch (err) {
  console.error(red(`ERROR: zip failed: ${err.message}`));
  process.exit(1);
}

// ─── File list + checksum ─────────────────────────────────────────────────────
console.log('Packed files:');
const listing = execSync(`zip -l "${zipPath}"`, { encoding: 'utf8' });
listing.split('\n').slice(3, -3).forEach(line => {
  const trimmed = line.trim();
  if (trimmed) console.log(`  ${trimmed}`);
});

// Write sha256
try {
  const checksum = execSync(`sha256sum "${zipPath}"`, { encoding: 'utf8', cwd: BUILD });
  fs.writeFileSync(zipPath + '.sha256', checksum.trim(), 'utf8');
  console.log(`\n  ${green('✓')} SHA256: ${checksum.split(' ')[0]}`);
} catch { /* sha256sum may not be available on all platforms */ }

const stats = fs.statSync(zipPath);
const sizeKb = (stats.size / 1024).toFixed(1);

console.log('');
console.log(`${green('✓')} Packed → ${zipPath} (${sizeKb} KB)`);
console.log('');
console.log('Load unpacked in Chrome:');
console.log(`  1. Extract ${zipName} to a folder`);
console.log('  2. chrome://extensions → Enable Developer mode');
console.log('  3. Load unpacked → select extracted folder');
console.log('');