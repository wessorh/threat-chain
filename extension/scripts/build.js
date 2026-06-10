#!/usr/bin/env node
// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.
/**
 * scripts/build.js — Extension build script
 *
 * Copies extension source files into dist/, optionally patching for
 * development (local API endpoint) vs production (mainnet endpoint).
 *
 * Usage:
 *   node scripts/build.js          # production build → dist/
 *   node scripts/build.js --dev    # dev build with local API endpoint
 */

'use strict';

const fs   = require('fs');
const path = require('path');

// ─── Config ──────────────────────────────────────────────────────────────────

const ROOT    = path.resolve(__dirname, '..');
const DIST    = path.join(ROOT, 'dist');
const IS_DEV  = process.argv.includes('--dev');

const API_PROD  = 'https://api.threatattest.io';
const API_LOCAL = 'http://localhost:1317';

// Files/dirs to copy verbatim
const COPY_ITEMS = [
  'manifest.json',
  'popup.html',
  'popup.js',
  'options.html',
  'threat-popup.html',
  'icons',
  'src/content.js',
];

// JS source files that need API endpoint substitution
const PATCH_JS = [
  'src/api.js',
  'src/background.js',
  'src/dns_identity.js',
];

// ─── Helpers ─────────────────────────────────────────────────────────────────

const green  = s => `\x1b[32m${s}\x1b[0m`;
const cyan   = s => `\x1b[36m${s}\x1b[0m`;
const yellow = s => `\x1b[33m${s}\x1b[0m`;
const bold   = s => `\x1b[1m${s}\x1b[0m`;

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

function copyItem(src, destDir) {
  const srcPath  = path.join(ROOT, src);
  const destPath = path.join(destDir, src);

  if (!fs.existsSync(srcPath)) {
    console.warn(yellow(`  ⚠  skipping (not found): ${src}`));
    return;
  }

  const stat = fs.statSync(srcPath);
  if (stat.isDirectory()) {
    copyDir(srcPath, path.join(destDir, src));
  } else {
    ensureDir(path.dirname(destPath));
    fs.copyFileSync(srcPath, destPath);
    console.log(`  ${green('✓')} ${src}`);
  }
}

function copyDir(src, dest) {
  ensureDir(dest);
  for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
    const srcEntry  = path.join(src, entry.name);
    const destEntry = path.join(dest, entry.name);
    if (entry.isDirectory()) {
      copyDir(srcEntry, destEntry);
    } else {
      fs.copyFileSync(srcEntry, destEntry);
    }
  }
  console.log(`  ${green('✓')} ${path.relative(ROOT, dest)}/`);
}

function patchJs(src, destDir) {
  const srcPath  = path.join(ROOT, src);
  const destPath = path.join(destDir, src);

  if (!fs.existsSync(srcPath)) {
    console.warn(yellow(`  ⚠  skipping patch (not found): ${src}`));
    return;
  }

  ensureDir(path.dirname(destPath));
  let content = fs.readFileSync(srcPath, 'utf8');

  if (IS_DEV) {
    // Replace prod API URL with local
    content = content.replace(
      new RegExp(escapeRegex(API_PROD), 'g'),
      API_LOCAL,
    );
    // Also catch any hardcoded localhost:1317 (keep as-is)
    console.log(`  ${green('✓')} ${src} ${yellow('[DEV: API→localhost]')}`);
  } else {
    // Ensure prod URL is set (in case of leftover local refs in source)
    content = content.replace(
      /http:\/\/localhost:\d+/g,
      API_PROD,
    );
    console.log(`  ${green('✓')} ${src}`);
  }

  fs.writeFileSync(destPath, content, 'utf8');
}

function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function patchManifest(destDir) {
  const dest = path.join(destDir, 'manifest.json');
  const m    = JSON.parse(fs.readFileSync(dest, 'utf8'));

  if (IS_DEV) {
    m.name        = m.name + ' (Dev)';
    m.description = '[DEV] ' + m.description;
  }

  // Stamp build metadata
  m._build_mode = IS_DEV ? 'development' : 'production';
  m._build_time = new Date().toISOString();

  fs.writeFileSync(dest, JSON.stringify(m, null, 2), 'utf8');
  console.log(`  ${green('✓')} manifest.json (patched)`);
}

function writeVersionFile(destDir) {
  // Read version from package.json
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
  const versionInfo = {
    version:    pkg.version,
    build_mode: IS_DEV ? 'development' : 'production',
    build_time: new Date().toISOString(),
  };
  fs.writeFileSync(
    path.join(destDir, 'version.json'),
    JSON.stringify(versionInfo, null, 2),
    'utf8',
  );
  console.log(`  ${green('✓')} version.json`);
}

// ─── Main ────────────────────────────────────────────────────────────────────

console.log('');
console.log(bold(cyan('ThreatAttest Shield Extension Build')));
console.log(`  Mode : ${IS_DEV ? yellow('development') : green('production')}`);
console.log(`  Dest : ${DIST}`);
console.log('');

// Clean dist
if (fs.existsSync(DIST)) {
  fs.rmSync(DIST, { recursive: true });
}
ensureDir(DIST);
ensureDir(path.join(DIST, 'src'));

// Copy static files
console.log('Copying static files...');
for (const item of COPY_ITEMS) {
  copyItem(item, DIST);
}

// Patch JS files with API endpoint
console.log('\nPatching JS source files...');
for (const src of PATCH_JS) {
  patchJs(src, DIST);
}

// Patch manifest
patchManifest(DIST);

// Write version file
writeVersionFile(DIST);

console.log('');
console.log(`${green('✓')} Build complete → ${DIST}`);
console.log('');