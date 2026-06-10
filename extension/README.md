# ThreatAttest Shield — Browser Extension

A Manifest V3 browser extension for **Brave** (and Chrome) that provides real-time threat intelligence by querying the **ThreatAttest blockchain** for every file you download, every domain you browse, and every IP address contacted by pages you visit.

---

## Features

| Feature | Description |
|---------|-------------|
| 📄 **Download Scanning** | Every completed download is SHA-256 hashed and checked against on-chain `FILE` attestations |
| 🌐 **Domain/URL Checking** | Every navigated URL is normalized and queried against on-chain `URL` attestations |
| 📡 **IP Address Checking** | IP addresses found in page resources are checked against on-chain `IPV4` attestations |
| ⚠️ **Threat Overlays** | An inline warning banner is injected into pages with active threats — with Block / Allow / Detail buttons |
| 🚫 **Download Popups** | A dedicated popup window asks Block / Allow / Snooze for dangerous downloads |
| 🔴 **Auto-block** | CRITICAL (and optionally HIGH) severity threats are blocked automatically |
| 🔔 **Notifications** | Desktop notifications for detected threats |
| 🔍 **Manual Check** | Check any URL, IPv4, or SHA-256 hash manually from the toolbar popup |
| ⚙️ **Options Page** | Configure node URL, severity thresholds, whitelists, auto-block rules |

---

## Installation (Brave / Chrome — Developer Mode)

### Prerequisites
- A running **ThreatAttest node** with the REST endpoint exposed (default: `http://localhost:1317`)
- Brave Browser (or any Chromium-based browser)

### Steps

1. **Download or clone** this extension directory.

2. Open Brave and navigate to:
   ```
   brave://extensions
   ```
   (or `chrome://extensions` in Chrome)

3. Enable **Developer mode** (toggle in the top-right corner).

4. Click **"Load unpacked"**.

5. Select the `threatattest-extension/` directory.

6. The **ThreatAttest Shield** extension will appear with the 🛡️ icon in your toolbar.

7. Click the toolbar icon → **⚙️ Settings** → enter your node URL and click **Save**.

---

## Quick Start

### 1. Start your ThreatAttest node

```bash
cd threatattest
./bin/threatattestd start --home .threatattestd
```

The REST API will be available at `http://localhost:1317`.

### 2. Configure the extension

Click the 🛡️ toolbar icon → ⚙️ → set **Node URL** to `http://localhost:1317` → **Test** → **Save**.

The status dot in the popup turns **green** when the node is reachable.

### 3. Browse normally

The extension silently checks every page and download in the background:

- **Green badge** = all clear
- **Yellow `!` badge** = MEDIUM threat detected on this tab
- **Red `!!!` badge** = HIGH/CRITICAL threat detected

---

## How It Works

### Download Checking

```
File downloaded
     │
     ▼
Re-fetch download URL → SHA-256 hash
     │
     ▼
GET /threatattest/attestation/v1/is-malicious?artifact_sha256={hex}
     │
     ├── Not found → ✅ Safe
     └── is_malicious: true
              │
              ├── severity=CRITICAL → Auto-cancel + notify
              └── severity<CRITICAL → Show decision popup
                        │
                        ├── 🚫 Block & Delete → cancel + erase download
                        ├── ✅ Allow This Time → proceed
                        ├── ⏱ Snooze 30min → allow temporarily
                        └── 📋 Always Allow → add to whitelist
```

### Domain/URL Checking

```
Navigation to https://example.com/path?q=1
     │
     ▼
Normalize URL (lowercase, sort params, strip fragment)
     │
     ▼
GET /threatattest/attestation/v1/is-malicious-url?url={normalized}
     │
     ├── Not found → ✅ Continue silently
     └── is_malicious: true
              │
              └── Inject warning overlay into page
                        │
                        ├── 🚫 Block Site → replace page content + add to session blocklist
                        ├── ✅ Allow Once → dismiss banner
                        └── View attestation ↗ → open chain REST URL
```

### IP Address Checking

```
Page loads → content script scans:
  - <script src>, <img src>, <link href> hostnames
  - DNS prefetch meta tags
  - PerformanceObserver resource timing entries
  - Dynamically added DOM nodes (MutationObserver)
     │
     ▼
For each IPv4 found (non-reserved):
GET /threatattest/attestation/v1/is-malicious-ipv4?ipv4={ip}
     │
     └── is_malicious: true → inject warning overlay
```

---

## REST API Endpoints Used

| Query | Endpoint |
|-------|----------|
| File SHA-256 | `GET /threatattest/attestation/v1/is-malicious?artifact_sha256={hex}` |
| URL | `GET /threatattest/attestation/v1/is-malicious-url?url={url}` |
| IPv4 | `GET /threatattest/attestation/v1/is-malicious-ipv4?ipv4={ip}` |
| Get attestation | `GET /threatattest/attestation/v1/attestation/{id}` |
| List by artifact | `GET /threatattest/attestation/v1/list-by-artifact?artifact_sha256={hex}` |
| Node info | `GET /cosmos/base/tendermint/v1beta1/node_info` |

---

## Severity Levels

| Level | Color | Auto-block | Popup |
|-------|-------|------------|-------|
| INFO (1) | 🔵 Blue | No | No (notification only) |
| LOW (2) | 🟢 Green | No | No (notification only) |
| MEDIUM (3) | 🟡 Yellow | No | Banner overlay |
| HIGH (4) | 🟠 Orange | Optional | Banner overlay |
| CRITICAL (5) | 🔴 Red | Yes (default) | Download popup |

---

## File Structure

```
threatattest-extension/
├── manifest.json          # MV3 manifest (permissions, entry points)
├── popup.html             # Toolbar popup UI
├── popup.js               # Toolbar popup logic
├── options.html           # Settings page
├── threat-popup.html      # Standalone decision popup (downloads)
├── src/
│   ├── background.js      # Service worker (download + nav monitoring)
│   ├── content.js         # In-page script (IP extraction, overlay)
│   └── api.js             # ThreatAttest chain REST client + cache
└── icons/
    ├── icon16.png
    ├── icon32.png
    ├── icon48.png
    └── icon128.png
```

---

## Settings Reference

| Setting | Default | Description |
|---------|---------|-------------|
| Node URL | `http://localhost:1317` | ThreatAttest REST endpoint |
| Check Downloads | ✅ | Hash + check every downloaded file |
| Check Domains/URLs | ✅ | Check every navigated URL |
| Check IPs | ✅ | Check IP addresses in page resources |
| Auto-block CRITICAL | ✅ | Silently block severity=5 |
| Auto-block HIGH | ❌ | Silently block severity=4 |
| Min Alert Severity | LOW (2) | Threshold for showing overlays/popups |
| Show Notifications | ✅ | Desktop notifications for threats |
| Whitelisted Domains | (empty) | Domains never checked |
| Whitelisted IPs | (empty) | IPs never checked |

---

## Limitations

- **File hashing**: Downloads are re-fetched from their original URL for hashing. Files > 50MB are skipped. Authenticated downloads (requiring cookies/session) may not be re-fetchable.
- **Blocking**: Navigation blocking (cancelling the request before the page loads) is not supported in MV3 for async operations. The threat overlay is injected after page load instead.
- **HTTPS inspection**: The extension only sees the hostname for HTTPS connections, not the full decrypted content of TLS traffic.
- **Local files**: `file://` URLs are not checked (no network activity to intercept).
- **Node required**: All checks require a running ThreatAttest node. If the node is offline, checks are silently skipped.

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Badge shows "OFF" | Check node URL in settings, run `./bin/threatattestd start` |
| No threat overlays | Check "Check Domains" is enabled; check Min Alert Severity setting |
| Downloads not checked | Check "Check Downloads" is enabled; file may be > 50MB |
| Extension not loading | Ensure Developer Mode is on in brave://extensions |
| CORS errors in console | Add `--unsafe-cors` flag when starting the node, or use a proxy |

---

## CORS Configuration

If the node and browser are on the same machine, you may need to start the node with CORS enabled:

```bash
./bin/threatattestd start \
  --home .threatattestd \
  --api.enable \
  --api.enabled-unsafe-cors \
  --api.address tcp://0.0.0.0:1317
```

Or configure `~/.threatattestd/config/app.toml`:
```toml
[api]
enable = true
enabled-unsafe-cors = true
address = "tcp://0.0.0.0:1317"
```
