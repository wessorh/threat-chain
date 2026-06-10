// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

// ============================================================
// ThreatAttest Shield — Content Script
// Runs in every page context (document_start).
// Responsibilities:
//   - Extract IP addresses from DNS prefetch hints, CSP, and resource URLs
//   - Report discovered IPs back to background for chain lookup
//   - Listen for injected overlay messages
// ============================================================

(function () {
  "use strict";

  // Only run in top-level frames
  if (window.self !== window.top) return;

  const PAGE_URL = window.location.href;
  const HOSTNAME = window.location.hostname;

  // ============================================================
  // IPv4 detection regex
  // ============================================================
  const IPV4_RE = /\b(\d{1,3}\.){3}\d{1,3}\b/g;

  // Reserved ranges to skip client-side
  const RESERVED_PREFIXES = [
    "0.", "10.", "127.", "169.254.", "172.16.", "172.17.", "172.18.",
    "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.",
    "172.31.", "192.0.2.", "192.168.", "198.18.", "198.19.", "198.51.100.",
    "203.0.113.", "224.", "225.", "226.", "227.", "228.", "229.", "230.",
    "231.", "232.", "233.", "234.", "235.", "236.", "237.", "238.", "239.",
    "240.", "255.",
  ];

  function isReserved(ip) {
    return RESERVED_PREFIXES.some(pfx => ip.startsWith(pfx));
  }

  // ============================================================
  // Collect IPs from page resources
  // ============================================================
  const discoveredIPs = new Set();

  function extractIPsFromString(str) {
    if (!str) return;
    const matches = str.match(IPV4_RE) || [];
    for (const ip of matches) {
      if (!isReserved(ip)) discoveredIPs.add(ip);
    }
  }

  function scanMetaTags() {
    // Content-Security-Policy meta tags
    document.querySelectorAll('meta[http-equiv="Content-Security-Policy"]').forEach(m => {
      extractIPsFromString(m.content);
    });
    // DNS prefetch
    document.querySelectorAll('link[rel="dns-prefetch"]').forEach(l => {
      extractIPsFromString(l.href);
    });
  }

  function scanResourceURLs() {
    // Script src, img src, iframe src, a href
    const selectors = "script[src], img[src], iframe[src], link[href], a[href]";
    document.querySelectorAll(selectors).forEach(el => {
      const url = el.src || el.href || "";
      try {
        const u = new URL(url);
        extractIPsFromString(u.hostname);
      } catch { /* ignore */ }
    });
  }

  function reportIPs() {
    const ips = Array.from(discoveredIPs);
    if (ips.length === 0) return;
    chrome.runtime.sendMessage({
      type: "PAGE_IPS",
      ips,
      url: PAGE_URL,
      tabId: null, // background will use sender.tab.id
    }).catch(() => {});
  }

  // ============================================================
  // Observe DOM mutations for dynamically injected resources
  // ============================================================
  const observer = new MutationObserver((mutations) => {
    for (const m of mutations) {
      for (const node of m.addedNodes) {
        if (node.nodeType !== 1) continue;
        const tag = node.tagName?.toLowerCase();
        if (["script", "img", "iframe", "link", "a"].includes(tag)) {
          const url = node.src || node.href || "";
          try {
            const u = new URL(url);
            extractIPsFromString(u.hostname);
          } catch { /* ignore */ }
        }
      }
    }
  });

  // ============================================================
  // Performance Observer: intercept network resource timing
  // This gives us actual IP addresses from PerformanceResourceTiming
  // if the browser exposes them (Chrome does for same-site or CORS-OK).
  // ============================================================
  function monitorResourceTiming() {
    try {
      const perfObs = new PerformanceObserver((list) => {
        for (const entry of list.getEntries()) {
          if (entry.entryType !== "resource") continue;
          // nextHopProtocol and serverTiming are available
          // Check if the initiator URL has an IP hostname
          try {
            const u = new URL(entry.name);
            extractIPsFromString(u.hostname);
          } catch { /* ignore */ }
        }
        reportIPs();
      });
      perfObs.observe({ entryTypes: ["resource"] });
    } catch { /* PerformanceObserver not available */ }
  }

  // ============================================================
  // Main execution
  // ============================================================
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => {
      scanMetaTags();
      scanResourceURLs();
      reportIPs();
    });
  } else {
    scanMetaTags();
    scanResourceURLs();
    reportIPs();
  }

  observer.observe(document.documentElement, { childList: true, subtree: true });
  monitorResourceTiming();

  // Re-scan after full page load
  window.addEventListener("load", () => {
    scanMetaTags();
    scanResourceURLs();
    reportIPs();
    observer.disconnect();
  });

  // ============================================================
  // Listen for messages from background (e.g. force re-check)
  // ============================================================
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === "RESCAN_PAGE") {
      discoveredIPs.clear();
      scanMetaTags();
      scanResourceURLs();
      reportIPs();
    }
  });

})();
