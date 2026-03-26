<div align="center">

<img src="icons/icon128.png" alt="PhishGuard Logo" width="96" />

# PhishGuard

**Real-time phishing link detection for your email, built as a Chrome extension.**

[![Version](https://img.shields.io/badge/version-2.0.0-blue?style=flat-square)](./manifest.json)
[![Manifest](https://img.shields.io/badge/Manifest-V3-green?style=flat-square)](https://developer.chrome.com/docs/extensions/mv3/intro/)
[![License](https://img.shields.io/badge/license-MIT-lightgrey?style=flat-square)](#license)
[![Platform](https://img.shields.io/badge/platform-Chrome-yellow?style=flat-square)](https://www.google.com/chrome/)
[![Status](https://img.shields.io/badge/status-under%20construction-orange?style=flat-square)](#roadmap)

> **This project is actively under construction.**
> Core detection is functional and battle-tested, but new layers, UI improvements, and enterprise features are being added continuously.
> Every improvement is documented in [`improvements/`](./improvements/) and pushed to this repository as it lands.

</div>

---

## Table of Contents

- [Overview](#overview)
- [What Makes It Different](#what-makes-it-different)
- [Supported Email Clients](#supported-email-clients)
- [How It Works](#how-it-works)
- [Detection Engine](#detection-engine)
  - [Heuristic Checks (21+)](#heuristic-checks-21)
  - [Threat Intelligence Layers](#threat-intelligence-layers)
  - [Advanced Attack Detection](#advanced-attack-detection)
- [Risk Scoring](#risk-scoring)
- [Architecture](#architecture)
- [Installation](#installation)
- [Configuration](#configuration)
- [Dashboard & Popup](#dashboard--popup)
- [Privacy](#privacy)
- [Improvements Log](#improvements-log)
- [Roadmap](#roadmap)
- [Known Limitations](#known-limitations)
- [Contributing](#contributing)
- [Author](#author)
- [License](#license)

---

## Overview

PhishGuard is a Chrome extension that scans every link in your email in real time, before you click it. It runs entirely in your browser. No email content is ever uploaded, no tracking, no telemetry.

It combines a **21-check heuristic engine** with **five threat intelligence layers** (OpenPhish, Google Safe Browsing, PhishTank, URLHaus, RDAP domain age) to assign each URL a risk score and visually annotate your inbox.

The detection engine is built to catch modern phishing techniques that simpler tools miss: Unicode homograph attacks, RTL Override spoofing, typosquatting with digit lookalikes, DGA-generated domains, credential injection, and more.

---

## What Makes It Different

| Feature | PhishGuard | Basic URL checker |
|---|:---:|:---:|
| Works inline in Gmail / Outlook | Yes | No |
| Heuristic engine (21+ local checks) | Yes | No |
| Bidi / RLO spoofing detection | Yes | Rarely |
| Unicode NFKC normalization | Yes | No |
| RDAP domain age verification | Yes | No |
| 5 threat intelligence feeds | Yes | 1-2 |
| IndexedDB persistent cache (survives SW restart) | Yes | N/A |
| Zero email content transmitted | Yes | Varies |
| Free, open source, no API required for core checks | Yes | Varies |

---

## Supported Email Clients

| Email Client | URL |
|---|---|
| Gmail | `mail.google.com` |
| Outlook Web (OWA) | `outlook.live.com`, `outlook.office.com`, `outlook.office365.com` |
| Yahoo Mail | `mail.yahoo.com` |
| ProtonMail | `mail.proton.me` |

---

## How It Works

```
Email opened in browser
        |
        v
content.js  (MutationObserver, fires on every DOM mutation)
  |-- Locates all <a href> elements in the email body
  |-- Unwraps redirect wrappers (SafeLinks, goo.gl, Mailchimp, etc.)
  |-- Pre-scans for Bidi / RLO control characters in raw href and display text
  +-- Sends URL batch to the background service worker
        |
        v
background.js  (Analysis Pipeline)
  |-- Layer 1: urlAnalyzer.js  (21+ heuristic checks, synchronous, no network)
  |-- Layer 2: OpenPhish feed  (6 h refresh, cached in chrome.storage.local)
  |-- Layer 3: Google Safe Browsing  (batch request, 30 min IDB cache)
  |-- Layer 4: RDAP domain age  (rdap.org, 24 h IDB cache)
  |-- Layer 5: PhishTank  (on-demand, score > 0, 1 h IDB cache)
  +-- Layer 6: URLHaus  (on-demand, score >= 50 only, quota protection)
        |
        v
content.js  (Visual Injection)
  |-- Red border    -> High Risk   (score 61-100)
  |-- Orange border -> Suspicious  (score 31-60)
  |-- Tooltip overlay  -> score, domain, triggered indicators, advice
  +-- Per-email scan summary banner

background.js  (Side Effects)
  |-- Badge counter  (red = high-risk count, orange = suspicious count)
  |-- Desktop notification  (high-risk only, 1 h cooldown per domain)
  +-- Persistent detection log  (up to 200 entries, chrome.storage.local)
```

---

## Detection Engine

### Heuristic Checks (21+)

All checks run locally, synchronously, with no network calls. Trusted domains (54 major services) skip heuristics entirely to prevent false positives.

| # | Check | Points |
|---|---|:---:|
| 1 | IP address used as hostname (IPv4 / IPv6) | +60 |
| 2 | URL shortener service (bit.ly, t.co, 20+ services) | +35 |
| 3 | Domain impersonation: Levenshtein distance <= 2 from a known brand | +35 |
| 4 | Trusted brand used as subdomain (`paypal.com.evil.xyz`) | +65 |
| 5 | Brand keyword in subdomain on untrusted registered domain | +35 |
| 6 | Non-ASCII / homograph characters in hostname | +40 |
| 7 | IDN Punycode label (`xn--` prefix, encoded look-alike) | +45 |
| 8 | Excessive subdomain depth (> 4 levels) | +25 |
| 9 | Suspicious TLD (`.xyz` `.top` `.work` `.club` `.pw` ...) | +25 |
| 10 | Free / abused TLD (`.tk` `.ml` `.cf` `.ga` `.gq`) | +50 |
| 11 | Unusually long URL (> 100 characters) | +10 |
| 12 | Multiple @ signs (credential harvesting pattern) | +30 |
| 13 | Open redirect pattern (`?url=` `?redirect=` `?goto=` ...) | +15 |
| 14 | Unencrypted HTTP (no TLS) | +10 |
| 15 | Dangerous file extension in path (`.exe` `.ps1` `.vbs` `.jar` ...) | +60 |
| 16 | Credential keywords in path (`/login` `/verify` `/billing` ...) | +20 |
| 17 | Free / abused hosting platform (replit.dev, 000webhostapp.com ...) | +35 |
| 18 | Non-standard port number | +20 |
| 19 | Hyphen abuse in domain root (>= 3 hyphens, DGA pattern) | +15 |
| 20 | Brand keyword in URL path (`/paypal`, `/amazon` on untrusted domain) | +20 |
| 21 | Credential injection in URL authority (`paypal.com@evil.com`) | +65 |
| 22 | ASCII digit lookalike substitution (`g00gle`, `paypa1`, `amaz0n`) | +50 |
| 23 | High-entropy domain: Shannon entropy > 3.5, vowel ratio < 20% | +25 |

### Threat Intelligence Layers

| Layer | Feed | Trigger | Cache | TTL |
|---|---|---|---|---|
| 2 | OpenPhish | All URLs | `chrome.storage.local` | 6 h |
| 3 | Google Safe Browsing | All URLs (requires API key) | IndexedDB | 30 min |
| 4 | RDAP domain age | Score > 0 | IndexedDB | 24 h |
| 5 | PhishTank | Score > 0 | IndexedDB | 1 h |
| 6 | URLHaus | Score >= 50 | On-demand | - |

### Advanced Attack Detection

#### RTL Override (RLO) / Bidirectional Control Characters

PhishGuard detects all 11 Unicode bidirectional formatting characters that have no legitimate use inside a URL. The most dangerous is `U+202E` (Right-To-Left Override). It forces text to render right-to-left, making `moc.rekcah\u202Eelgoog` display as `googlehacker.com`.

Detection runs **before** the WHATWG URL parser, which strips these characters and erases the evidence. If bidi chars are found in the display text of a link (not just the `href`), the content script flags it directly without a background round-trip. **+75 pts.**

#### Unicode NFKC Normalization

Attackers substitute visually identical Unicode variants for ASCII characters:

- Fullwidth letters: `ｇｏｏｇｌｅ.com` -> `google.com`
- Mathematical bold: `𝗴𝗼𝗼𝗴𝗹𝗲.com` -> `google.com`
- Mathematical italic: `𝘨𝘰𝘰𝘨𝘭𝘦.com` -> `google.com`

Chrome's URL parser normalises these via IDNA processing, making them invisible to post-parse checks. PhishGuard compares the raw URL against its NFKC form before parsing to catch the manipulation before it disappears. **+50 pts.**

#### Trusted Domain Bypass Prevention

Both the RLO and NFKC attacks can produce a parsed hostname that matches a trusted domain (`google.com`) while the raw URL contains spoofing characters. PhishGuard blocks the trusted-domain whitelist exit when either attack is detected, ensuring the full scoring pipeline still runs.

---

## Risk Scoring

Scores cap at 100. Risk level is determined after all layers complete.

| Score | Risk Level | Visual Treatment |
|---|---|---|
| 0-30 | Safe | No decoration |
| 31-60 | Suspicious | Orange border + tooltip |
| 61-100 | High Risk | Red border + tooltip + optional desktop notification |

---

## Architecture

```
PhishGuard-extention/
|
|-- manifest.json          MV3 manifest, permissions, CSP, content script config
|-- background.js          Service worker, analysis pipeline, threat feeds, badge, notifications
|-- urlAnalyzer.js         Heuristic engine, 21+ checks, fully synchronous, zero network
|-- idb.js                 IndexedDB cache layer, persistent caches for RDAP/SB/PhishTank/notifications
|
|-- content.js             Content script, DOM monitoring, URL unwrapping, visual injection
|-- styles.css             Injected styles, link highlights, tooltips, scan banner
|
|-- popup.html             Dashboard markup
|-- popup.js               Dashboard logic, stats, detection log, CSV export
|-- popup.css              Dashboard styles
|
|-- settings.html          Settings page markup
|-- settings.js            Settings logic, API key input, feature toggles
|-- settings.css           Settings styles
|
|-- icons/                 Extension icons (16, 32, 48, 128 px)
|-- generate_icons.py      One-time icon generator (Pillow)
|
+-- improvements/          Improvement mini-READMEs, one file per shipped feature
    |-- 2026-03-24-rlo-bidi-attack-detection.md
    |-- 2026-03-24-unicode-normalization.md
    +-- 2026-03-25-indexeddb-persistent-cache.md
```

### Key Design Decisions

**Manifest V3:** Service worker replaces the persistent background page. All caches are stored in IndexedDB (not in-memory Maps) because MV3 service workers are killed after ~30 s of inactivity.

**Layered scoring:** Heuristics run first (synchronous, free, instant). Threat intelligence feeds run only when needed: Safe Browsing for all URLs, RDAP/PhishTank for score > 0, URLHaus for score >= 50. This protects free-tier API quotas and keeps scan latency low for clearly safe URLs.

**Pre-parse attack detection:** RLO and NFKC checks run on the raw URL string *before* `new URL()` is called. Chrome's WHATWG URL parser normalises both bidi control characters and fullwidth Unicode variants during IDNA processing, making them permanently invisible to any post-parse check.

**IndexedDB caching:** RDAP (24 h), Safe Browsing (30 min), PhishTank (1 h), and notification dedup (1 h) are all persisted in IndexedDB so they survive service worker restarts. A `phishguard-cache-prune` alarm fires every 12 h to sweep expired entries.

**Content script is an IIFE:** Not an ES module. MV3 content scripts cannot be loaded as modules; the IIFE wraps all state to avoid polluting the global scope.

**No email body reading:** Only `element.getAttribute('href')` and `element.textContent` on `<a>` elements are accessed. No text nodes, no form values, no email body.

---

## Installation

### Developer Mode (from source)

1. Clone this repository
   ```bash
   git clone https://github.com/YOUR_USERNAME/PhishGuard-extention.git
   ```
2. Open Chrome and navigate to `chrome://extensions/`
3. Enable **Developer mode** (toggle in the top-right corner)
4. Click **Load unpacked**
5. Select the `PhishGuard-extention` folder
6. The PhishGuard icon appears in your toolbar

### Regenerate Icons (optional)

```bash
pip install Pillow
python generate_icons.py
```

---

## Configuration

Click the PhishGuard toolbar icon, then open **Settings**.

### API Keys

| Key | Where to get it | Required |
|---|---|:---:|
| Google Safe Browsing API Key | Google Cloud Console -> Enable Safe Browsing API -> Credentials | Recommended |
| PhishTank API Key | phishtank.com/api_info.php | Optional |

**Google Safe Browsing setup:**
1. Open Google Cloud Console and create or select a project
2. Navigate to **APIs & Services -> Library** and enable the **Safe Browsing API**
3. Go to **APIs & Services -> Credentials** and create an API key
4. Paste the key into PhishGuard Settings -> Safe Browsing API Key

### Feature Toggles

| Feature | Default | Description |
|---|:---:|---|
| Desktop Notifications | On | Alert on high-risk detections (1 h cooldown per domain) |
| Domain Age Check | On | RDAP lookup to verify when the domain was registered |
| Google Safe Browsing | On | Real-time lookup against Google's malware/phishing database |
| PhishTank | Off | Community phishing database; works without a key at lower rate limits |

---

## Dashboard & Popup

Click the PhishGuard icon to open the dashboard:

- **Stats bar:** links scanned / suspicious / high-risk for the current session
- **Threat index:** percentage bar showing the proportion of risky links detected
- **Recent indicators:** last 10 triggered detection rule labels
- **Detection log:** up to 200 entries with timestamp, full URL, domain, risk level badge, score, domain age tag, and all triggered indicator labels
- **Export CSV:** download the log as `phishguard-YYYY-MM-DD.csv`
- **Clear log:** wipe all stored entries

---

## Privacy

| Data | Collected? | Notes |
|---|:---:|---|
| Email body / text content | **Never** | Only `href` attributes on `<a>` tags are accessed |
| URLs sent externally | Conditionally | Only for score > 0 (PhishTank / RDAP) or score >= 50 (URLHaus), or all URLs if Safe Browsing API key is configured |
| Detection log | Local only | `chrome.storage.local`, never synced, never transmitted |
| API keys | Local only | `chrome.storage.sync`, synced to your Google account only |
| Analytics / telemetry | **Never** | No tracking of any kind |

---

## Improvements Log

Every improvement shipped to this repository is documented in [`improvements/`](./improvements/). Each file covers what was added, what was improved, why the change was made, and which files were changed.

| Date | Improvement |
|---|---|
| 2026-03-24 | [RTL Override (RLO) & Bidi attack detection](./improvements/2026-03-24-rlo-bidi-attack-detection.md) |
| 2026-03-24 | [Unicode NFKC normalization before all checks](./improvements/2026-03-24-unicode-normalization.md) |
| 2026-03-25 | [IndexedDB persistent cache layer](./improvements/2026-03-25-indexeddb-persistent-cache.md) |
| 2026-03-26 | [Failed API calls cached as unchecked (bug fix)](./improvements/2026-03-26-failed-api-calls-unchecked.md) |

---

## Roadmap

The items below are planned for upcoming releases. Checked items are shipped.

### v2.0 - Core Engine (current)
- [x] 21+ heuristic checks in `urlAnalyzer.js`
- [x] OpenPhish feed (6 h refresh)
- [x] Google Safe Browsing API integration
- [x] RDAP domain age verification
- [x] PhishTank integration
- [x] URLHaus on-demand lookup
- [x] Badge counter and desktop notifications
- [x] RTL Override (RLO) and Bidi control character detection
- [x] Unicode NFKC normalization before all heuristic checks
- [x] IndexedDB persistent caches (survive service worker restarts)
- [x] Trusted-domain bypass prevention for RLO / Unicode spoofing attacks

### v2.1 - New Detection Layers
- [ ] Parse Gmail / Outlook authentication result headers (DMARC / SPF / DKIM `fail` signals)
- [ ] Sender domain impersonation scoring (heuristic analysis of the `From:` domain)
- [ ] VirusTotal URL lookup integration (optional, free tier: 4 req/min)
- [ ] QR code extraction from email images via browser `BarcodeDetector` API

### v2.2 - UX & Accuracy
- [ ] Score contribution breakdown in tooltips (e.g. "Brand in subdomain: +65 pts")
- [ ] "Mark as Safe" / "Confirm Phishing" feedback buttons on tooltips
- [ ] Per-user domain allowlist via right-click context menu
- [ ] Credential submission blocker: intercept `submit` event on flagged phishing forms
- [x] Failed API calls treated as "unchecked" rather than cached as "safe"

### v3.0 - Enterprise
- [ ] SIEM / SOC webhook: POST high-risk detections as JSON to a configurable endpoint
- [ ] Admin-managed allowlists and detection thresholds via Chrome enterprise policy
- [ ] Machine learning scoring layer trained on labeled phishing datasets

---

## Known Limitations

- **Zero-day phishing kits:** unknown pages not yet indexed in any threat feed are caught by heuristics only; novel techniques may slip through
- **No TLS certificate validation:** the extension cannot verify whether a site's SSL certificate matches its claimed identity
- **Trusted domain bypass:** the 54 whitelisted domains skip all heuristic checks; a link from a compromised trusted domain would not be flagged by heuristics (it would still be checked against threat feeds)
- **QR codes:** images containing QR codes with malicious URLs are not analyzed (planned for v2.1)
- **No DMARC/SPF/DKIM:** sender authentication headers are not parsed; a spoofed sender domain is not factored into the score (planned for v2.1)

---

## Contributing

Contributions are welcome. This project is actively evolving.

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-improvement`
3. Make your changes and test by loading the extension in Chrome Developer Mode
4. Document your improvement in `improvements/YYYY-MM-DD-short-title.md` following the format in existing files
5. Open a pull request with a clear description of what was added, what was improved, and why

### Manual Testing Checklist

Before submitting, verify the extension does not regress on these cases:

```
# IP address -> High Risk
http://192.168.1.1/login/secure

# URL shortener -> Suspicious
https://bit.ly/3xAmple

# Digit lookalike -> High Risk
https://paypa1-secure.com/verify

# Brand in subdomain -> High Risk
https://paypal.malicious-site.com/login

# Excessive subdomains -> Suspicious
https://a.b.c.d.e.evil.com/steal

# Redirect chain -> Suspicious
https://evil.com/?url=https://bank.com

# Free abused TLD -> High Risk
https://steal-credentials.tk/login

# RLO attack -> High Risk
# (URL containing U+202E, Right-To-Left Override)

# Unicode homograph -> High Risk
# google.com in fullwidth ASCII
```

### PR Checklist

- [ ] Tested on Gmail and Outlook Web
- [ ] No console errors in background service worker (`chrome://extensions/` -> Inspect views)
- [ ] No console errors in content script (DevTools -> Console on any supported mail page)
- [ ] New detection rules do not false-positive on the trusted domain whitelist
- [ ] Improvement documented in `improvements/YYYY-MM-DD-*.md`

---

## Author

**Anas TAGUI**

Built with a focus on real-world phishing technique coverage, browser extension security constraints, and zero-telemetry privacy.

---

## License

MIT License, free for personal, educational, and portfolio use.

---

<div align="center">

*PhishGuard does not guarantee detection of all phishing attempts.*
*It is a defensive aid, not a replacement for security awareness training or enterprise email security.*

</div>
