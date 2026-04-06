# QR Code Extraction via BarcodeDetector API

## What was added

**`content.js`**

- `QR_BANNER_ATTR = 'data-phishguard-qr'` — guard attribute preventing repeated scans per container.
- `QR_MIN_SIZE = 50` — minimum image dimension (px) required before attempting QR detection. Filters out tracking pixels, spacer images, and icons that cannot contain scannable QR codes.
- `injectQRBanner(container, flagged, totalFound)` — injects a styled warning banner when one or more QR-embedded URLs are flagged. Shows domain, score pill, and advice ("Do not scan it with your phone").
- `scanQRCodesInContainer(container)` — async function that:
  1. Guards against double-execution with `QR_BANNER_ATTR`.
  2. Feature-detects `BarcodeDetector` (Chrome 83+ only; silently no-ops elsewhere).
  3. Calls `BarcodeDetector.getSupportedFormats()` and aborts if `qr_code` is not listed.
  4. Filters `<img>` elements to those that are fully loaded (`complete`) and meet `QR_MIN_SIZE`.
  5. Runs `detector.detect(img)` for each qualifying image; catches `SecurityError` (cross-origin) per image and continues.
  6. Collects all `rawValue` strings that match `^https?://`.
  7. Sends them to `background.js` via the existing `ANALYZE_URLS` message — full 5-layer pipeline (heuristics + OpenPhish + Safe Browsing + PhishTank + URLHaus).
  8. If any result is `suspicious` or `high-risk`, calls `injectQRBanner`.

## What was improved

**`scanEmailContainers()` in `content.js`**

- `scanQRCodesInContainer(container)` is kicked off in parallel with `analyzeSenderDomain(container)` immediately after the auth check, so QR scanning and sender analysis run concurrently.
- Both the "no links" early-continue path and the main path await `qrPromise` before `injectScanBanner`, preserving the intended banner stacking order.

**Banner prepend order (top to bottom after this change):**

```
[Scan banner]      <- URL link counts, last prepend, visual top
[QR banner]        <- QR threat warning (if any)
[Sender banner]    <- sender domain impersonation
[Auth banner]      <- DMARC/SPF/DKIM failures
[Email body]
```

## Why

### The attack

QR code phishing ("quishing") is a growing evasion technique. Attackers embed a QR code image in an email body instead of a hyperlink. Because the destination URL is encoded in a bitmap, it is invisible to text-based link scanners, Safe Links wrappers, and email gateway filters that only inspect `<a href>` attributes.

The user scans the QR code with their phone. The phone's camera app opens the URL directly, outside any browser extension, giving the attacker a clean delivery path.

### Why BarcodeDetector

`BarcodeDetector` is a native browser API (W3C Shape Detection API, available in Chrome 83+ which covers all MV3 targets). It runs on-device using optimised native code with no latency or privacy cost. It requires no third-party library and adds zero weight to the extension.

### Why `QR_MIN_SIZE = 50`

A scannable QR code requires at minimum ~21 modules per side. At screen resolution, a QR code smaller than 50x50 px is either a tracking pixel, an icon, or a logo — none of which will contain a phishing URL. Skipping small images prevents unnecessary `detect()` calls on images that cannot match.

### Why silently skip cross-origin images

`BarcodeDetector.detect()` throws a `SecurityError` when called on a tainted cross-origin `<img>` element. Rather than forcing all images through a CORS fetch (which would fail for most email-linked images that lack `Access-Control-Allow-Origin`), the code catches the error per image and continues. Legitimate QR codes that carry phishing URLs are typically hosted inline or on attacker-controlled domains that do not enforce strict CORS, so in practice the scan still catches the threat.

### Why reuse ANALYZE_URLS

QR-extracted URLs go through exactly the same 5-layer pipeline as anchor links: heuristics (urlAnalyzer.js), OpenPhish feed, Google Safe Browsing, RDAP domain age, PhishTank, and URLHaus (for score >= 50). No new pipeline, no new message type. The only difference is the source of the URLs.

## Files changed

| File | Change |
|---|---|
| `content.js` | Added `QR_BANNER_ATTR`, `QR_MIN_SIZE` constants; added `injectQRBanner()` and `scanQRCodesInContainer()` functions; updated `scanEmailContainers()` to start QR scan in parallel and await before scan banner |
