# RTL Override (RLO) & Bidirectional Control Character Detection

## What was added

**`urlAnalyzer.js`**
- `BIDI_CONTROL_RE` — compiled regex covering all 11 Unicode bidirectional formatting characters that have no legitimate use in a URL string:
  - `U+202A` LEFT-TO-RIGHT EMBEDDING (LRE)
  - `U+202B` RIGHT-TO-LEFT EMBEDDING (RLE)
  - `U+202C` POP DIRECTIONAL FORMATTING (PDF)
  - `U+202D` LEFT-TO-RIGHT OVERRIDE (LRO)
  - `U+202E` RIGHT-TO-LEFT OVERRIDE (RLO) ← most abused
  - `U+2066` LEFT-TO-RIGHT ISOLATE (LRI)
  - `U+2067` RIGHT-TO-LEFT ISOLATE (RLI)
  - `U+2068` FIRST STRONG ISOLATE (FSI)
  - `U+2069` POP DIRECTIONAL ISOLATE (PDI)
  - `U+200E` LEFT-TO-RIGHT MARK (LRM)
  - `U+200F` RIGHT-TO-LEFT MARK (RLM)
- `SCORING.RLO_ATTACK` — new scoring entry, +75 pts (high confidence: no legitimate URL ever contains bidi control chars)
- `hasRLO` flag — computed on `rawUrl` before any parsing takes place
- `isSpoofed` flag — combines `hasRLO || hasNormVariants` to gate both trusted-domain early exits

**`content.js`**
- `BIDI_CONTROL_RE` — same regex, defined locally in the content script scope
- `applyBidiDisplayWarning(anchor)` — injects a "High Risk / RLO" tooltip on anchors whose visible text or raw `href` attribute contains bidi chars; fires synchronously without a background round-trip
- Bidi pre-scan loop in `scanEmailContainers` — checks `element.getAttribute('href')` (raw, before unwrapping) and `element.textContent` for bidi chars before the async background call

## What was improved

**`urlAnalyzer.js` — three bugs fixed:**

1. **Silent `null` on parse failure** — Chrome's `new URL()` strips or rejects bidi chars during WHATWG URL normalization. A bidi-poisoned URL that failed parsing previously returned `null` and was ignored entirely. Now: if `safeParseURL` returns `null` but `hasRLO` is true, the function returns a `high-risk` result with `score: 75` instead.

2. **Trusted-domain whitelist bypass** — An attacker can craft a URL whose *parsed* hostname resolves to `google.com` (trusted) while bidi chars in the raw string make it visually appear as a malicious domain. The old trusted-domain early exits returned `score: 0, safe` unconditionally. Fixed: both exits now check `&& !isSpoofed` before returning safe.

3. **Post-parse invisibility** — The RLO check is placed *before* `safeParseURL` and *before* the trusted-domain exit for the same reason: the parser erases the evidence. Checking on `rawUrl` preserves it.

## Why

The RLO attack exploits how Unicode bidirectional text rendering works:

- `U+202E` (RLO) forces all following characters to render right-to-left
- An attacker writes `"moc.rekcah\u202Eelgoog"` — this *displays* as `"googlehacker.com"` in many renderers
- The actual href points to the phishing domain; the user sees a trusted brand name

The display-text variant (caught in `content.js`) is even more dangerous: the `href` is a clean evil URL, but the visible anchor text uses RLO to look like `https://google.com`. The URL analyzer only receives the href — it never sees the display text — so the content script must handle this independently.

## Files changed

| File | Change |
|------|--------|
| `urlAnalyzer.js` | Added `BIDI_CONTROL_RE`, `SCORING.RLO_ATTACK`; added `hasRLO` pre-parse check; fixed `null` return path; fixed both trusted-domain early exits with `!isSpoofed` guard |
| `content.js` | Added `BIDI_CONTROL_RE`, `applyBidiDisplayWarning()`, bidi pre-scan loop in `scanEmailContainers` |
