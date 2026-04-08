# VirusTotal URL Lookup - Zero-Day Phishing Detection

## What was added

**`background.js`**

- `VT_CACHE_TTL = 24 * 60 * 60 * 1000` constant: 24-hour IDB cache per URL (free tier is 500 req/day).
- `vtUrlId(url)` helper: encodes a URL to the base64url format VirusTotal v3 uses as a resource ID (`btoa(url)` with URL-safe char substitution and padding stripped). Returns `null` on encoding failure so the check is skipped gracefully.
- `checkVirusTotal(url, apiKey)`: async function that:
  1. Checks IDB cache (`virustotal` store). Serves cached result if within 24 h.
  2. On `{ failed: true }` cache entry, respects `FAIL_RETRY_TTL` (5 min) before retrying.
  3. Makes a GET request to `https://www.virustotal.com/api/v3/urls/{urlId}` with `x-apikey` header.
  4. On HTTP 404: URL is not yet in VT database - returns `null` without caching (will retry on next scan).
  5. On HTTP 429: rate limited - caches as failed with short TTL and returns `null`.
  6. On success: extracts `last_analysis_stats` and returns `{ malicious, suspicious, harmless, total }`.
  7. On any other error: caches as `{ failed: true }` and returns `null`.
- Layer 6 in `handleAnalyzeURLs`: VirusTotal is queried when:
  - `settings.virusTotalEnabled && settings.virusTotalApiKey` are both set
  - `analysis.score > 0` (URL is already suspicious from heuristics)
  - None of the earlier definitive hits fired (`threatFeedHit`, `safeBrowsingHit`, `urlhausHit`, `phishTankHit`)

  Scoring applied from VT result:
  - `malicious >= 3`: +60 pts, high-risk, label `"VirusTotal: flagged by X/Y security engines"`
  - `malicious 1-2`: +35 pts, suspicious/high-risk, label `"...X/Y engine(s) - verify manually"`
  - `suspicious >= 5` (no malicious): +15 pts, label `"...flagged as suspicious by X/Y engines"`

- `loadSettings` defaults updated: `virusTotalEnabled: true`, `virusTotalApiKey: ''`

**`idb.js`**

- `DB_VERSION` bumped from 1 to 2: triggers `onupgradeneeded` in existing installs, which creates the new store.
- `'virustotal'` added to `STORES`: new object store keyed by full URL, value shape `{ result, cachedAt }` or `{ failed: true, cachedAt }`.

**`settings.html`**

- New VirusTotal section between PhishTank and Notifications:
  - Enable/disable toggle (`toggle-virustotal`)
  - API key input with reveal button (`vt-api-key`, `btn-reveal-vt`)
  - Status indicator (`vt-status`)
  - Score table showing the three detection tiers

**`settings.js`**

- `DEFAULTS` updated with `virusTotalEnabled: true` and `virusTotalApiKey: ''`
- `toggleVT`, `vtKeyInput`, `vtStatus` DOM refs added
- `validateVTKey(key)`: validates that the key is exactly 64 lowercase hex characters (VirusTotal's key format)
- Load, save, and reset paths all handle the new VT fields
- `addReveal('btn-reveal-vt', vtKeyInput)` wired up
- `vtKeyInput` gets an `input` event listener calling `validateVTKey`

## What was improved

The `loadSettings` default object in `background.js` now includes VT defaults so the service worker never crashes with undefined property access even before the user opens Settings.

## Why

### The gap

OpenPhish, PhishTank, and URLHaus all operate on known-bad URL databases. A phishing kit deployed 30 minutes ago will not be in any of these feeds. Heuristics catch structural patterns but an attacker using a legitimately-looking domain with no prior history can score 0 on all five existing layers.

VirusTotal aggregates 70+ independent antivirus engines and URL scanners. Security companies submit newly discovered phishing URLs to VT continuously. A URL that defeats every feed check often still gets flagged by 2-3 VT engines within an hour of the campaign launching, which is well within the window of a phishing attack.

### Why only query when score > 0

VirusTotal's free tier is 4 req/min / 500 req/day. Querying VT for every URL in every email would exhaust the daily quota within a few minutes of reading email. Restricting to URLs that already scored above zero from heuristics limits VT calls to genuinely suspicious URLs only.

### Why skip when prior definitive hits fired

If Safe Browsing, PhishTank, URLHaus, or the OpenPhish feed already confirmed the URL as malicious, querying VT provides no additional value and wastes quota. The `vtHit` flag is still set when VT does fire, so downstream code can distinguish the source.

### Why 24-hour cache TTL

VirusTotal results for a URL are relatively stable once a verdict is established. A 24-hour cache means each unique URL is checked at most once per day, keeping daily usage well within the 500-request free tier limit for normal email volumes.

### Why treat 404 as unchecked (not safe)

A 404 from VT means the URL has never been submitted or analyzed before. That is actually a signal worth noting for zero-day detection: brand-new URLs that no one has scanned yet are often malicious infrastructure. Treating 404 as "safe" would be wrong. Treating it as unchecked (returning `null`, no IDB entry) means the URL will be re-queried on the next scan, allowing VT to eventually see it once another scanner submits it.

### Why 429 is cached as failed (not silently skipped)

If VT rate-limits us, caching a `{ failed: true }` entry with `FAIL_RETRY_TTL` prevents hammering the endpoint on the same URL every few seconds. After 5 minutes the cache expires and the request is retried.

## Files changed

| File | Change |
|---|---|
| `background.js` | Added `VT_CACHE_TTL`, `vtUrlId()`, `checkVirusTotal()`; added Layer 6 in `handleAnalyzeURLs`; updated `loadSettings` defaults |
| `idb.js` | Bumped `DB_VERSION` to 2; added `'virustotal'` to `STORES` |
| `settings.html` | Added VirusTotal section with toggle, key input, reveal button, status indicator, and score table |
| `settings.js` | Added `DEFAULTS` fields, DOM refs, `validateVTKey()`, load/save/reset wiring, reveal button and input listener |
