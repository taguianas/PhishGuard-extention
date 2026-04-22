# URL Shortener Expansion

## What was added

### `urlAnalyzer.js`
- Local `isShortener` flag inside `analyzeURL()`, set when the hostname matches the shortener list check.
- New return field on `analyzeURL()` results: `isShortener: boolean`, so `background.js` can decide whether to follow a redirect without re-running the shortener regex.
- `SCORING` is now exported so `background.js` can read `SCORING.URL_SHORTENER.label` without duplicating the string.

### `idb.js`
- New IndexedDB store `'shorteners'` added to `STORES`.
- `DB_VERSION` bumped from 3 to 4 so existing users get the new store created automatically on upgrade.
- Store shape: `{ expandedUrl, cachedAt }` for successful expansions, `{ failed: true, cachedAt }` for failures (so we don't hammer a broken shortener on every email).

### `background.js`
- Constants: `SHORTENER_TTL = 24h`, `SHORTENER_TIMEOUT = 6s`.
- New setting `shortenerExpansionEnabled` (default `true`).
- `hasShortenerPermission()` - checks if the broad `https://*/*` host permission has been granted at runtime (required because redirect targets are unknown statically).
- `expandShortener(shortUrl)`:
  - IDB cache lookup first. Respects `SHORTENER_TTL` for hits, `FAIL_RETRY_TTL` for prior failures.
  - `fetch` with `redirect: 'follow'`, `credentials: 'omit'`, `AbortSignal.timeout(6000)`.
  - HEAD first; falls back to GET if HEAD returns same URL (some shorteners reject HEAD). Body is immediately cancelled on GET to avoid downloading the destination page.
  - Reads `response.url` as the final URL.
  - Caches both successes and failures.
- `mergeShortenerExpansion(analysis, destAnalysis, expandedUrl)`:
  - Drops the generic `+35` URL_SHORTENER indicator (would double-count when a clean `bit.ly` -> `google.com` resolves).
  - Adds a context-aware replacement: `"URL shortener resolves to trusted destination: X"` (+0) when the destination is safe/dev, or `"URL shortener hides destination: X"` (+15) otherwise.
  - Folds destination indicators into the short-link analysis (deduped by label, score capped at 100).
  - Recomputes `riskLevel` preserving `'developer'` when appropriate.
  - Attaches `expandedUrl` and `expandedDomain` to the original analysis.
- New Phase 0b in `handleAnalyzeURLs()` that runs shortener expansions in parallel via `Promise.all` and runs `analyzeURL()` recursively on the resolved destinations before feeds fire.
- `pending[]` entries now carry `urlForFeeds` + `domainForFeeds` - the effective post-expansion URL used by Safe Browsing, OpenPhish, RDAP, PhishTank, URLHaus, and VirusTotal so all threat-feed layers see the real destination.
- `'shorteners'` store added to `pruneAllCaches()` with `SHORTENER_TTL`.
- Webhook payload now carries `expandedUrl` and `expandedDomain` so SOC analysts see both the short link and the real destination.

### `content.js`
- Tooltip now renders a `"Resolves to"` row under `"Domain"` when `result.expandedDomain` is set and differs from the source domain.

### `settings.html`
- New `"URL Shortener Expansion"` section (before the SIEM Webhook section) with a toggle and description listing known supported shorteners and the 24h cache note.

### `settings.js`
- `shortenerExpansionEnabled: true` added to `DEFAULTS`.
- `toggleShort` DOM ref for `#toggle-shortener`.
- `loadSettings()` / `saveSettings()` / `resetSettings()` all handle the new flag.
- `saveSettings()` calls `chrome.permissions.request({ origins: ['https://*/*', 'http://*/*'] })` when the toggle is enabled; if the user denies, the toggle is flipped back off before persisting.

### `improvements/2026-04-21-url-shortener-expansion.md`
- This documentation file.

## What was improved

- **Threat-feed lookups now follow the real URL.** Safe Browsing / OpenPhish / RDAP / PhishTank / URLHaus / VirusTotal all receive the expanded URL rather than the short-link wrapper. Before this change, a `bit.ly/abc` pointing to a real phishing site would only ever be checked by the feeds as `bit.ly/abc`, which is never on any blocklist.
- **Shortener scoring is no longer a blanket penalty.** The old behaviour added a flat +35 for any shortener, even a legitimate `t.co` wrapper around a Fortune-500 domain. Now a shortener that resolves to a trusted or dev destination scores 0, while one that resolves to anything else keeps the +15 penalty plus whatever the destination itself scores.
- **Permission handling is graceful.** If the user denies the broad host permission at toggle-on, the setting snaps back off and persists as off, rather than silently failing later at fetch time.

## Why

Phishers routinely hide the real destination behind `bit.ly`, `t.co`, `tinyurl.com`, `cutt.ly`, `is.gd`, `ow.ly`, `rebrand.ly`, and dozens of other shorteners. Before this change:
- None of PhishGuard's domain-based heuristics (trusted-domain list, typosquatting, brand impersonation, RLO/bidi, NFKC variants, homograph, suspicious TLD) could fire, because the hostname `bit.ly` is just `bit.ly`.
- Threat-feed lookups were equally useless: the feeds don't track individual short-link slugs.
- The only signal was the flat `URL_SHORTENER = +35` indicator, which overpenalizes legitimate wrapped links (Twitter's `t.co`, marketing emails) and underpenalizes outright phishing.

Following the redirect client-side surfaces the real destination so every existing heuristic, every paid feed, and every notification/webhook sees the URL the victim would actually land on. Caching per short-link in IDB with a 24h TTL keeps the feature cheap: a single click-through per unique short-link per day even for blast campaigns.

## Files changed

- `urlAnalyzer.js` - export `SCORING`, add `isShortener` flag and return field (~lines 10 + inside `analyzeURL`).
- `idb.js` - `DB_VERSION` = 4, add `'shorteners'` to `STORES`, header comment updated.
- `background.js`:
  - imports: line 9 (import `SCORING` alongside `analyzeURL`).
  - constants: line 26 (`SHORTENER_TTL`, `SHORTENER_TIMEOUT`).
  - webhook payload: lines 138-139 (`expandedUrl`, `expandedDomain`).
  - shortener logic: lines 285-380 (`expandShortener`, `mergeShortenerExpansion`, `hasShortenerPermission`).
  - settings default: line 480.
  - `handleAnalyzeURLs()` Phase 0b + `urlForFeeds`/`domainForFeeds` plumbing: lines ~820-900.
  - `pruneAllCaches()`: line 1162.
- `content.js` - tooltip "Resolves to" row (inside the result-tooltip template builder).
- `settings.html` - new `"URL Shortener Expansion"` section (lines 208-227).
- `settings.js` - DEFAULTS, `toggleShort` ref, load/save/reset, permission-request flow.
