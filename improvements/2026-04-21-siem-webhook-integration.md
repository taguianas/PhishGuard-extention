# SIEM Webhook Integration

## What was added
- New settings in `chrome.storage.sync.phishguard_settings`:
  - `webhookEnabled: boolean` (default `false`)
  - `webhookUrl: string` (must be `https://`)
  - `webhookAuthHeader: string` (optional, sent as the `Authorization` HTTP header)
- New IDB store `'webhooks'` in `idb.js` (DB_VERSION bumped 2 to 3). Key = detection URL, value = `{ lastSentAt }`. Used to dedup webhook POSTs per URL across a 1-hour cooldown.
- `WEBHOOK_COOLDOWN_MS = 60 * 60 * 1000` and `WEBHOOK_TIMEOUT_MS = 8000` constants in `background.js`.
- `postToWebhook(result, settings)` in `background.js`: builds the JSON payload, posts it to the configured endpoint, adds the `Authorization` header when present, and records the send in the `webhooks` IDB store on success.
- Payload shape:
  ```json
  {
    "source": "phishguard",
    "version": "<manifest version>",
    "timestamp": "<ISO8601>",
    "detection": {
      "url", "domain", "score", "riskLevel",
      "indicators": [{ "score", "label" }],
      "domainAge": null | { ageInDays, registeredDate, domain },
      "feedHits": { "openphish", "safeBrowsing", "phishTank", "urlHaus", "virusTotal" },
      "allowlisted": boolean
    }
  }
  ```
- New Settings UI section (`settings.html`): toggle, URL input, optional Authorization header input (password field, eye-toggle), and a collapsible example-payload `<details>`/`<pre>` block.
- `webhookOrigin(url)` + `validateWebhookUrl(url)` helpers in `settings.js`.
- Runtime permission request via `chrome.permissions.request({ origins: [origin] })` when the user saves a webhook for an origin the extension does not yet hold. If the user denies, the toggle is automatically switched off and the status line explains why.
- `optional_host_permissions: ["https://*/*", "http://*/*"]` added to `manifest.json` so user-supplied webhook origins can be granted at runtime without re-listing them statically.
- `pruneAllCaches()` now also prunes the `webhooks` store on the existing 12-hour alarm, reusing the `lastSentAt` timestamp. `idb.js idbPrune` was extended to recognise `lastSentAt` alongside `cachedAt` and `lastNotifiedAt`.
- Settings CSS: `.pg-details`, `.pg-details > summary`, and `.pg-code` rules for the collapsible example payload.

## What was improved
- `loadSettings()` in `background.js` returns the three new webhook defaults alongside the existing ones; the spread of `data.phishguard_settings` preserves user values on top.
- `handleAnalyzeURLs()` Phase 3 now fires `postToWebhook(analysis, settings)` alongside `notifyHighRisk(analysis)` on every high-risk detection, both fire-and-forget so the analysis pipeline is never blocked by a slow SIEM endpoint.
- `settings.js saveSettings` now awaits `chrome.permissions.request` for the webhook origin before persisting; denial flips `webhookEnabled` back to `false` and surfaces an error in the status pill.

## Why
- Enterprise and SOC users need detections to flow into their existing telemetry stack (Splunk HEC, Elastic, Sentinel, custom collectors) rather than living only inside the browser extension. Without a webhook, PhishGuard evidence is invisible to the security team.
- A simple JSON POST is the lowest-common-denominator interface: Splunk HEC accepts raw JSON with a `Splunk <token>` Authorization header, Elastic `_bulk` accepts JSON over HTTPS with `Authorization: ApiKey ...`, and custom endpoints almost universally parse JSON bodies.
- Per-URL dedup with a 1-hour window prevents a newsletter with 50 copies of the same phishing link, or a user reloading an email five times in a minute, from fanning out 50+ identical SIEM events: one signal per URL per hour is enough to drive alerting.
- Using `optional_host_permissions` + a runtime request keeps the installed-state permission footprint small: the extension does NOT ask for blanket "all sites" permission at install. Permission is only granted for the specific webhook host the user configures.
- `lastSentAt` key is written only on a successful POST so a 500 or network failure does not suppress retries during the next scan.

## Files changed
- `manifest.json`: added `optional_host_permissions` block with `https://*/*` and `http://*/*`.
- `idb.js`: bumped `DB_VERSION` 2 to 3, added `'webhooks'` to `STORES`, extended `idbPrune` cursor to recognise `lastSentAt` as an age field, updated the header comment listing the stores.
- `background.js`: added `WEBHOOK_COOLDOWN_MS` / `WEBHOOK_TIMEOUT_MS` constants, added `postToWebhook()` function with a full-payload builder and `Authorization`-header handling, wired the call into the Phase-3 high-risk branch in `handleAnalyzeURLs()`, extended `loadSettings()` defaults with the three webhook keys, and added `idbPrune('webhooks', WEBHOOK_COOLDOWN_MS)` to `pruneAllCaches()`.
- `settings.html`: new SIEM Webhook section with toggle, URL input, Authorization header input, reveal button, status pill, and a collapsible example-payload `<details>` element.
- `settings.js`: extended `DEFAULTS`, added `toggleWH` / `whUrlInput` / `whAuthInput` / `whStatus` refs, extended `loadSettings` / `saveSettings` / `resetSettings`, added `webhookOrigin()` + `validateWebhookUrl()` helpers, added reveal binding for the auth header input, wired runtime permission request on save.
- `settings.css`: added `.pg-details`, `.pg-details > summary`, `.pg-details[open] > summary`, and `.pg-code` rules.
