# IndexedDB Persistent Cache Layer

## What was added

**`idb.js`** (new file — 80 lines)
- `openDB()` — opens (or reuses) the `phishguard-cache` IndexedDB database, version 1. Creates four object stores on first run or upgrade:
  - `rdap`          — keyed by registered domain; value `{ result, cachedAt }`
  - `safebrowsing`  — keyed by full URL;          value `{ flagged, cachedAt }`
  - `phishtank`     — keyed by full URL;           value `{ flagged, cachedAt }`
  - `notifications` — keyed by domain;             value `{ lastNotifiedAt }`
- `idbGet(storeName, key)` — promise-based point read; returns stored value or `null`
- `idbSet(storeName, key, value)` — promise-based upsert
- `idbDelete(storeName, key)` — promise-based delete
- `idbPrune(storeName, ttlMs)` — cursor-based sweep: deletes all entries whose `cachedAt` (or `lastNotifiedAt`) is older than `ttlMs`; returns count of deleted entries

**`background.js`**
- `import { idbGet, idbSet, idbPrune } from './idb.js'`
- `PT_CACHE_TTL` constant (1 h) — was previously a file-local `const` inside `checkPhishTank`, now promoted to the top-level constants block alongside the other TTLs
- `CACHE_PRUNE_MS` constant (12 h) — documents the IDB pruning interval
- `chrome.alarms.create('phishguard-cache-prune', { periodInMinutes: 720 })` — wakes the service worker every 12 h to prune stale IDB entries
- `pruneAllCaches()` — calls `idbPrune` on all four stores in parallel; logs deleted counts

## What was improved

All four caches that previously lived in in-memory `Map`s have been migrated to IndexedDB:

| Previous `Map` | IDB store | Where used |
|---|---|---|
| `rdapCache` (Map) | `'rdap'` | `checkDomainAge()` |
| `sbCache` (Map) | `'safebrowsing'` | `checkGoogleSafeBrowsing()` |
| `phishTankCache` (Map) + `PT_CACHE_TTL` | `'phishtank'` | `checkPhishTank()` |
| `notifiedDomains` (Map) | `'notifications'` | `notifyHighRisk()` |

**`checkGoogleSafeBrowsing`** — cache reads are now done in parallel:
```js
// Before: sequential for-loop with synchronous Map.get()
for (const url of urls) { const hit = sbCache.get(url); ... }

// After: single Promise.all over all IDB reads — all fire concurrently
const cacheHits = await Promise.all(urls.map(url => idbGet('safebrowsing', url)));
```
Cache writes are also parallel (`Promise.all` over `idbSet` calls).

**`checkDomainAge`** — the inline `store()` helper is now `async` because `idbSet` is async; its callers (`return store(null)`, `return store({...})`) now correctly await the write before returning the result.

**`checkPhishTank`** — `const phishTankCache = new Map()` and `const PT_CACHE_TTL` removed from the module scope; TTL promoted to top-level constants.

**`notifyHighRisk`** — the old `notifiedDomains.get(domain) || 0` pattern is replaced with a structured IDB read: `(await idbGet('notifications', domain))?.lastNotifiedAt`.

**Alarm handler** — extended to also dispatch `pruneAllCaches()` on the new `'phishguard-cache-prune'` alarm.

## Why

**Root cause: MV3 service workers are ephemeral.**
Chrome kills the background service worker after ~30 seconds of inactivity. Every restart destroyed the four in-memory caches, causing:

1. **RDAP API hammering** — a previously checked domain would be re-queried on every SW restart, burning RDAP quota and slowing down scans. The 24 h TTL was effectively meaningless.

2. **Safe Browsing / PhishTank quota waste** — same problem. A URL seen many times in a session could be checked against the external API on every restart instead of being served from cache.

3. **Notification dedup failure** — the 1 h `NOTIFY_COOLDOWN` was supposed to prevent repeat notifications for the same domain. Because `notifiedDomains` was reset on restart, the user could receive multiple notifications per hour if the SW kept dying and waking up.

**Why IndexedDB instead of `chrome.storage.local`?**

| Property | `chrome.storage.local` | IndexedDB |
|---|---|---|
| Size limit | 5 MB (hard) | ~80% of disk (soft) |
| Cursor / range operations | None | Yes (`openCursor`) |
| Concurrent read parallelism | No (serialized internally) | Yes (multiple transactions) |
| TTL sweep (prune) | Must read entire object, filter, re-write | Single cursor transaction |
| Already used for | Stats, log, feed domains | Caches only |

`chrome.storage.local` already holds the stats log (up to 200 entries) and the OpenPhish feed (thousands of domain strings). Adding four unbounded URL-keyed caches to it risked hitting the 5 MB ceiling. IndexedDB has no practical size limit and supports cursor sweeps for efficient TTL pruning.

## Files changed

| File | Change |
|------|--------|
| `idb.js` | **New file** — full IndexedDB wrapper with `idbGet`, `idbSet`, `idbDelete`, `idbPrune`, singleton connection |
| `background.js` | Added `idb.js` import; removed 4 in-memory Maps; replaced all cache reads/writes with `idbGet`/`idbSet`; parallelized SB cache reads/writes; added `PT_CACHE_TTL` + `CACHE_PRUNE_MS` constants; added `phishguard-cache-prune` alarm; added `pruneAllCaches()` |
