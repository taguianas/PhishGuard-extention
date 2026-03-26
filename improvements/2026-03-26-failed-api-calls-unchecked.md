# Failed API Calls Cached as Unchecked (Bug Fix)

## What was added

**`background.js`**
- `FAIL_RETRY_TTL` constant: 5 minutes. The window during which a recently failed API call is treated as unchecked before being retried.
- `{ failed: true, cachedAt }` IDB entry shape: written on network/API errors instead of `{ flagged: false }` or `{ result: null }`. The `failed` flag distinguishes a genuine API failure from a successful clean result.

## What was improved

Three functions previously wrote a "safe" result to IDB on error. All three are fixed.

**`checkGoogleSafeBrowsing` - cache read logic:**

Before:
```js
if (hit && now - hit.cachedAt < SB_CACHE_TTL) {
  if (hit.flagged) flagged.add(urls[i]);
} else {
  uncached.push(urls[i]);
}
```

After:
```js
if (hit?.failed) {
  if (now - hit.cachedAt >= FAIL_RETRY_TTL) uncached.push(urls[i]);
  // else: within retry window, treat as unchecked (skip)
} else if (hit && now - hit.cachedAt < SB_CACHE_TTL) {
  if (hit.flagged) flagged.add(urls[i]);
} else {
  uncached.push(urls[i]);
}
```

**`checkGoogleSafeBrowsing` - catch block:**

Before: `idbSet('safebrowsing', url, { flagged: false, cachedAt: now })`
After:  `idbSet('safebrowsing', url, { failed: true, cachedAt: now })`

**`checkDomainAge` (RDAP) - cache read logic:**

Before: `if (cached && Date.now() - cached.cachedAt < RDAP_CACHE_TTL) return cached.result;`
After: checks `cached.failed` first; if within retry window, returns null (unchecked) without assuming safe.

**`checkDomainAge` - catch block:**

Before: `idbSet('rdap', registeredDomain, { result: null, cachedAt: Date.now() })`
After:  `idbSet('rdap', registeredDomain, { failed: true, cachedAt: Date.now() })`

Note: `store(null)` when `!res.ok` or no registration event is NOT changed. Those are valid RDAP responses (domain not in registry, no date available), not failures.

**`checkPhishTank` - cache read logic:**

Before: `if (cached && now - cached.cachedAt < PT_CACHE_TTL) return cached.flagged;`
After: checks `cached.failed` first; if within retry window, returns false (unchecked) without assuming the URL is clean.

**`checkPhishTank` - catch block:**

Before: `idbSet('phishtank', url, { flagged: false, cachedAt: now })`
After:  `idbSet('phishtank', url, { failed: true, cachedAt: now })`

## Why

When an API call fails (network timeout, 5xx, DNS error), the old code wrote a negative/clean result to IDB:

- `{ flagged: false }` for Safe Browsing and PhishTank
- `{ result: null }` for RDAP

This created a security hole: a URL that Safe Browsing or PhishTank would have flagged as phishing got a free pass for the full TTL (30 min for SB, 1 h for PhishTank) whenever the API was temporarily unavailable. The heuristic score still applied, but the reputation layer was silently skipped and treated as "clean."

**The attack window:** if an attacker's phishing kit goes up during a period of Safe Browsing API downtime, the first scan caches `flagged: false`. All subsequent scans within the 30-minute TTL serve this cached "clean" result without re-checking, even after the API comes back online.

**The fix:** write `{ failed: true }` instead. The cache read logic now distinguishes three states:

| IDB entry | Meaning | Behavior |
|---|---|---|
| `{ flagged: false, cachedAt }` | API responded: URL is clean | Serve from cache, no penalty |
| `{ flagged: true, cachedAt }` | API responded: URL is malicious | Serve from cache, add score |
| `{ failed: true, cachedAt }` | API call failed | Treat as unchecked; retry after 5 min |
| `null` (no entry) | Never checked | Call the API |

The 5-minute retry window (`FAIL_RETRY_TTL`) prevents hammering a down API on every scan while keeping the unchecked window short.

## Files changed

| File | Change |
|---|---|
| `background.js` | Added `FAIL_RETRY_TTL` constant; fixed cache read and catch block in `checkGoogleSafeBrowsing`, `checkDomainAge`, and `checkPhishTank` |
