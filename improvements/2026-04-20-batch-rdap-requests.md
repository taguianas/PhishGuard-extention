# Batch RDAP Requests

## What was added
- Phase-split pipeline in `handleAnalyzeURLs()` with an explicit Phase 2 batch step for RDAP domain-age lookups.
- `rdapDomains` set built by iterating all `pending` analyses once and de-duplicating by `analysis.domain`.
- `Promise.all([...rdapDomains].map(d => checkDomainAge(d)))` fan-out for parallel unique-domain lookups.
- `ageMap: Map<domain, ageInfo|null>` indexed lookup when applying scores back to each analysis.
- Console summary log: `[PhishGuard] RDAP batch: N unique domain(s) for M URL(s)` so the dedup ratio is visible in dev-tools.

## What was improved
- Previous flow walked URLs one at a time and called `await checkDomainAge(analysis.domain)` inside the per-URL loop. For an email with N links to the same registered domain (a very common newsletter / marketing pattern), that was N sequential awaits: even when the IDB cache absorbed the actual HTTP call, N back-to-back IDB round trips still blocked the pipeline.
- The new Phase 2 collects unique eligible domains once, then parallelizes: 1 HTTP call per unique domain, and independent domains overlap their latency instead of queueing. For the 20-identical-domains example the worst case drops from 20 serial lookups to 1 network call plus 19 map lookups.
- Layers 4, 5, 6 (PhishTank, URLHaus, VirusTotal) still run per-URL in Phase 3, but they no longer sit behind a chain of RDAP awaits, so their start time is deterministic and earlier on average.
- Same eligibility rules preserved: `score > 0`, not a developer host, no OpenPhish hit, no Safe Browsing hit. The re-application loop in Phase 2 re-checks these flags so a URL that got `threatFeedHit` or `safeBrowsingHit` in Phase 1 still skips the age scoring even if another analysis for the same domain is eligible.

## Why
- RDAP lookups were the slowest synchronous step in the per-URL pipeline (up to 6 s timeout each). Serializing N of them for the same domain was pure waste: the result is identical for every URL under that registered domain.
- Rendering the tooltip / banner waits on `handleAnalyzeURLs()` returning, so shaving per-URL RDAP time directly reduces the user-visible "scanning" delay on link-heavy emails.
- Respects the existing IDB cache (24 h TTL) and failed-call retry window (5 min): unique-domain fan-out still goes through `checkDomainAge()` which short-circuits on cache hits, so the optimization is free on already-warm caches and only helps cold ones.
- Keeps API-quota behavior identical: de-duplication can never increase RDAP traffic, only decrease it.

## Files changed
- `background.js`: refactored `handleAnalyzeURLs()` into three phases (Phase 1 heuristic + OpenPhish + Safe Browsing, Phase 2 batch RDAP, Phase 3 per-URL paid layers + allowlist + notifications). No change to `checkDomainAge()` itself, `handleAnalyzeSender()` (already single-domain), scoring rules, or IDB cache layout.
