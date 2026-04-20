# Unicode NFKC Normalization Before All Checks

## What was added

**`urlAnalyzer.js`**
- `SCORING.UNICODE_NORMALIZATION` - new scoring entry, +50 pts, fires when the raw URL contains Unicode compatibility characters that collapse to different ASCII characters under NFKC normalization
- `normRawUrl` - `rawUrl.normalize('NFKC')`, computed before parsing
- `hasNormVariants` - boolean flag: `normRawUrl !== rawUrl`
- `normHostname` - `hostname.normalize('NFKC').toLowerCase()`, derived after parsing; used for all comparison-based checks
- `normPathname` - `pathname.normalize('NFKC')`; used for all path-based checks
- `isSpoofed` flag - `hasRLO || hasNormVariants`; gates both trusted-domain early exits

## What was improved

**Every comparison-based check in `analyzeURL` was updated to use `normHostname` or `normPathname`:**

| Check | Before | After | Reason |
|-------|--------|-------|--------|
| `checkIPAddress` | `hostname` | `normHostname` | Fullwidth digits `１９２…` collapse to ASCII digits |
| `checkURLShortener` | `hostname` | `normHostname` | Fullwidth domain names collapse to ASCII |
| `checkDomainImpersonation` | `hostname` | `normHostname` | Fullwidth brand names `ｐａｙｐａｌ` collapse before Levenshtein |
| `checkTrustedBrandInSubdomain` | `hostname` | `normHostname` | Fullwidth trusted-brand labels collapse before set lookup |
| `checkBrandInSubdomain` | `hostname` | `normHostname` | Same |
| `checkSuspiciousTLD` | `hostname` | `normHostname` | Fullwidth TLD chars collapse before suffix check |
| `checkIDNHomograph` | `hostname` | `normHostname` | `xn--` is ASCII; no functional change, but consistent |
| `checkFreeHosting` | `hostname` | `normHostname` | Fullwidth hosting domain chars collapse |
| `checkHyphenAbuse` | `hostname` | `normHostname` | Fullwidth hyphen `U+FF0D` collapses to ASCII `-` before counting |
| `checkBrandInPath` | `pathname` | `normPathname` | Fullwidth brand chars in path collapse |
| `checkDangerousExtension` | `pathname` | `normPathname` | Fullwidth extension chars e.g. `．ｅｘｅ` collapse to `.exe` |
| `checkSuspiciousPath` | `pathname` | `normPathname` | Fullwidth keyword chars collapse before matching |
| `checkLookalikeDigits` | `hostname` | `normHostname` | Fullwidth digits collapse to ASCII first, then digit-substitution map applies |
| `checkHighEntropyDomain` | `hostname` | `normHostname` | Entropy measured on ASCII-collapsed form |
| Excessive subdomains | `hostname.split('.')` | `hostParts` (from `normHostname`) | Consistent source |
| `regDomainKey` derivation | `hostname.toLowerCase()` | `normHostname` | Consistent source for trusted-domain lookup |

**`checkSuspiciousCharacters` intentionally kept on original `hostname`** - if we passed `normHostname`, fullwidth chars would already be collapsed to ASCII and the HOMOGRAPH check would silently pass. The original must be preserved here so non-ASCII is still visible for detection.

**Trusted-domain early exits patched:**
- `if (isMultiTLD && !hasRLO)` → `if (isMultiTLD && !isSpoofed)`
- `if (TRUSTED_DOMAINS.has(regDomainKey) && !hasRLO)` → `if (TRUSTED_DOMAINS.has(regDomainKey) && !isSpoofed)`

## Why

NFKC normalization catches a class of homograph attacks that every other check was completely blind to:

**Fullwidth ASCII (U+FF01 to U+FF5E):**
```
ｇｏｏｇｌｅ.com  →  google.com   (after NFKC)
ｐａｙｐａｌ.com  →  paypal.com
```

**Mathematical alphanumeric symbols (U+1D400 to U+1D7FF):**
```
𝗴𝗼𝗼𝗴𝗹𝗲.com  →  google.com   (bold)
𝘨𝘰𝘰𝘨𝘭𝘦.com  →  google.com   (italic)
𝙜𝙤𝙤𝙜𝙡𝙚.com  →  google.com   (bold italic)
```

**Why the check must happen before parsing:**
Chrome's WHATWG URL parser applies IDNA processing to hostnames, which includes Unicode mapping steps that already normalize fullwidth chars. By the time `parsed.hostname` is read, `ｇｏｏｇｌｅ.com` has become `google.com` - the evidence is gone. Comparing `rawUrl` against `rawUrl.normalize('NFKC')` before parsing captures the manipulation before the parser erases it.

**Why the trusted-domain exit must be blocked:**
`ｇｏｏｇｌｅ.com` → parsed hostname = `google.com` → `TRUSTED_DOMAINS.has('google.com')` = `true` → old code returned `score: 0, safe`. With `hasNormVariants` gating the exit, the full analysis runs and `UNICODE_NORMALIZATION` (+50 pts) is added.

**Two-track design - original vs normalized:**
The HOMOGRAPH check (`checkSuspiciousCharacters`) must receive the *original* `hostname` because that check's entire purpose is to detect non-ASCII characters. If we normalized first, fullwidth chars would become ASCII and the check would return false - creating a gap where `UNICODE_NORMALIZATION` fires but `HOMOGRAPH` doesn't. Both checks complement each other and must operate on different inputs.

## Files changed

| File | Change |
|------|--------|
| `urlAnalyzer.js` | Added `SCORING.UNICODE_NORMALIZATION`; added `normRawUrl`, `hasNormVariants` pre-parse checks; added `normHostname`, `normPathname` post-parse; added `isSpoofed` flag; updated 14 check call sites; updated `hostParts`/`regDomainKey` derivation; patched both trusted-domain early exits |
