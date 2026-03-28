# DMARC / SPF / DKIM Header Parsing

## What was added

**`content.js`**

- `AUTH_BANNER_ATTR = 'data-phishguard-auth'` - guard attribute on each email container to prevent duplicate auth banner injection.
- `AUTH_FAIL_SCORES = { dmarc: 40, spf: 30, dkim: 25 }` - penalty weights per failed check.
- `AUTH_HEADER_SELECTORS` - array of DOM selectors for Gmail, Outlook Web App, Yahoo Mail, and ProtonMail header regions (not the email body).
- `AUTH_RESULT_RE` - regex matching `dmarc=<result>`, `spf=<result>`, `dkim=<result>` anywhere in text.
- `parseAuthResults(container)` - two-phase DOM search that locates authentication result text without scanning the email body (to prevent false positives from body content mentioning these keywords). Phase 1 queries known header-area selectors. Phase 2 walks up to 5 ancestor levels and inspects sibling branches that do not contain the body element.
- `buildAuthRisk(authResults)` - maps result strings to score entries. `fail` applies the full penalty; SPF `softfail` applies 15 pts (half of the 30 pt SPF fail penalty). `pass`, `none`, `neutral`, and `permerror` add 0 pts.
- `injectAuthBanner(container, entries, totalScore)` - prepends an inline-styled banner showing each failed check as a pill (`CHECK | result +Xpts`) with a total score contribution and advisory text. The banner is color-coded: red accent for totalScore >= 40 (DMARC fail or equivalent), amber for lower totals.

## What was improved

**`scanEmailContainers()`** in `content.js`:

Auth header parsing is called at the top of the container loop, before the `if (!links.length) continue` guard. This ensures that emails with no links (e.g., pure HTML credential-form emails) are still checked for authentication failures.

The `AUTH_BANNER_ATTR` attribute is set to `'done'` on the container immediately, regardless of whether failures are found, so the DOM scan only ever runs once per email regardless of how many MutationObserver triggers fire.

## Why

### The attack this addresses

Email spoofing lets an attacker send a message with `From: security@yourbank.com` while the actual sending infrastructure is entirely unrelated to the bank. DMARC, SPF, and DKIM are the three email authentication standards that detect this:

| Check | What it verifies |
|---|---|
| SPF | The sending IP is authorized by the domain's DNS to send mail for it |
| DKIM | The message body and key headers were signed by a key published in the domain's DNS |
| DMARC | SPF and/or DKIM pass AND the authenticated domain aligns with the `From:` header |

A DMARC fail is the strongest signal: it means the domain owner has published a policy that explicitly disavows this message. SPF and DKIM fails individually are weaker but still meaningful.

### Why parse from DOM, not the Gmail API

Fetching raw message headers via the Gmail API requires OAuth, user consent, and an API key. The DOM approach is zero-auth and works on any device where the user has Gmail open, including Outlook Web App, Yahoo Mail, and ProtonMail.

### Why search outside the email body

A phisher could embed the text `dmarc=pass spf=pass dkim=pass` in the visible email body to fool a naive full-document scanner. The two-phase approach in `parseAuthResults` restricts the search to DOM regions that are structurally above or sibling to the email body, which are the header metadata areas rendered by the mail client.

### Score weighting rationale

| Fail | Points | Reason |
|---|---|---|
| `dmarc=fail` | +40 | Explicit domain-owner disavowal; policy-level signal |
| `spf=fail` | +30 | Sending server not authorized; hard fail (not softfail) |
| `spf=softfail` | +15 | Authorized-ish but outside expected range; weak signal |
| `dkim=fail` | +25 | Signature invalid or missing; may indicate tampering |

### Banner ordering

`injectAuthBanner` prepends to the container. `injectScanBanner` (called later, after URL results return) also prepends. This naturally produces the correct top-down order:

```
[URL scan results banner]   <- top: immediate, actionable
[Auth failure banner]       <- below: contextual, informational
[Email body]
```

## Files changed

| File | Change |
|---|---|
| `content.js` | Added `AUTH_BANNER_ATTR`, `AUTH_FAIL_SCORES`, `AUTH_HEADER_SELECTORS`, `AUTH_RESULT_RE` constants; added `parseAuthResults()`, `buildAuthRisk()`, `injectAuthBanner()`; updated `scanEmailContainers()` to call auth parsing once per container before the links guard |
