# Sender Domain Impersonation Detection

## What was added

**`background.js`**
- `'ANALYZE_SENDER'` message handler entry in `chrome.runtime.onMessage.addListener`.
- `handleAnalyzeSender(domain)` function: constructs `https://<domain>/` and runs it through the existing `analyzeURL()` heuristic engine, then applies the OpenPhish threat feed check (domain-level) and RDAP domain age scoring. Skips Safe Browsing, PhishTank, and URLHaus because those APIs expect full phishing URLs, not sender domains.

**`content.js`**
- `SENDER_BANNER_ATTR = 'data-phishguard-sender'` constant — guard attribute preventing duplicate analysis per container.
- `extractSenderDomain(container)` — three-phase DOM search for the sender's email domain:
  - **Phase 1**: Gmail's `.gD[email]` attribute (most reliable; Gmail renders `<span class="gD" email="x@y.com">`). Stops at `.nH` / `.adO` to avoid picking up a different message's sender in a thread.
  - **Phase 2**: email-address pattern in known `AUTH_HEADER_SELECTORS` elements that are outside the body.
  - **Phase 3**: `From:` regex pattern in sibling branches of the container's ancestors.
- `analyzeSenderDomain(container)` — async wrapper that sets the guard attribute immediately, calls `extractSenderDomain`, and sends `ANALYZE_SENDER` to background. Returns `{ result, domain }` or `null`.
- `injectSenderWarning(container, analysis, domain)` — prepends an inline-styled warning banner when `riskLevel` is `suspicious` or `high-risk`. Shows the domain in monospace, up to 4 heuristic indicator lines, a risk score pill, and advisory text color-coded by severity.

## What was improved

**`scanEmailContainers()`** in `content.js`:
- `analyzeSenderDomain(container)` is kicked off as a promise immediately after the synchronous auth check — before `extractLinks` — so it runs in parallel with link extraction.
- `!links.length` early-continue path now awaits `senderPromise` before continuing, so emails with no links (e.g., pure credential-form emails) still get a sender warning if warranted.
- `senderPromise` is awaited BEFORE `injectScanBanner`, not after. This ensures the scan banner's `prepend` is the last DOM write, keeping it visually on top.

**Banner visual ordering** (top to bottom after a full scan):
```
[URL scan banner]         <- prepended last (injectScanBanner)
[Sender warning]          <- prepended second-to-last (injectSenderWarning)
[Auth failure banner]     <- prepended first (injectAuthBanner)
[Email body]
```

## Why

### The attack

Most credential-phishing emails rely on sender spoofing: the `From:` display name says "PayPal Security" but the actual sending domain is `paypa1-accountsupport.com` or `secure-paypal.verify-id.net`. Link analysis alone misses this — the email body links might go to a freshly registered lookalike, but the initial trust signal a user sees is the sender.

Running the sender domain through the existing heuristic engine catches:
- **Typosquatting** — `paypa1.com`, `micros0ft.com` (Levenshtein distance <= 2 from a brand)
- **Homoglyph substitution** — `pаypal.com` (Cyrillic а instead of Latin a)
- **Brand keyword in non-trusted domain** — `paypal-verify-now.com`
- **Subdomain spoofing** — `paypal.com.login-secure.ru`
- **Suspicious TLD** — `paypal.top`, `amazon.xyz`
- **Newly registered domain** (via RDAP) — domain registered 3 days ago, impersonating a bank

All of these checks already exist in `urlAnalyzer.js`. This feature reuses them at zero implementation cost.

### Why only heuristics + feed + RDAP (no Safe Browsing / PhishTank / URLHaus)

| API | Designed for | Suitable for sender domain? |
|---|---|---|
| Safe Browsing | Full phishing/malware URLs | No — the fake `https://domain/` URL will rarely be in Google's URL database |
| PhishTank | Specific confirmed phishing page URLs | No — checks exact URLs, not domains |
| URLHaus | Malware distribution URLs | No — abuse.ch is malware-focused, not sender-domain spoofing |
| OpenPhish | Phishing domain feed | Yes — domain-level entries |
| RDAP | Domain registration age | Yes — new domains impersonating brands are a primary indicator |

### Why stop at `.nH` / `.adO` in Phase 1

Gmail renders an entire email thread inside a single `.nH` wrapper. If we climb too high, we might find the `.gD[email]` of a different message in the thread and attribute the wrong sender to the body we're analyzing. Stopping at `.nH` or `.adO` (Gmail's per-message container) ensures we only find the sender for the specific message.

### TRUSTED_DOMAINS pass-through

`analyzeURL()` exits early with `riskLevel: 'safe'` for any domain in `TRUSTED_DOMAINS` (google.com, microsoft.com, paypal.com, etc.). This means legitimate emails from known brands never trigger a false-positive sender warning.

## Files changed

| File | Change |
|---|---|
| `background.js` | Added `'ANALYZE_SENDER'` to message handler; added `handleAnalyzeSender(domain)` function |
| `content.js` | Added `SENDER_BANNER_ATTR` constant; added `extractSenderDomain()`, `analyzeSenderDomain()`, `injectSenderWarning()`; updated `scanEmailContainers()` banner ordering and `!links.length` path |
