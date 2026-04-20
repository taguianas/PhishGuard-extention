# Developer risk level: False Positive Reduction for Developers

## What was added
- New risk level `'developer'` inserted between `'safe'` and `'suspicious'` in the risk hierarchy.
- `DEVELOPER_DOMAIN_SUFFIXES` set in `urlAnalyzer.js`: 27 well-known dev/preview/staging hosts (replit.dev, repl.co, glitch.me, glitch.com, stackblitz.io, codesandbox.io, codepen.io, jsfiddle.net, plnkr.co, ngrok.io, ngrok-free.app, ngrok.app, loca.lt, trycloudflare.com, githubpreview.dev, gitpod.io, localhost.run, vercel.app, netlify.app, onrender.com, railway.app, fly.dev, herokuapp.com, pages.dev, workers.dev, lovable.app, bolt.new).
- `DEVELOPER_EXACT_HOSTS` set for bare loopback hosts: `localhost`, `127.0.0.1`, `0.0.0.0`, `::1`, `[::1]`.
- `isPrivateIP(hostname)` helper: matches RFC 1918 IPv4 (10/8, 172.16/12, 192.168/16), loopback (127/8), link-local (169.254/16), IPv4 0/8, and IPv6 loopback (`::1`), unique-local (`fc00::/7`, `fd00::/8`), link-local (`fe80::/10`).
- `isDeveloperHost(hostname)` helper: strips `www.`, matches exact hosts, private IPs, or any registered dev suffix (exact or subdomain).
- `SCORING.DEVELOPER_HOST` entry: `{ score: 15, label: '...' }`.
- New CSS classes: `a.phishguard-developer` (dashed blue outline), `.phishguard-tooltip.dev-level`, `.phishguard-verdict.dev`, `.phishguard-advice.info`, `.phishguard-tooltip.dev-level .phishguard-ind-score` (blue informational pill).

## What was improved
- `analyzeURL()` early-return: if the host is a developer host AND is not spoofed (no RLO / NFKC variants), returns immediately with `riskLevel: 'developer'`, bypassing the IP_ADDRESS (+60) and FREE_MALICIOUS_TLD penalties that used to mark `127.0.0.1` and `10.0.0.5` as high-risk.
- `background.js` threat-feed pipeline: introduced `isDeveloper` flag and skipped Layer 3 (RDAP), Layer 4 (PhishTank), Layer 5 (URLHaus), Layer 6 (VirusTotal) for dev hosts to preserve quota; Layer 1 (OpenPhish) and Layer 2 (Safe Browsing) still run, so genuinely malicious `*.replit.dev` phishing pages still escalate.
- `content.js applyWarning()`: now a three-way switch (critical / suspicious / developer) for link class, tooltip modifier, verdict label, and advice copy. Developer advice is informational: "Development / preview host: unless you expected this link, verify before entering credentials."
- `countProcessedLinks()` and `injectScanBanner()`: now count developer links separately and show a distinct blue banner: "X developer/preview link(s) detected: low risk, verify if unexpected."
- Spoofing takes precedence: `if (!isSpoofed && isDeveloperHost(...))` ensures a replit.dev host with bidi override or NFKC lookalike still falls through to full high-risk scoring.

## Why
Developers and technical users routinely receive and send links to:
- Local servers (`localhost`, `127.0.0.1`, private RFC 1918 IPs) during dev testing.
- Ephemeral preview deploys (`vercel.app`, `netlify.app`, `*.pages.dev`, `*.workers.dev`).
- Code sandboxes (`replit.dev`, `glitch.me`, `stackblitz.io`, `codesandbox.io`).
- Tunnel services (`ngrok.io`, `*.trycloudflare.com`, `loca.lt`).

Before this change these hosts triggered IP_ADDRESS (+60), FREE_MALICIOUS_TLD, and occasionally NO_HTTPS penalties, landing at high-risk with alarming red tooltips. Technical users learned to ignore PhishGuard warnings, which erodes trust for the cases that actually matter. The developer level keeps these hosts visible (blue dashed outline, informational pill, +15 score) without crying wolf, while still allowing OpenPhish and Safe Browsing to override to high-risk for genuine abuse on these same shared platforms.

## Files changed
- `urlAnalyzer.js`: added `DEVELOPER_DOMAIN_SUFFIXES`, `DEVELOPER_EXACT_HOSTS`, `isPrivateIP()`, `isDeveloperHost()`, `SCORING.DEVELOPER_HOST`, and the early-return block inside `analyzeURL()` (placed after the `isSpoofed` check, before check #1 IP address).
- `background.js`: added `const isDeveloper = analysis.riskLevel === 'developer';` in `handleAnalyzeURLs` loop; added `&& !isDeveloper` guard to Layers 3, 4, 5, 6.
- `content.js`: rewrote `applyWarning()` to three risk levels; updated `countProcessedLinks()` to track developer count; updated `injectScanBanner()` with developer branch and blue status color `#4a90d9`.
- `styles.css`: added `a.phishguard-developer`, `.phishguard-tooltip.dev-level`, `.phishguard-verdict.dev`, `.phishguard-advice.info`, and the `.phishguard-tooltip.dev-level .phishguard-ind-score` blue pill override; adjusted the red-pill selector to `:not(.warn-level):not(.dev-level)`.
