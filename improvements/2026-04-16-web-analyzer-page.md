# Web Analyzer Page (URL + Email)

## What was added
- `analyzer.html` - standalone web app page with URL Analyzer and Email Analyzer tabs
- `analyzer.css` - full-page dark-theme stylesheet consistent with the extension design system
- `analyzer.js` - main app controller: tab switching, analysis dispatch, localStorage auth, history
- `emailAnalyzer.js` - new ES module with 8 email-specific heuristic checks, exports `analyzeEmail()`

## What was improved
- None (all new files)

## Why
Provides a public-facing web interface for the two core analyzers. The tool is fully usable
without any account. Optional sign-in (localStorage-based, no server) enables persistent
analysis history so returning users can review past URL and email checks. This makes the
detection capability accessible outside of the browser extension context.

## Files changed
- `analyzer.html` - full page layout: tabs, URL/email input forms, history sidebar, auth modal
- `analyzer.css` - grid layout, result cards, score ring, history sidebar, modal styles
- `analyzer.js` - auth (register/login/session via localStorage), URL/email analysis dispatch,
                  history persistence, result card renderer
- `emailAnalyzer.js` - 8 checks: reply-to mismatch, display-name spoofing, free email domain,
                       urgency keywords, brand-in-subject, phishing body patterns,
                       suspicious attachment keywords, embedded URL analysis via `analyzeURL()`
