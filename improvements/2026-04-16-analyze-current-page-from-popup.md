# Analyze Current Page from Popup

## What was added
- `openAnalyzerForActiveTab()` function in [popup.js](../popup.js) that calls `chrome.tabs.query({ active: true, currentWindow: true })`, tests the returned tab URL with `/^https?:\/\//i`, and either opens `analyzer.html?url=<encoded-url>` when the active tab is a real web page or opens `analyzer.html` bare when the active tab is a chrome-internal page, an extension page, or unreadable
- `"activeTab"` added to the `permissions` array in [manifest.json](../manifest.json) so that `chrome.tabs.query` returns the `url` field for the tab the user just invoked the extension on

## What was improved
- The `#btn-open-analyzer` click handler, added in the previous improvement (`2026-04-16-analyzer-launcher-in-popup.md`), has been upgraded. It was bound directly to `chrome.tabs.create` with a static analyzer URL. It now delegates to `openAnalyzerForActiveTab`, which preserves the existing "open empty analyzer" behavior for non-web tabs while adding the prefill behavior for ordinary web pages.
- Reuses the `?url=` query-string contract introduced for the context menu feature (`2026-04-16-context-menu-link-analyzer.md`). One mechanism, two entry points, no duplicate prefill logic.

## Why
Users often open the popup while looking at a page they are unsure about. The previous flow forced them to copy the address bar, open the analyzer, paste, and click Analyze. This now becomes a single click on the popup's "Analyzer" button: the active tab URL is passed through, and `autoAnalyzeFromQuery()` in `analyzer.js` runs the analysis immediately on page load. The analysis remains anonymous by default (no sign-in required), with history saving gated on login via the existing `pushHistory` guard in `analyzer.js`. Using `activeTab` instead of the broader `"tabs"` permission keeps the permission surface minimal: access is granted only for the tab the user explicitly engaged with by opening the popup, not for every tab in the browser.

## Files changed
- `manifest.json` - added `"activeTab"` to the `permissions` array (same change as the context-menu improvement; declared here because the popup prefill is what actually needs it)
- `popup.js` - the `DOMContentLoaded` handler now binds `#btn-open-analyzer` to `openAnalyzerForActiveTab` instead of an inline arrow function; `openAnalyzerForActiveTab` defined immediately after the `DOMContentLoaded` block
- No changes to `analyzer.js` for this feature specifically: the `autoAnalyzeFromQuery()` IIFE added for the context-menu feature already handles the prefill and auto-run for any entry point that opens `analyzer.html?url=...`
