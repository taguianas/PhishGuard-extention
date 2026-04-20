# Analyzer Launcher Button in Popup

## What was added
- New "Analyzer" button in the popup header (`popup.html`) that opens `analyzer.html` in a new browser tab
- `btn-open-analyzer` click handler in `popup.js` using `chrome.tabs.create({ url: chrome.runtime.getURL('analyzer.html') })`
- New CSS classes `.pg-header-actions` and `.pg-header-btn` in `popup.css` for the header button group styling (accent hover, matches existing dark theme)
- Wrapper `<div class="pg-header-actions">` in the popup header that groups the new Analyzer button and the existing Settings gear

## What was improved
- The popup header layout was reorganized so the Settings gear is no longer a lone action: it now sits inside `.pg-header-actions` next to the new launcher, giving the header a proper action group

## Why
`analyzer.html` (the full-page URL + Email analyzer) was added in `2026-04-16-web-analyzer-page.md` but was unreachable from the extension itself: no link in the popup, no link in settings, not referenced in the manifest. Users had no way to discover or open it. Exposing it from the popup makes the analyzer accessible with one click, which is the main entry point for the user flow described: anyone can run URL / email analysis without any sign-in, and signing in only unlocks the optional saved-history sidebar (already implemented in `analyzer.js` via the `if (!username) return;` guard in `pushHistory`).

## Files changed
- `popup.html` - replaced the bare settings anchor with a `.pg-header-actions` wrapper containing the new `#btn-open-analyzer` button (magnifier SVG icon + "Analyzer" label) and the existing `#btn-settings` gear
- `popup.js` - added `chrome.tabs.create` click handler for `#btn-open-analyzer` inside the existing `DOMContentLoaded` listener
- `popup.css` - added `.pg-header-actions` flex container and `.pg-header-btn` style with accent hover; existing `.pg-settings-btn` rules left unchanged
