# Right-Click "Analyze link with PhishGuard"

## What was added
- Chrome context menu item registered in [background.js](../background.js) with `id = 'phishguard-analyze-link'` that appears on any element with `contexts: ['link']`
- `registerContextMenu()` helper that calls `chrome.contextMenus.removeAll()` before `create()` so reloading the extension never produces duplicate menu items
- `chrome.runtime.onInstalled` and `chrome.runtime.onStartup` listeners both registered to `registerContextMenu` (the service worker can be cold-started either way)
- `chrome.contextMenus.onClicked` listener that filters on the menu id, reads `info.linkUrl`, and opens `analyzer.html?url=<encoded-link>` in a new tab via `chrome.tabs.create` with `chrome.runtime.getURL`
- `autoAnalyzeFromQuery()` IIFE at the end of [analyzer.js](../analyzer.js) that reads `?url=` from `window.location.search`, fills `#url-input`, and calls `runURLAnalysis()` immediately

## What was improved
- The `contextMenus` permission was already declared in the manifest but had no code using it. It is now wired up.
- The analyzer page, previously only reachable from the popup's "Analyzer" button with an empty form, now accepts a URL prefill through a query string, enabling one-click analysis flows from anywhere.

## Why
Phishing links reach users in many places outside of their email client: Discord, Slack, Twitter, forums, search results, documents. The existing extension only scans links inside supported webmail clients (Gmail / Outlook / Yahoo / Proton / iCloud / Zoho / Yandex / GMX / Fastmail). With the new context menu, a user can right-click any link on any site and run the full PhishGuard analyzer against it in seconds, without copy-pasting the URL, and without ever signing in. This dramatically widens the coverage of the tool and keeps the existing "sign-in only saves history" policy intact: anonymous users still get the verdict, signed-in users additionally get the entry stored in their sidebar.

## Files changed
- `manifest.json` - `permissions` array gained `"activeTab"` (needed for the companion popup feature; context menu itself only needs `contextMenus`, which was already present)
- `background.js` - appended the context menu block after the init IIFE (approx. lines 893-920): `PG_CTX_MENU_ID` constant, `registerContextMenu()`, `chrome.runtime.onInstalled` + `onStartup` listeners, `chrome.contextMenus.onClicked` listener
- `analyzer.js` - appended `autoAnalyzeFromQuery()` IIFE after the `renderAuthArea(); renderHistory();` init lines, reads `URLSearchParams` for `url`, prefills `urlInput.value`, calls `runURLAnalysis()`
