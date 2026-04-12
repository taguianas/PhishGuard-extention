# Per-User Domain Allowlist via Context Menu

## What was added

**`manifest.json`**

- `"contextMenus"` added to `permissions` array: required for `chrome.contextMenus` API.
- `"https://www.virustotal.com/*"` added to `host_permissions`: was missing from the VirusTotal feature (Feature 10).

**`background.js`**

- `CONTEXT_MENU_ID = 'phishguard-allow-domain'` constant.
- `EMAIL_PATTERNS` array: the six email client URL patterns where the context menu appears. Restricts the menu item to relevant pages only.
- `chrome.contextMenus.create()` call: creates a single "PhishGuard: Allow this domain" menu item for `contexts: ['link']`, scoped to `documentUrlPatterns: EMAIL_PATTERNS`. Called at service worker startup; suppresses "duplicate id" errors on SW restarts.
- `chrome.contextMenus.onClicked` listener: extracts the hostname from `info.linkUrl`, calls the existing `handleFeedback(url, domain, 'safe', [])` to add the domain to the allowlist. Logs the action to console.
- `GET_ALLOWLIST` message handler: returns the `allowlist` map from `phishguard_feedback` storage. Used by the settings page to render the allowlist table.
- `REMOVE_ALLOWLIST` message handler: deletes a specific domain from the allowlist, saves the updated feedback object, and responds with `{ ok: true }`. Used by the settings page's remove button.

**`settings.html`**

- New "Domain Allowlist" section between Domain Age and About:
  - Descriptive text explaining that allowlisted domains get reduced risk scores.
  - Empty-state message ("No domains allowlisted yet.").
  - A table with columns: Domain, Times Marked Safe, Last Marked, and a remove button column.
  - The table is hidden when the allowlist is empty, shown when populated.

**`settings.js`**

- `loadAllowlist()` function: sends `GET_ALLOWLIST` to background, renders the allowlist table sorted by most recently marked safe. Each row shows the domain (monospace), mark count, formatted date, and a remove button.
- `removeAllowlistEntry(domain)` function: sends `REMOVE_ALLOWLIST` with the domain, then reloads the allowlist to reflect the removal.
- `loadAllowlist()` is called on page load alongside `loadSettings()`.

**`settings.css`**

- `.pg-btn-remove` class: styled as a compact red-outlined button with ✕ character. On hover, fills solid red with white text for clear destructive-action signaling.
- `.pg-empty` class: italic muted text for empty-state messages.

## What was improved

The allowlist system built in Feature 11 (user feedback loop) had no way to manage entries outside of the tooltip buttons. Users could add domains to the allowlist but had no UI to view or remove them. This feature adds:

1. **Right-click context menu** for one-click allowlisting from any flagged link, without needing to hover and click the tooltip button.
2. **Settings page management** for reviewing and removing allowlisted domains, giving users full control over their allowlist.

## Why

### The gap

Feature 11 added tooltip buttons for "Mark as Safe" / "Confirm Phishing". But there are two problems:
1. The tooltip buttons only appear on hover and require a multi-step interaction (hover, read tooltip, click button). A right-click context menu is faster for users who already know a domain is safe.
2. Once a domain is allowlisted, there is no way to remove it without editing code or clearing all extension data. Users need a management UI to review and clean up their allowlist.

### Why `chrome.contextMenus`

The context menu API is the standard Chrome extension pattern for right-click actions. It integrates naturally with the browser's existing right-click flow, requires no DOM injection, and works on any link element. Using `documentUrlPatterns` restricts the menu item to the six supported email clients, so it does not clutter right-click menus on other sites.

### Why reuse `handleFeedback`

The context menu click handler calls the same `handleFeedback(url, domain, 'safe', [])` that the tooltip buttons use. This ensures a single code path for allowlist management: one storage format, one adjustment algorithm, no divergence.

### Why the empty `[]` indicators array

When allowlisting via context menu, we don't have access to the specific indicators that triggered the warning (unlike the tooltip path, which reads them from the DOM). Passing an empty array means the allowlist entry starts with zero per-indicator dismissals. The allowlist adjustment formula handles this gracefully: `entry.count` still increments, and after 3 context-menu marks the score reduction kicks in even without indicator-level tracking (via the `entry.count < 3` guard and the 0.3 ratio floor).

### Why the settings page table

Users need visibility into what they've allowlisted. The table shows domain, number of times marked safe, and when it was last marked. The remove button sends `REMOVE_ALLOWLIST` to background, which deletes the entry from `phishguard_feedback.allowlist` and the table refreshes. This gives users full reversibility.

## Files changed

| File | Change |
|---|---|
| `manifest.json` | Added `"contextMenus"` to permissions; added `"https://www.virustotal.com/*"` to host_permissions |
| `background.js` | Added context menu creation, click handler, `GET_ALLOWLIST` and `REMOVE_ALLOWLIST` message handlers |
| `settings.html` | Added Domain Allowlist section with table and empty-state message |
| `settings.js` | Added `loadAllowlist()` and `removeAllowlistEntry()` functions |
| `settings.css` | Added `.pg-btn-remove` and `.pg-empty` classes |
