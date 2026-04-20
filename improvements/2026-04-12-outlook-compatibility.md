# Outlook Compatibility Fix

## What was added

**`content.js`**

- Outlook-specific selectors in `EMAIL_BODY_SELECTORS`:
  - `[data-app-section="ConversationContainer"] [role="document"]`
  - `div[class*="allowTextSelection"]`
  - `div.customScrollBar[role="region"]`
- Outlook-specific selectors in `AUTH_HEADER_SELECTORS`:
  - `[role="heading"][aria-level]`
  - `[class*="senderContainer"]`
  - `[class*="FromContainer"]`
  - `[class*="ItemHeader"]`
- Outlook-specific path in `extractSenderDomain()`: queries `[class*="senderContainer"] [title]`, `[class*="FromContainer"] [title]`, `[class*="ItemHeader"] [title]`, `[role="heading"] [title]`, `button[title*="@"]`, `span[title*="@"]`, and `[aria-label*="@"]` to find the sender email address in Outlook's DOM.
- Iframe fallback in `findEmailContainers()`: when no containers are found and the script is running inside an iframe (`window !== window.top`), falls back to `document.body` if it contains any anchor elements.

**`manifest.json`**

- `https://outlook.com/*` added to both `content_scripts.matches` and `host_permissions`: the bare `outlook.com` domain was missing, causing the content script not to load on that URL variant.
- `"all_frames": true` added to the content scripts block: Outlook renders email content inside iframes, so the content script must run in all frames to reach the actual email DOM.

**`background.js`**

- `https://outlook.com/*` added to `EMAIL_PATTERNS`: ensures the context menu appears on the bare Outlook domain as well.

## What was improved

PhishGuard worked in Gmail but failed silently in Outlook. Five root causes were identified and fixed:

1. **Missing URL pattern:** `https://outlook.com/*` was not in the manifest's `matches` or `host_permissions` arrays. Users accessing Outlook via that URL variant would never see the content script load.

2. **No iframe support:** Outlook renders email bodies inside nested iframes. Without `all_frames: true`, the content script only ran in the top-level frame, which contains navigation chrome but no email content.

3. **Fragile DOM selectors:** `EMAIL_BODY_SELECTORS` and `AUTH_HEADER_SELECTORS` were written for Gmail's DOM structure. Outlook uses completely different class names and ARIA attributes.

4. **Gmail-specific sender extraction:** `extractSenderDomain()` relied on Gmail's `[email="..."]` attribute pattern. Outlook stores sender information in `title` and `aria-label` attributes on spans and buttons.

5. **No iframe fallback:** Even with `all_frames: true`, if none of the email body selectors matched (e.g., due to a DOM restructure), there was no fallback. The new iframe detection checks `window !== window.top` and uses `document.body` as a last resort.

Additionally, console logs and doc comments were updated from "Gmail"-specific wording to platform-neutral wording ("monitoring email" instead of "monitoring Gmail").

## Why

### The gap

PhishGuard was built and tested exclusively against Gmail's DOM. Outlook was listed as a supported platform in the manifest's `matches` array, but the actual content script logic was tightly coupled to Gmail's HTML structure. When a user opened Outlook, the content script either did not load at all (missing URL pattern, no iframe support) or loaded but found zero email containers (wrong selectors).

### Why `all_frames: true`

Gmail renders email content in the main document. Outlook renders it inside one or more iframes. Chrome's content script injection defaults to `all_frames: false`, meaning the script only runs in the top frame. Setting `all_frames: true` ensures the script runs in every frame, including the ones where Outlook places the actual email body and links.

### Why the iframe fallback

Even with correct selectors, Outlook occasionally restructures its DOM across updates. The iframe fallback (`window !== window.top` plus checking for anchor elements) provides a safety net: if no selector matches but the frame contains links, we scan it anyway. This makes the extension resilient to minor Outlook DOM changes.

### Why platform-neutral logging

The content script now runs on Gmail, Outlook, Yahoo Mail, and ProtonMail. Logging "monitoring Gmail" when running on Outlook is confusing during debugging. The updated messages say "monitoring email" so they are accurate regardless of which client loaded the script.

## Files changed

| File | Change |
|---|---|
| `manifest.json` | Added `https://outlook.com/*` to matches and host_permissions; added `all_frames: true` |
| `content.js` | Added Outlook selectors, Outlook sender extraction, iframe fallback, platform-neutral logging |
| `background.js` | Added `https://outlook.com/*` to `EMAIL_PATTERNS` |
