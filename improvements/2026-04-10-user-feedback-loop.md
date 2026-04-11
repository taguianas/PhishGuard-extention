# User Feedback Loop - "Mark as Safe" / "Confirm Phishing"

## What was added

**`content.js`**

- `escapeAttr(str)` helper: escapes a string for safe use inside a double-quoted HTML attribute value. Prevents XSS if URL or domain contains special characters.
- `handleFeedbackClick(e)` function: click handler using event delegation on the tooltip.
  - Reads `data-fb` attribute from the clicked button (`'safe'` or `'phishing'`).
  - Reads URL and domain from `data-phishguard-fb-url` / `data-phishguard-fb-domain` attributes on the `.phishguard-feedback` container.
  - Collects indicator labels from the tooltip's `<ul>`.
  - Sends `SUBMIT_FEEDBACK` message to background.js (fire-and-forget).
  - Replaces the button row with a confirmation message ("Marked as safe - score will be adjusted" or "Confirmed phishing - thank you").
- Updated `applyWarning()`: tooltip now includes a `.phishguard-feedback` div with two buttons (`Phishing` and `Safe`) after the advice section. The tooltip gets a click event listener wired to `handleFeedbackClick`.

**`background.js`**

- `FEEDBACK_KEY = 'phishguard_feedback'` constant: storage key in `chrome.storage.local`.
- `loadFeedback()` / `saveFeedback(fb)`: read/write the feedback object from chrome.storage.local.
- `handleFeedback(url, domain, feedback, indicators)`:
  - On `'safe'`: creates or updates the domain's allowlist entry with a count, timestamp, and per-indicator dismissal tally. Removes the URL from the confirmed-phishing map (in case the user changed their mind).
  - On `'phishing'`: stores confirmation with timestamp and indicators. Removes the domain from the allowlist (in case the user changed their mind).
- `applyAllowlistAdjustment(analysis)`:
  - Called after all 6 detection layers complete, before the result is pushed.
  - Loads the feedback store. If the analysis domain has an allowlist entry, counts how many current indicators were previously dismissed.
  - Applies a score reduction proportional to: (a) fraction of dismissed indicators, and (b) number of times the user marked the domain safe (capped at 5).
  - Reduction is hard-capped at 80% of the original score, so even an allowlisted domain can still be flagged if it triggers enough new indicators.
  - Appends a negative-score indicator entry so the user can see the adjustment in the tooltip.
- `SUBMIT_FEEDBACK` message type added to `chrome.runtime.onMessage` listener, routing to `handleFeedback`.

**`styles.css`**

New classes for the feedback UI:
- `.phishguard-feedback` - flex row with top border separating it from the advice section
- `.phishguard-feedback-label` - "Is this correct?" label (uppercase, gray)
- `.phishguard-fb-btn` - base button styles (shared)
- `.phishguard-fb-phishing` / `.phishguard-fb-phishing:hover` - red ghost button
- `.phishguard-fb-safe` / `.phishguard-fb-safe:hover` - green ghost button
- `.phishguard-fb-done` - italic confirmation text replacing buttons after click
- `.phishguard-fb-done-safe` - green variant
- `.phishguard-fb-done-phishing` - red variant

## What was improved

**Detection pipeline in `handleAnalyzeURLs()`**: `applyAllowlistAdjustment(analysis)` is called after all 6 detection layers but before the result is pushed to the results array. This ensures the allowlist interacts with the full score rather than an intermediate one.

**`pruneAllCaches()`**: now also prunes the `'virustotal'` IDB store.

## Why

### The problem

Every heuristic-based system produces false positives. A user who frequently receives legitimate emails from a domain with an unusual structure (e.g., a corporate domain that triggers subdomain brand checks) will see repeated warnings they cannot dismiss. Over time, this trains the user to ignore all warnings, defeating the purpose of the extension.

### How the feedback loop solves it

1. **Immediate relief**: clicking "Safe" replaces the buttons with a confirmation message so the user knows the feedback was registered.
2. **Future scoring adjustment**: when the same domain appears again, `applyAllowlistAdjustment` reduces the score based on how many of the same indicators the user previously dismissed. If 100% of the indicators are the same ones the user marked as safe, the score drops significantly. If new indicators appear (e.g., the domain starts triggering VirusTotal hits), the reduction is smaller and the warning stays visible.
3. **Cap at 80%**: the maximum score reduction is 80%, so a domain cannot be fully silenced by the allowlist alone. If a previously "safe" domain gets compromised and starts triggering new high-severity indicators, the warning will still surface.
4. **Confirm phishing**: positive feedback goes into the confirmed-phishing log and removes the domain from the allowlist (if it was there). This gives the user a way to undo a mistaken "safe" marking.
5. **Mutual exclusion**: marking a domain safe removes it from the confirmed map, and confirming phishing removes it from the allowlist. Users can flip their judgment at any time.

### Why per-indicator tracking

A naive allowlist would suppress all warnings for a domain. But a domain might be legitimately triggering "brand in subdomain" (because the company actually uses that pattern) while also having a new indicator like "VirusTotal: flagged by 5 engines." Tracking which specific indicators were dismissed lets the system distinguish between "indicators the user already reviewed and accepted" and "new indicators that deserve attention."

### Why the reduction formula

```
reduction = min(
  floor(score * max(ratio, 0.3) * min(count, 5) / 5),
  floor(score * 0.8)
)
```

- `ratio` = fraction of current indicators that were previously dismissed (0 to 1)
- `count` = number of times the user marked this domain safe (capped at 5)
- `0.3` floor on ratio: even if only 1 out of 5 indicators was previously dismissed, the user still gets a small reduction (they told us they trust this domain)
- `count / 5` ramp: the first "safe" mark gives a 20% effect; by the 5th mark the full ratio applies
- `0.8` hard cap: never reduce more than 80% of the original score

## Files changed

| File | Change |
|---|---|
| `content.js` | Added `escapeAttr()`, `handleFeedbackClick()`; updated `applyWarning()` tooltip HTML to include feedback buttons and click listener |
| `background.js` | Added `FEEDBACK_KEY`, `loadFeedback()`, `saveFeedback()`, `handleFeedback()`, `applyAllowlistAdjustment()`; added `SUBMIT_FEEDBACK` message handler; wired allowlist adjustment into `handleAnalyzeURLs` after all 6 detection layers; added VT to `pruneAllCaches()` |
| `styles.css` | Added `.phishguard-feedback`, `.phishguard-feedback-label`, `.phishguard-fb-btn`, `.phishguard-fb-phishing`, `.phishguard-fb-safe`, `.phishguard-fb-done`, `.phishguard-fb-done-safe`, `.phishguard-fb-done-phishing` |
