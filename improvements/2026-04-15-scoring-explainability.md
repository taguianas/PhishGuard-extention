# Scoring Explainability

## What was added

**`content.js`**

- Each indicator in the link tooltip now renders as two parts: the human-readable label and a score pill showing the point contribution (e.g., `Brand keyword in subdomain on untrusted domain` `+35 pts`). Implemented in `applyWarning()` by emitting `<span class="phishguard-ind-label">` and `<span class="phishguard-ind-score">` inside each `<li>`.
- New `data-indicator-label` attribute on every indicator `<li>`. The feedback handler reads this attribute instead of `textContent` so the clean label (without the "+N pts" pill) is what gets sent to the background allowlist.

**`popup.js`**

- `renderIndicators()` accepts both legacy string indicators and the new `{score, label}` object form. When a score is present, it renders a separate `<span class="pg-ind-score">+N pts</span>` next to the label.
- `exportCSV()` formats indicator entries as `Label (+N pts)` when a score is present, falling back to the bare label for legacy entries.

**`styles.css`**

- New `.phishguard-ind-label` and `.phishguard-ind-score` classes for the link tooltip. The score pill uses a monospace font, a subtle warning-toned background, and is right-aligned within a flex `<li>` row.
- `.phishguard-tooltip-body ul li` now uses flex layout so the label and score pill align cleanly.

**`popup.css`**

- New `.pg-ind-label` and `.pg-ind-score` classes for the popup dashboard's indicators list, mirroring the tooltip layout but using the popup's `--warn` color palette.
- `.pg-indicators li` now uses flex layout to position the label and the score pill on the same row.

## What was improved

**`background.js`**

- `stats.recentIndicators` (the rolling list of recent indicator labels shown in the popup) now stores `{score, label}` objects instead of plain label strings. The dedup check was updated to compare by `label` while preserving any pre-existing string entries.
- `stats.log[].indicators` now stores `{score, label}` objects instead of an array of label strings. The popup's CSV export and indicator renderer were updated to handle both formats so existing log entries from older versions still display correctly.

## Why

The tooltip and popup already listed the indicators that triggered a warning, but every indicator looked equally important. A user looking at six warnings had no way to know which one drove the score from "safe" to "high-risk" (a `+75 pts` RLO attack) versus which one was a small contributor (a `+10 pts` HTTP-only signal). The score breakdown was already computed inside `urlAnalyzer.js` (each `add()` call pushes `{score, label}`), but the score field was being thrown away at the rendering boundary.

Surfacing the per-indicator score:

1. **Builds trust.** Users see exactly how the 0-100 risk score was assembled. Nothing is hidden, nothing is magic.
2. **Helps prioritize.** A "Suspicious" verdict with a single `+35 pts` indicator is very different from one with three `+15 pts` indicators stacking up. The user can judge whether the verdict is conservative or aggressive at a glance.
3. **Improves the feedback loop.** When a user clicks "Mark as Safe," they now have a clear picture of which signals drove the false positive, which in turn helps them decide whether the allowlist entry is justified.
4. **Makes debugging easier.** During development and bug reports, the rendered breakdown shows exactly which scoring rules fired, removing the need to dig into the code or the SCORING table.

The change is purely additive at the data layer: indicators were already `{score, label}` objects in `urlAnalyzer.js`. The fix was to stop flattening them to bare strings at the tooltip, popup, and storage boundaries.

Backward compatibility is preserved: `renderIndicators()` and the CSV exporter both handle the legacy string form, so log entries written by older versions of the extension still display correctly (just without the score pill).

## Files changed

| File | Change |
|---|---|
| `content.js` | `applyWarning()` lines around indicator rendering: emit `<span class="phishguard-ind-label">` + `<span class="phishguard-ind-score">`; add `data-indicator-label` to each `<li>`. `handleFeedbackClick()` reads `data-indicator-label` instead of `textContent`. |
| `styles.css` | Updated `.phishguard-tooltip-body ul li` to flex layout. Added `.phishguard-ind-label` and `.phishguard-ind-score` classes. |
| `popup.js` | `renderIndicators()` rewritten to handle `{score, label}` objects and render a score pill. `exportCSV()` formats indicators as `Label (+N pts)` when a score is present. |
| `popup.css` | Updated `.pg-indicators li` to flex layout. Added `.pg-ind-label` and `.pg-ind-score` classes. |
| `background.js` | `handleAnalyzeURLs()`: `stats.recentIndicators` now stores `{score, label}` objects, dedup uses label-only comparison. `stats.log[].indicators` stores `{score, label}` objects. |
