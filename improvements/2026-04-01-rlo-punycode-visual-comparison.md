# RLO + Punycode Visual Comparison

## What was added

**`urlAnalyzer.js`**

- `decodePunycodeLabel(label)` - pure-JS RFC 3492 Punycode decoder. Converts a single `xn--` label to its Unicode form without any external dependency. Handles the full Punycode algorithm (basic code points, delta decoding, bias adaptation). Returns the label unchanged on malformed input so it never throws.
- `decodeIDNHostname(hostname)` - splits a hostname on `.`, runs each label through `decodePunycodeLabel`, and rejoins. Converts `xn--pypl-ppa8b.com` to `pаypal.com` (with Cyrillic а).

## What was improved

**Check 0a - RLO / Bidi attack** (two paths, both updated):

Before:
```
label: 'Bidirectional control character in URL - visual direction-reversal spoofing attack (RLO/LRO)'
```

After (post-parse path, line ~535):
```
label: `Bidi/RLO attack: URL contains direction-reversal characters - visually appears as "${cleanDisplay}"`
```

After (pre-parse / parse-fail path, line ~490):
```
label: `Bidi/RLO attack: URL contains direction-reversal characters - visually appears as "${cleanDisplay}"`
```

Both paths already computed `cleanDisplay` (raw URL with bidi chars stripped). Now that value is embedded in the indicator label so the UI can show the user exactly what visual form the attacker intended.

**Check 12 - IDN Punycode homograph** (updated):

Before:
```js
add(SCORING.IDN_PUNYCODE);
// static label only
```

After:
```js
const unicodeForm = decodeIDNHostname(normHostname);
// If the decoded Unicode form resembles a known brand:
label: `Punycode IDN homograph: appears as "pаypal.com" - resembles "paypal.com"`
// Otherwise:
label: `Punycode IDN homograph: appears as "xn--..." (xn-- encoded internationalized domain)`
```

The label is dynamically constructed: the decoded Unicode hostname is shown first (what the user would visually read), then the brand it resembles (from the existing `checkDomainImpersonation` check applied to the Unicode registered domain).

## Why

### The attack

A Punycode homograph attack registers a domain like `xn--pypl-ppa8b.com`. Browsers render this as `pаypal.com` in the address bar. The Cyrillic `а` (U+0430) is visually identical to Latin `a`. A user reading the indicator text `Internationalized domain name (IDN) - possible homograph attack` has no idea what the domain looks like or what it is pretending to be.

With this change, the indicator reads:
> Punycode IDN homograph: appears as "pаypal.com" - resembles "paypal.com"

The user immediately knows:
1. What the domain looks like when rendered
2. Which legitimate brand it is impersonating

### The RLO problem

The Right-to-Left Override character (U+202E) reverses the visual rendering direction. A URL like `https://secure.moc‮gpj.yenom‬.evil.com/` appears to show a `.jpg` file on `money.com` when the actual destination is `evil.com`. Without the visual comparison in the indicator, the user sees a score and a generic label but cannot tell what deception was attempted.

With this change, the indicator shows the bidi-stripped form so the user can compare the displayed URL against what the browser actually navigated to.

### Why inline RFC 3492 (not a library)

`urlAnalyzer.js` is an ES module imported by the background service worker. Adding an npm dependency would require a bundler, which this extension does not use. The Punycode algorithm is well-specified, short, and stable - the entire decoder fits in ~50 lines. Using the browser's own WHATWG URL API is not viable here because we need the Unicode label, not the ASCII-compatible encoding (ACE) form.

### Why `checkDomainImpersonation` on the Unicode registered domain

After decoding `xn--pypl-ppa8b.com` to `pаypal.com`, we extract the registered domain part (`paypal.com` with Cyrillic а) and run it through `checkDomainImpersonation`, which already does Levenshtein + NFKC + known-brand matching. This reuses existing logic and finds the impersonated brand without adding new brand lists.

## Files changed

| File | Change |
|---|---|
| `urlAnalyzer.js` | Added `decodePunycodeLabel()` and `decodeIDNHostname()` after `checkIDNHomograph`; updated check 0a (both pre-parse and post-parse paths) to embed `cleanDisplay` in the indicator label; updated check 12 to decode and compare the Punycode hostname |
