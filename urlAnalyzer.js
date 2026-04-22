/**
 * PhishGuard URL Analyzer
 * Heuristic engine: all checks are synchronous, no network calls.
 */

// ─── Trusted registered domains (skip all heuristics) ────────────────────────
const TRUSTED_DOMAINS = new Set([
  'google.com', 'googleapis.com', 'gstatic.com', 'googleusercontent.com',
  'gmail.com', 'youtube.com', 'android.com', 'chrome.com',
  'microsoft.com', 'office.com', 'live.com', 'outlook.com', 'microsoftonline.com',
  'windows.com', 'bing.com', 'azure.com', 'office365.com', 'microsoftedge.com',
  'apple.com', 'icloud.com',
  'amazon.com', 'amazonaws.com',
  'facebook.com', 'instagram.com', 'whatsapp.com', 'meta.com',
  'twitter.com', 'x.com',
  'linkedin.com',
  'github.com', 'githubusercontent.com',
  'paypal.com', 'netflix.com', 'dropbox.com', 'slack.com',
  'zoom.us', 'adobe.com', 'cloudflare.com', 'wikipedia.org',
  'stripe.com', 'shopify.com', 'salesforce.com', 'hubspot.com',
]);

// ─── URL shortener services ───────────────────────────────────────────────────
const URL_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'short.io',
  'rebrand.ly', 'tiny.cc', 'is.gd', 'buff.ly', 'ift.tt', 'adf.ly',
  'shorte.st', 'linktr.ee', 'cutt.ly', 'shorturl.at', 'bl.ink',
  'rb.gy', 'clck.ru', 'x.co', 'lnkd.in', 'soo.gd',
]);

// ─── Brand keywords (impersonation / subdomain spoofing) ─────────────────────
// Full list: used for path checks and domain impersonation
const BRAND_KEYWORDS = [
  'paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook', 'instagram',
  'netflix', 'dropbox', 'linkedin', 'twitter', 'bank', 'secure', 'login',
  'signin', 'verify', 'account', 'update', 'confirm', 'wallet', 'crypto',
  'binance', 'coinbase', 'chase', 'wellsfargo', 'citibank', 'dhl', 'fedex',
  'ups', 'usps', 'irs', 'gov', 'ebay', 'stripe', 'shopify', 'steam',
  'discord', 'roblox', 'office365', 'docusign', 'wetransfer',
];

// Actual company/service names only: used for subdomain and impersonation checks.
// Generic action words (login, verify, account…) are excluded here to prevent
// false positives on legitimate subdomains like account.hackthebox.com.
const BRAND_NAMES = new Set([
  'paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook', 'instagram',
  'netflix', 'dropbox', 'linkedin', 'twitter', 'binance', 'coinbase',
  'chase', 'wellsfargo', 'citibank', 'dhl', 'fedex', 'ups', 'usps',
  'ebay', 'stripe', 'shopify', 'steam', 'discord', 'roblox', 'docusign', 'wetransfer',
  'office365', 'irs',
]);

// ─── Multi-part ccTLD registry (eTLD+1 fix) ──────────────────────────────────
// Prevents false positives on legitimate domains like paypal.co.uk, google.com.au
const MULTI_PART_TLDS = new Set([
  'co.uk', 'co.jp', 'co.in', 'co.kr', 'co.nz', 'co.za', 'co.id', 'co.il',
  'com.au', 'com.br', 'com.mx', 'com.ar', 'com.cn', 'com.tw', 'com.hk',
  'org.uk', 'net.au', 'gov.uk', 'ac.uk',
]);

// ─── TLD sets ─────────────────────────────────────────────────────────────────
const SUSPICIOUS_TLDS = new Set([
  '.xyz', '.top', '.club', '.work', '.date', '.racing', '.win',
  '.stream', '.buzz', '.click', '.link', '.online', '.site', '.website', '.tech',
  '.pw', '.cc', '.su', '.ws', '.biz',
]);

// Free TLDs with near-zero legitimate usage
const FREE_MALICIOUS_TLDS = new Set(['.tk', '.ml', '.cf', '.ga', '.gq']);

// Known free / frequently-abused hosting platforms
const FREE_HOSTING_DOMAINS = new Set([
  '000webhostapp.com', 'byethost.com', 'byet.host', 'infinityfree.net',
  'awardspace.com', 'freehosting.com', 'profreehost.com',
  'weebly.com', 'wixsite.com', 'jimdo.com',
  'tiiny.site', 'tiiny.host',
  'glitch.me', 'replit.dev', 'repl.co',
  'surge.sh', 'on.fleek.co',
]);

// Dangerous executable / script extensions in URL paths
const DANGEROUS_EXTENSIONS = new Set([
  '.exe', '.bat', '.cmd', '.com', '.scr', '.pif',
  '.ps1', '.psm1', '.psd1', '.vbs', '.vbe', '.js', '.jse',
  '.hta', '.wsf', '.wsh', '.msi', '.msp', '.jar', '.reg',
]);

// Credential / action keywords in URL path: only suspicious on untrusted domains
const SUSPICIOUS_PATH_KEYWORDS = [
  'login', 'signin', 'sign-in', 'logon',
  'verify', 'verification', 'validate',
  'update', 'confirm', 'secure',
  'account', 'credential', 'password', 'passwd', 'reset-password',
  'banking', 'payment', 'billing', 'invoice',
  'webscr', 'wallet', 'recover',
];

// ─── Bidi / RLO control character set ────────────────────────────────────────
/**
 * Unicode bidirectional formatting characters that have no legitimate use inside
 * a URL string.  The most dangerous is U+202E (RIGHT-TO-LEFT OVERRIDE / RLO):
 * it forces all following characters to render right-to-left, allowing an
 * attacker to make "moc.rekcah\u202Eelgoog" display as "googlehacker.com".
 *
 *  U+202A  LEFT-TO-RIGHT EMBEDDING  (LRE)
 *  U+202B  RIGHT-TO-LEFT EMBEDDING  (RLE)
 *  U+202C  POP DIRECTIONAL FORMATTING (PDF)
 *  U+202D  LEFT-TO-RIGHT OVERRIDE   (LRO)
 *  U+202E  RIGHT-TO-LEFT OVERRIDE   (RLO) ← most abused
 *  U+2066  LEFT-TO-RIGHT ISOLATE    (LRI)
 *  U+2067  RIGHT-TO-LEFT ISOLATE    (RLI)
 *  U+2068  FIRST STRONG ISOLATE     (FSI)
 *  U+2069  POP DIRECTIONAL ISOLATE  (PDI)
 *  U+200E  LEFT-TO-RIGHT MARK       (LRM)
 *  U+200F  RIGHT-TO-LEFT MARK       (RLM)
 */
const BIDI_CONTROL_RE = /[\u202A-\u202E\u2066-\u2069\u200E\u200F]/;

// ─── Scoring table ────────────────────────────────────────────────────────────
export const SCORING = {
  IP_ADDRESS:            { score: 60, label: 'IP address used as domain' },
  URL_SHORTENER:         { score: 35, label: 'URL shortener service detected' },
  DOMAIN_IMPERSONATION:  { score: 35, label: 'Domain impersonation detected' },
  SUSPICIOUS_CHARS:      { score: 15, label: 'Suspicious characters in hostname' },
  EXCESSIVE_SUBDOMAINS:  { score: 25, label: 'Excessive subdomain depth' },
  TRUSTED_BRAND_SUBDOMAIN:{ score: 65, label: 'Trusted brand used as subdomain on untrusted domain' },
  BRAND_IN_SUBDOMAIN:    { score: 35, label: 'Brand keyword in subdomain on untrusted domain' },
  SUSPICIOUS_TLD:        { score: 25, label: 'Uncommon or suspicious TLD' },
  FREE_MALICIOUS_TLD:    { score: 50, label: 'Free/abused TLD (.tk .ml .cf .ga .gq)' },
  LONG_URL:              { score: 10, label: 'Unusually long URL' },
  MULTIPLE_AT_SIGNS:     { score: 30, label: 'Multiple @ signs in URL (credential harvesting)' },
  REDIRECT_CHAIN:        { score: 15, label: 'Open redirect pattern detected in URL' },
  HTTP_ONLY:             { score: 10, label: 'Unencrypted HTTP connection (no TLS)' },
  HOMOGRAPH:             { score: 40, label: 'Non-ASCII characters in hostname (possible homograph)' },
  // ── New checks ──
  IDN_PUNYCODE:          { score: 45, label: 'Internationalized domain name (IDN): possible homograph attack' },
  DANGEROUS_EXTENSION:   { score: 60, label: 'URL path contains a dangerous executable/script extension' },
  SUSPICIOUS_PATH:       { score: 20, label: 'URL path contains credential-harvesting keywords' },
  FREE_HOSTING:          { score: 35, label: 'Domain hosted on a known free/abused hosting platform' },
  NONSTANDARD_PORT:      { score: 20, label: 'Non-standard port number in URL' },
  HYPHEN_ABUSE:          { score: 15, label: 'Excessive hyphens in domain (algorithmically generated pattern)' },
  BRAND_IN_PATH:         { score: 20, label: 'Brand name in URL path on untrusted domain' },
  // ── New checks ──
  DATA_URI:              { score: 90, label: 'Non-HTTP protocol (data:/javascript:/blob:): definite phishing indicator' },
  CREDENTIAL_IN_URL:     { score: 65, label: 'Domain or brand used as username in URL (credential spoofing)' },
  LOOKALIKE_DIGITS:      { score: 50, label: 'ASCII digit/character substitution detected (homoglyph attack)' },
  HIGH_ENTROPY:          { score: 25, label: 'High-entropy domain: possible algorithmically generated domain (DGA)' },
  RLO_ATTACK:            { score: 75, label: 'Bidirectional control character in URL: visual direction-reversal spoofing attack (RLO/LRO)' },
  UNICODE_NORMALIZATION: { score: 50, label: 'URL contains Unicode compatibility characters (fullwidth/mathematical) that disguise the real domain' },
  DEVELOPER_HOST:        { score: 15, label: 'Developer / dev-environment host: low phishing risk for this class of URL, but still verify before entering credentials' },
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

function safeParseURL(rawUrl) {
  try {
    // Allow data:/javascript:/blob: through as-is; prefix everything else with https://
    const url = /^(https?|data|javascript|blob):/i.test(rawUrl) ? rawUrl : 'https://' + rawUrl;
    return new URL(url);
  } catch { return null; }
}

function checkIPAddress(hostname) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || /^\[?[0-9a-fA-F:]+\]?$/.test(hostname);
}

function checkURLShortener(hostname) {
  return URL_SHORTENERS.has(hostname.replace(/^www\./, ''));
}

// ─── Developer / dev-environment detection ────────────────────────────────────
// These hosts are overwhelmingly benign for technical users: a phishing feed
// hit on replit.dev is still dangerous and is caught by the feed layer later,
// but by default an unknown replit.dev / glitch.me / localhost URL should
// produce an informational "Developer" label rather than a high-risk alarm.
//
// The eTLD-based entries (e.g. "replit.dev") match that suffix and any
// subdomain (e.g. "my-app.replit.dev"). Exact hostnames (e.g. "localhost")
// match only the literal string.
const DEVELOPER_DOMAIN_SUFFIXES = new Set([
  // Online IDEs / sandbox deployments
  'replit.dev',
  'repl.co',
  'glitch.me',
  'glitch.com',
  'stackblitz.io',
  'codesandbox.io',
  'codepen.io',
  'jsfiddle.net',
  'plnkr.co',
  // Dev tunnels
  'ngrok.io',
  'ngrok-free.app',
  'ngrok.app',
  'loca.lt',            // localtunnel.me subdomains use *.loca.lt
  'trycloudflare.com',
  'githubpreview.dev',
  'gitpod.io',
  'localhost.run',
  // Preview deploys that are clearly dev-mode, not prod
  'vercel.app',         // production apps usually have custom domains
  'netlify.app',
  'onrender.com',
  'railway.app',
  'fly.dev',
  'herokuapp.com',
  'pages.dev',          // Cloudflare Pages previews
  'workers.dev',        // Cloudflare Workers
  'lovable.app',
  'bolt.new',
]);

const DEVELOPER_EXACT_HOSTS = new Set([
  'localhost',
  '127.0.0.1',
  '0.0.0.0',
  '::1',
  '[::1]',
]);

/**
 * Return true if the hostname is a private / loopback IP (IPv4 RFC 1918,
 * IPv4 link-local, IPv6 loopback, IPv6 unique local). These hosts resolve to
 * a machine on the user's own network and cannot be a phishing target in the
 * conventional sense.
 */
function isPrivateIP(hostname) {
  // IPv4
  const v4 = hostname.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (v4) {
    const [a, b] = [+v4[1], +v4[2]];
    if (a === 10) return true;                           // 10.0.0.0/8
    if (a === 127) return true;                          // loopback 127.0.0.0/8
    if (a === 172 && b >= 16 && b <= 31) return true;    // 172.16.0.0/12
    if (a === 192 && b === 168) return true;             // 192.168.0.0/16
    if (a === 169 && b === 254) return true;             // link-local
    if (a === 0) return true;                            // 0.0.0.0/8
    return false;
  }
  // IPv6 loopback / unique-local / link-local
  const bare = hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (bare === '::1' || bare === '::') return true;
  if (/^fc[0-9a-f]{2}:/.test(bare) || /^fd[0-9a-f]{2}:/.test(bare)) return true;  // fc00::/7
  if (/^fe[89ab][0-9a-f]:/.test(bare)) return true;     // fe80::/10 link-local
  return false;
}

/**
 * Return true if the hostname belongs to a recognized development environment
 * (online IDE, tunnel, preview deploy, loopback, or private network). Matches
 * both exact hostnames (localhost) and eTLD-style suffixes (*.replit.dev).
 */
function isDeveloperHost(hostname) {
  const bare = hostname.replace(/^www\./, '').toLowerCase();
  if (DEVELOPER_EXACT_HOSTS.has(bare)) return true;
  if (isPrivateIP(bare)) return true;
  // Suffix match: for each labeled suffix, check whether the hostname ends
  // with ".suffix" or equals "suffix".
  for (const suffix of DEVELOPER_DOMAIN_SUFFIXES) {
    if (bare === suffix || bare.endsWith('.' + suffix)) return true;
  }
  return false;
}

/**
 * Levenshtein distance: used for typosquatting detection.
 */
function levenshtein(a, b) {
  const m = Array.from({ length: b.length + 1 }, (_, i) => [i]);
  for (let j = 0; j <= a.length; j++) m[0][j] = j;
  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      m[i][j] = b[i-1] === a[j-1] ? m[i-1][j-1]
        : 1 + Math.min(m[i-1][j-1], m[i][j-1], m[i-1][j]);
    }
  }
  return m[b.length][a.length];
}

/**
 * Domain impersonation: compare the registered domain root (and its hyphen-segments)
 * against known brand names using Levenshtein and substring matching.
 */
function checkDomainImpersonation(hostname) {
  const bare    = hostname.replace(/^www\./, '').toLowerCase();
  const parts   = bare.split('.');
  const domRoot = parts[parts.length - 2];                          // e.g. "paypa1-secure"
  const segs    = [domRoot, ...domRoot.split('-').filter(s => s.length >= 4)];

  for (const brand of BRAND_NAMES) {
    if (brand.length < 4) continue;
    for (const seg of segs) {
      if (seg === brand) continue;
      if (levenshtein(seg, brand) <= 2 && seg.length >= brand.length - 2)
        return { detected: true, brand };
    }
    if (domRoot.includes(brand) && domRoot !== brand)
      return { detected: true, brand };
  }
  return { detected: false };
}

/**
 * Brand keyword present in subdomain labels (on an untrusted registered domain).
 */
function checkBrandInSubdomain(hostname) {
  const bare    = hostname.replace(/^www\./, '').toLowerCase();
  const parts   = bare.split('.');
  if (parts.length <= 2) return false;
  const regRoot = parts[parts.length - 2];
  const subs    = parts.slice(0, -2).join('.');
  for (const brand of BRAND_NAMES) {
    if (brand.length < 4) continue;
    if (regRoot === brand) continue;  // legitimate subdomain of the brand itself
    if (subs.includes(brand)) return true;
  }
  return false;
}

/**
 * Entire trusted domain (e.g. "google.com") used as a subdomain label,
 * the classic "accounts.google.com.evil.com" phishing pattern.
 */
function checkTrustedBrandInSubdomain(hostname, regDomainKey) {
  if (TRUSTED_DOMAINS.has(regDomainKey)) return false;
  const lower = hostname.toLowerCase();
  for (const trusted of TRUSTED_DOMAINS) {
    if (lower.startsWith(trusted + '.') || lower.includes('.' + trusted + '.'))
      return true;
  }
  return false;
}

function checkSuspiciousCharacters(hostname) {
  if (/[^\x00-\x7F]/.test(hostname)) return { suspicious: true, homograph: true };
  return { suspicious: /%[0-9a-fA-F]{2}/.test(hostname), homograph: false };
}

function checkSuspiciousTLD(hostname) {
  for (const tld of FREE_MALICIOUS_TLDS)  if (hostname.endsWith(tld)) return 'free';
  for (const tld of SUSPICIOUS_TLDS)      if (hostname.endsWith(tld)) return 'suspicious';
  return null;
}

// ─── NEW CHECK 1 ─────────────────────────────────────────────────────────────
/**
 * IDN / Punycode homograph detection.
 * Any hostname label beginning with "xn--" is an internationalized label.
 * Attackers use Unicode look-alike characters to spoof brands:
 *   pаypal.com (Cyrillic "а") encodes as xn--pypl-ppa8b.com
 */
function checkIDNHomograph(hostname) {
  return hostname.toLowerCase().split('.').some(label => label.startsWith('xn--'));
}

/**
 * RFC 3492 Punycode decoder: converts a single xn-- label to its Unicode form.
 * Returns the original label unchanged if decoding fails or no xn-- prefix is present.
 * Implemented inline so urlAnalyzer.js stays a self-contained ES module with no deps.
 */
function decodePunycodeLabel(label) {
  const lower = label.toLowerCase();
  if (!lower.startsWith('xn--')) return label;
  const code = lower.slice(4); // strip "xn--" prefix

  // Punycode constants (RFC 3492)
  const BASE = 36, TMIN = 1, TMAX = 26, SKEW = 38, DAMP = 700;
  const INITIAL_BIAS = 72, INITIAL_N = 128;

  function adapt(delta, numPoints, firstTime) {
    delta = firstTime ? Math.floor(delta / DAMP) : delta >> 1;
    delta += Math.floor(delta / numPoints);
    let k = 0;
    while (delta > Math.floor(((BASE - TMIN) * TMAX) / 2)) {
      delta = Math.floor(delta / (BASE - TMIN));
      k += BASE;
    }
    return k + Math.floor(((BASE - TMIN + 1) * delta) / (delta + SKEW));
  }

  function digitOf(c) {
    const v = c.charCodeAt(0);
    if (v - 48 < 10)  return v - 22; // '0'-'9' -> 26-35
    if (v - 65 < 26)  return v - 65; // 'A'-'Z' -> 0-25
    if (v - 97 < 26)  return v - 97; // 'a'-'z' -> 0-25
    return BASE;
  }

  try {
    const delimIdx = code.lastIndexOf('-');
    const basicPart = delimIdx >= 0 ? code.slice(0, delimIdx) : '';
    const extPart   = delimIdx >= 0 ? code.slice(delimIdx + 1) : code;

    const output = [...basicPart].map(c => c.charCodeAt(0));
    let i = 0, n = INITIAL_N, bias = INITIAL_BIAS;
    let pos = 0;

    while (pos < extPart.length) {
      const oldi = i;
      let w = 1;
      for (let k = BASE; ; k += BASE) {
        if (pos >= extPart.length) throw new Error('overflow');
        const digit = digitOf(extPart[pos++]);
        if (digit >= BASE) throw new Error('bad digit');
        i += digit * w;
        const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
        if (digit < t) break;
        w *= BASE - t;
      }
      const outLen = output.length + 1;
      bias = adapt(i - oldi, outLen, oldi === 0);
      n += Math.floor(i / outLen);
      i %= outLen;
      output.splice(i, 0, n);
      i++;
    }

    return output.map(cp => String.fromCodePoint(cp)).join('');
  } catch (_) {
    return label; // malformed Punycode - return as-is
  }
}

/**
 * Decode all xn-- labels in a hostname to their Unicode forms.
 * e.g. "xn--pypl-ppa8b.com" -> "pаypal.com" (Cyrillic а)
 */
function decodeIDNHostname(hostname) {
  return hostname.toLowerCase().split('.').map(decodePunycodeLabel).join('.');
}

// ─── NEW CHECK 2 ─────────────────────────────────────────────────────────────
/**
 * Dangerous file extension in URL path.
 * Detects drive-by download and malware delivery URLs.
 */
function checkDangerousExtension(pathname) {
  const lower = pathname.toLowerCase().split('?')[0];  // strip query before checking
  for (const ext of DANGEROUS_EXTENSIONS) {
    if (lower.endsWith(ext) || lower.includes(ext + '/') || lower.includes(ext + '?'))
      return true;
  }
  return false;
}

// ─── NEW CHECK 3 ─────────────────────────────────────────────────────────────
/**
 * Suspicious credential-related keywords in URL path.
 * Only meaningful on untrusted domains (trusted domains exit early).
 */
function checkSuspiciousPath(pathname) {
  const lower = decodeURIComponent(pathname).toLowerCase();
  return SUSPICIOUS_PATH_KEYWORDS.some(kw => lower.includes('/' + kw));
}

// ─── NEW CHECK 4 ─────────────────────────────────────────────────────────────
/**
 * Free / abused hosting platform detection.
 * These services are free to sign up for and heavily abused in phishing campaigns.
 */
function checkFreeHosting(hostname) {
  const bare = hostname.replace(/^www\./, '').toLowerCase();
  for (const platform of FREE_HOSTING_DOMAINS) {
    if (bare === platform || bare.endsWith('.' + platform)) return true;
  }
  return false;
}

// ─── NEW CHECK 5 ─────────────────────────────────────────────────────────────
/**
 * Non-standard port detection.
 * Legitimate services serve on 80/443. Phishing kits often use high ports.
 */
function checkNonStandardPort(parsedUrl) {
  const port = parsedUrl.port;
  if (!port) return false;
  const p = parseInt(port, 10);
  return p !== 80 && p !== 443;
}

// ─── NEW CHECK 6 ─────────────────────────────────────────────────────────────
/**
 * Hyphen abuse in domain root.
 * Algorithmically generated phishing domains often contain many hyphens:
 *   secure-account-login-verify.com
 */
function checkHyphenAbuse(hostname) {
  const bare    = hostname.replace(/^www\./, '').toLowerCase();
  const domRoot = bare.split('.')[0];
  return (domRoot.match(/-/g) || []).length >= 3;
}

// ─── NEW CHECK 7 ─────────────────────────────────────────────────────────────
/**
 * Brand keyword present in URL path on an untrusted domain.
 * e.g. evil.com/paypal/login: attacker mirrors a brand's login page
 */
function checkBrandInPath(pathname) {
  const lower = decodeURIComponent(pathname).toLowerCase();
  // Use BRAND_NAMES (actual company names) to avoid false positives on legitimate
  // sites whose paths contain generic words like /login, /account, /verify
  for (const brand of BRAND_NAMES) {
    if (brand.length < 5) continue;
    if (lower.includes('/' + brand))  return brand;
  }
  return null;
}

// ─── NEW CHECK 8 ─────────────────────────────────────────────────────────────
/**
 * Credential injection: URL contains a username/password in the authority.
 * Classic spoofing pattern: https://paypal.com@evil.com/login
 * The browser's URL parser places "paypal.com" as the username, "evil.com" as the host.
 */
function checkCredentialInURL(parsed) {
  return parsed.username !== '' || parsed.password !== '';
}

// ─── NEW CHECK 9 ─────────────────────────────────────────────────────────────
/**
 * ASCII digit/lookalike character substitution.
 * Attackers swap letters for visually similar digits: g00gle.com, paypa1.com, amaz0n.com
 * Normalise the SLD by replacing common substitutions then check for brand match.
 */
const DIGIT_LOOKALIKE = { '0':'o', '1':'l', '3':'e', '4':'a', '5':'s', '6':'b', '7':'t', '8':'b' };

function normalizeLookalikes(str) {
  return str.replace(/[01345678]/g, c => DIGIT_LOOKALIKE[c]);
}

function checkLookalikeDigits(hostname) {
  const sld = hostname.replace(/^www\./, '').toLowerCase().split('.').slice(-2, -1)[0] || '';
  if (!/[01345678]/.test(sld)) return null;           // no substitutable digits present
  const normalized = normalizeLookalikes(sld);
  if (normalized === sld) return null;
  for (const brand of BRAND_NAMES) {
    if (brand.length < 4) continue;
    if (normalized === brand || levenshtein(normalized, brand) <= 1)
      return brand;
  }
  return null;
}

// ─── NEW CHECK 10 ────────────────────────────────────────────────────────────
/**
 * High-entropy domain detection (DGA / algorithmically generated domains).
 * Legitimate domains tend to be pronounceable (contain vowels).
 * DGA-generated domains often have near-zero vowels and high Shannon entropy.
 */
function shannonEntropy(str) {
  const freq = {};
  for (const c of str) freq[c] = (freq[c] || 0) + 1;
  const n = str.length;
  return -Object.values(freq).reduce((sum, f) => sum + (f / n) * Math.log2(f / n), 0);
}

function checkHighEntropyDomain(hostname) {
  const sld = hostname.replace(/^www\./, '').toLowerCase().split('.').slice(-2, -1)[0] || '';
  if (sld.length < 10) return false;                   // short domains are inconclusive
  const vowelRatio = (sld.match(/[aeiou]/g) || []).length / sld.length;
  return shannonEntropy(sld) > 3.5 && vowelRatio < 0.2;
}

// ─── Main export ──────────────────────────────────────────────────────────────

/**
 * Analyze a raw URL and return a risk assessment.
 * @returns {{ url, domain, score, riskLevel, indicators } | null}
 */
export function analyzeURL(rawUrl) {
  // ── Pre-parse: bidi / RLO check ───────────────────────────────────────────
  // MUST run before safeParseURL because Chrome's URL parser strips or rejects
  // bidi control characters during normalization, making them invisible to all
  // post-parse checks.  If bidi chars cause the parse to fail entirely, we still
  // return a high-risk result instead of silently returning null.
  const hasRLO = BIDI_CONTROL_RE.test(rawUrl);

  // ── Pre-parse: NFKC normalization check ────────────────────────────────────
  // ALSO checked before parsing.  Chrome's WHATWG URL parser normalises hostnames
  // via IDNA, so by the time we read `parsed.hostname` the fullwidth characters
  // are already gone and the attack is invisible.  Comparing `rawUrl` against its
  // NFKC form catches the manipulation in the original string before the parser
  // erases the evidence.
  //
  // What NFKC normalization maps to ASCII:
  //   • Fullwidth ASCII   ｇｏｏｇｌｅ  (U+FF41 to U+FF5A)  → google
  //   • Math bold         𝗴𝗼𝗼𝗴𝗹𝗲      (U+1D400 to U+1D7FF) → google
  //   • Math italic       𝘨𝘰𝘰𝘨𝘭𝘦      (U+1D400 to U+1D7FF) → google
  //   • Superscript nums  ⁰¹²³…        → 0123…
  //   • Compatibility ligatures  ﬀ ﬁ ﬂ → ff fi fl
  const normRawUrl      = rawUrl.normalize('NFKC');
  const hasNormVariants = normRawUrl !== rawUrl;

  const parsed = safeParseURL(rawUrl);
  if (!parsed) {
    if (hasRLO) {
      // Strip bidi chars for display; the raw URL is still stored as evidence.
      const cleanDisplay = rawUrl.replace(BIDI_CONTROL_RE, '').slice(0, 80);
      return {
        url: rawUrl,
        domain: cleanDisplay,
        score: 75,
        riskLevel: 'high-risk',
        indicators: [{ ...SCORING.RLO_ATTACK,
          label: `Bidi/RLO attack: URL contains direction-reversal characters - visually appears as "${cleanDisplay}"` }],
      };
    }
    return null;
  }

  const { hostname, protocol, href, pathname, search, port } = parsed;
  const indicators = [];
  let   totalScore = 0;
  let   isShortener = false;

  const add = (entry) => { indicators.push(entry); totalScore += entry.score; };

  // ── Normalised variants for comparison-based checks ───────────────────────
  // `hostname` (original, from URL parser) is preserved for:
  //   • HOMOGRAPH check  : must see non-ASCII chars before they're collapsed
  //   • IDN Punycode     : xn-- labels are already ASCII, unaffected
  //   • Result display   : show the real domain to the user
  //
  // `normHostname` (NFKC + lowercase) is used for every check that compares
  //   against brand names, TLD lists, or trusted-domain sets so that fullwidth /
  //   mathematical Unicode variants are reduced to their ASCII equivalents first.
  //
  // `normPathname`: same principle applied to the URL path.
  const normHostname = hostname.normalize('NFKC').toLowerCase();
  const normPathname = pathname.normalize('NFKC');

  // ── 0. Dangerous non-HTTP protocol ───────────────────────────────────────
  if (protocol === 'data:' || protocol === 'javascript:' || protocol === 'blob:')
    return { url: rawUrl, domain: rawUrl.slice(0, 60), score: 90, riskLevel: 'high-risk',
             indicators: [SCORING.DATA_URI] };

  // ── 0a. RLO / Bidi control character attack ───────────────────────────────
  // Placed before the trusted-domain exit on purpose: an attacker can craft a URL
  // whose parsed hostname resolves to a trusted domain (e.g. google.com) while bidi
  // chars in the raw string make it visually appear as a different, malicious domain.
  // Without this guard, the trusted-domain exit would whitelist such a URL.
  if (hasRLO) {
    const cleanDisplay = rawUrl.replace(BIDI_CONTROL_RE, '').slice(0, 80);
    add({ ...SCORING.RLO_ATTACK,
          label: `Bidi/RLO attack: URL contains direction-reversal characters - visually appears as "${cleanDisplay}"` });
  }

  // ── 0b. Unicode compatibility character (NFKC normalization) attack ───────
  // Same placement rationale as RLO: ｇｏｏｇｌｅ.com parses to google.com via
  // Chrome's IDNA processing, which would trigger the trusted-domain early exit
  // and return score 0.  We must block that exit when normalization variants exist.
  if (hasNormVariants) add(SCORING.UNICODE_NORMALIZATION);

  // ── Trusted domain early exit (with eTLD+1 support) ──────────────────────
  // Use normHostname so fullwidth/math-script domain labels are reduced to ASCII
  // before matching against the trusted-domain set.
  const hostParts  = normHostname.split('.');
  const lastTwo    = hostParts.slice(-2).join('.');
  const isMultiTLD = MULTI_PART_TLDS.has(lastTwo) && hostParts.length >= 3;

  // Compute the registered domain key: for .co.uk style TLDs use 3 labels
  const regDomainKey = isMultiTLD ? hostParts.slice(-3).join('.') : lastTwo;

  // Do NOT exit early if RLO or NFKC normalization variants were found.
  // Both attacks can make the parsed hostname look like a trusted domain while
  // the raw URL contains the spoofing characters: whitelisting them would be
  // a silent security hole.
  const isSpoofed = hasRLO || hasNormVariants;

  if (isMultiTLD && !isSpoofed) {
    const brandRoot = hostParts[hostParts.length - 3];
    for (const trusted of TRUSTED_DOMAINS) {
      if (trusted.split('.')[0] === brandRoot)
        return { url: href, domain: hostname, score: 0, riskLevel: 'safe', indicators };
    }
  }

  if (TRUSTED_DOMAINS.has(regDomainKey) && !isSpoofed)
    return { url: href, domain: hostname, score: 0, riskLevel: 'safe', indicators };

  // ── Developer / dev-environment early exit ───────────────────────────────
  // Hosts like replit.dev, glitch.me, localhost, 127.0.0.1, and 192.168.x.x
  // get a dedicated "developer" risk level instead of the high-risk label
  // that an IP-literal URL (check #1) or an uncommon TLD (check #7) would
  // otherwise trigger. This reduces false-positive noise for technical users
  // previewing their own work, while still leaving the threat-intelligence
  // layer in background.js free to flag these hosts if they appear in
  // OpenPhish / Safe Browsing / URLHaus.
  //
  // RLO / NFKC spoofing (isSpoofed) takes precedence: an attacker who puts
  // bidi characters in a replit.dev hostname should NOT get the friendly
  // developer label.
  if (!isSpoofed && isDeveloperHost(normHostname)) {
    return {
      url:        href,
      domain:     hostname,
      score:      SCORING.DEVELOPER_HOST.score,
      riskLevel:  'developer',
      indicators: [SCORING.DEVELOPER_HOST],
    };
  }

  // ── 1. IP address ─────────────────────────────────────────────────────────
  // normHostname: fullwidth digits (e.g. １９２．１６８…) collapse to ASCII digits
  if (checkIPAddress(normHostname))
    add(SCORING.IP_ADDRESS);

  // ── 2. URL shortener ──────────────────────────────────────────────────────
  // Flag the indicator AND expose isShortener on the result so the background
  // layer knows to fetch the real destination and re-analyze it.
  if (checkURLShortener(normHostname)) {
    add(SCORING.URL_SHORTENER);
    isShortener = true;
  }

  // ── 3. Domain impersonation / typosquatting ───────────────────────────────
  // normHostname: fullwidth/math-script brand names (ｐａｙｐａｌ) collapse to
  // their ASCII form before Levenshtein comparison, catching the spoofing variant.
  const imp = checkDomainImpersonation(normHostname);
  if (imp.detected)
    add({ ...SCORING.DOMAIN_IMPERSONATION,
          label: `Domain impersonation: possible "${imp.brand}" spoofing` });

  // ── 4. Subdomain brand checks ─────────────────────────────────────────────
  if (checkTrustedBrandInSubdomain(normHostname, regDomainKey))
    add(SCORING.TRUSTED_BRAND_SUBDOMAIN);
  else if (checkBrandInSubdomain(normHostname))
    add(SCORING.BRAND_IN_SUBDOMAIN);

  // ── 5. Suspicious / homograph characters in hostname ─────────────────────
  // INTENTIONALLY uses the original `hostname` (not normHostname) so that
  // non-ASCII characters are still present for detection.  If we passed
  // normHostname here, fullwidth chars would already be collapsed to ASCII
  // and the homograph check would silently pass.
  const chars = checkSuspiciousCharacters(hostname);
  if (chars.homograph)       add(SCORING.HOMOGRAPH);
  else if (chars.suspicious) add(SCORING.SUSPICIOUS_CHARS);

  // ── 6. Excessive subdomains ───────────────────────────────────────────────
  // hostParts is already derived from normHostname (set above)
  if (hostParts.length > 4)
    add(SCORING.EXCESSIVE_SUBDOMAINS);

  // ── 7. TLD risk ───────────────────────────────────────────────────────────
  const tld = checkSuspiciousTLD(normHostname);
  if (tld === 'free')            add(SCORING.FREE_MALICIOUS_TLD);
  else if (tld === 'suspicious') add(SCORING.SUSPICIOUS_TLD);

  // ── 8. Long URL ───────────────────────────────────────────────────────────
  if (href.length > 100)
    add(SCORING.LONG_URL);

  // ── 9. Multiple @ signs ───────────────────────────────────────────────────
  if ((href.match(/@/g) || []).length > 1)
    add(SCORING.MULTIPLE_AT_SIGNS);

  // ── 10. Open redirect pattern ─────────────────────────────────────────────
  const pathAndHost = parsed.origin + normPathname;
  if (/https?:\/\/.+https?:\/\//i.test(pathAndHost)
      || /[?&](url|redirect|redir|goto|dest|destination)=/i.test(search))
    add(SCORING.REDIRECT_CHAIN);

  // ── 11. HTTP only ─────────────────────────────────────────────────────────
  if (protocol === 'http:')
    add(SCORING.HTTP_ONLY);

  // ── 12. IDN / Punycode homograph ─────────────────────────────────────────
  // xn-- labels are ASCII: normHostname and hostname behave the same here.
  // Decode to Unicode and compare against known brands for a specific label.
  if (checkIDNHomograph(normHostname)) {
    const unicodeForm = decodeIDNHostname(normHostname);
    // Find any brand the decoded hostname resembles (after stripping its own xn-- labels)
    const unicodeRegistered = unicodeForm.split('.').slice(-2).join('.');
    const impCheck = checkDomainImpersonation(unicodeRegistered);
    let idnLabel;
    if (impCheck.detected) {
      idnLabel = `Punycode IDN homograph: appears as "${unicodeForm}" - resembles "${impCheck.brand}"`;
    } else {
      idnLabel = `Punycode IDN homograph: appears as "${unicodeForm}" (xn-- encoded internationalized domain)`;
    }
    add({ ...SCORING.IDN_PUNYCODE, label: idnLabel });
  }

  // ── 13. Dangerous file extension in path ─────────────────────────────────
  // normPathname: fullwidth extension chars (e.g. ．ｅｘｅ) collapse to .exe
  if (checkDangerousExtension(normPathname))
    add(SCORING.DANGEROUS_EXTENSION);

  // ── 14. Credential keywords in URL path ──────────────────────────────────
  // normPathname: fullwidth keyword chars collapse before keyword matching
  if (checkSuspiciousPath(normPathname))
    add(SCORING.SUSPICIOUS_PATH);

  // ── 15. Free / abused hosting platform ───────────────────────────────────
  if (checkFreeHosting(normHostname))
    add(SCORING.FREE_HOSTING);

  // ── 16. Non-standard port ─────────────────────────────────────────────────
  // Port is always ASCII digits: no normalization difference
  if (checkNonStandardPort(parsed))
    add(SCORING.NONSTANDARD_PORT);

  // ── 17. Hyphen abuse ─────────────────────────────────────────────────────
  // normHostname: fullwidth hyphens (U+FF0D) collapse to ASCII hyphen before counting
  if (checkHyphenAbuse(normHostname))
    add(SCORING.HYPHEN_ABUSE);

  // ── 18. Brand name in URL path ────────────────────────────────────────────
  // normPathname: fullwidth brand name chars collapse before matching
  const brandInPath = checkBrandInPath(normPathname);
  if (brandInPath)
    add({ ...SCORING.BRAND_IN_PATH,
          label: `Brand name "/${brandInPath}" in URL path on untrusted domain` });

  // ── 19. Credential injection (user@host spoofing) ─────────────────────────
  // parsed.username / .password are always ASCII after URL parsing
  if (checkCredentialInURL(parsed))
    add(SCORING.CREDENTIAL_IN_URL);

  // ── 20. ASCII digit/lookalike substitution ────────────────────────────────
  // normHostname: fullwidth digits collapse to ASCII first, then the digit-
  // substitution map (0→o, 1→l…) is applied: catches both attack variants.
  const lookalikeMatch = checkLookalikeDigits(normHostname);
  if (lookalikeMatch)
    add({ ...SCORING.LOOKALIKE_DIGITS,
          label: `ASCII digit substitution impersonating "${lookalikeMatch}" (e.g. 0→o, 1→l)` });

  // ── 21. High-entropy / DGA domain ─────────────────────────────────────────
  // normHostname: entropy is measured on the ASCII-collapsed form so fullwidth
  // characters don't artificially inflate the entropy score.
  if (checkHighEntropyDomain(normHostname))
    add(SCORING.HIGH_ENTROPY);

  // ── Final score ───────────────────────────────────────────────────────────
  totalScore = Math.min(totalScore, 100);
  const riskLevel = totalScore <= 30 ? 'safe'
    : totalScore <  60 ? 'suspicious'
    : 'high-risk';

  return { url: href, domain: hostname, score: totalScore, riskLevel, indicators, isShortener };
}
