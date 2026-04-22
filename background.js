/**
 * PhishGuard - Background Service Worker v2
 *
 * Improvements in this version:
 *   #1  Badge counter   - live threat count on the extension icon
 *   #2  Notifications   - desktop alert when a high-risk link is detected
 *   #3  Google Safe Browsing API - real-time URL reputation check
 *   #4  RDAP domain age - flag newly registered domains
 *
 * Existing features retained: OpenPhish feed, URLHaus, stats/log.
 */

import { analyzeURL, SCORING }              from './urlAnalyzer.js';
import { idbGet, idbSet, idbPrune }         from './idb.js';

// ─── Constants ────────────────────────────────────────────────────────────────

const FEED_TTL_MS         = 6  * 60 * 60 * 1000;  // 6 h  - OpenPhish refresh
const RDAP_CACHE_TTL      = 24 * 60 * 60 * 1000;  // 24 h - RDAP per-domain cache
const SB_CACHE_TTL        = 30 * 60 * 1000;        // 30 m - Safe Browsing cache
const PT_CACHE_TTL        = 60 * 60 * 1000;        // 1 h  - PhishTank cache
const VT_CACHE_TTL        = 24 * 60 * 60 * 1000;  // 24 h - VirusTotal cache (free tier: 500 req/day)
const NOTIFY_COOLDOWN     = 60 * 60 * 1000;        // 1 h  - dedup per domain
const WEBHOOK_COOLDOWN_MS = 60 * 60 * 1000;        // 1 h  - webhook dedup per URL
const WEBHOOK_TIMEOUT_MS  = 8 * 1000;              // 8 s  - webhook POST timeout
const SHORTENER_TTL       = 24 * 60 * 60 * 1000;  // 24 h - shortener expansion cache
const SHORTENER_TIMEOUT   = 6 * 1000;              // 6 s  - shortener unfurl timeout
const CACHE_PRUNE_MS      = 12 * 60 * 60 * 1000;  // 12 h - IDB pruning interval
const FAIL_RETRY_TTL      =  5 * 60 * 1000;        // 5 m  - retry window after a failed API call

// TLDs with reliable RDAP registry support
const RDAP_SUPPORTED_TLDS = new Set([
  'com', 'net', 'org', 'info', 'biz', 'co', 'io', 'xyz', 'online',
  'site', 'top', 'club', 'tech', 'store', 'app', 'dev', 'ai', 'live',
  'pro', 'us', 'eu', 'de', 'fr', 'uk', 'ca', 'au',
]);

// ─── In-Memory State ──────────────────────────────────────────────────────────

let phishingFeedDomains = new Set();
let feedLastUpdated     = 0;

// NOTE: rdapCache, sbCache, phishTankCache, and notifiedDomains have been
// moved to IndexedDB (idb.js) so they persist across service-worker restarts.
// In-memory Maps only lasted ~30 s in MV3 before the SW was killed.

// Session counters (drive the badge; reset on service worker restart)
let sessionHighRisk   = 0;
let sessionSuspicious = 0;

// ─────────────────────────────────────────────────────────────────────────────
// IMPROVEMENT #1 - Badge Counter
// Shows a live count on the extension icon:
//   Red   = high-risk links this session
//   Orange = suspicious links (only if no high-risk)
//   Empty  = all clean
// ─────────────────────────────────────────────────────────────────────────────

function updateBadge() {
  if (sessionHighRisk > 0) {
    const text = sessionHighRisk > 99 ? '99+' : String(sessionHighRisk);
    chrome.action.setBadgeText({ text });
    chrome.action.setBadgeBackgroundColor({ color: '#ef4444' });
    chrome.action.setBadgeTextColor({ color: '#ffffff' });
  } else if (sessionSuspicious > 0) {
    const text = sessionSuspicious > 99 ? '99+' : String(sessionSuspicious);
    chrome.action.setBadgeText({ text });
    chrome.action.setBadgeBackgroundColor({ color: '#f59e0b' });
    chrome.action.setBadgeTextColor({ color: '#ffffff' });
  } else {
    chrome.action.setBadgeText({ text: '' });
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// IMPROVEMENT #2 - Desktop Notifications
// Fires a system notification the first time a high-risk domain is seen
// in any given hour. Respects the user's notification toggle in settings.
// ─────────────────────────────────────────────────────────────────────────────

async function notifyHighRisk(result) {
  const settings = await loadSettings();
  if (!settings.notificationsEnabled) return;

  const now     = Date.now();
  const cached  = await idbGet('notifications', result.domain);
  if (cached && now - cached.lastNotifiedAt < NOTIFY_COOLDOWN) return;
  await idbSet('notifications', result.domain, { lastNotifiedAt: now });

  const topIndicators = result.indicators
    .slice(0, 3)
    .map(i => i.label)
    .join('  •  ');

  chrome.notifications.create(`phishguard-${now}`, {
    type:               'basic',
    iconUrl:            chrome.runtime.getURL('icons/icon48.png'),
    title:              'PhishGuard: Phishing Link Detected',
    message:            `${result.domain}   :   Score: ${result.score}/100`,
    contextMessage:     topIndicators || 'Open PhishGuard for details.',
    priority:           2,
    requireInteraction: false,
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// SIEM Webhook Integration
// Posts high-risk detections as JSON to a user-configured webhook URL so they
// can be ingested by Splunk HEC, Elastic, a custom SOC endpoint, or any HTTP
// collector. The endpoint origin is requested as an optional_host_permission
// when the user first saves the URL in Settings.
//
// Dedup: each exact URL is reported at most once per WEBHOOK_COOLDOWN_MS so a
// newsletter with 50 copies of the same phishing link does not fan out 50
// identical events. Uses the 'webhooks' IDB store.
// ─────────────────────────────────────────────────────────────────────────────

async function postToWebhook(result, settings) {
  if (!settings.webhookEnabled) return;

  const endpoint = (settings.webhookUrl || '').trim();
  if (!endpoint) return;

  // Dedup per URL
  const now    = Date.now();
  const cached = await idbGet('webhooks', result.url);
  if (cached && now - cached.lastSentAt < WEBHOOK_COOLDOWN_MS) return;

  // Build the payload. Keep indicator objects verbatim {score, label} so the
  // receiver can reason about score contribution per rule.
  const payload = {
    source:    'phishguard',
    version:   chrome.runtime.getManifest().version,
    timestamp: new Date(now).toISOString(),
    detection: {
      url:        result.url,
      domain:     result.domain,
      expandedUrl:    result.expandedUrl    || null,
      expandedDomain: result.expandedDomain || null,
      score:      result.score,
      riskLevel:  result.riskLevel,
      indicators: (result.indicators || []).map(i => ({ score: i.score, label: i.label })),
      domainAge:  result.domainAge || null,
      feedHits: {
        openphish:    !!result.threatFeedHit,
        safeBrowsing: !!result.safeBrowsingHit,
        phishTank:    !!result.phishTankHit,
        urlHaus:      !!result.urlhausHit,
        virusTotal:   !!result.vtHit,
      },
      allowlisted: !!result.allowlisted,
    },
  };

  const headers = { 'Content-Type': 'application/json' };
  const auth    = (settings.webhookAuthHeader || '').trim();
  if (auth) headers['Authorization'] = auth; // e.g. "Bearer …" or "Splunk …"

  try {
    const res = await fetch(endpoint, {
      method:  'POST',
      headers,
      body:    JSON.stringify(payload),
      signal:  AbortSignal.timeout(WEBHOOK_TIMEOUT_MS),
      // no credentials: this is SIEM ingestion, not a cross-origin login
    });
    if (!res.ok) throw new Error(`webhook ${res.status}`);
    await idbSet('webhooks', result.url, { lastSentAt: now });
    console.log(`[PhishGuard] Webhook POST OK (${res.status}) for ${result.domain}`);
  } catch (err) {
    console.warn('[PhishGuard] Webhook POST failed:', err.message);
    // Do NOT dedup on failure: the next scan should retry.
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// IMPROVEMENT #3 - Google Safe Browsing API
// Sends a single batch request for all URLs in one scan.
// Results are cached per-URL for 30 minutes to preserve API quota.
// The API key is stored in chrome.storage.sync via the Settings page.
// ─────────────────────────────────────────────────────────────────────────────

async function checkGoogleSafeBrowsing(urls, apiKey) {
  if (!apiKey || urls.length === 0) return new Set();

  const now        = Date.now();
  const flagged    = new Set();

  // Serve from IDB cache where possible (parallel reads)
  const cacheHits = await Promise.all(urls.map(url => idbGet('safebrowsing', url)));
  const uncached  = [];
  for (let i = 0; i < urls.length; i++) {
    const hit = cacheHits[i];
    if (hit?.failed) {
      // Previous call failed. Retry once the short window expires; treat as unchecked in the meantime.
      if (now - hit.cachedAt >= FAIL_RETRY_TTL) uncached.push(urls[i]);
      // else: within retry window - skip this URL (unchecked, not assumed safe)
    } else if (hit && now - hit.cachedAt < SB_CACHE_TTL) {
      if (hit.flagged) flagged.add(urls[i]);
    } else {
      uncached.push(urls[i]);
    }
  }

  if (uncached.length === 0) return flagged;

  try {
    const body = {
      client: { clientId: 'phishguard', clientVersion: '2.0.0' },
      threatInfo: {
        threatTypes: [
          'MALWARE',
          'SOCIAL_ENGINEERING',
          'UNWANTED_SOFTWARE',
          'POTENTIALLY_HARMFUL_APPLICATION',
        ],
        platformTypes:    ['ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries:    uncached.map(url => ({ url })),
      },
    };

    const res = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(apiKey)}`,
      {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify(body),
        signal:  AbortSignal.timeout(8_000),
      }
    );

    if (!res.ok) throw new Error(`Safe Browsing API ${res.status}`);

    const data        = await res.json();
    const matchedUrls = new Set((data.matches || []).map(m => m.threat.url));

    // Cache all results (including clean ones) - parallel writes
    await Promise.all(uncached.map(url => {
      const isFlagged = matchedUrls.has(url);
      if (isFlagged) flagged.add(url);
      return idbSet('safebrowsing', url, { flagged: isFlagged, cachedAt: now });
    }));

    console.log(`[PhishGuard] Safe Browsing: checked ${uncached.length} URLs, ${flagged.size} flagged`);
  } catch (err) {
    console.warn('[PhishGuard] Safe Browsing API failed:', err.message);
    // Cache as failed (not safe) so the next scan within 5 min treats these as unchecked,
    // and retries the API after the retry window expires.
    await Promise.all(uncached.map(url =>
      idbSet('safebrowsing', url, { failed: true, cachedAt: now })
    ));
  }

  return flagged;
}

// ─────────────────────────────────────────────────────────────────────────────
// URL Shortener Expansion
// Follows t.co, bit.ly, tinyurl.com, cutt.ly, is.gd, ow.ly, rebrand.ly (and
// 15+ other common shorteners) to their real destinations by issuing a HEAD
// request with redirect: 'follow'. The final URL is read off response.url,
// then fed back into analyzeURL() so every downstream heuristic + threat feed
// sees the real destination, not the opaque short-link.
//
// Requires runtime <all_urls> permission (any origin may be the redirect
// target). Declared as optional_host_permissions in manifest.json and
// requested by settings.js when the user enables the feature.
//
// Results cached per-short-link in the 'shorteners' IDB store for 24 h.
// Failed calls are cached short (FAIL_RETRY_TTL) so transient errors don't
// block retries.
// ─────────────────────────────────────────────────────────────────────────────

async function hasShortenerPermission() {
  try {
    return await chrome.permissions.contains({
      origins: ['https://*/*', 'http://*/*'],
    });
  } catch {
    return false;
  }
}

async function expandShortener(shortUrl) {
  const now    = Date.now();
  const cached = await idbGet('shorteners', shortUrl);
  if (cached?.failed) {
    if (now - cached.cachedAt < FAIL_RETRY_TTL) return null;
  } else if (cached && now - cached.cachedAt < SHORTENER_TTL) {
    return cached.expandedUrl;
  }

  const store = async (value) => {
    await idbSet('shorteners', shortUrl, { ...value, cachedAt: Date.now() });
    return value.expandedUrl || null;
  };

  // HEAD first (no body). Many shorteners (t.co, bit.ly) support it.
  // Fall back to GET with body cancelled for the few that reject HEAD.
  const attempt = async (method) => {
    const res = await fetch(shortUrl, {
      method,
      redirect: 'follow',
      signal:   AbortSignal.timeout(SHORTENER_TIMEOUT),
      // credentials: 'omit' keeps this from leaking cookies to the shortener
      credentials: 'omit',
    });
    // Cancel the body stream we don't need
    try { res.body?.cancel?.(); } catch {}
    return res.url || null;
  };

  try {
    let finalUrl = await attempt('HEAD');
    if (!finalUrl || finalUrl === shortUrl) {
      finalUrl = await attempt('GET');
    }
    if (!finalUrl || finalUrl === shortUrl) {
      return store({ expandedUrl: null });
    }
    return store({ expandedUrl: finalUrl });
  } catch (err) {
    console.warn(`[PhishGuard] Shortener expansion failed for ${shortUrl}:`, err.message);
    await idbSet('shorteners', shortUrl, { failed: true, cachedAt: Date.now() });
    return null;
  }
}

/**
 * Merge a shortener's destination analysis into the original analysis.
 * Replaces the generic URL_SHORTENER indicator with a specific "resolves to X"
 * message naming the real destination, then folds in every destination
 * indicator (deduped by label, score capped at 100). Preserves analysis.url
 * and analysis.domain as the short-link values so the UI shows what the user
 * actually sees in the email, with expandedUrl / expandedDomain added as
 * extra context.
 */
function mergeShortenerExpansion(analysis, destAnalysis, expandedUrl) {
  // Drop the generic URL_SHORTENER indicator and back out its score
  const genericLabel = SCORING.URL_SHORTENER.label;
  const idx = analysis.indicators.findIndex(i => i.label === genericLabel);
  if (idx >= 0) {
    const removed = analysis.indicators.splice(idx, 1)[0];
    analysis.score = Math.max(0, analysis.score - removed.score);
  }

  // Add a specific "resolves to …" indicator. When the destination itself is
  // safe (trusted domain), give it a 0-score informational note; otherwise a
  // small transparency tax so a shortener is never strictly safer than its
  // destination.
  const expandLabel = destAnalysis.riskLevel === 'safe'
    ? `URL shortener resolves to trusted destination: ${destAnalysis.domain}`
    : `URL shortener hides destination: ${destAnalysis.domain}`;
  const expandScore = destAnalysis.riskLevel === 'safe' ? 0 : 15;
  analysis.indicators.push({ score: expandScore, label: expandLabel });
  analysis.score = Math.min(analysis.score + expandScore, 100);

  // Fold in every destination indicator (deduped)
  for (const ind of destAnalysis.indicators) {
    if (!analysis.indicators.some(x => x.label === ind.label)) {
      analysis.indicators.push(ind);
      analysis.score = Math.min(analysis.score + ind.score, 100);
    }
  }

  // Recompute riskLevel from final score; preserve 'developer' when the
  // destination is a dev host and score is still low.
  if (destAnalysis.riskLevel === 'developer' && analysis.score < 60) {
    analysis.riskLevel = 'developer';
  } else {
    analysis.riskLevel = analysis.score >= 60 ? 'high-risk'
                       : analysis.score > 30  ? 'suspicious'
                       : 'safe';
  }

  analysis.expandedUrl    = expandedUrl;
  analysis.expandedDomain = destAnalysis.domain;
}

// ─────────────────────────────────────────────────────────────────────────────
// IMPROVEMENT #4 - RDAP Domain Age Check
// Uses the public RDAP proxy (rdap.org) to find when a domain was registered.
// Newly registered domains are a strong phishing signal:
//   < 7 days  → +50 pts (high-risk on its own)
//   < 30 days → +35 pts
//   < 90 days → +15 pts
// Results are cached in memory for 24 h.
// ─────────────────────────────────────────────────────────────────────────────

async function checkDomainAge(hostname) {
  const parts = hostname.toLowerCase().split('.');
  const tld   = parts[parts.length - 1];
  if (!RDAP_SUPPORTED_TLDS.has(tld)) return null;

  const registeredDomain = parts.slice(-2).join('.');

  const cached = await idbGet('rdap', registeredDomain);
  const now    = Date.now();
  if (cached?.failed) {
    if (now - cached.cachedAt < FAIL_RETRY_TTL) return null; // unchecked, retry window active
    // else fall through and retry
  } else if (cached && now - cached.cachedAt < RDAP_CACHE_TTL) {
    return cached.result;
  }

  const store = async (result) => {
    await idbSet('rdap', registeredDomain, { result, cachedAt: Date.now() });
    return result;
  };

  try {
    const res = await fetch(`https://rdap.org/domain/${registeredDomain}`, {
      signal:  AbortSignal.timeout(6_000),
      headers: { Accept: 'application/rdap+json' },
    });

    if (!res.ok) return store(null);

    const data     = await res.json();
    const regEvent = (data.events || []).find(e => e.eventAction === 'registration');
    if (!regEvent) return store(null);

    const ageInDays = (Date.now() - new Date(regEvent.eventDate).getTime()) / 86_400_000;
    return store({ ageInDays, registeredDate: regEvent.eventDate, domain: registeredDomain });
  } catch (err) {
    await idbSet('rdap', registeredDomain, { failed: true, cachedAt: Date.now() });
    console.warn(`[PhishGuard] RDAP failed for ${registeredDomain}:`, err.message);
    return null;
  }
}

function applyDomainAgeScore(analysis, ageInfo) {
  if (!ageInfo) return;

  const { ageInDays, registeredDate } = ageInfo;
  const dateStr = new Date(registeredDate).toLocaleDateString(undefined, {
    year: 'numeric', month: 'short', day: 'numeric',
  });

  let pts = 0;
  let label = '';

  if (ageInDays < 7) {
    pts   = 50;
    label = `Domain registered only ${Math.floor(ageInDays)} day(s) ago : ${dateStr}`;
  } else if (ageInDays < 30) {
    pts   = 35;
    label = `Domain registered ${Math.floor(ageInDays)} days ago : ${dateStr}`;
  } else if (ageInDays < 90) {
    pts   = 15;
    label = `Domain registered ${Math.floor(ageInDays)} days ago : ${dateStr}`;
  }

  if (pts > 0) {
    analysis.indicators.push({ score: pts, label });
    analysis.score = Math.min(analysis.score + pts, 100);
    analysis.riskLevel = analysis.score >= 60 ? 'high-risk'
      : analysis.score > 30 ? 'suspicious'
      : 'safe';
  }
}

// ─── Settings Helper ──────────────────────────────────────────────────────────

async function loadSettings() {
  const data = await chrome.storage.sync.get(['phishguard_settings']);
  return {
    notificationsEnabled: true,
    domainAgeEnabled:     true,
    safeBrowsingEnabled:  true,
    safeBrowsingApiKey:   '',
    phishTankEnabled:     true,
    phishTankApiKey:      '',
    virusTotalEnabled:    true,
    virusTotalApiKey:     '',
    webhookEnabled:       false,
    webhookUrl:           '',
    webhookAuthHeader:    '',
    shortenerExpansionEnabled: true,
    ...data.phishguard_settings,
  };
}

// ─── OpenPhish Feed ───────────────────────────────────────────────────────────

async function fetchOpenPhishFeed() {
  try {
    const res = await fetch('https://openphish.com/feed.txt', {
      cache:  'no-store',
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) throw new Error(`OpenPhish returned ${res.status}`);
    const domains = new Set();
    for (const line of (await res.text()).split('\n')) {
      const t = line.trim();
      if (!t) continue;
      try { domains.add(new URL(t).hostname.toLowerCase()); } catch {}
    }
    return domains;
  } catch (err) {
    console.warn('[PhishGuard] OpenPhish fetch failed:', err.message);
    return new Set();
  }
}

async function refreshFeedIfNeeded() {
  if (Date.now() - feedLastUpdated < FEED_TTL_MS) return;
  console.log('[PhishGuard] Refreshing OpenPhish feed…');
  const domains = await fetchOpenPhishFeed();
  if (domains.size > 0) {
    phishingFeedDomains = domains;
    feedLastUpdated     = Date.now();
    await chrome.storage.local.set({ feedDomains: [...domains], feedLastUpdated });
    console.log(`[PhishGuard] Feed updated: ${domains.size} domains`);
  }
}

function isInThreatFeed(domain) {
  const lower = domain.toLowerCase();
  if (phishingFeedDomains.has(lower)) return true;
  const parts = lower.split('.');
  return parts.length > 2 && phishingFeedDomains.has(parts.slice(-2).join('.'));
}

// ─── PhishTank ────────────────────────────────────────────────────────────────
// Community-curated phishing database. Free API key at https://www.phishtank.com/api_info.php
// Works without a key at a lower rate limit.

async function checkPhishTank(url, apiKey) {
  const now    = Date.now();
  const cached = await idbGet('phishtank', url);
  if (cached?.failed) {
    if (now - cached.cachedAt < FAIL_RETRY_TTL) return false; // unchecked, retry window active
    // else fall through and retry
  } else if (cached && now - cached.cachedAt < PT_CACHE_TTL) {
    return cached.flagged;
  }

  try {
    const body = new URLSearchParams({ url, format: 'json' });
    if (apiKey) body.set('app_key', apiKey);

    const res = await fetch('https://checkurl.phishtank.com/checkurl/', {
      method:  'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded',
                 'User-Agent':   'phishguard/2.0' },
      body,
      signal:  AbortSignal.timeout(8_000),
    });
    if (!res.ok) throw new Error(`PhishTank ${res.status}`);

    const data    = await res.json();
    const flagged = data?.results?.in_database === true
                 && data?.results?.valid === 'yes';

    await idbSet('phishtank', url, { flagged, cachedAt: now });
    return flagged;
  } catch (err) {
    console.warn('[PhishGuard] PhishTank query failed:', err.message);
    await idbSet('phishtank', url, { failed: true, cachedAt: now });
    return false;
  }
}

// ─── VirusTotal ───────────────────────────────────────────────────────────────
// Free tier: 4 req/min, 500 req/day.
// Uses the v3 URL lookup endpoint. A 404 means the URL is not yet in VT's
// database (genuinely unknown), which is treated as unchecked, not safe.

/**
 * Encode a URL to the base64url format VirusTotal v3 uses as a resource ID.
 * Returns null if the URL cannot be encoded (should not happen for valid hrefs).
 */
function vtUrlId(url) {
  try {
    return btoa(url).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  } catch {
    return null;
  }
}

async function checkVirusTotal(url, apiKey) {
  if (!apiKey) return null;

  const now    = Date.now();
  const cached = await idbGet('virustotal', url);
  if (cached?.failed) {
    if (now - cached.cachedAt < FAIL_RETRY_TTL) return null;
    // else fall through and retry
  } else if (cached && now - cached.cachedAt < VT_CACHE_TTL) {
    return cached.result;
  }

  const urlId = vtUrlId(url);
  if (!urlId) return null;

  try {
    const res = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
      headers: { 'x-apikey': apiKey },
      signal:  AbortSignal.timeout(8_000),
    });

    if (res.status === 404) {
      // URL not in VT database - cannot determine safety; don't cache so we retry later
      return null;
    }

    if (res.status === 429) {
      // Rate limited - cache as failed with short retry window
      await idbSet('virustotal', url, { failed: true, cachedAt: now });
      console.warn('[PhishGuard] VirusTotal rate limit hit (429)');
      return null;
    }

    if (!res.ok) throw new Error(`VirusTotal ${res.status}`);

    const data  = await res.json();
    const stats = data?.data?.attributes?.last_analysis_stats || {};
    const result = {
      malicious:  stats.malicious  || 0,
      suspicious: stats.suspicious || 0,
      harmless:   stats.harmless   || 0,
      total: (stats.malicious || 0) + (stats.suspicious || 0)
           + (stats.harmless  || 0) + (stats.undetected || 0),
    };

    await idbSet('virustotal', url, { result, cachedAt: now });
    console.log(`[PhishGuard] VirusTotal: ${result.malicious} malicious, ${result.suspicious} suspicious / ${result.total} engines`);
    return result;
  } catch (err) {
    console.warn('[PhishGuard] VirusTotal query failed:', err.message);
    await idbSet('virustotal', url, { failed: true, cachedAt: now });
    return null;
  }
}

// ─── URLHaus ──────────────────────────────────────────────────────────────────

async function queryURLHaus(url) {
  try {
    const res = await fetch('https://urlhaus-api.abuse.ch/v1/url/', {
      method: 'POST',
      body:   new URLSearchParams({ url }),
      signal: AbortSignal.timeout(8_000),
    });
    if (!res.ok) return false;
    return (await res.json()).query_status === 'is_listed';
  } catch (err) {
    console.warn('[PhishGuard] URLHaus query failed:', err.message);
    return false;
  }
}

// ─── Message Handler ──────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg.type === 'ANALYZE_URLS') {
    handleAnalyzeURLs(msg.urls).then(sendResponse);
    return true;
  }
  if (msg.type === 'ANALYZE_SENDER') {
    handleAnalyzeSender(msg.domain).then(sendResponse);
    return true;
  }
  if (msg.type === 'SUBMIT_FEEDBACK') {
    handleFeedback(msg.url, msg.domain, msg.feedback, msg.indicators).then(sendResponse);
    return true;
  }
  if (msg.type === 'GET_ALLOWLIST') {
    loadFeedback().then(fb => sendResponse(fb.allowlist || {}));
    return true;
  }
  if (msg.type === 'REMOVE_ALLOWLIST') {
    loadFeedback().then(async fb => {
      delete fb.allowlist[msg.domain];
      await saveFeedback(fb);
      sendResponse({ ok: true });
    });
    return true;
  }
  if (msg.type === 'GET_STATS') {
    chrome.storage.local.get(['phishguard_stats'], d =>
      sendResponse(d.phishguard_stats || defaultStats()));
    return true;
  }
  if (msg.type === 'CLEAR_STATS') {
    sessionHighRisk   = 0;
    sessionSuspicious = 0;
    updateBadge();
    chrome.storage.local.set({ phishguard_stats: defaultStats() }, () =>
      sendResponse({ ok: true }));
    return true;
  }
});

// ─── User Feedback / Allowlist ────────────────────────────────────────────────
// Users can mark URLs as "safe" (false positive) or "confirm phishing".
// "safe" feedback adds the domain to a per-user allowlist stored in
// chrome.storage.local. The allowlist suppresses future warnings for that
// domain by subtracting points from matching indicator categories.
//
// "phishing" feedback is stored in the log for future analytics.

const FEEDBACK_KEY = 'phishguard_feedback';

async function loadFeedback() {
  const data = await chrome.storage.local.get([FEEDBACK_KEY]);
  return data[FEEDBACK_KEY] || { allowlist: {}, confirmed: {} };
}

async function saveFeedback(fb) {
  await chrome.storage.local.set({ [FEEDBACK_KEY]: fb });
}

/**
 * Process a user feedback event.
 * @param {string} url        - the flagged URL
 * @param {string} domain     - its registered domain
 * @param {'safe'|'phishing'} feedback
 * @param {string[]} indicators - indicator labels active at the time of feedback
 */
async function handleFeedback(url, domain, feedback, indicators) {
  const fb = await loadFeedback();

  if (feedback === 'safe') {
    if (!fb.allowlist[domain]) fb.allowlist[domain] = { count: 0, indicators: {} };
    fb.allowlist[domain].count++;
    fb.allowlist[domain].lastMarkedSafe = Date.now();
    // Track which indicator types the user dismissed so we can weight them down
    for (const label of (indicators || [])) {
      fb.allowlist[domain].indicators[label] =
        (fb.allowlist[domain].indicators[label] || 0) + 1;
    }
    // Remove from confirmed list if user changes their mind
    delete fb.confirmed[url];
  }

  if (feedback === 'phishing') {
    fb.confirmed[url] = {
      domain,
      confirmedAt: Date.now(),
      indicators: indicators || [],
    };
    // Remove from allowlist if user changes their mind about this domain
    delete fb.allowlist[domain];
  }

  await saveFeedback(fb);
  return { ok: true };
}

/**
 * Apply allowlist score adjustment to an analysis result.
 * If the domain was previously marked safe by the user, reduce the score
 * proportionally to the number of times it was marked and how many of the
 * current indicators were previously dismissed.
 *
 * @param {object} analysis - mutable analyzeURL result
 */
async function applyAllowlistAdjustment(analysis) {
  const fb = await loadFeedback();
  const entry = fb.allowlist[analysis.domain];
  if (!entry) return;

  // Count how many of the current indicators were previously dismissed
  let dismissedCount = 0;
  for (const ind of analysis.indicators) {
    if (entry.indicators[ind.label]) dismissedCount++;
  }

  // If user marked this domain safe and at least half the current indicators
  // are the same ones they previously dismissed, apply a score reduction.
  // Reduction is capped at 80% of the original score to keep truly dangerous
  // URLs visible even with an allowlist entry.
  if (dismissedCount === 0 && entry.count < 3) return;

  const ratio     = analysis.indicators.length > 0
    ? dismissedCount / analysis.indicators.length
    : 0;
  const reduction = Math.min(
    Math.floor(analysis.score * Math.max(ratio, 0.3) * Math.min(entry.count, 5) / 5),
    Math.floor(analysis.score * 0.8),
  );

  if (reduction > 0) {
    analysis.score     = Math.max(analysis.score - reduction, 0);
    analysis.riskLevel = analysis.score >= 60 ? 'high-risk'
                       : analysis.score > 30  ? 'suspicious' : 'safe';
    analysis.indicators.push({
      score: -reduction,
      label: `User allowlist: score reduced by ${reduction} (domain marked safe ${entry.count} time${entry.count > 1 ? 's' : ''})`,
    });
    analysis.allowlisted = true;
  }
}

// ─── Analysis Pipeline ────────────────────────────────────────────────────────

async function handleAnalyzeURLs(urls) {
  await refreshFeedIfNeeded();
  const settings = await loadSettings();
  const results  = [];

  // ── Phase 0: parse every URL with the synchronous heuristic analyzer ────
  const pending = [];
  for (const rawUrl of urls) {
    const analysis = analyzeURL(rawUrl);
    if (!analysis) continue;
    pending.push({ rawUrl, analysis });
  }

  // ── Phase 0b: shortener expansion ───────────────────────────────────────
  // For every URL the analyzer flagged as a shortener (bit.ly, t.co, etc.),
  // fetch the real destination in parallel, re-run the analyzer on it, and
  // merge the indicators back into the original analysis. All downstream
  // layers (OpenPhish, Safe Browsing, RDAP, PhishTank, URLHaus, VT) then see
  // the real destination via urlForFeeds / domainForFeeds.
  //
  // Requires runtime host permission for <all_urls> since the redirect
  // target is unknown a priori. Skipped silently if the user never granted
  // that permission in Settings.
  if (settings.shortenerExpansionEnabled) {
    const shortenerTargets = pending.filter(p => p.analysis.isShortener);
    if (shortenerTargets.length > 0 && await hasShortenerPermission()) {
      const expansions = await Promise.all(
        shortenerTargets.map(p => expandShortener(p.rawUrl))
      );
      let expandedCount = 0;
      for (let i = 0; i < shortenerTargets.length; i++) {
        const expanded = expansions[i];
        if (!expanded || expanded === shortenerTargets[i].rawUrl) continue;
        const destAnalysis = analyzeURL(expanded);
        if (!destAnalysis) continue;
        mergeShortenerExpansion(shortenerTargets[i].analysis, destAnalysis, expanded);
        expandedCount++;
      }
      if (expandedCount > 0) {
        console.log(`[PhishGuard] Shorteners: expanded ${expandedCount}/${shortenerTargets.length} link(s)`);
      }
    }
  }

  // ── Effective URL / domain for every downstream threat feed layer ──────
  // If a shortener was expanded, feeds see the real destination. Otherwise
  // they fall back to the raw URL / parsed domain.
  for (const p of pending) {
    p.urlForFeeds    = p.analysis.expandedUrl    || p.rawUrl;
    p.domainForFeeds = p.analysis.expandedDomain || p.analysis.domain;
  }

  // ── Batch Safe Browsing across all effective URLs (one call total) ─────
  const sbFlagged = (settings.safeBrowsingEnabled && settings.safeBrowsingApiKey)
    ? await checkGoogleSafeBrowsing(pending.map(p => p.urlForFeeds), settings.safeBrowsingApiKey)
    : new Set();

  // ── Phase 1: OpenPhish + Safe Browsing ─────────────────────────────────
  // Developer hosts (replit.dev, localhost, private IPs, etc.) skip the
  // paid / rate-limited threat feed layers to avoid quota waste, but still
  // pass through the free ones (OpenPhish, Safe Browsing): a genuinely
  // malicious replit.dev URL flagged by Safe Browsing SHOULD still be
  // promoted from "developer" to "high-risk".
  for (const p of pending) {
    const { analysis, urlForFeeds, domainForFeeds } = p;
    p.isDeveloper = analysis.riskLevel === 'developer';

    // Layer 1: OpenPhish community feed (checks expanded domain)
    if (isInThreatFeed(domainForFeeds)) {
      analysis.indicators.push({ score: 50, label: 'Domain in threat intelligence feed (OpenPhish)' });
      analysis.score     = Math.min(analysis.score + 50, 100);
      analysis.riskLevel = 'high-risk';
      analysis.threatFeedHit = true;
    }

    // Layer 2: Google Safe Browsing (checks expanded URL)
    if (sbFlagged.has(urlForFeeds)) {
      analysis.indicators.push({ score: 60, label: 'URL flagged by Google Safe Browsing' });
      analysis.score     = 100;
      analysis.riskLevel = 'high-risk';
      analysis.safeBrowsingHit = true;
    }
  }

  // ── Phase 2: batch RDAP domain age lookup ──────────────────────────────
  // Collect unique eligible domains first, then fire all RDAP calls in
  // parallel. For an email with 20 links to the same domain this turns
  // 20 sequential lookups (even if most were IDB cache hits) into 1
  // network call + 19 fan-out no-ops. Independent domains also overlap
  // their latency instead of queueing behind one another.
  // Skipped for developer hosts: replit.dev is 7+ years old, querying RDAP
  // would consume quota to learn something irrelevant to phishing risk.
  if (settings.domainAgeEnabled) {
    const rdapDomains = new Set();
    for (const { analysis, isDeveloper, domainForFeeds } of pending) {
      if (analysis.score > 0 && !isDeveloper
          && !analysis.threatFeedHit && !analysis.safeBrowsingHit) {
        rdapDomains.add(domainForFeeds);
      }
    }

    if (rdapDomains.size > 0) {
      const ageMap  = new Map();
      const domains = [...rdapDomains];
      const ageInfos = await Promise.all(domains.map(d => checkDomainAge(d)));
      for (let i = 0; i < domains.length; i++) ageMap.set(domains[i], ageInfos[i]);

      for (const { analysis, isDeveloper, domainForFeeds } of pending) {
        if (isDeveloper || analysis.threatFeedHit || analysis.safeBrowsingHit) continue;
        if (!ageMap.has(domainForFeeds)) continue;
        const ageInfo = ageMap.get(domainForFeeds);
        applyDomainAgeScore(analysis, ageInfo);
        if (ageInfo) analysis.domainAge = ageInfo;
      }

      if (domains.length > 0) {
        console.log(`[PhishGuard] RDAP batch: ${domains.length} unique domain(s) for ${pending.length} URL(s)`);
      }
    }
  }

  // ── Phase 3: per-URL paid / rate-limited layers + allowlist ────────────
  for (const { analysis, isDeveloper, urlForFeeds } of pending) {
    // Layer 4: PhishTank - dedicated phishing database (on-demand per suspicious URL)
    // Skipped for developer hosts (see Layer 3 rationale).
    if (settings.phishTankEnabled && analysis.score > 0 && !isDeveloper
        && !analysis.threatFeedHit && !analysis.safeBrowsingHit) {
      const ptHit = await checkPhishTank(urlForFeeds, settings.phishTankApiKey);
      if (ptHit) {
        analysis.indicators.push({ score: 55, label: 'URL confirmed in PhishTank phishing database' });
        analysis.score     = Math.min(analysis.score + 55, 100);
        analysis.riskLevel = 'high-risk';
        analysis.phishTankHit = true;
      }
    }

    // Layer 5: URLHaus on-demand (only for high-risk candidates, spare quota).
    // Skipped for developer hosts: score never reaches 50 for pure developer
    // hosts anyway, but the explicit skip makes the intent clear.
    if (analysis.score >= 50 && !isDeveloper
        && !analysis.threatFeedHit && !analysis.safeBrowsingHit) {
      const hit = await queryURLHaus(urlForFeeds);
      if (hit) {
        analysis.indicators.push({ score: 50, label: 'URL flagged by URLHaus (abuse.ch)' });
        analysis.score     = 100;
        analysis.riskLevel = 'high-risk';
        analysis.urlhausHit = true;
      }
    }

    // Layer 6: VirusTotal (optional, free tier: 4 req/min / 500 req/day)
    // Only queried when URL is already suspicious from heuristics and no definitive
    // hit found yet. Catches zero-day phishing kits not yet in feed databases.
    // Skipped for developer hosts to preserve the VT daily quota.
    if (settings.virusTotalEnabled && settings.virusTotalApiKey
        && analysis.score > 0 && !isDeveloper
        && !analysis.threatFeedHit && !analysis.safeBrowsingHit
        && !analysis.urlhausHit   && !analysis.phishTankHit) {
      const vtResult = await checkVirusTotal(urlForFeeds, settings.virusTotalApiKey);
      if (vtResult) {
        if (vtResult.malicious >= 3) {
          analysis.indicators.push({
            score: 60,
            label: `VirusTotal: flagged by ${vtResult.malicious}/${vtResult.total} security engines`,
          });
          analysis.score     = Math.min(analysis.score + 60, 100);
          analysis.riskLevel = 'high-risk';
          analysis.vtHit     = true;
        } else if (vtResult.malicious >= 1) {
          analysis.indicators.push({
            score: 35,
            label: `VirusTotal: flagged by ${vtResult.malicious}/${vtResult.total} security engine(s) - verify manually`,
          });
          analysis.score     = Math.min(analysis.score + 35, 100);
          analysis.riskLevel = analysis.score >= 60 ? 'high-risk' : 'suspicious';
          analysis.vtHit     = true;
        } else if (vtResult.suspicious >= 5) {
          analysis.indicators.push({
            score: 15,
            label: `VirusTotal: flagged as suspicious by ${vtResult.suspicious}/${vtResult.total} engines`,
          });
          analysis.score     = Math.min(analysis.score + 15, 100);
          analysis.riskLevel = analysis.score >= 60 ? 'high-risk'
                             : analysis.score > 30  ? 'suspicious' : 'safe';
        }
      }
    }

    // Apply user allowlist score adjustment (after all detection layers)
    await applyAllowlistAdjustment(analysis);

    results.push(analysis);

    // Fire notification + SIEM webhook (non-blocking)
    if (analysis.riskLevel === 'high-risk') {
      notifyHighRisk(analysis);
      postToWebhook(analysis, settings);
    }
  }

  await updateStats(results);
  return results;
}

// ─── Sender Domain Analysis ───────────────────────────────────────────────────

/**
 * Run heuristic + feed + RDAP checks on a sender's email domain.
 * Skips Safe Browsing, PhishTank, and URLHaus: those APIs expect full URLs
 * and would waste quota on domain-only input that often returns nothing useful.
 *
 * @param {string} domain - registered domain extracted from the From: header
 * @returns {object|null} - same shape as a single analyzeURL() result, or null
 */
async function handleAnalyzeSender(domain) {
  if (!domain || !domain.includes('.')) return null;

  // Construct a minimal URL so the existing heuristic engine can parse it
  const analysis = analyzeURL(`https://${domain}/`);
  if (!analysis) return null;

  // Layer 1: OpenPhish community feed (domain-level hit is directly relevant)
  await refreshFeedIfNeeded();
  if (isInThreatFeed(domain)) {
    analysis.indicators.push({ score: 50, label: 'Sender domain in threat intelligence feed (OpenPhish)' });
    analysis.score     = Math.min(analysis.score + 50, 100);
    analysis.riskLevel = 'high-risk';
  }

  // Layer 2: RDAP domain age: a brand-new domain impersonating a bank is a
  // very strong signal; skip if already max-scored or feed-flagged.
  if (!analysis.threatFeedHit && analysis.score > 0) {
    const settings = await loadSettings();
    if (settings.domainAgeEnabled) {
      const ageInfo = await checkDomainAge(domain);
      applyDomainAgeScore(analysis, ageInfo);
      if (ageInfo) analysis.domainAge = ageInfo;
    }
  }

  return analysis;
}

// ─── Stats & Badge Update ─────────────────────────────────────────────────────

function defaultStats() {
  return {
    totalScanned:     0,
    suspicious:       0,
    highRisk:         0,
    lastScan:         null,
    recentIndicators: [],
    log:              [],
  };
}

async function updateStats(results) {
  const stored = await chrome.storage.local.get(['phishguard_stats']);
  const stats  = stored.phishguard_stats || defaultStats();

  stats.totalScanned += results.length;
  stats.lastScan      = new Date().toISOString();

  for (const r of results) {
    if (r.riskLevel === 'suspicious') {
      stats.suspicious++;
      sessionSuspicious++;
    }
    if (r.riskLevel === 'high-risk') {
      stats.highRisk++;
      sessionHighRisk++;

      // Keep recentIndicators as {score, label} objects so the popup can
      // display the score contribution alongside the label.
      for (const ind of r.indicators) {
        if (!stats.recentIndicators.some(existing =>
          (existing && existing.label ? existing.label : existing) === ind.label)) {
          stats.recentIndicators.unshift({ score: ind.score, label: ind.label });
        }
      }
      stats.recentIndicators = stats.recentIndicators.slice(0, 10);

      stats.log.unshift({
        timestamp:  new Date().toISOString(),
        url:        r.url,
        domain:     r.domain,
        score:      r.score,
        riskLevel:  r.riskLevel,
        indicators: r.indicators.map(i => ({ score: i.score, label: i.label })),
        domainAge:  r.domainAge ? `${Math.floor(r.domainAge.ageInDays)} days old` : null,
      });
      stats.log = stats.log.slice(0, 200);
    }
  }

  await chrome.storage.local.set({ phishguard_stats: stats });
  updateBadge(); // always update badge after a scan
}

// ─── Context Menu: "Allow this domain" ────────────────────────────────────────
// Adds a right-click menu item on links inside supported email clients.
// Clicking it extracts the domain and adds it to the per-user allowlist,
// giving the user a one-click way to suppress false positives.

const CONTEXT_MENU_ID = 'phishguard-allow-domain';

// Email client URL patterns where the context menu is relevant
const EMAIL_PATTERNS = [
  'https://mail.google.com/*',
  'https://outlook.live.com/*',
  'https://outlook.office.com/*',
  'https://outlook.office365.com/*',
  'https://outlook.com/*',
  'https://mail.yahoo.com/*',
  'https://mail.proton.me/*',
];

// Create menu item once at SW startup; chrome.contextMenus.create is idempotent
// when called with the same id, so repeated SW restarts are safe.
chrome.contextMenus.create({
  id:                  CONTEXT_MENU_ID,
  title:               'PhishGuard: Allow this domain',
  contexts:            ['link'],
  documentUrlPatterns: EMAIL_PATTERNS,
}, () => chrome.runtime.lastError); // suppress "duplicate id" errors on SW restart

chrome.contextMenus.onClicked.addListener(async (info) => {
  if (info.menuItemId !== CONTEXT_MENU_ID) return;
  if (!info.linkUrl) return;

  let domain;
  try { domain = new URL(info.linkUrl).hostname.toLowerCase(); } catch { return; }

  // Reuse the existing feedback infrastructure to add to allowlist
  await handleFeedback(info.linkUrl, domain, 'safe', []);
  console.log(`[PhishGuard] Domain added to allowlist via context menu: ${domain}`);
});

// ─── Alarms & Startup ─────────────────────────────────────────────────────────

chrome.alarms.create('phishguard-feed-refresh',  { periodInMinutes: 360 });
chrome.alarms.create('phishguard-cache-prune',    { periodInMinutes: 720 }); // 12 h

chrome.alarms.onAlarm.addListener(alarm => {
  if (alarm.name === 'phishguard-feed-refresh') {
    feedLastUpdated = 0;
    refreshFeedIfNeeded();
  }
  if (alarm.name === 'phishguard-cache-prune') {
    pruneAllCaches();
  }
});

async function pruneAllCaches() {
  try {
    const [rdapDel, sbDel, ptDel, vtDel, notifDel, whDel, shDel] = await Promise.all([
      idbPrune('rdap',          RDAP_CACHE_TTL),
      idbPrune('safebrowsing',  SB_CACHE_TTL),
      idbPrune('phishtank',     PT_CACHE_TTL),
      idbPrune('virustotal',    VT_CACHE_TTL),
      idbPrune('notifications', NOTIFY_COOLDOWN),
      idbPrune('webhooks',      WEBHOOK_COOLDOWN_MS),
      idbPrune('shorteners',    SHORTENER_TTL),
    ]);
    console.log(`[PhishGuard] Cache pruned : rdap:${rdapDel} sb:${sbDel} pt:${ptDel} vt:${vtDel} notif:${notifDel} webhook:${whDel} shortener:${shDel} entries removed`);
  } catch (err) {
    console.warn('[PhishGuard] Cache prune failed:', err.message);
  }
}

(async () => {
  const stored = await chrome.storage.local.get(['feedDomains', 'feedLastUpdated']);
  if (stored.feedDomains) {
    phishingFeedDomains = new Set(stored.feedDomains);
    feedLastUpdated     = stored.feedLastUpdated || 0;
    console.log(`[PhishGuard] Restored ${phishingFeedDomains.size} feed domains from cache`);
  }
  refreshFeedIfNeeded();
})();

// ─── Context Menu: "Analyze link with PhishGuard" ─────────────────────────────
// Right-click any link anywhere in Chrome to open the analyzer page prefilled
// with that URL. No sign-in is required to run the analysis; the context menu
// is just a shortcut into the existing analyzer flow.
const PG_CTX_MENU_ID = 'phishguard-analyze-link';

function registerContextMenu() {
  // removeAll first so reloading the extension does not create duplicate items
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({
      id:       PG_CTX_MENU_ID,
      title:    'Analyze link with PhishGuard',
      contexts: ['link'],
    });
  });
}

chrome.runtime.onInstalled.addListener(registerContextMenu);
chrome.runtime.onStartup.addListener(registerContextMenu);

chrome.contextMenus.onClicked.addListener((info) => {
  if (info.menuItemId !== PG_CTX_MENU_ID || !info.linkUrl) return;
  const target = chrome.runtime.getURL(
    `analyzer.html?url=${encodeURIComponent(info.linkUrl)}`
  );
  chrome.tabs.create({ url: target });
});
