/**
 * PhishGuard – Background Service Worker v2
 *
 * Improvements in this version:
 *   #1  Badge counter   – live threat count on the extension icon
 *   #2  Notifications   – desktop alert when a high-risk link is detected
 *   #3  Google Safe Browsing API – real-time URL reputation check
 *   #4  RDAP domain age – flag newly registered domains
 *
 * Existing features retained: OpenPhish feed, URLHaus, stats/log.
 */

import { analyzeURL }                       from './urlAnalyzer.js';
import { idbGet, idbSet, idbPrune }         from './idb.js';

// ─── Constants ────────────────────────────────────────────────────────────────

const FEED_TTL_MS      = 6  * 60 * 60 * 1000;  // 6 h  - OpenPhish refresh
const RDAP_CACHE_TTL   = 24 * 60 * 60 * 1000;  // 24 h - RDAP per-domain cache
const SB_CACHE_TTL     = 30 * 60 * 1000;        // 30 m - Safe Browsing cache
const PT_CACHE_TTL     = 60 * 60 * 1000;        // 1 h  - PhishTank cache
const NOTIFY_COOLDOWN  = 60 * 60 * 1000;        // 1 h  - dedup per domain
const CACHE_PRUNE_MS   = 12 * 60 * 60 * 1000;  // 12 h - IDB pruning interval
const FAIL_RETRY_TTL   =  5 * 60 * 1000;        // 5 m  - retry window after a failed API call

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
// IMPROVEMENT #1 – Badge Counter
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
// IMPROVEMENT #2 – Desktop Notifications
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
    message:            `${result.domain}   —   Score: ${result.score}/100`,
    contextMessage:     topIndicators || 'Open PhishGuard for details.',
    priority:           2,
    requireInteraction: false,
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// IMPROVEMENT #3 – Google Safe Browsing API
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

    // Cache all results (including clean ones) — parallel writes
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
// IMPROVEMENT #4 – RDAP Domain Age Check
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
    label = `Domain registered only ${Math.floor(ageInDays)} day(s) ago — ${dateStr}`;
  } else if (ageInDays < 30) {
    pts   = 35;
    label = `Domain registered ${Math.floor(ageInDays)} days ago — ${dateStr}`;
  } else if (ageInDays < 90) {
    pts   = 15;
    label = `Domain registered ${Math.floor(ageInDays)} days ago — ${dateStr}`;
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

// ─── Analysis Pipeline ────────────────────────────────────────────────────────

async function handleAnalyzeURLs(urls) {
  await refreshFeedIfNeeded();
  const settings = await loadSettings();
  const results  = [];

  // Batch Safe Browsing request (one call for all URLs — efficient)
  const sbFlagged = (settings.safeBrowsingEnabled && settings.safeBrowsingApiKey)
    ? await checkGoogleSafeBrowsing(urls, settings.safeBrowsingApiKey)
    : new Set();

  for (const rawUrl of urls) {
    const analysis = analyzeURL(rawUrl);
    if (!analysis) continue;

    // Layer 1: OpenPhish community feed
    if (isInThreatFeed(analysis.domain)) {
      analysis.indicators.push({ score: 50, label: 'Domain in threat intelligence feed (OpenPhish)' });
      analysis.score     = Math.min(analysis.score + 50, 100);
      analysis.riskLevel = 'high-risk';
      analysis.threatFeedHit = true;
    }

    // Layer 2: Google Safe Browsing
    if (sbFlagged.has(rawUrl)) {
      analysis.indicators.push({ score: 60, label: 'URL flagged by Google Safe Browsing' });
      analysis.score     = 100;
      analysis.riskLevel = 'high-risk';
      analysis.safeBrowsingHit = true;
    }

    // Layer 3: RDAP domain age (only for already-suspicious, saves API calls)
    if (settings.domainAgeEnabled && analysis.score > 0
        && !analysis.threatFeedHit && !analysis.safeBrowsingHit) {
      const ageInfo = await checkDomainAge(analysis.domain);
      applyDomainAgeScore(analysis, ageInfo);
      if (ageInfo) analysis.domainAge = ageInfo;
    }

    // Layer 4: PhishTank — dedicated phishing database (on-demand per suspicious URL)
    if (settings.phishTankEnabled && analysis.score > 0
        && !analysis.threatFeedHit && !analysis.safeBrowsingHit) {
      const ptHit = await checkPhishTank(rawUrl, settings.phishTankApiKey);
      if (ptHit) {
        analysis.indicators.push({ score: 55, label: 'URL confirmed in PhishTank phishing database' });
        analysis.score     = Math.min(analysis.score + 55, 100);
        analysis.riskLevel = 'high-risk';
        analysis.phishTankHit = true;
      }
    }

    // Layer 5: URLHaus on-demand (only for high-risk candidates, spare quota)
    if (analysis.score >= 50 && !analysis.threatFeedHit && !analysis.safeBrowsingHit) {
      const hit = await queryURLHaus(rawUrl);
      if (hit) {
        analysis.indicators.push({ score: 50, label: 'URL flagged by URLHaus (abuse.ch)' });
        analysis.score     = 100;
        analysis.riskLevel = 'high-risk';
        analysis.urlhausHit = true;
      }
    }

    results.push(analysis);

    // Fire notification (non-blocking)
    if (analysis.riskLevel === 'high-risk') notifyHighRisk(analysis);
  }

  await updateStats(results);
  return results;
}

// ─── Sender Domain Analysis ───────────────────────────────────────────────────

/**
 * Run heuristic + feed + RDAP checks on a sender's email domain.
 * Skips Safe Browsing, PhishTank, and URLHaus — those APIs expect full URLs
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

  // Layer 2: RDAP domain age — a brand-new domain impersonating a bank is a
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

      for (const ind of r.indicators) {
        if (!stats.recentIndicators.includes(ind.label))
          stats.recentIndicators.unshift(ind.label);
      }
      stats.recentIndicators = stats.recentIndicators.slice(0, 10);

      stats.log.unshift({
        timestamp:  new Date().toISOString(),
        url:        r.url,
        domain:     r.domain,
        score:      r.score,
        riskLevel:  r.riskLevel,
        indicators: r.indicators.map(i => i.label),
        domainAge:  r.domainAge ? `${Math.floor(r.domainAge.ageInDays)} days old` : null,
      });
      stats.log = stats.log.slice(0, 200);
    }
  }

  await chrome.storage.local.set({ phishguard_stats: stats });
  updateBadge(); // always update badge after a scan
}

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
    const [rdapDel, sbDel, ptDel, notifDel] = await Promise.all([
      idbPrune('rdap',          RDAP_CACHE_TTL),
      idbPrune('safebrowsing',  SB_CACHE_TTL),
      idbPrune('phishtank',     PT_CACHE_TTL),
      idbPrune('notifications', NOTIFY_COOLDOWN),
    ]);
    console.log(`[PhishGuard] Cache pruned — rdap:${rdapDel} sb:${sbDel} pt:${ptDel} notif:${notifDel} entries removed`);
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
