/**
 * PhishGuard – Gmail Content Script
 * Monitors Gmail for opened emails, extracts links, requests analysis,
 * and injects visual warnings.
 */

(function () {
  'use strict';

  // -------------------------------------------------------------------
  // Constants
  // -------------------------------------------------------------------
  const SCAN_DEBOUNCE_MS = 600;
  const PROCESSED_ATTR   = 'data-phishguard-scanned';
  const BANNER_CLASS     = 'phishguard-scan-banner';

  /**
   * Email body selectors per platform — ordered from most to least specific.
   * Covers Gmail, Outlook Web, Yahoo Mail, ProtonMail.
   */
  const EMAIL_BODY_SELECTORS = [
    // Gmail
    '.a3s.aiL',
    '.a3s',
    '.ii.gt .a3s',
    '.ii.gt',
    '.adn.ads',
    // Outlook Web App (OWA / office365 / outlook.live.com)
    '[aria-label="Message body"]',
    '.wide-content-host',
    '[class*="ReadingPaneContent"] [class*="messageBody"]',
    '[class*="ReadingPaneContent"]',
    '[data-app-section="ConversationContainer"] [class*="body"]',
    // Yahoo Mail
    '[data-test-id="message-view-body"]',
    '.msg-body',
    '[data-test-id="rte"]',
    // ProtonMail
    '.proton-raw',
    '[class*="proton-html-body"]',
  ];

  /**
   * Known redirect/proxy URL patterns used by email platforms.
   * Gmail, Outlook, Yahoo, LinkedIn all wrap external links — we must unwrap
   * to get the real destination before analysis.
   */
  const REDIRECT_PARAMS = {
    // Google / Gmail
    'google.com':                          ['q', 'url'],
    // Microsoft Outlook Safe Links
    'safelinks.protection.outlook.com':    ['url'],
    // Facebook / Instagram
    'l.facebook.com':                      ['u'],
    'l.instagram.com':                     ['u'],
    // LinkedIn
    'lnkd.in':                             ['url'],
    'linkedin.com':                        ['url'],  // linkedin.com/safety/go?url=
    // Twitter / X
    't.co':                                ['url'],
    // Yahoo Mail redirect
    'r.search.yahoo.com':                  ['u'],
    'r3.search.yahoo.com':                 ['u'],
    'clicks.aweber.com':                   ['url'],
    // Mailchimp / SendGrid tracking links
    'mailchi.mp':                          ['u'],
    'click.mailchimp.com':                 ['u'],
    'u.ng.sendgrid.net':                   ['url'],
    // Constant Contact
    'click.constantcontact.com':           ['url'],
    // HubSpot
    'track.hubspot.com':                   ['redirect_url'],
  };

  // -------------------------------------------------------------------
  // Bidi / RLO detection (runs in content script — no background needed)
  // -------------------------------------------------------------------
  /**
   * Unicode bidirectional control characters — identical set to urlAnalyzer.js.
   * Checked here against anchor *display text* which the URL analyzer never sees.
   */
  const BIDI_CONTROL_RE = /[\u202A-\u202E\u2066-\u2069\u200E\u200F]/;

  /**
   * Inject an inline warning banner on an anchor whose visible text contains
   * bidi control characters.  The href may be completely clean — the attack
   * spoofs the *displayed* URL, not the destination.
   *
   * Example: <a href="https://evil.com">https://google.co\u202Em</a>
   *   renders as: "https://google.com" in some renderers, href goes to evil.com.
   */
  function applyBidiDisplayWarning(anchor) {
    if (anchor.hasAttribute('data-phishguard-bidi')) return;
    anchor.setAttribute('data-phishguard-bidi', 'true');
    anchor.classList.add('phishguard-high-risk');

    const safe = s => String(s).replace(/[&<>"']/g, c =>
      ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]));

    const tooltip = document.createElement('div');
    tooltip.className = 'phishguard-tooltip';
    tooltip.innerHTML = `
      <div class="phishguard-tooltip-header">
        <span class="phishguard-verdict">High Risk</span>
        <span class="phishguard-score-pill">RLO</span>
      </div>
      <div class="phishguard-tooltip-body">
        <div class="phishguard-domain-row">
          <span class="phishguard-domain-label">Display text spoofed</span>
        </div>
        <span class="phishguard-indicators-label">Indicators</span>
        <ul><li>Bidirectional control character (RLO/LRO) in visible link text — the displayed URL is not what it appears to be</li></ul>
        <div class="phishguard-advice critical">
          Do not trust the displayed address. Check the real destination before clicking.
        </div>
      </div>
    `;

    const wrapper = document.createElement('span');
    wrapper.className = 'phishguard-wrapper';
    wrapper.appendChild(tooltip);

    anchor.setAttribute('aria-label',
      'PhishGuard: High risk — link display text contains direction-reversal spoofing characters');
    anchor.parentNode.insertBefore(wrapper, anchor);
    wrapper.appendChild(anchor);
  }

  // -------------------------------------------------------------------
  // Debounce
  // -------------------------------------------------------------------
  function debounce(fn, delay) {
    let timer;
    return (...args) => { clearTimeout(timer); timer = setTimeout(() => fn(...args), delay); };
  }

  // -------------------------------------------------------------------
  // Unwrap redirect/proxy URLs to get the real destination
  // -------------------------------------------------------------------
  function unwrapURL(rawHref) {
    let href = rawHref;
    // Iteratively unwrap (some links are double-wrapped)
    for (let i = 0; i < 3; i++) {
      let parsed;
      try { parsed = new URL(href); } catch { break; }

      const host = parsed.hostname.replace(/^www\./, '');
      const params = REDIRECT_PARAMS[host];
      if (!params) break;

      let unwrapped = null;
      for (const p of params) {
        const val = parsed.searchParams.get(p);
        if (val) { unwrapped = decodeURIComponent(val); break; }
      }
      if (!unwrapped || unwrapped === href) break;
      href = unwrapped;
    }
    return href;
  }

  // -------------------------------------------------------------------
  // Find email body containers currently visible in DOM
  // -------------------------------------------------------------------
  function findEmailContainers() {
    const seen = new Set();
    const results = [];
    for (const sel of EMAIL_BODY_SELECTORS) {
      for (const el of document.querySelectorAll(sel)) {
        if (!seen.has(el)) { seen.add(el); results.push(el); }
      }
    }
    return results;
  }

  // -------------------------------------------------------------------
  // Extract unprocessed anchors from a container
  // -------------------------------------------------------------------
  function extractLinks(container) {
    const links = [];
    for (const a of container.querySelectorAll('a[href]')) {
      if (a.hasAttribute(PROCESSED_ATTR)) continue;
      const href = a.getAttribute('href');
      if (!href || href.startsWith('mailto:') || href.startsWith('#')
          || href.startsWith('javascript:')) continue;
      const realHref = unwrapURL(href);
      links.push({ element: a, href: realHref, displayHref: href });
    }
    return links;
  }

  // -------------------------------------------------------------------
  // Build and inject tooltip + highlight for a flagged link
  // -------------------------------------------------------------------
  function applyWarning(anchor, result) {
    anchor.setAttribute(PROCESSED_ATTR, 'true');
    const isCritical = result.riskLevel === 'high-risk';

    anchor.classList.add(isCritical ? 'phishguard-high-risk' : 'phishguard-suspicious');

    const indicatorLines = result.indicators
      .map(i => `<li>${escapeHTML(i.label)}</li>`).join('');

    const tooltip = document.createElement('div');
    tooltip.className = 'phishguard-tooltip' + (isCritical ? '' : ' warn-level');
    tooltip.innerHTML = `
      <div class="phishguard-tooltip-header">
        <span class="phishguard-verdict${isCritical ? '' : ' warn'}">
          ${isCritical ? 'High Risk' : 'Suspicious'}
        </span>
        <span class="phishguard-score-pill">${result.score}/100</span>
      </div>
      <div class="phishguard-tooltip-body">
        <div class="phishguard-domain-row">
          <span class="phishguard-domain-label">Domain</span>
          <span class="phishguard-domain-value">${escapeHTML(result.domain)}</span>
        </div>
        <span class="phishguard-indicators-label">Indicators</span>
        <ul>${indicatorLines}</ul>
        <div class="phishguard-advice${isCritical ? ' critical' : ''}">
          ${isCritical
            ? 'Do not interact with this link. Report this email as phishing.'
            : 'Exercise caution before clicking this link.'}
        </div>
      </div>
    `;

    const wrapper = document.createElement('span');
    wrapper.className = 'phishguard-wrapper';
    wrapper.appendChild(tooltip);

    anchor.setAttribute('aria-label',
      `PhishGuard: ${isCritical ? 'High risk' : 'Suspicious'} link — ${result.domain} (${result.score}/100)`);

    anchor.parentNode.insertBefore(wrapper, anchor);
    wrapper.appendChild(anchor);
  }

  function markSafe(anchor) {
    anchor.setAttribute(PROCESSED_ATTR, 'true');
  }

  function escapeHTML(str) {
    const m = { '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' };
    return String(str).replace(/[&<>"']/g, c => m[c]);
  }

  // -------------------------------------------------------------------
  // Form scanner — detects phishing forms embedded in HTML emails
  // Attackers embed <form action="https://evil.com/steal"> in emails
  // to harvest credentials without a redirect.
  // -------------------------------------------------------------------
  const FORM_ATTR = 'data-phishguard-form';

  function scanFormsInContainers(containers) {
    for (const container of containers) {
      for (const form of container.querySelectorAll('form[action]')) {
        if (form.hasAttribute(FORM_ATTR)) continue;
        form.setAttribute(FORM_ATTR, 'true');

        const action = form.getAttribute('action');
        if (!action || action.startsWith('#') || action.startsWith('mailto:')) continue;

        let actionHost;
        try {
          actionHost = new URL(action, window.location.href).hostname;
        } catch { continue; }

        // Flag if form submits outside the current mail provider's domain
        const currentHost = window.location.hostname;
        if (actionHost && actionHost !== currentHost && !actionHost.endsWith('.' + currentHost)) {
          injectFormWarning(form, actionHost);
        }
      }
    }
  }

  function injectFormWarning(form, externalDomain) {
    const banner = document.createElement('div');
    banner.style.cssText = [
      'display:block', 'margin:6px 0', 'padding:7px 12px',
      'background:#1a0f0f', 'border:1px solid #6b2020',
      'border-left:3px solid #c0392b', 'border-radius:3px',
      'font-family:Segoe UI,system-ui,sans-serif', 'font-size:12px',
      'color:#c8ccd4', 'line-height:1.5',
    ].join(';');
    banner.innerHTML =
      `<strong style="color:#c0392b;font-size:10.5px;text-transform:uppercase;letter-spacing:.05em">PhishGuard — Suspicious Form</strong><br>` +
      `This email contains a form that submits data to <code style="font-family:Consolas,monospace;color:#8ab4f8">${escapeHTML(externalDomain)}</code>. ` +
      `Do not enter any credentials.`;
    form.parentNode.insertBefore(banner, form);
  }

  // -------------------------------------------------------------------
  // Per-email scan banner
  // -------------------------------------------------------------------

  /**
   * Count processed links in a container by reading their DOM classes.
   * 'pending' links (sent to background but not yet resolved) are excluded.
   */
  function countProcessedLinks(container) {
    let highRisk = 0, suspicious = 0, safe = 0;
    for (const a of container.querySelectorAll(`a[${PROCESSED_ATTR}]`)) {
      if (a.getAttribute(PROCESSED_ATTR) === 'pending') continue;
      if (a.classList.contains('phishguard-high-risk'))    highRisk++;
      else if (a.classList.contains('phishguard-suspicious')) suspicious++;
      else safe++;
    }
    return { total: highRisk + suspicious + safe, highRisk, suspicious };
  }

  /**
   * Inject (or refresh) a scan-summary banner at the top of the email container.
   * Called after each batch of results is applied.
   */
  function injectScanBanner(container) {
    const stats = countProcessedLinks(container);
    if (stats.total === 0) return;   // no settled results yet

    // Remove previous banner so we can re-render with updated counts
    container.querySelector('.' + BANNER_CLASS)?.remove();

    const level  = stats.highRisk > 0 ? 'high-risk'
                 : stats.suspicious > 0 ? 'suspicious'
                 : 'safe';
    const color  = level === 'high-risk' ? '#c0392b'
                 : level === 'suspicious' ? '#b87333'
                 : '#2e7d52';

    let status;
    if (level === 'high-risk') {
      status = `${stats.highRisk} high-risk link${stats.highRisk > 1 ? 's' : ''} detected` +
               (stats.suspicious > 0 ? ` · ${stats.suspicious} suspicious` : '') +
               ' — do not click flagged links';
    } else if (level === 'suspicious') {
      status = `${stats.suspicious} suspicious link${stats.suspicious > 1 ? 's' : ''} detected — verify before clicking`;
    } else {
      status = `${stats.total} link${stats.total > 1 ? 's' : ''} scanned — no threats detected`;
    }

    const banner = document.createElement('div');
    banner.className = BANNER_CLASS;
    // Inline styles ensure the banner renders correctly inside any email client's DOM
    banner.style.cssText = [
      'display:flex', 'align-items:center', 'gap:8px',
      'margin:0 0 12px 0', 'padding:6px 12px',
      'background:#141517', 'border:1px solid #26282c',
      `border-left:3px solid ${color}`, 'border-radius:0 3px 3px 0',
      'font-family:Segoe UI,system-ui,sans-serif', 'font-size:11.5px',
      'color:#8a9ab0', 'line-height:1.5', 'box-sizing:border-box',
      'max-width:100%',
    ].join(';');

    banner.innerHTML =
      `<span style="color:${color};font-weight:600;font-size:10px;` +
      `text-transform:uppercase;letter-spacing:.07em;white-space:nowrap">PhishGuard</span>` +
      `<span style="color:#2a2e38;user-select:none"> │ </span>` +
      `<span>${escapeHTML(status)}</span>`;

    container.prepend(banner);
  }

  // -------------------------------------------------------------------
  // Core scan
  // -------------------------------------------------------------------
  async function scanEmailContainers() {
    const containers = findEmailContainers();
    if (!containers.length) return;

    // Scan for embedded phishing forms (runs on every pass, fast)
    scanFormsInContainers(containers);

    for (const container of containers) {
      const links = extractLinks(container);
      if (!links.length) continue;

      // ── Bidi display-text pre-scan (synchronous, no network) ────────────────
      // The URL analyzer only receives the href; it cannot see anchor display text.
      // An attacker can use a clean href with bidi chars in the visible text to make
      // "https://evil.com" appear to display as "https://google.com".
      // Check both the raw (pre-unwrap) href attribute and the anchor's visible text.
      for (const { element } of links) {
        const rawHref    = element.getAttribute('href') || '';
        const displayTxt = element.textContent || '';
        if (BIDI_CONTROL_RE.test(rawHref) || BIDI_CONTROL_RE.test(displayTxt)) {
          applyBidiDisplayWarning(element);
        }
      }

      // Mark immediately to prevent double-processing
      for (const { element } of links) element.setAttribute(PROCESSED_ATTR, 'pending');

      const urls = links.map(l => l.href);

      let results;
      try {
        results = await chrome.runtime.sendMessage({ type: 'ANALYZE_URLS', urls });
      } catch (err) {
        console.warn('[PhishGuard] Background unavailable:', err.message);
        for (const { element } of links) element.setAttribute(PROCESSED_ATTR, 'true');
        continue;
      }

      if (!Array.isArray(results)) {
        for (const { element } of links) element.setAttribute(PROCESSED_ATTR, 'true');
        continue;
      }

      // Build result lookup by normalized URL
      const resultMap = new Map();
      for (const r of results) resultMap.set(r.url, r);

      for (const { element, href } of links) {
        let key = href;
        try { key = new URL(/^https?:\/\//i.test(href) ? href : 'https://' + href).href; } catch {}

        const result = resultMap.get(key);
        if (result && result.riskLevel !== 'safe') {
          applyWarning(element, result);
        } else {
          markSafe(element);
        }
      }

      // Inject / refresh the per-email summary banner
      injectScanBanner(container);
    }
  }

  const debouncedScan = debounce(scanEmailContainers, SCAN_DEBOUNCE_MS);

  // -------------------------------------------------------------------
  // MutationObserver — react to Gmail dynamically loading email content
  // -------------------------------------------------------------------
  const observer = new MutationObserver((mutations) => {
    for (const m of mutations) {
      if (m.addedNodes.length) { debouncedScan(); return; }
    }
  });

  observer.observe(document.body, { childList: true, subtree: true });

  // Initial scan
  scanEmailContainers();

  console.log('[PhishGuard] Active — monitoring Gmail for phishing links');
})();
