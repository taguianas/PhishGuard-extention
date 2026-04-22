/**
 * PhishGuard - Content Script (Gmail, Outlook, Yahoo, ProtonMail)
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
  const AUTH_BANNER_ATTR   = 'data-phishguard-auth';
  const SENDER_BANNER_ATTR = 'data-phishguard-sender';
  const QR_BANNER_ATTR     = 'data-phishguard-qr';

  /** Minimum image dimension (px) to attempt QR scanning: skips tracking pixels. */
  const QR_MIN_SIZE = 50;

  /**
   * Score penalty for each failed email authentication check.
   * DMARC is weighted highest: a DMARC fail means the sending domain
   * explicitly disavows the message, which is a strong spoofing signal.
   */
  const AUTH_FAIL_SCORES = { dmarc: 40, spf: 30, dkim: 25 };

  /**
   * DOM selectors for email header / metadata regions across Gmail,
   * Outlook Web App, Yahoo Mail, and ProtonMail. We search these elements
   * BEFORE the email body to locate "Authentication-Results" text without
   * picking up false positives from body content that mentions these terms.
   */
  const AUTH_HEADER_SELECTORS = [
    // Gmail: expanded sender detail rows / message header area
    '.adn.ads',
    '.gE.iv.gt',
    '.ajA',
    '.gs',
    // Outlook Web App (multiple versions / layouts)
    '[class*="ReadingPaneHeader"]',
    '[class*="MessageHeader"]',
    '[role="heading"][aria-level]',
    '[class*="senderContainer"]',
    '[class*="FromContainer"]',
    '[class*="ItemHeader"]',
    '[data-app-section="ConversationContainer"] [class*="header"]',
    // Yahoo Mail
    '[data-test-id="message-view-header"]',
    // ProtonMail
    '[class*="HeaderTitle"]',
  ];

  /** Matches dmarc=<result>, spf=<result>, dkim=<result> in header text. */
  const AUTH_RESULT_RE = /\b(dmarc|spf|dkim)=(\w+)/gi;

  /**
   * Email body selectors per platform: ordered from most to least specific.
   * Covers Gmail, Outlook Web, Yahoo Mail, ProtonMail.
   */
  const EMAIL_BODY_SELECTORS = [
    // Gmail
    '.a3s.aiL',
    '.a3s',
    '.ii.gt .a3s',
    '.ii.gt',
    '.adn.ads',
    // Outlook Web App (OWA / office365 / outlook.live.com / outlook.com)
    // Primary: ARIA label is stable across OWA redesigns
    '[aria-label="Message body"]',
    // Fluent UI reading pane (new OWA 2024+)
    '[data-app-section="ConversationContainer"] [role="document"]',
    '[data-app-section="ConversationContainer"] [class*="body"]',
    // Classic OWA / Office 365
    '[class*="ReadingPaneContent"] [class*="messageBody"]',
    '[class*="ReadingPaneContent"]',
    '.wide-content-host',
    // OWA iframe fallback: if the email body is in an iframe and
    // all_frames is true, the content script runs inside that frame.
    // In that case the body IS the top-level element.
    'div[class*="allowTextSelection"]',
    'div.customScrollBar[role="region"]',
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
   * Gmail, Outlook, Yahoo, LinkedIn all wrap external links: we must unwrap
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
  // Bidi / RLO detection (runs in content script, no background needed)
  // -------------------------------------------------------------------
  /**
   * Unicode bidirectional control characters: identical set to urlAnalyzer.js.
   * Checked here against anchor *display text* which the URL analyzer never sees.
   */
  const BIDI_CONTROL_RE = /[\u202A-\u202E\u2066-\u2069\u200E\u200F]/;

  /**
   * Inject an inline warning banner on an anchor whose visible text contains
   * bidi control characters.  The href may be completely clean: the attack
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
        <ul><li>Bidirectional control character (RLO/LRO) in visible link text : the displayed URL is not what it appears to be</li></ul>
        <div class="phishguard-advice critical">
          Do not trust the displayed address. Check the real destination before clicking.
        </div>
      </div>
    `;

    const wrapper = document.createElement('span');
    wrapper.className = 'phishguard-wrapper';
    wrapper.appendChild(tooltip);

    anchor.setAttribute('aria-label',
      'PhishGuard: High risk : link display text contains direction-reversal spoofing characters');
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
    // Iframe fallback: with all_frames enabled, the content script may be
    // running inside an Outlook iframe whose body IS the email content.
    // If no selectors matched and we are inside a frame, treat the <body>
    // itself as the container (only if it has links to scan).
    if (!results.length && window !== window.top) {
      const body = document.body;
      if (body && body.querySelectorAll('a[href]').length > 0) {
        results.push(body);
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
    const isCritical  = result.riskLevel === 'high-risk';
    const isDeveloper = result.riskLevel === 'developer';

    // Pick the right CSS class so the link outline matches the risk level:
    // critical = red, suspicious = amber, developer = muted blue (informational).
    const linkClass = isCritical   ? 'phishguard-high-risk'
                    : isDeveloper  ? 'phishguard-developer'
                    :                'phishguard-suspicious';
    anchor.classList.add(linkClass);

    // Each indicator renders with its score contribution so users see why a link
    // was flagged. The raw label is stashed in data-indicator-label so feedback
    // submission can still send the unformatted label back to the background.
    const indicatorLines = result.indicators
      .map(i => {
        const label = escapeHTML(i.label);
        const pts   = Number(i.score) || 0;
        const sign  = pts >= 0 ? '+' : '';
        return `<li data-indicator-label="${escapeAttr(i.label)}">`
             + `<span class="phishguard-ind-label">${label}</span>`
             + `<span class="phishguard-ind-score">${sign}${pts} pts</span>`
             + `</li>`;
      }).join('');

    // Tooltip class modifier: warn-level (amber) for suspicious,
    // dev-level (muted blue) for developer, no modifier for high-risk.
    const tooltipMod = isCritical ? '' : isDeveloper ? ' dev-level' : ' warn-level';

    const verdict = isCritical   ? 'High Risk'
                  : isDeveloper  ? 'Developer'
                  :                'Suspicious';

    // Verdict text class picks the color for the header label
    const verdictCls = isCritical  ? ''
                     : isDeveloper ? ' dev'
                     :               ' warn';

    const adviceText = isCritical
      ? 'Do not interact with this link. Report this email as phishing.'
      : isDeveloper
        ? 'Development / preview host: unless you expected this link, verify before entering credentials.'
        : 'Exercise caution before clicking this link.';

    const adviceCls = isCritical  ? ' critical'
                    : isDeveloper ? ' info'
                    :               '';

    const tooltip = document.createElement('div');
    tooltip.className = 'phishguard-tooltip' + tooltipMod;
    tooltip.innerHTML = `
      <div class="phishguard-tooltip-header">
        <span class="phishguard-verdict${verdictCls}">
          ${verdict}
        </span>
        <span class="phishguard-score-pill">${result.score}/100</span>
      </div>
      <div class="phishguard-tooltip-body">
        <div class="phishguard-domain-row">
          <span class="phishguard-domain-label">Domain</span>
          <span class="phishguard-domain-value">${escapeHTML(result.domain)}</span>
        </div>
        ${result.expandedDomain && result.expandedDomain !== result.domain ? `
        <div class="phishguard-domain-row">
          <span class="phishguard-domain-label">Resolves to</span>
          <span class="phishguard-domain-value">${escapeHTML(result.expandedDomain)}</span>
        </div>` : ''}
        <span class="phishguard-indicators-label">Indicators</span>
        <ul>${indicatorLines}</ul>
        <div class="phishguard-advice${adviceCls}">
          ${adviceText}
        </div>
        <div class="phishguard-feedback" data-phishguard-fb-url="${escapeAttr(result.url)}"
             data-phishguard-fb-domain="${escapeAttr(result.domain)}">
          <span class="phishguard-feedback-label">Is this correct?</span>
          <button class="phishguard-fb-btn phishguard-fb-phishing" data-fb="phishing"
                  title="Confirm this is phishing">&#9888; Phishing</button>
          <button class="phishguard-fb-btn phishguard-fb-safe" data-fb="safe"
                  title="Mark as safe (false positive)">&#10003; Safe</button>
        </div>
      </div>
    `;

    // Wire up feedback buttons (event delegation on the tooltip)
    tooltip.addEventListener('click', handleFeedbackClick);

    const wrapper = document.createElement('span');
    wrapper.className = 'phishguard-wrapper';
    wrapper.appendChild(tooltip);

    anchor.setAttribute('aria-label',
      `PhishGuard: ${verdict} link : ${result.domain} (${result.score}/100)`);

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

  /** Escape a string for use inside an HTML attribute value (double-quoted). */
  function escapeAttr(str) {
    return String(str).replace(/&/g, '&amp;').replace(/"/g, '&quot;')
                      .replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  // -------------------------------------------------------------------
  // User feedback: "Mark as Safe" / "Confirm Phishing"
  // -------------------------------------------------------------------

  /**
   * Click handler for feedback buttons inside tooltips.
   * Uses event delegation: a single listener on the tooltip catches clicks
   * on either button via the data-fb attribute.
   */
  function handleFeedbackClick(e) {
    const btn = e.target.closest('[data-fb]');
    if (!btn) return;

    e.preventDefault();
    e.stopPropagation();

    const feedback  = btn.getAttribute('data-fb'); // 'safe' or 'phishing'
    const container = btn.closest('.phishguard-feedback');
    if (!container) return;

    const url    = container.getAttribute('data-phishguard-fb-url');
    const domain = container.getAttribute('data-phishguard-fb-domain');

    // Collect indicator labels from the sibling <ul> in the tooltip.
    // We read data-indicator-label rather than textContent so we get the clean
    // label (without the "+N pts" score pill that is rendered alongside it).
    const tooltipBody = container.closest('.phishguard-tooltip-body');
    const indicators  = tooltipBody
      ? [...tooltipBody.querySelectorAll('ul li')].map(li =>
          li.getAttribute('data-indicator-label') || li.textContent.trim())
      : [];

    // Send to background for storage
    chrome.runtime.sendMessage({
      type: 'SUBMIT_FEEDBACK',
      url,
      domain,
      feedback,
      indicators,
    }).catch(() => {}); // fire-and-forget

    // Visual confirmation: replace buttons with a thank-you message
    container.innerHTML = feedback === 'safe'
      ? '<span class="phishguard-fb-done phishguard-fb-done-safe">Marked as safe - score will be adjusted</span>'
      : '<span class="phishguard-fb-done phishguard-fb-done-phishing">Confirmed phishing - thank you</span>';
  }

  // -------------------------------------------------------------------
  // Form scanner: detects phishing forms embedded in HTML emails
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
      `<strong style="color:#c0392b;font-size:10.5px;text-transform:uppercase;letter-spacing:.05em">PhishGuard - Suspicious Form</strong><br>` +
      `This email contains a form that submits data to <code style="font-family:Consolas,monospace;color:#8ab4f8">${escapeHTML(externalDomain)}</code>. ` +
      `Do not enter any credentials.`;
    form.parentNode.insertBefore(banner, form);

    // Intercept submission and require explicit user confirmation
    attachSubmitBlocker(form, externalDomain);
  }

  /**
   * Attach a capture-phase submit listener that blocks the form and shows
   * a modal dialog. The user must actively choose "Submit Anyway" to proceed.
   * Using capture phase ensures we fire before any inline onsubmit handlers.
   */
  function attachSubmitBlocker(form, externalDomain) {
    function handleSubmit(e) {
      e.preventDefault();
      e.stopImmediatePropagation();
      showSubmitBlockerDialog(externalDomain, () => {
        // User confirmed - remove blocker so form.submit() goes through cleanly
        form.removeEventListener('submit', handleSubmit, true);
        form.submit();
      });
    }
    form.addEventListener('submit', handleSubmit, true);
  }

  /**
   * Show a full-screen blocking modal when a flagged form is submitted.
   * Closes on: Cancel button, overlay click, or Escape key.
   * Only calls onConfirm() if the user explicitly clicks "Submit Anyway".
   */
  function showSubmitBlockerDialog(externalDomain, onConfirm) {
    document.getElementById('phishguard-dialog-overlay')?.remove();

    const overlay = document.createElement('div');
    overlay.id = 'phishguard-dialog-overlay';
    overlay.innerHTML = `
      <div class="phishguard-dialog" role="alertdialog"
           aria-modal="true" aria-labelledby="pg-dlg-title" aria-describedby="pg-dlg-desc">
        <div class="phishguard-dialog-header">
          <span class="phishguard-verdict" id="pg-dlg-title">Credential Submission Blocked</span>
          <span class="phishguard-score-pill">PhishGuard</span>
        </div>
        <div class="phishguard-dialog-body" id="pg-dlg-desc">
          <p class="phishguard-dlg-lead">
            This form is attempting to send your data to an external domain:
          </p>
          <div class="phishguard-dlg-domain">${escapeHTML(externalDomain)}</div>
          <p class="phishguard-dlg-detail">
            Forms embedded in emails are a common credential-harvesting technique.
            Submitting could expose your username, password, or other sensitive data to attackers.
          </p>
          <ul class="phishguard-dlg-reasons">
            <li>Form destination does not match this mail provider</li>
            <li>Legitimate services never request credentials via email forms</li>
            <li>Submission target: <code>${escapeHTML(externalDomain)}</code></li>
          </ul>
        </div>
        <div class="phishguard-dialog-actions">
          <button class="phishguard-btn-safe" id="pg-btn-cancel">Cancel (Stay Safe)</button>
          <button class="phishguard-btn-risk" id="pg-btn-proceed">Submit Anyway</button>
        </div>
      </div>
    `;

    document.body.appendChild(overlay);

    // Focus the safe button immediately for keyboard users
    overlay.querySelector('#pg-btn-cancel').focus();

    overlay.querySelector('#pg-btn-cancel').addEventListener('click', () => {
      overlay.remove();
    });

    overlay.querySelector('#pg-btn-proceed').addEventListener('click', () => {
      overlay.remove();
      onConfirm();
    });

    // Dismiss on backdrop click
    overlay.addEventListener('click', e => {
      if (e.target === overlay) overlay.remove();
    });

    // Dismiss on Escape
    function onKeydown(e) {
      if (e.key === 'Escape') {
        overlay.remove();
        document.removeEventListener('keydown', onKeydown);
      }
    }
    document.addEventListener('keydown', onKeydown);
  }

  // -------------------------------------------------------------------
  // Email authentication header parsing (DMARC / SPF / DKIM)
  // Reads "Authentication-Results" values from the email header DOM area.
  // Searches OUTSIDE the email body to avoid false positives from
  // body content that happens to mention these keywords.
  // -------------------------------------------------------------------

  /**
   * Locate and parse email authentication results for the given email
   * body container. Uses a two-phase strategy:
   *
   * Phase 1: query known header-area selectors. Elements that are inside
   *          the body, or that contain the body, are skipped.
   * Phase 2: walk up to 5 ancestor levels and inspect sibling branches
   *          for any element whose text includes authentication keywords.
   *
   * @param {Element} container - email body element (e.g. .a3s.aiL)
   * @returns {{ dmarc?: string, spf?: string, dkim?: string }|null}
   */
  function parseAuthResults(container) {
    let headerText = '';
    AUTH_RESULT_RE.lastIndex = 0;

    // Phase 1: known header-area selectors
    for (const sel of AUTH_HEADER_SELECTORS) {
      for (const el of document.querySelectorAll(sel)) {
        // Skip elements that are inside the body or that wrap it
        if (container.contains(el) || el.contains(container)) continue;
        headerText += (el.innerText || '') + '\n';
      }
    }

    // Phase 2: walk ancestors and inspect sibling branches
    if (!AUTH_RESULT_RE.test(headerText)) {
      AUTH_RESULT_RE.lastIndex = 0;
      let node = container.parentElement;
      for (let depth = 0; depth < 5 && node; depth++, node = node.parentElement) {
        for (const child of node.children) {
          if (child.contains(container)) continue; // skip the branch containing the body
          const text = child.innerText || '';
          if (/\b(dmarc|spf|dkim)=/i.test(text)) headerText += text + '\n';
        }
        if (AUTH_RESULT_RE.test(headerText)) break;
      }
    }

    AUTH_RESULT_RE.lastIndex = 0;
    if (!headerText.trim()) return null;

    const results = {};
    let match;
    while ((match = AUTH_RESULT_RE.exec(headerText)) !== null) {
      const key = match[1].toLowerCase();
      const val = match[2].toLowerCase();
      // If the same check appears multiple times, keep the worst result
      if (!results[key] || val === 'fail') results[key] = val;
    }
    AUTH_RESULT_RE.lastIndex = 0;

    return Object.keys(results).length ? results : null;
  }

  /**
   * Calculate the total risk score and the list of failure entries
   * from a parsed auth result object.
   * SPF softfail is treated as half the full SPF fail penalty (15 pts).
   *
   * @param {{ dmarc?: string, spf?: string, dkim?: string }} authResults
   * @returns {{ score: number, entries: Array<{check, result, pts}> }}
   */
  function buildAuthRisk(authResults) {
    let score = 0;
    const entries = [];

    for (const [check, result] of Object.entries(authResults)) {
      const basePts = AUTH_FAIL_SCORES[check];
      if (!basePts) continue;

      if (result === 'fail') {
        score += basePts;
        entries.push({ check: check.toUpperCase(), result: 'fail', pts: basePts });
      } else if (result === 'softfail' && check === 'spf') {
        const pts = Math.round(basePts / 2);
        score += pts;
        entries.push({ check: 'SPF', result: 'softfail', pts });
      }
      // pass / none / neutral / permerror → no penalty
    }

    return { score, entries };
  }

  /**
   * Inject an email authentication warning banner at the top of the
   * email container. The scan banner's later prepend will naturally
   * place itself above this one, giving the ordering:
   *   [URL scan results banner]   <- top, action-focused
   *   [Auth failure banner]       <- below, contextual
   *
   * @param {Element} container
   * @param {Array<{check, result, pts}>} entries - failed checks only
   * @param {number} totalScore
   */
  function injectAuthBanner(container, entries, totalScore) {
    if (!entries.length) return;

    const isCritical = totalScore >= 40;
    const accentColor = isCritical ? '#c0392b' : '#b87333';
    const borderColor = isCritical ? '#4a2020' : '#4a3820';

    const pills = entries.map(({ check, result, pts }) =>
      `<span style="display:inline-flex;align-items:center;gap:3px;` +
      `margin:0 4px 2px 0;padding:1px 7px;background:#111214;` +
      `border:1px solid ${borderColor};border-radius:2px;white-space:nowrap">` +
      `<span style="font-weight:700;font-size:10px;color:${accentColor}">${escapeHTML(check)}</span>` +
      `<span style="color:#3a3e48;font-size:9px;margin:0 1px">|</span>` +
      `<span style="font-size:10px;color:#c8ccd4;text-transform:uppercase">${escapeHTML(result)}</span>` +
      `<span style="font-size:9px;color:#5a6272;margin-left:3px">+${pts}pts</span>` +
      `</span>`
    ).join('');

    const advice = isCritical
      ? 'Authentication failures may indicate spoofing or a forged sender. Do not trust this email.'
      : 'Partial authentication failure. Verify the sender before acting on this email.';

    const banner = document.createElement('div');
    banner.setAttribute(AUTH_BANNER_ATTR, 'true');
    banner.style.cssText = [
      'display:block', 'margin:0 0 6px 0', 'padding:7px 12px',
      'background:#141517', `border:1px solid ${borderColor}`,
      `border-left:3px solid ${accentColor}`, 'border-radius:0 3px 3px 0',
      'font-family:Segoe UI,system-ui,sans-serif', 'font-size:11.5px',
      'color:#8a9ab0', 'line-height:1.5', 'box-sizing:border-box', 'max-width:100%',
    ].join(';');
    banner.innerHTML =
      `<div style="display:flex;align-items:center;gap:8px;margin-bottom:5px">` +
        `<span style="color:${accentColor};font-weight:600;font-size:10px;` +
          `text-transform:uppercase;letter-spacing:.07em;white-space:nowrap">PhishGuard</span>` +
        `<span style="color:#2a2e38;user-select:none"> │ </span>` +
        `<span>Email authentication failed : risk score` +
          `<strong style="color:${accentColor};margin-left:4px">+${totalScore}</strong></span>` +
      `</div>` +
      `<div style="margin-bottom:5px">${pills}</div>` +
      `<div style="font-size:10.5px;color:#5a6272">${escapeHTML(advice)}</div>`;

    container.prepend(banner);
  }

  // -------------------------------------------------------------------
  // Sender domain impersonation detection
  // Extracts the From: email domain and runs it through the heuristic
  // engine in background.js (ANALYZE_SENDER message type).
  // -------------------------------------------------------------------

  /**
   * Extract the sender's email domain from the DOM surrounding a given
   * email body container. Never reads inside the body itself.
   *
   * Three fallback approaches:
   *   1. Gmail's .gD[email] attribute: most reliable for Gmail.
   *   2. Email-address pattern in known header-area selectors.
   *   3. "From:" pattern in sibling branches of the container's ancestors.
   *
   * @param {Element} container - email body element
   * @returns {string|null} lowercase domain, e.g. "paypa1.com"
   */
  function extractSenderDomain(container) {
    // ── Platform-specific fast paths ──────────────────────────

    // Gmail: <span class="gD" email="x@y.z">
    let node = container.parentElement;
    for (let depth = 0; depth < 8 && node && node.tagName !== 'BODY'; depth++, node = node.parentElement) {
      const gd = node.querySelector('.gD[email]');
      if (gd && !container.contains(gd)) {
        const raw = (gd.getAttribute('email') || '').toLowerCase();
        const domain = raw.split('@')[1];
        if (domain && domain.includes('.')) return domain;
      }
      // Stop at known Gmail wrapper to avoid wrong thread sender
      if (node.classList.contains('nH') || node.classList.contains('adO')) break;
    }

    // Outlook: sender shown in spans / buttons with title or aria-label
    // containing the email address. Walk ancestors to find header region.
    node = container.parentElement;
    for (let depth = 0; depth < 10 && node && node.tagName !== 'BODY'; depth++, node = node.parentElement) {
      // Look for elements Outlook uses to display the sender email
      const candidates = node.querySelectorAll(
        '[class*="senderContainer"] [title], ' +
        '[class*="FromContainer"] [title], ' +
        '[class*="ItemHeader"] [title], ' +
        '[role="heading"] [title], ' +
        'button[title*="@"], ' +
        'span[title*="@"], ' +
        '[aria-label*="@"]'
      );
      for (const el of candidates) {
        if (container.contains(el)) continue;
        const text = el.getAttribute('title') || el.getAttribute('aria-label') || '';
        const m = text.match(/([\w.+%-]+@([\w.-]+\.[a-z]{2,}))/i);
        if (m) return m[2].toLowerCase();
      }
    }

    // ── Generic fallbacks (work on any platform) ─────────────

    // Header-region selectors: search for email pattern in known header elements
    for (const sel of AUTH_HEADER_SELECTORS) {
      for (const el of document.querySelectorAll(sel)) {
        if (container.contains(el) || el.contains(container)) continue;
        const match = (el.innerText || '').match(/<?([\w.+%-]+@([\w.-]+\.[a-z]{2,}))>?/i);
        if (match) return match[2].toLowerCase();
      }
    }

    // Walk ancestors, inspect sibling branches for "From:" line
    node = container.parentElement;
    for (let depth = 0; depth < 5 && node; depth++, node = node.parentElement) {
      for (const child of node.children) {
        if (child.contains(container)) continue;
        const fromMatch = (child.innerText || '').match(/from:.*?<?([\w.+%-]+@([\w.-]+\.[a-z]{2,}))>?/i);
        if (fromMatch) return fromMatch[2].toLowerCase();
      }
    }

    return null;
  }

  /**
   * Send the sender domain to background for heuristic + feed + RDAP analysis.
   * Sets SENDER_BANNER_ATTR immediately so this only ever runs once per container.
   *
   * @param {Element} container
   * @returns {{ result: object, domain: string }|null}
   */
  async function analyzeSenderDomain(container) {
    if (container.hasAttribute(SENDER_BANNER_ATTR)) return null;
    container.setAttribute(SENDER_BANNER_ATTR, 'done');

    const domain = extractSenderDomain(container);
    if (!domain) return null;

    try {
      const result = await chrome.runtime.sendMessage({ type: 'ANALYZE_SENDER', domain });
      return result ? { result, domain } : null;
    } catch (err) {
      console.warn('[PhishGuard] Sender analysis failed:', err.message);
      return null;
    }
  }

  /**
   * Inject a sender impersonation warning banner into the email container.
   * Only called when riskLevel is 'suspicious' or 'high-risk'.
   *
   * The scan banner's later prepend will appear above this one, giving
   * the correct top-to-bottom order:
   *   [URL scan banner]      <- most actionable
   *   [Sender warning]       <- identity context
   *   [Auth failure banner]  <- authentication context
   *
   * @param {Element} container
   * @param {object} analysis  - analyzeURL() result from background
   * @param {string} domain    - the extracted sender domain
   */
  function injectSenderWarning(container, analysis, domain) {
    if (analysis.riskLevel === 'safe') return;

    const isCritical  = analysis.riskLevel === 'high-risk';
    const accentColor = isCritical ? '#c0392b' : '#b87333';
    const borderColor = isCritical ? '#4a2020' : '#4a3820';

    const indicatorLines = (analysis.indicators || [])
      .slice(0, 4)  // cap at 4 to keep banner compact
      .map(i => `<li style="font-size:11px;color:#c8ccd4;padding:2px 0 2px 10px;` +
                `margin-bottom:2px;border-left:2px solid #3a3c40;line-height:1.4">` +
                `${escapeHTML(i.label)}</li>`)
      .join('');

    const verdict = isCritical ? 'Sender Domain : High Risk' : 'Sender Domain : Suspicious';
    const advice  = isCritical
      ? 'This sender domain appears to impersonate a known brand. Do not trust links or attachments.'
      : 'The sender domain has suspicious characteristics. Verify the sender before acting.';

    const banner = document.createElement('div');
    banner.setAttribute(SENDER_BANNER_ATTR, 'warning');
    banner.style.cssText = [
      'display:block', 'margin:0 0 6px 0', 'padding:8px 12px',
      'background:#141517', `border:1px solid ${borderColor}`,
      `border-left:3px solid ${accentColor}`, 'border-radius:0 3px 3px 0',
      'font-family:Segoe UI,system-ui,sans-serif', 'font-size:11.5px',
      'color:#8a9ab0', 'line-height:1.5', 'box-sizing:border-box', 'max-width:100%',
    ].join(';');
    banner.innerHTML =
      `<div style="display:flex;align-items:center;gap:8px;margin-bottom:5px">` +
        `<span style="color:${accentColor};font-weight:600;font-size:10px;` +
          `text-transform:uppercase;letter-spacing:.07em;white-space:nowrap">PhishGuard</span>` +
        `<span style="color:#2a2e38;user-select:none"> │ </span>` +
        `<span>${escapeHTML(verdict)}</span>` +
        `<span style="margin-left:auto;font-family:Consolas,monospace;font-size:10px;` +
          `color:${accentColor};background:#111214;border:1px solid ${borderColor};` +
          `border-radius:2px;padding:1px 6px">${analysis.score}/100</span>` +
      `</div>` +
      `<div style="font-family:Consolas,monospace;font-size:11.5px;color:#8ab4f8;` +
        `margin-bottom:6px">${escapeHTML(domain)}</div>` +
      (indicatorLines
        ? `<ul style="list-style:none;margin:0 0 6px;padding:0">${indicatorLines}</ul>`
        : '') +
      `<div style="font-size:10.5px;color:${isCritical ? '#a93226' : '#5a6272'}">${escapeHTML(advice)}</div>`;

    container.prepend(banner);
  }

  // -------------------------------------------------------------------
  // QR Code detection (BarcodeDetector API, Chrome 83+)
  // -------------------------------------------------------------------

  /**
   * Inject a banner listing QR-embedded URLs that failed the risk check.
   *
   * @param {Element} container   - email body container
   * @param {object[]} flagged    - analyzeURL results with riskLevel !== 'safe'
   * @param {number}   totalFound - total QR URLs detected (including safe ones)
   */
  function injectQRBanner(container, flagged, totalFound) {
    const isHigh = flagged.some(r => r.riskLevel === 'high-risk');
    const color  = isHigh ? '#c0392b' : '#b87333';
    const border = isHigh ? '#4a2020' : '#4a3820';
    const verdict = isHigh ? 'QR Code - High Risk' : 'QR Code - Suspicious';

    const domainLines = flagged.slice(0, 4).map(r =>
      `<li style="font-size:11px;color:#c8ccd4;padding:2px 0 2px 10px;` +
      `margin-bottom:2px;border-left:2px solid #3a3c40;line-height:1.4">` +
      `${escapeHTML(r.domain)} <span style="color:${color};font-size:10px">` +
      `[${r.score}/100]</span></li>`
    ).join('');

    const advice = isHigh
      ? 'A QR code in this email leads to a high-risk URL. Do not scan it with your phone.'
      : 'A QR code in this email leads to a suspicious URL. Verify the destination before scanning.';

    const banner = document.createElement('div');
    banner.setAttribute(QR_BANNER_ATTR, 'warning');
    banner.style.cssText = [
      'display:block', 'margin:0 0 6px 0', 'padding:8px 12px',
      'background:#141517', `border:1px solid ${border}`,
      `border-left:3px solid ${color}`, 'border-radius:0 3px 3px 0',
      'font-family:Segoe UI,system-ui,sans-serif', 'font-size:11.5px',
      'color:#8a9ab0', 'line-height:1.5', 'box-sizing:border-box', 'max-width:100%',
    ].join(';');
    banner.innerHTML =
      `<div style="display:flex;align-items:center;gap:8px;margin-bottom:5px">` +
        `<span style="color:${color};font-weight:600;font-size:10px;` +
          `text-transform:uppercase;letter-spacing:.07em;white-space:nowrap">PhishGuard</span>` +
        `<span style="color:#2a2e38;user-select:none"> │ </span>` +
        `<span>${escapeHTML(verdict)}</span>` +
        `<span style="margin-left:auto;font-family:Consolas,monospace;font-size:10px;` +
          `color:${color};background:#111214;border:1px solid ${border};` +
          `border-radius:2px;padding:1px 6px">${flagged.length}/${totalFound} risky</span>` +
      `</div>` +
      `<ul style="list-style:none;margin:0 0 6px;padding:0">${domainLines}</ul>` +
      `<div style="font-size:10.5px;color:${isHigh ? '#a93226' : '#5a6272'}">${escapeHTML(advice)}</div>`;

    container.prepend(banner);
  }

  /**
   * Use the BarcodeDetector API to scan all images in a container for QR codes.
   * Any QR-encoded URL is sent through the full ANALYZE_URLS pipeline. If any
   * result is flagged, a warning banner is injected.
   *
   * - Skips containers already scanned (QR_BANNER_ATTR guard).
   * - Skips images smaller than QR_MIN_SIZE (tracking pixels, icons).
   * - Silently ignores cross-origin SecurityErrors per image.
   * - No-ops on browsers without BarcodeDetector or without qr_code format support.
   *
   * @param {Element} container
   */
  async function scanQRCodesInContainer(container) {
    if (container.hasAttribute(QR_BANNER_ATTR)) return;
    // BarcodeDetector is Chrome 83+; gracefully degrade on unsupported browsers
    if (typeof BarcodeDetector === 'undefined') return;

    container.setAttribute(QR_BANNER_ATTR, 'done');

    let detector;
    try {
      const formats = await BarcodeDetector.getSupportedFormats();
      if (!formats.includes('qr_code')) return;
      detector = new BarcodeDetector({ formats: ['qr_code'] });
    } catch {
      return;
    }

    // Only scan images that are fully loaded and large enough to be QR codes
    const images = [...container.querySelectorAll('img')].filter(img =>
      img.complete && img.naturalWidth >= QR_MIN_SIZE && img.naturalHeight >= QR_MIN_SIZE
    );
    if (!images.length) return;

    const urlRE = /^https?:\/\//i;
    const qrURLs = [];

    for (const img of images) {
      try {
        const codes = await detector.detect(img);
        for (const code of codes) {
          const raw = (code.rawValue || '').trim();
          if (urlRE.test(raw)) qrURLs.push(raw);
        }
      } catch {
        // SecurityError for tainted cross-origin images, or decode failure: skip
      }
    }

    if (!qrURLs.length) return;

    let results;
    try {
      results = await chrome.runtime.sendMessage({ type: 'ANALYZE_URLS', urls: qrURLs });
    } catch {
      return;
    }

    if (!Array.isArray(results)) return;

    const flagged = results.filter(r => r.riskLevel !== 'safe');
    if (!flagged.length) return;

    injectQRBanner(container, flagged, qrURLs.length);
  }

  // -------------------------------------------------------------------
  // Per-email scan banner
  // -------------------------------------------------------------------

  /**
   * Count processed links in a container by reading their DOM classes.
   * 'pending' links (sent to background but not yet resolved) are excluded.
   */
  function countProcessedLinks(container) {
    let highRisk = 0, suspicious = 0, developer = 0, safe = 0;
    for (const a of container.querySelectorAll(`a[${PROCESSED_ATTR}]`)) {
      if (a.getAttribute(PROCESSED_ATTR) === 'pending') continue;
      if (a.classList.contains('phishguard-high-risk'))       highRisk++;
      else if (a.classList.contains('phishguard-suspicious')) suspicious++;
      else if (a.classList.contains('phishguard-developer'))  developer++;
      else safe++;
    }
    return { total: highRisk + suspicious + developer + safe,
             highRisk, suspicious, developer };
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

    // Banner severity priority: high-risk > suspicious > developer > safe.
    // Developer links alone get their own informational banner (blue) rather
    // than the green "no threats detected" banner, because there IS something
    // to note (the link points to a dev environment).
    const level  = stats.highRisk > 0 ? 'high-risk'
                 : stats.suspicious > 0 ? 'suspicious'
                 : stats.developer > 0 ? 'developer'
                 : 'safe';
    const color  = level === 'high-risk'  ? '#c0392b'
                 : level === 'suspicious' ? '#b87333'
                 : level === 'developer'  ? '#4a90d9'
                 :                          '#2e7d52';

    let status;
    if (level === 'high-risk') {
      status = `${stats.highRisk} high-risk link${stats.highRisk > 1 ? 's' : ''} detected` +
               (stats.suspicious > 0 ? ` · ${stats.suspicious} suspicious` : '') +
               ' : do not click flagged links';
    } else if (level === 'suspicious') {
      status = `${stats.suspicious} suspicious link${stats.suspicious > 1 ? 's' : ''} detected - verify before clicking`;
    } else if (level === 'developer') {
      status = `${stats.developer} developer/preview link${stats.developer > 1 ? 's' : ''} detected - low risk, verify if unexpected`;
    } else {
      status = `${stats.total} link${stats.total > 1 ? 's' : ''} scanned : no threats detected`;
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
      // Auth header check (synchronous DOM scan, once per container)
      // Runs before the links guard so emails with no links are still checked.
      if (!container.hasAttribute(AUTH_BANNER_ATTR)) {
        container.setAttribute(AUTH_BANNER_ATTR, 'done');
        const authResults = parseAuthResults(container);
        if (authResults) {
          const { score, entries } = buildAuthRisk(authResults);
          if (entries.length) injectAuthBanner(container, entries, score);
        }
      }

      // Sender domain impersonation check (async, once per container).
      // Runs in parallel with link extraction; awaited before URL results
      // so all banners are prepended in the correct top-to-bottom order.
      const senderPromise = analyzeSenderDomain(container);

      // QR code scan runs in parallel: BarcodeDetector is async but fast.
      // Awaited before scan banner so banner prepend order is preserved.
      const qrPromise = scanQRCodesInContainer(container);

      const links = extractLinks(container);
      if (!links.length) {
        // No links, but still surface sender + QR warnings if found
        const senderData = await senderPromise;
        if (senderData?.result) injectSenderWarning(container, senderData.result, senderData.domain);
        await qrPromise;
        continue;
      }

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

      // Await sender + QR analysis BEFORE injecting the scan banner so that
      // the scan banner's prepend is the last one, keeping it at the visual top.
      // Final order (top to bottom): scan banner -> QR banner -> sender warning -> auth banner.
      const senderData = await senderPromise;
      if (senderData?.result) injectSenderWarning(container, senderData.result, senderData.domain);
      await qrPromise;

      // Inject / refresh the per-email summary banner
      injectScanBanner(container);
    }
  }

  const debouncedScan = debounce(scanEmailContainers, SCAN_DEBOUNCE_MS);

  // -------------------------------------------------------------------
  // MutationObserver: react to dynamically loaded email content
  // -------------------------------------------------------------------
  const observer = new MutationObserver((mutations) => {
    for (const m of mutations) {
      if (m.addedNodes.length) { debouncedScan(); return; }
    }
  });

  observer.observe(document.body, { childList: true, subtree: true });

  // Initial scan
  scanEmailContainers();

  console.log('[PhishGuard] Active - monitoring email for phishing links');
})();
