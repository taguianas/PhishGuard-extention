/**
 * PhishGuard Analyzer - Main app controller
 * Handles: tab switching, URL analysis, Email analysis, auth, history
 */

import { analyzeURL }   from './urlAnalyzer.js';
import { analyzeEmail } from './emailAnalyzer.js';

// ── Storage keys ──────────────────────────────────────────────────────────────
const USERS_KEY   = 'pg_users';       // { username: hashedPw }
const SESSION_KEY = 'pg_session';     // current username string
const HIST_PREFIX = 'pg_hist_';       // + username -> array of entries

// ── Simple password hash (djb2 - local-only, not security-critical) ───────────
function hashPw(str) {
  let h = 5381;
  for (let i = 0; i < str.length; i++) h = ((h << 5) + h) ^ str.charCodeAt(i);
  return (h >>> 0).toString(36);
}

// ── Auth helpers ──────────────────────────────────────────────────────────────
function getUsers()       { return JSON.parse(localStorage.getItem(USERS_KEY) || '{}'); }
function saveUsers(u)     { localStorage.setItem(USERS_KEY, JSON.stringify(u)); }
function getSession()     { return localStorage.getItem(SESSION_KEY) || null; }
function setSession(u)    { localStorage.setItem(SESSION_KEY, u); }
function clearSession()   { localStorage.removeItem(SESSION_KEY); }

function register(username, password) {
  if (!username || username.length < 2) return 'Username must be at least 2 characters.';
  if (!password || password.length < 6) return 'Password must be at least 6 characters.';
  const users = getUsers();
  if (users[username]) return 'Username already exists.';
  users[username] = hashPw(password);
  saveUsers(users);
  return null;
}

function login(username, password) {
  const users = getUsers();
  if (!users[username]) return 'Username not found.';
  if (users[username] !== hashPw(password)) return 'Incorrect password.';
  return null;
}

// ── History helpers ───────────────────────────────────────────────────────────
function getHistory(username) {
  return JSON.parse(localStorage.getItem(HIST_PREFIX + username) || '[]');
}

function saveHistory(username, entries) {
  localStorage.setItem(HIST_PREFIX + username, JSON.stringify(entries));
}

function pushHistory(username, entry) {
  if (!username) return;
  const hist = getHistory(username);
  hist.unshift({ ...entry, ts: Date.now() });
  if (hist.length > 200) hist.length = 200;
  saveHistory(username, hist);
}

function clearHistory(username) {
  localStorage.removeItem(HIST_PREFIX + username);
}

// ── DOM refs ──────────────────────────────────────────────────────────────────
const authArea       = document.getElementById('auth-area');
const authModal      = document.getElementById('auth-modal');
const modalClose     = document.getElementById('modal-close');
const siUsername     = document.getElementById('si-username');
const siPassword     = document.getElementById('si-password');
const siError        = document.getElementById('si-error');
const siSubmit       = document.getElementById('si-submit');
const suUsername     = document.getElementById('su-username');
const suPassword     = document.getElementById('su-password');
const suError        = document.getElementById('su-error');
const suSubmit       = document.getElementById('su-submit');
const historyList    = document.getElementById('history-list');
const clearHistoryBtn = document.getElementById('clear-history-btn');
const urlInput       = document.getElementById('url-input');
const urlAnalyzeBtn  = document.getElementById('url-analyze-btn');
const urlResults     = document.getElementById('url-results');
const emailFrom      = document.getElementById('email-from');
const emailReplyTo   = document.getElementById('email-replyto');
const emailSubject   = document.getElementById('email-subject');
const emailBody      = document.getElementById('email-body');
const emailAnalyzeBtn = document.getElementById('email-analyze-btn');
const emailClearBtn  = document.getElementById('email-clear-btn');
const emailResults   = document.getElementById('email-results');

// ── Tab switching ─────────────────────────────────────────────────────────────
document.querySelectorAll('.an-tab').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.an-tab').forEach(t => { t.classList.remove('active'); t.setAttribute('aria-selected', 'false'); });
    document.querySelectorAll('.an-panel').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    btn.setAttribute('aria-selected', 'true');
    document.getElementById('tab-' + btn.dataset.tab).classList.add('active');
  });
});

// ── Modal tab switching ───────────────────────────────────────────────────────
document.querySelectorAll('.an-modal-tab').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.an-modal-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.an-modal-panel').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById('panel-' + btn.dataset.modalTab).classList.add('active');
    clearModalErrors();
  });
});

// ── Auth UI helpers ───────────────────────────────────────────────────────────
function openAuthModal() {
  authModal.classList.remove('hidden');
  siUsername.focus();
}

function closeAuthModal() {
  authModal.classList.add('hidden');
  clearModalErrors();
  siUsername.value = ''; siPassword.value = '';
  suUsername.value = ''; suPassword.value = '';
}

function clearModalErrors() {
  siError.classList.add('hidden'); siError.textContent = '';
  suError.classList.add('hidden'); suError.textContent = '';
}

modalClose.addEventListener('click', closeAuthModal);
authModal.addEventListener('click', e => { if (e.target === authModal) closeAuthModal(); });

// ── Render auth area ──────────────────────────────────────────────────────────
function renderAuthArea() {
  const user = getSession();
  if (user) {
    authArea.innerHTML = `
      <div class="an-user-info">
        <span class="an-user-name">Signed in as <strong>${escapeHtml(user)}</strong></span>
        <button class="an-btn-ghost sm" id="signout-btn">Sign out</button>
      </div>`;
    document.getElementById('signout-btn').addEventListener('click', () => {
      clearSession();
      renderAuthArea();
      renderHistory();
    });
  } else {
    authArea.innerHTML = `
      <button class="an-btn-ghost sm" id="open-auth-btn">Sign In / Sign Up</button>`;
    document.getElementById('open-auth-btn').addEventListener('click', openAuthModal);
  }
}

// ── Sign-in submit ────────────────────────────────────────────────────────────
siSubmit.addEventListener('click', () => {
  const err = login(siUsername.value.trim(), siPassword.value);
  if (err) {
    siError.textContent = err;
    siError.classList.remove('hidden');
    return;
  }
  setSession(siUsername.value.trim());
  closeAuthModal();
  renderAuthArea();
  renderHistory();
});

// Allow Enter key in sign-in form
[siUsername, siPassword].forEach(el => el.addEventListener('keydown', e => { if (e.key === 'Enter') siSubmit.click(); }));

// ── Sign-up submit ────────────────────────────────────────────────────────────
suSubmit.addEventListener('click', () => {
  const err = register(suUsername.value.trim(), suPassword.value);
  if (err) {
    suError.textContent = err;
    suError.classList.remove('hidden');
    return;
  }
  setSession(suUsername.value.trim());
  closeAuthModal();
  renderAuthArea();
  renderHistory();
});

[suUsername, suPassword].forEach(el => el.addEventListener('keydown', e => { if (e.key === 'Enter') suSubmit.click(); }));

// ── Clear history ─────────────────────────────────────────────────────────────
clearHistoryBtn.addEventListener('click', () => {
  const user = getSession();
  if (!user) return;
  clearHistory(user);
  renderHistory();
});

// ── Render history sidebar ────────────────────────────────────────────────────
function renderHistory() {
  const user = getSession();
  if (!user) {
    historyList.innerHTML = '<p class="an-empty-history">Sign in to save and view your analysis history.</p>';
    return;
  }
  const hist = getHistory(user);
  if (hist.length === 0) {
    historyList.innerHTML = '<p class="an-empty-history">No analyses saved yet.</p>';
    return;
  }
  historyList.innerHTML = hist.map(entry => {
    const time = new Date(entry.ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const date = new Date(entry.ts).toLocaleDateString([], { month: 'short', day: 'numeric' });
    return `
      <div class="an-history-item">
        <div class="an-hi-top">
          <span class="an-hi-type">${entry.type === 'url' ? 'URL' : 'Email'}</span>
          <span class="an-hi-time">${date} ${time}</span>
        </div>
        <div class="an-hi-domain">${escapeHtml(entry.label.slice(0, 60))}${entry.label.length > 60 ? '...' : ''}</div>
        <span class="an-hi-badge ${entry.riskLevel}">${entry.riskLevel}</span>
      </div>`;
  }).join('');
}

// ── Result card builder ───────────────────────────────────────────────────────
function buildResultCard(result, type, extraContent = '') {
  const circumference = 2 * Math.PI * 22;
  const offset = circumference * (1 - result.score / 100);
  const label  = type === 'url' ? result.domain || result.url : 'Email analysis';

  return `
    <div class="an-result-card">
      <div class="an-result-header ${result.riskLevel}">
        <div class="an-score-ring">
          <svg viewBox="0 0 52 52">
            <circle class="track" cx="26" cy="26" r="22"/>
            <circle class="fill ${result.riskLevel}" cx="26" cy="26" r="22"
              stroke-dasharray="${circumference.toFixed(2)}"
              stroke-dashoffset="${offset.toFixed(2)}"/>
          </svg>
          <span class="an-score-num ${result.riskLevel}">${result.score}</span>
        </div>
        <div class="an-result-meta">
          <div class="an-result-domain">${escapeHtml(label)}</div>
          <span class="an-risk-badge ${result.riskLevel}">${result.riskLevel}</span>
        </div>
      </div>
      ${result.indicators.length > 0
        ? `<ul class="an-indicators">${result.indicators.map(ind =>
            `<li><span class="an-ind-label">${escapeHtml(ind.label)}</span><span class="an-ind-score">+${ind.score}</span></li>`
          ).join('')}</ul>`
        : `<p class="an-no-indicators">No suspicious indicators detected.</p>`
      }
      ${extraContent}
    </div>`;
}

// ── URL Analyzer ──────────────────────────────────────────────────────────────
urlAnalyzeBtn.addEventListener('click', runURLAnalysis);
urlInput.addEventListener('keydown', e => { if (e.key === 'Enter') runURLAnalysis(); });

function runURLAnalysis() {
  const raw = urlInput.value.trim();
  if (!raw) { urlInput.focus(); return; }

  urlAnalyzeBtn.disabled = true;
  urlAnalyzeBtn.textContent = 'Analyzing...';

  // analyzeURL is synchronous but wrap in rAF so button text updates
  requestAnimationFrame(() => {
    try {
      const result = analyzeURL(raw);
      if (!result) {
        urlResults.innerHTML = `<p style="color:var(--muted);font-size:12px;margin-top:8px">Could not parse URL. Check that it is a valid address.</p>`;
      } else {
        urlResults.innerHTML = buildResultCard(result, 'url');
        const user = getSession();
        pushHistory(user, { type: 'url', label: result.domain || result.url, riskLevel: result.riskLevel, score: result.score });
        renderHistory();
      }
    } catch (err) {
      urlResults.innerHTML = `<p style="color:var(--danger);font-size:12px;margin-top:8px">Error: ${escapeHtml(err.message)}</p>`;
    } finally {
      urlAnalyzeBtn.disabled = false;
      urlAnalyzeBtn.textContent = 'Analyze';
    }
  });
}

// ── Email Analyzer ────────────────────────────────────────────────────────────
emailAnalyzeBtn.addEventListener('click', runEmailAnalysis);
emailClearBtn.addEventListener('click', () => {
  emailFrom.value = ''; emailReplyTo.value = '';
  emailSubject.value = ''; emailBody.value = '';
  emailResults.innerHTML = '';
});

function runEmailAnalysis() {
  const from    = emailFrom.value.trim();
  const replyTo = emailReplyTo.value.trim();
  const subject = emailSubject.value.trim();
  const body    = emailBody.value;

  if (!from && !subject && !body) {
    emailFrom.focus();
    return;
  }

  emailAnalyzeBtn.disabled = true;
  emailAnalyzeBtn.textContent = 'Analyzing...';

  requestAnimationFrame(() => {
    try {
      const result = analyzeEmail({ from, replyTo, subject, body });

      // Build URL sub-results if any
      let urlSubHtml = '';
      if (result.urlResults.length > 0) {
        const items = result.urlResults.map(r =>
          `<div class="an-url-sub-item">
            <span class="an-url-sub-domain">${escapeHtml(r.domain || r.url)}</span>
            <span class="an-hi-badge ${r.riskLevel}">${r.riskLevel}</span>
           </div>`
        ).join('');
        urlSubHtml = `
          <div class="an-url-sub">
            <div class="an-url-sub-title">Embedded Links (${result.urlResults.length})</div>
            ${items}
          </div>`;
      }

      const emailLabel = from || subject || 'Email';
      const emailResult = { ...result, domain: emailLabel, url: emailLabel };
      emailResults.innerHTML = buildResultCard(emailResult, 'email', urlSubHtml);

      const user = getSession();
      pushHistory(user, { type: 'email', label: from || subject || 'Email', riskLevel: result.riskLevel, score: result.score });
      renderHistory();
    } catch (err) {
      emailResults.innerHTML = `<p style="color:var(--danger);font-size:12px;margin-top:8px">Error: ${escapeHtml(err.message)}</p>`;
    } finally {
      emailAnalyzeBtn.disabled = false;
      emailAnalyzeBtn.textContent = 'Analyze Email';
    }
  });
}

// ── Utility ───────────────────────────────────────────────────────────────────
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ── Init ──────────────────────────────────────────────────────────────────────
renderAuthArea();
renderHistory();

// ── Auto-analyze from ?url= query param ───────────────────────────────────────
// Populated by the context menu ("Analyze link with PhishGuard") and by the
// popup's "Analyze current page" shortcut. Runs anonymously: sign-in is never
// required to trigger analysis, it only controls whether history is saved.
(function autoAnalyzeFromQuery() {
  const params = new URLSearchParams(window.location.search);
  const prefillUrl = params.get('url');
  if (!prefillUrl) return;
  urlInput.value = prefillUrl;
  // URL tab is already the default-active tab, so no tab switch needed
  runURLAnalysis();
})();
