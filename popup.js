/**
 * PhishGuard - Popup
 */

document.addEventListener('DOMContentLoaded', () => {
  loadStats();
  document.getElementById('btn-clear-log').addEventListener('click', clearLog);
  document.getElementById('btn-export-csv').addEventListener('click', exportCSV);
  document.getElementById('btn-settings').addEventListener('click', () =>
    chrome.runtime.openOptionsPage());
  document.getElementById('btn-open-analyzer').addEventListener('click', openAnalyzerForActiveTab);
});

// Opens analyzer.html; if the active tab is an http(s) page, prefills the
// URL field so one click analyzes the page the user is currently looking at.
// Falls back to opening an empty analyzer for chrome://, extension pages, etc.
function openAnalyzerForActiveTab() {
  const base = chrome.runtime.getURL('analyzer.html');
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tabUrl = tabs && tabs[0] && tabs[0].url;
    const isWebUrl = typeof tabUrl === 'string' && /^https?:\/\//i.test(tabUrl);
    const target = isWebUrl
      ? `${base}?url=${encodeURIComponent(tabUrl)}`
      : base;
    chrome.tabs.create({ url: target });
  });
}

// ── Load ──────────────────────────────────────────────────────────────────────
async function loadStats() {
  let stats;
  try {
    stats = await chrome.runtime.sendMessage({ type: 'GET_STATS' });
  } catch {
    setStatus('Background unavailable - reload email tab', false);
    return;
  }
  if (!stats) stats = empty();

  renderStats(stats);
  renderBar(stats);
  renderIndicators(stats.recentIndicators || []);
  renderLog(stats.log || []);
  renderFooter(stats.lastScan);
}

// ── Renderers ─────────────────────────────────────────────────────────────────
function renderStats(s) {
  setText('stat-total',     s.totalScanned ?? 0);
  setText('stat-suspicious', s.suspicious  ?? 0);
  setText('stat-high-risk', s.highRisk      ?? 0);
}

function renderBar(s) {
  const total  = s.totalScanned || 0;
  const risky  = (s.suspicious || 0) + (s.highRisk || 0);
  const pct    = total > 0 ? Math.min((risky / total) * 100, 100) : 0;
  const fill   = document.getElementById('pg-bar-fill');
  const status = document.getElementById('pg-threat-status');

  fill.style.width = pct + '%';

  if (s.highRisk > 0) {
    fill.className      = 'pg-bar-fill danger';
    status.textContent  = 'Critical';
    status.className    = 'pg-threat-status danger';
  } else if (s.suspicious > 0) {
    fill.className      = 'pg-bar-fill warn';
    status.textContent  = 'Elevated';
    status.className    = 'pg-threat-status warn';
  } else {
    fill.className      = 'pg-bar-fill';
    status.textContent  = total > 0 ? 'Clear' : '-';
    status.className    = 'pg-threat-status' + (total > 0 ? ' ok' : '');
  }
}

function renderIndicators(list) {
  const ul = document.getElementById('pg-indicators-list');
  ul.innerHTML = '';
  if (!list.length) {
    ul.innerHTML = '<li class="pg-empty">No indicators recorded</li>';
    return;
  }
  for (const item of list) {
    // Accept either a plain string (legacy log entries) or a {score, label}
    // object (new format): both render, only the new format shows the pill.
    const label = (item && typeof item === 'object') ? item.label : String(item);
    const score = (item && typeof item === 'object' && typeof item.score === 'number')
      ? item.score : null;

    const li = document.createElement('li');

    const labelSpan = document.createElement('span');
    labelSpan.className = 'pg-ind-label';
    labelSpan.textContent = label;
    li.appendChild(labelSpan);

    if (score !== null) {
      const scoreSpan = document.createElement('span');
      scoreSpan.className = 'pg-ind-score';
      const sign = score >= 0 ? '+' : '';
      scoreSpan.textContent = `${sign}${score} pts`;
      li.appendChild(scoreSpan);
    }

    ul.appendChild(li);
  }
}

function renderLog(entries) {
  const el = document.getElementById('pg-log');
  el.innerHTML = '';
  if (!entries.length) {
    el.innerHTML = '<p class="pg-empty">No entries</p>';
    return;
  }
  for (const e of entries) {
    const row  = document.createElement('div');
    row.className = 'pg-log-entry';

    const dot  = document.createElement('span');
    dot.className = `pg-log-severity ${e.riskLevel}`;

    const body = document.createElement('div');
    body.className = 'pg-log-content';

    const url  = document.createElement('div');
    url.className = 'pg-log-url';
    url.textContent = e.url.length > 55 ? e.url.slice(0, 52) + '…' : e.url;
    url.title = e.url;

    const meta = document.createElement('div');
    meta.className = 'pg-log-meta';

    const levelTag = document.createElement('span');
    levelTag.className = `tag ${e.riskLevel}`;
    levelTag.textContent = e.riskLevel === 'high-risk' ? 'High Risk' : 'Suspicious';

    const scoreTag = document.createElement('span');
    scoreTag.textContent = `Score ${e.score}/100`;

    const timeTag = document.createElement('span');
    timeTag.textContent = new Date(e.timestamp).toLocaleTimeString(undefined, {
      hour: '2-digit', minute: '2-digit',
    });

    meta.append(levelTag, scoreTag, timeTag);
    if (e.domainAge) {
      const ageTag = document.createElement('span');
      ageTag.textContent = e.domainAge;
      meta.appendChild(ageTag);
    }

    body.append(url, meta);
    row.append(dot, body);
    el.appendChild(row);
  }
}

function renderFooter(lastScan) {
  const el = document.getElementById('last-scan');
  el.textContent = lastScan
    ? 'Last scan ' + new Date(lastScan).toLocaleTimeString(undefined, {
        hour: '2-digit', minute: '2-digit',
      })
    : 'No scans yet';
}

// ── Actions ───────────────────────────────────────────────────────────────────
async function clearLog() {
  try { await chrome.runtime.sendMessage({ type: 'CLEAR_STATS' }); } catch {}
  loadStats();
}

async function exportCSV() {
  let stats;
  try { stats = await chrome.runtime.sendMessage({ type: 'GET_STATS' }); } catch { return; }

  const log = stats?.log || [];
  if (!log.length) { flashBtn('btn-export-csv', 'Nothing to export'); return; }

  const headers = ['Timestamp','URL','Domain','Risk Level','Score','Domain Age','Indicators'];
  const rows    = log.map(e => [
    e.timestamp, e.url, e.domain, e.riskLevel,
    e.score ?? '', e.domainAge || '',
    (e.indicators || [])
      .map(i => {
        // Support legacy string[] entries and new {score, label} entries
        if (i && typeof i === 'object') {
          const sign = (i.score >= 0 ? '+' : '');
          return `${i.label} (${sign}${i.score} pts)`;
        }
        return String(i);
      })
      .join(' | '),
  ]);

  const csv  = [headers, ...rows]
    .map(r => r.map(c => `"${String(c).replace(/"/g, '""')}"`).join(','))
    .join('\r\n');

  const blob = new Blob(['\uFEFF' + csv], { type: 'text/csv;charset=utf-8;' });
  const a    = Object.assign(document.createElement('a'), {
    href:     URL.createObjectURL(blob),
    download: `phishguard-${new Date().toISOString().slice(0,10)}.csv`,
  });
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(a.href);

  flashBtn('btn-export-csv', `Exported ${log.length} rows`);
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function empty() {
  return { totalScanned:0, suspicious:0, highRisk:0, lastScan:null, recentIndicators:[], log:[] };
}
function setText(id, v) {
  const el = document.getElementById(id);
  if (el) el.textContent = v;
}
function setStatus(msg, active = true) {
  const txt = document.getElementById('pg-status-text');
  const dot = document.getElementById('pg-dot');
  if (txt) txt.textContent = msg;
  if (dot) { dot.className = 'pg-dot ' + (active ? 'active' : 'inactive'); }
}
function flashBtn(id, msg) {
  const btn = document.getElementById(id);
  if (!btn) return;
  const orig = btn.textContent;
  btn.textContent = msg;
  btn.disabled = true;
  setTimeout(() => { btn.textContent = orig; btn.disabled = false; }, 2500);
}
