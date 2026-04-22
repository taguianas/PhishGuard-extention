/**
 * PhishGuard - Settings Page
 */

const DEFAULTS = {
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
};

// ── DOM refs ──────────────────────────────────────────────────────────────────
const toggleNotif  = document.getElementById('toggle-notifications');
const toggleDomAge = document.getElementById('toggle-domainAge');
const toggleSB     = document.getElementById('toggle-safebrowsing');
const togglePT     = document.getElementById('toggle-phishtank');
const toggleVT     = document.getElementById('toggle-virustotal');
const sbKeyInput   = document.getElementById('sb-api-key');
const ptKeyInput   = document.getElementById('pt-api-key');
const vtKeyInput   = document.getElementById('vt-api-key');
const sbStatus     = document.getElementById('sb-status');
const vtStatus     = document.getElementById('vt-status');
const toggleWH     = document.getElementById('toggle-webhook');
const whUrlInput   = document.getElementById('webhook-url');
const whAuthInput  = document.getElementById('webhook-auth');
const whStatus     = document.getElementById('webhook-status');
const toggleShort  = document.getElementById('toggle-shortener');
const saveBanner   = document.getElementById('save-banner');

// ── Load ──────────────────────────────────────────────────────────────────────
async function loadSettings() {
  const data = await chrome.storage.sync.get(['phishguard_settings']);
  const s    = { ...DEFAULTS, ...data.phishguard_settings };

  toggleNotif.checked  = s.notificationsEnabled;
  toggleDomAge.checked = s.domainAgeEnabled;
  toggleSB.checked     = s.safeBrowsingEnabled;
  togglePT.checked     = s.phishTankEnabled;
  toggleVT.checked     = s.virusTotalEnabled;
  toggleWH.checked     = s.webhookEnabled;
  toggleShort.checked  = s.shortenerExpansionEnabled;
  sbKeyInput.value     = s.safeBrowsingApiKey  || '';
  ptKeyInput.value     = s.phishTankApiKey     || '';
  vtKeyInput.value     = s.virusTotalApiKey    || '';
  whUrlInput.value     = s.webhookUrl          || '';
  whAuthInput.value    = s.webhookAuthHeader   || '';

  validateSBKey(s.safeBrowsingApiKey);
  validateVTKey(s.virusTotalApiKey);
  validateWebhookUrl(s.webhookUrl);
}

// ── Save ──────────────────────────────────────────────────────────────────────
async function saveSettings() {
  const s = {
    notificationsEnabled: toggleNotif.checked,
    domainAgeEnabled:     toggleDomAge.checked,
    safeBrowsingEnabled:  toggleSB.checked,
    phishTankEnabled:     togglePT.checked,
    virusTotalEnabled:    toggleVT.checked,
    webhookEnabled:       toggleWH.checked,
    shortenerExpansionEnabled: toggleShort.checked,
    safeBrowsingApiKey:   sbKeyInput.value.trim(),
    phishTankApiKey:      ptKeyInput.value.trim(),
    virusTotalApiKey:     vtKeyInput.value.trim(),
    webhookUrl:           whUrlInput.value.trim(),
    webhookAuthHeader:    whAuthInput.value.trim(),
  };

  // If the webhook is enabled with a valid URL, request host permission for
  // its origin. Without this, the service-worker fetch() would fail CORS-style.
  if (s.webhookEnabled && s.webhookUrl) {
    const origin = webhookOrigin(s.webhookUrl);
    if (origin) {
      try {
        const granted = await chrome.permissions.request({ origins: [origin] });
        if (!granted) {
          whStatus.textContent = 'Permission for this origin was denied. Webhook disabled.';
          whStatus.className   = 'pg-api-status err';
          s.webhookEnabled     = false;
          toggleWH.checked     = false;
        }
      } catch (err) {
        console.warn('[PhishGuard Settings] permission request failed:', err);
      }
    }
  }

  // Shortener expansion needs access to any origin (the redirect target is
  // unknown until we follow it). Request the broad host permission only when
  // the user enables the toggle. If denied, flip the toggle back off.
  if (s.shortenerExpansionEnabled) {
    try {
      const granted = await chrome.permissions.request({
        origins: ['https://*/*', 'http://*/*'],
      });
      if (!granted) {
        s.shortenerExpansionEnabled = false;
        toggleShort.checked         = false;
      }
    } catch (err) {
      console.warn('[PhishGuard Settings] shortener permission request failed:', err);
    }
  }

  await chrome.storage.sync.set({ phishguard_settings: s });
  validateSBKey(s.safeBrowsingApiKey);
  validateWebhookUrl(s.webhookUrl);
  showBanner();
}

// ── Reset ─────────────────────────────────────────────────────────────────────
async function resetSettings() {
  await chrome.storage.sync.set({ phishguard_settings: DEFAULTS });
  toggleNotif.checked  = DEFAULTS.notificationsEnabled;
  toggleDomAge.checked = DEFAULTS.domainAgeEnabled;
  toggleSB.checked     = DEFAULTS.safeBrowsingEnabled;
  togglePT.checked     = DEFAULTS.phishTankEnabled;
  toggleVT.checked     = DEFAULTS.virusTotalEnabled;
  toggleWH.checked     = DEFAULTS.webhookEnabled;
  toggleShort.checked  = DEFAULTS.shortenerExpansionEnabled;
  sbKeyInput.value     = '';
  ptKeyInput.value     = '';
  vtKeyInput.value     = '';
  whUrlInput.value     = '';
  whAuthInput.value    = '';
  validateSBKey('');
  validateVTKey('');
  validateWebhookUrl('');
  showBanner();
}

// ── Validation ────────────────────────────────────────────────────────────────
function validateSBKey(key) {
  if (!key) { sbStatus.textContent = ''; sbStatus.className = 'pg-api-status'; return; }
  const ok = key.length >= 30 && /^[A-Za-z0-9_-]+$/.test(key);
  sbStatus.textContent = ok ? 'API key set - Safe Browsing active.'
                            : 'Key format looks incorrect - verify in Google Cloud Console.';
  sbStatus.className   = 'pg-api-status ' + (ok ? 'ok' : 'err');
}

function validateVTKey(key) {
  if (!key) { vtStatus.textContent = ''; vtStatus.className = 'pg-api-status'; return; }
  // VirusTotal API keys are exactly 64 hexadecimal characters
  const ok = /^[0-9a-f]{64}$/.test(key);
  vtStatus.textContent = ok ? 'API key set - VirusTotal active.'
                            : 'Key format looks incorrect - VirusTotal keys are 64 hex characters.';
  vtStatus.className   = 'pg-api-status ' + (ok ? 'ok' : 'err');
}

function webhookOrigin(url) {
  try {
    const u = new URL(url);
    if (u.protocol !== 'https:' && u.protocol !== 'http:') return null;
    return `${u.protocol}//${u.host}/*`;
  } catch {
    return null;
  }
}

function validateWebhookUrl(url) {
  if (!url) { whStatus.textContent = ''; whStatus.className = 'pg-api-status'; return; }
  let parsed;
  try { parsed = new URL(url); }
  catch {
    whStatus.textContent = 'Not a valid URL.';
    whStatus.className   = 'pg-api-status err';
    return;
  }
  if (parsed.protocol !== 'https:') {
    whStatus.textContent = 'Webhook URL must use HTTPS.';
    whStatus.className   = 'pg-api-status err';
    return;
  }
  whStatus.textContent = `Webhook active: ${parsed.origin}`;
  whStatus.className   = 'pg-api-status ok';
}

// ── Reveal toggles ────────────────────────────────────────────────────────────
function addReveal(btnId, inputEl) {
  document.getElementById(btnId)?.addEventListener('click', () => {
    inputEl.type = inputEl.type === 'password' ? 'text' : 'password';
  });
}
addReveal('btn-reveal',    sbKeyInput);
addReveal('btn-reveal-pt', ptKeyInput);
addReveal('btn-reveal-vt', vtKeyInput);
addReveal('btn-reveal-wh', whAuthInput);

sbKeyInput.addEventListener('input', () => validateSBKey(sbKeyInput.value.trim()));
vtKeyInput.addEventListener('input', () => validateVTKey(vtKeyInput.value.trim()));
whUrlInput.addEventListener('input', () => validateWebhookUrl(whUrlInput.value.trim()));

// ── Handlers ──────────────────────────────────────────────────────────────────
document.getElementById('btn-save') .addEventListener('click', saveSettings);
document.getElementById('btn-reset').addEventListener('click', resetSettings);

function showBanner() {
  saveBanner.hidden = false;
  setTimeout(() => { saveBanner.hidden = true; }, 3000);
}

// ── Allowlist Management ─────────────────────────────────────────────────────
const allowlistTable = document.getElementById('allowlist-table');
const allowlistBody  = document.getElementById('allowlist-body');
const allowlistEmpty = document.getElementById('allowlist-empty');

async function loadAllowlist() {
  let list;
  try {
    list = await chrome.runtime.sendMessage({ type: 'GET_ALLOWLIST' });
  } catch {
    return; // background unavailable
  }

  const domains = Object.keys(list || {});
  if (!domains.length) {
    allowlistTable.hidden = true;
    allowlistEmpty.hidden = false;
    return;
  }

  allowlistEmpty.hidden = true;
  allowlistTable.hidden = false;
  allowlistBody.innerHTML = '';

  // Sort by most recently marked safe
  domains.sort((a, b) => (list[b].lastMarkedSafe || 0) - (list[a].lastMarkedSafe || 0));

  for (const domain of domains) {
    const entry = list[domain];
    const tr = document.createElement('tr');

    const tdDomain = document.createElement('td');
    tdDomain.textContent = domain;
    tdDomain.style.fontFamily = 'Consolas, monospace';
    tdDomain.style.fontSize   = '11.5px';

    const tdCount = document.createElement('td');
    tdCount.className = 'num';
    tdCount.textContent = entry.count || 1;

    const tdDate = document.createElement('td');
    tdDate.textContent = entry.lastMarkedSafe
      ? new Date(entry.lastMarkedSafe).toLocaleDateString(undefined, {
          year: 'numeric', month: 'short', day: 'numeric',
        })
      : '-';

    const tdAction = document.createElement('td');
    const removeBtn = document.createElement('button');
    removeBtn.className = 'pg-btn-icon pg-btn-remove';
    removeBtn.textContent = '\u2715'; // ✕
    removeBtn.title = 'Remove from allowlist';
    removeBtn.addEventListener('click', () => removeAllowlistEntry(domain));
    tdAction.appendChild(removeBtn);

    tr.append(tdDomain, tdCount, tdDate, tdAction);
    allowlistBody.appendChild(tr);
  }
}

async function removeAllowlistEntry(domain) {
  try {
    await chrome.runtime.sendMessage({ type: 'REMOVE_ALLOWLIST', domain });
  } catch {
    return;
  }
  loadAllowlist();
}

loadSettings();
loadAllowlist();
