/**
 * PhishGuard – Settings Page
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
  sbKeyInput.value     = s.safeBrowsingApiKey  || '';
  ptKeyInput.value     = s.phishTankApiKey     || '';
  vtKeyInput.value     = s.virusTotalApiKey    || '';

  validateSBKey(s.safeBrowsingApiKey);
  validateVTKey(s.virusTotalApiKey);
}

// ── Save ──────────────────────────────────────────────────────────────────────
async function saveSettings() {
  const s = {
    notificationsEnabled: toggleNotif.checked,
    domainAgeEnabled:     toggleDomAge.checked,
    safeBrowsingEnabled:  toggleSB.checked,
    phishTankEnabled:     togglePT.checked,
    virusTotalEnabled:    toggleVT.checked,
    safeBrowsingApiKey:   sbKeyInput.value.trim(),
    phishTankApiKey:      ptKeyInput.value.trim(),
    virusTotalApiKey:     vtKeyInput.value.trim(),
  };
  await chrome.storage.sync.set({ phishguard_settings: s });
  validateSBKey(s.safeBrowsingApiKey);
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
  sbKeyInput.value     = '';
  ptKeyInput.value     = '';
  vtKeyInput.value     = '';
  validateSBKey('');
  validateVTKey('');
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

// ── Reveal toggles ────────────────────────────────────────────────────────────
function addReveal(btnId, inputEl) {
  document.getElementById(btnId)?.addEventListener('click', () => {
    inputEl.type = inputEl.type === 'password' ? 'text' : 'password';
  });
}
addReveal('btn-reveal',    sbKeyInput);
addReveal('btn-reveal-pt', ptKeyInput);
addReveal('btn-reveal-vt', vtKeyInput);

sbKeyInput.addEventListener('input', () => validateSBKey(sbKeyInput.value.trim()));
vtKeyInput.addEventListener('input', () => validateVTKey(vtKeyInput.value.trim()));

// ── Handlers ──────────────────────────────────────────────────────────────────
document.getElementById('btn-save') .addEventListener('click', saveSettings);
document.getElementById('btn-reset').addEventListener('click', resetSettings);

function showBanner() {
  saveBanner.hidden = false;
  setTimeout(() => { saveBanner.hidden = true; }, 3000);
}

loadSettings();
