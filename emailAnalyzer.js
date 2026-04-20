/**
 * PhishGuard Email Analyzer
 * Analyzes email fields for phishing indicators.
 * Imports analyzeURL from urlAnalyzer.js for embedded link checks.
 */

import { analyzeURL } from './urlAnalyzer.js';

const FREE_EMAIL_DOMAINS = new Set([
  'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com',
  'icloud.com', 'protonmail.com', 'proton.me', 'mail.com', 'yandex.com',
  'yandex.ru', 'zoho.com', 'gmx.com', 'fastmail.com', 'tutanota.com',
  'live.com', 'msn.com', 'yahoo.co.uk', 'yahoo.co.in',
]);

const URGENCY_PATTERNS = [
  'urgent', 'immediately', 'action required', 'account suspended', 'account locked',
  'account closed', 'verify now', 'expires today', 'expires soon', 'limited time',
  'final notice', 'security alert', 'unusual activity', 'suspicious activity',
  'your account will be', 'last chance', 'confirm now', 'act now',
  'click here to verify', 'validate your', 'must respond',
];

const PHISHING_BODY_PATTERNS = [
  'enter your password', 'confirm your password', 'verify your account',
  'update your payment', 'your account has been', 'we have detected',
  'unusual sign-in', 'confirm your identity', 'your card will be charged',
  'enter your credit card', 'social security', 'bank account number',
  'wire transfer', 'gift card', 'send money', 'provide your credentials',
  'login credentials', 'one-time password', 'one time pin',
];

const BRAND_NAMES_EMAIL = [
  'paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook', 'instagram',
  'netflix', 'dropbox', 'linkedin', 'twitter', 'binance', 'coinbase',
  'chase', 'wellsfargo', 'citibank', 'dhl', 'fedex', 'ups', 'usps',
  'ebay', 'stripe', 'shopify', 'steam', 'discord', 'roblox', 'docusign',
  'wetransfer', 'office365', 'irs',
];

const SUSPICIOUS_ATTACHMENT_KEYWORDS = [
  '.exe', '.bat', '.cmd', '.scr', '.vbs', '.ps1', '.jar', '.msi',
  '.docm', '.xlsm', '.pptm',
];

function extractDomain(emailStr) {
  const match = emailStr.match(/@([a-zA-Z0-9._-]+)/);
  return match ? match[1].toLowerCase() : null;
}

function extractDisplayName(emailStr) {
  const quoted = emailStr.match(/^"([^"]+)"/);
  if (quoted) return quoted[1].toLowerCase();
  const angled = emailStr.match(/^([^<@]+)<[^>]+>/);
  if (angled) return angled[1].trim().toLowerCase();
  return null;
}

function extractURLsFromText(text) {
  const urlRe = /https?:\/\/[^\s"'<>\])\u200B]+/gi;
  return Array.from(new Set(text.match(urlRe) || []));
}

/**
 * Analyze an email for phishing indicators.
 * @param {{ from: string, replyTo: string, subject: string, body: string }}
 * @returns {{ score, riskLevel, indicators, urlResults }}
 */
export function analyzeEmail({ from = '', replyTo = '', subject = '', body = '' }) {
  const indicators = [];
  let score = 0;
  const add = (entry) => { indicators.push(entry); score += entry.score; };

  const fromDomain  = extractDomain(from);
  const fromDisplay = extractDisplayName(from);
  const replyDomain = replyTo ? extractDomain(replyTo) : null;

  // 1. Reply-To domain mismatch
  if (fromDomain && replyDomain && fromDomain !== replyDomain) {
    add({ score: 40, label: `Reply-To mismatch: From domain "${fromDomain}" - replies routed to "${replyDomain}"` });
  }

  // 2. Sender display name spoofing
  if (fromDisplay && fromDomain) {
    for (const brand of BRAND_NAMES_EMAIL) {
      if (brand.length < 4) continue;
      if (fromDisplay.includes(brand) && !fromDomain.includes(brand)) {
        add({ score: 50, label: `Sender display name impersonates "${brand}" but actual domain is "${fromDomain}"` });
        break;
      }
    }
  }

  // 3. Free email domain (low weight alone - amplified by other signals)
  if (fromDomain && FREE_EMAIL_DOMAINS.has(fromDomain)) {
    add({ score: 10, label: `Sender uses a free email service (${fromDomain})` });
  }

  // 4. Urgency / pressure language in subject
  const subjectLower = subject.toLowerCase();
  const foundUrgency = URGENCY_PATTERNS.filter(p => subjectLower.includes(p));
  if (foundUrgency.length > 0) {
    add({ score: Math.min(foundUrgency.length * 15, 45),
          label: `Urgency language in subject: "${foundUrgency.slice(0, 3).join('", "')}"` });
  }

  // 5. Brand name in subject but sender domain does not belong to that brand
  for (const brand of BRAND_NAMES_EMAIL) {
    if (brand.length < 4) continue;
    if (subjectLower.includes(brand) && fromDomain && !fromDomain.includes(brand)) {
      add({ score: 30, label: `Subject references "${brand}" but sender domain "${fromDomain}" is not ${brand}'s official domain` });
      break;
    }
  }

  // 6. Credential-harvesting patterns in body
  const bodyLower = body.toLowerCase();
  const foundPhishing = PHISHING_BODY_PATTERNS.filter(p => bodyLower.includes(p));
  if (foundPhishing.length > 0) {
    add({ score: Math.min(foundPhishing.length * 15, 45),
          label: `Credential-harvesting patterns in body: "${foundPhishing.slice(0, 2).join('", "')}"` });
  }

  // 7. Suspicious attachment file type references in body
  const foundAttach = SUSPICIOUS_ATTACHMENT_KEYWORDS.filter(e => bodyLower.includes(e));
  if (foundAttach.length > 0) {
    add({ score: 35, label: `Suspicious file types referenced in body: ${foundAttach.join(', ')}` });
  }

  // 8. Extract and analyze embedded URLs
  const rawUrls  = extractURLsFromText(body);
  const urlResults = [];
  for (const url of rawUrls.slice(0, 15)) {
    try {
      const result = analyzeURL(url);
      if (result) urlResults.push(result);
    } catch (_) {}
  }

  const highRisk  = urlResults.filter(r => r.riskLevel === 'high-risk');
  const suspicious = urlResults.filter(r => r.riskLevel === 'suspicious');
  if (highRisk.length > 0) {
    add({ score: 60, label: `${highRisk.length} high-risk link(s) embedded in email body` });
  } else if (suspicious.length > 0) {
    add({ score: 30, label: `${suspicious.length} suspicious link(s) embedded in email body` });
  }

  score = Math.min(score, 100);
  const riskLevel = score <= 30 ? 'safe' : score < 60 ? 'suspicious' : 'high-risk';

  return { score, riskLevel, indicators, urlResults };
}
