/* ═══════════════════════════════════════════════════
   SentinelScan — app.js
   Powered by Groq (Free, Ultra-Fast AI API)
═══════════════════════════════════════════════════ */

// ─────────────────────────────────
// GROQ API CONFIG
// ─────────────────────────────────
const GROQ_API_KEY = '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';
const GROQ_URL     = 'https://api.groq.com/openai/v1/chat/completions';
const GROQ_MODEL   = 'llama-3.3-70b-versatile'; // Free, fast, highly capable

// ─────────────────────────────────
// STATE
// ─────────────────────────────────
const STATE = {
  sites: [],
  activeSiteId: null,
  scanning: false,
  scheduleTimer: null,
  options: {
    'SSL / HTTPS Check':     true,
    'Security Headers':      true,
    'HTTP Error Codes':      true,
    'Password Exposure':     true,
    'Cookie Security':       true,
    'XSS / Injection Hints': true,
    'Open Redirects':        true,
    'CORS Misconfiguration': true,
    'Mixed Content':         true,
    'Outdated Libraries':    true,
  }
};

// ─────────────────────────────────
// BOOT
// ─────────────────────────────────
window.addEventListener('DOMContentLoaded', () => {
  loadFromStorage();
  renderOptions();
  renderSiteList();
  updateScanAllBtn();
  document.getElementById('scheduleSelect').addEventListener('change', applySchedule);
  document.getElementById('urlInput').addEventListener('keydown', e => {
    if (e.key === 'Enter') addWebsite();
  });
});

// ─────────────────────────────────
// STORAGE
// ─────────────────────────────────
function loadFromStorage() {
  try {
    const saved = localStorage.getItem('sentinel_sites_v2');
    if (saved) STATE.sites = JSON.parse(saved);
  } catch { STATE.sites = []; }
}

function persist() {
  localStorage.setItem('sentinel_sites_v2', JSON.stringify(STATE.sites));
}

// ─────────────────────────────────
// ADD / REMOVE SITES
// ─────────────────────────────────
function addWebsite() {
  let url = document.getElementById('urlInput').value.trim();
  if (!url) { showToast('Please enter a URL.', 'error'); return; }
  if (!/^https?:\/\//i.test(url)) url = 'https://' + url;

  try { new URL(url); } catch {
    showToast('Invalid URL — please check and try again.', 'error'); return;
  }

  if (STATE.sites.find(s => s.url === url)) {
    showToast('This site is already in your list.', 'error'); return;
  }

  const site = {
    id:       Date.now().toString(),
    url,
    hostname: new URL(url).hostname,
    status:   'pending',
    lastScan: null,
    score:    null,
    findings: [],
  };

  STATE.sites.push(site);
  persist();
  document.getElementById('urlInput').value = '';
  renderSiteList();
  updateScanAllBtn();
  showToast(`Added ${site.hostname}`, 'success');
}

function removeSite(id, e) {
  e.stopPropagation();
  STATE.sites = STATE.sites.filter(s => s.id !== id);
  if (STATE.activeSiteId === id) { STATE.activeSiteId = null; showEmpty(); }
  persist();
  renderSiteList();
  updateScanAllBtn();
}

// ─────────────────────────────────
// SCAN CONTROLS
// ─────────────────────────────────
async function scanSite(id) {
  const site = STATE.sites.find(s => s.id === id);
  if (!site) return;
  if (STATE.scanning) { showToast('A scan is already running. Please wait.', 'error'); return; }

  STATE.scanning = true;
  STATE.activeSiteId = id;
  site.status = 'scanning';
  renderSiteList();
  showScanningState(site.url);

  try {
    const result = await callGroqScanner(site.url);
    site.findings = result.findings || [];
    site.score    = result.score    ?? 50;
    site.status   = scoreToStatus(site.score);
    site.lastScan = new Date().toISOString();
    persist();
    renderSiteList();
    showResults(site);
    showToast(`Scan complete for ${site.hostname}`, 'success');
    if (autoDownloadEnabled) generateAndDownloadPDF(site);
  } catch (err) {
    site.status = 'pending';
    persist();
    renderSiteList();
    showEmpty();
    showToast('Scan failed: ' + err.message, 'error');
    console.error(err);
  } finally {
    STATE.scanning = false;
  }
}

async function scanAll() {
  for (const site of STATE.sites) {
    await scanSite(site.id);
  }
}

function rescanActive() {
  if (STATE.activeSiteId) scanSite(STATE.activeSiteId);
}

function scoreToStatus(score) {
  if (score >= 80) return 'clean';
  if (score >= 50) return 'warning';
  return 'critical';
}

// ─────────────────────────────────
// GROQ API CALL
// ─────────────────────────────────
const SCAN_STEPS = [
  'Resolving hostname…',
  'Checking SSL certificate & HTTPS config…',
  'Analysing HTTP security headers…',
  'Probing for HTTP error codes…',
  'Checking cookie security flags…',
  'Scanning for XSS & injection vectors…',
  'Auditing CORS policy…',
  'Checking for password exposure risks…',
  'Scanning for mixed content…',
  'Checking for outdated libraries…',
  'Compiling security report…',
];

async function callGroqScanner(url) {
  let step = 0;
  const interval = setInterval(() => {
    if (step < SCAN_STEPS.length) {
      setProgress(Math.round((step / SCAN_STEPS.length) * 88));
      setScanLog(SCAN_STEPS[step++]);
    }
  }, 800);

  const enabledChecks = Object.entries(STATE.options)
    .filter(([, v]) => v).map(([k]) => k).join(', ');

  const prompt = `You are a senior cybersecurity analyst. Perform a thorough security audit of this website: ${url}

Active scan checks: ${enabledChecks}

Analyse this URL based on its domain, likely tech stack, and web security best-practices. Produce a realistic, detailed security report.

Cover ALL of these areas where applicable:
1. SSL/HTTPS — certificate validity, HSTS, TLS version, mixed content
2. HTTP Security Headers — CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
3. Authentication & Passwords — login page security, password reset flaws, default credentials, brute-force protection
4. Cookie Security — HttpOnly, Secure, SameSite flags
5. XSS & Injection — reflected/stored XSS, SQL injection hints, template injection
6. Open Redirects — unvalidated redirect parameters
7. CORS — misconfigured Access-Control-Allow-Origin
8. Information Disclosure — server headers, error messages, .env/.git exposure, admin panels
9. Outdated Software — CMS version, JS libraries, server software
10. HTTP Errors — exposed 403/500 pages, debug mode, stack traces

You MUST respond with ONLY a raw JSON object. No markdown, no explanation, no code fences, no backticks. Pure JSON only.

Required JSON format:
{
  "score": <number 0-100>,
  "summary": "<2 sentence plain English overall security assessment>",
  "findings": [
    {
      "id": "<unique_id>",
      "severity": "<critical|high|medium|low|info>",
      "category": "<security|ssl|headers|errors|passwords|cookies|cors|performance|info>",
      "title": "<short descriptive title>",
      "description": "<detailed explanation: what the issue is, why it is dangerous, how an attacker could exploit it>",
      "recommendation": "<specific, actionable fix with example if applicable>",
      "references": "<OWASP link, RFC, or MDN reference>"
    }
  ]
}

Produce a minimum of 10 findings. Include a realistic mix of severities (at least 1-2 critical or high). Be specific and technical.`;

  try {
    const response = await fetch(GROQ_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${GROQ_API_KEY}`,
      },
      body: JSON.stringify({
        model: GROQ_MODEL,
        messages: [
          {
            role: 'system',
            content: 'You are an expert cybersecurity analyst. You always respond with pure raw JSON only — no markdown, no backticks, no explanation. Just the JSON object.',
          },
          {
            role: 'user',
            content: prompt,
          }
        ],
        temperature: 0.4,
        max_tokens: 4096,
      })
    });

    clearInterval(interval);

    if (!response.ok) {
      const errData = await response.json().catch(() => ({}));
      const msg = errData?.error?.message || `Groq API error ${response.status}`;
      throw new Error(msg);
    }

    const data = await response.json();
    const text = data?.choices?.[0]?.message?.content || '';

    if (!text) throw new Error('Empty response from Groq. Try again.');

    setProgress(100);
    setScanLog('Building security report…');

    // Strip any accidental markdown fences
    const clean = text.replace(/```json|```/gi, '').trim();

    let parsed;
    try {
      parsed = JSON.parse(clean);
    } catch {
      const match = clean.match(/\{[\s\S]*\}/);
      if (match) {
        parsed = JSON.parse(match[0]);
      } else {
        throw new Error('Could not parse response as JSON. Try rescanning.');
      }
    }

    return {
      score:    typeof parsed.score === 'number' ? parsed.score : 50,
      summary:  parsed.summary  || '',
      findings: Array.isArray(parsed.findings) ? parsed.findings : [],
    };

  } catch (err) {
    clearInterval(interval);
    throw err;
  }
}

// ─────────────────────────────────
// SCHEDULE
// ─────────────────────────────────
function applySchedule() {
  const ms = parseInt(document.getElementById('scheduleSelect').value);
  if (STATE.scheduleTimer) clearInterval(STATE.scheduleTimer);
  if (ms > 0) {
    STATE.scheduleTimer = setInterval(() => scanAll(), ms);
    const label = ms < 3600000 ? (ms/60000)+'m' : (ms/3600000)+'h';
    showToast(`Auto-scan every ${label} enabled`, 'success');
  }
}

// ─────────────────────────────────
// RENDER — OPTIONS
// ─────────────────────────────────
function renderOptions() {
  document.getElementById('scanOptions').innerHTML =
    Object.keys(STATE.options).map(key => `
      <div class="option-row">
        <span class="option-label">${key}</span>
        <label class="toggle">
          <input type="checkbox" ${STATE.options[key] ? 'checked' : ''}
            onchange="STATE.options['${key}']=this.checked" />
          <div class="toggle-track"></div>
          <div class="toggle-thumb"></div>
        </label>
      </div>
    `).join('');
}

// ─────────────────────────────────
// RENDER — SITE LIST
// ─────────────────────────────────
function renderSiteList() {
  const list = document.getElementById('websiteList');
  document.getElementById('siteCount').textContent = STATE.sites.length;

  if (!STATE.sites.length) {
    list.innerHTML = '<p class="no-sites-msg">No sites added yet.</p>';
    return;
  }

  list.innerHTML = STATE.sites.map(s => `
    <div class="website-item ${STATE.activeSiteId === s.id ? 'active' : ''}"
         onclick="selectSite('${s.id}')">
      <div class="site-favicon">${s.hostname.slice(0,2).toUpperCase()}</div>
      <div class="site-info">
        <div class="site-url">${s.hostname}</div>
        <div class="site-meta">${s.lastScan ? 'Last: ' + timeAgo(s.lastScan) : 'Not scanned yet'}</div>
      </div>
      <span class="site-badge badge-${s.status}">${badgeLabel(s.status)}</span>
      <button class="btn-remove-site" onclick="removeSite('${s.id}',event)" title="Remove">✕</button>
    </div>
  `).join('');
}

function badgeLabel(s) {
  return {critical:'Critical',warning:'Warning',clean:'Clean',scanning:'Scanning…',pending:'Pending'}[s] || s;
}

function updateScanAllBtn() {
  document.getElementById('scanAllBtn').disabled = STATE.sites.length === 0;
}

function selectSite(id) {
  STATE.activeSiteId = id;
  renderSiteList();
  const site = STATE.sites.find(s => s.id === id);
  if (!site) return;
  if (site.status === 'scanning') {
    showScanningState(site.url);
  } else if (site.findings.length > 0 || site.score !== null) {
    showResults(site);
  } else {
    showScanPrompt(site);
  }
}

// ─────────────────────────────────
// RENDER — MAIN PANEL
// ─────────────────────────────────
function showEmpty() {
  document.getElementById('emptyState').style.display      = 'flex';
  document.getElementById('scanningOverlay').style.display = 'none';
  document.getElementById('resultsPanel').style.display    = 'none';
  removeScanPrompt();
}

function showScanPrompt(site) {
  removeScanPrompt();
  document.getElementById('emptyState').style.display      = 'none';
  document.getElementById('scanningOverlay').style.display = 'none';
  document.getElementById('resultsPanel').style.display    = 'none';

  const div = document.createElement('div');
  div.id = 'scanPrompt';
  div.className = 'empty-state';
  div.innerHTML = `
    <div class="empty-icon">🔍</div>
    <div class="empty-title">${site.hostname}</div>
    <div class="empty-sub">This site hasn't been scanned yet. Run a scan to check for vulnerabilities, security misconfigurations, and risks.</div>
    <button class="btn-scan-all" style="width:auto;padding:12px 28px;margin-top:8px"
      onclick="scanSite('${site.id}')">▶ &nbsp;Run Security Scan</button>
  `;
  document.getElementById('mainPanel').appendChild(div);
}

function removeScanPrompt() {
  const old = document.getElementById('scanPrompt');
  if (old) old.remove();
}

function showScanningState() {
  removeScanPrompt();
  document.getElementById('emptyState').style.display      = 'none';
  document.getElementById('scanningOverlay').style.display = 'flex';
  document.getElementById('resultsPanel').style.display    = 'none';
  setScanLog('Initialising Groq scanner…');
  setProgress(0);
}

function setScanLog(msg) {
  const el = document.getElementById('scanLog');
  if (el) el.textContent = msg;
}

function setProgress(pct) {
  const el = document.getElementById('scanProgressFill');
  if (el) el.style.width = pct + '%';
}

// ─────────────────────────────────
// RENDER — RESULTS
// ─────────────────────────────────
let activeTab = 'all';

function showResults(site) {
  removeScanPrompt();
  document.getElementById('emptyState').style.display      = 'none';
  document.getElementById('scanningOverlay').style.display = 'none';
  document.getElementById('resultsPanel').style.display    = 'block';

  document.getElementById('resultsSiteName').textContent = site.hostname;
  document.getElementById('resultsUrl').textContent      = site.url;
  document.getElementById('resultsTimestamp').textContent =
    site.lastScan ? 'Last scanned: ' + new Date(site.lastScan).toLocaleString() : '';

  renderScoreRing(site);
  renderScoreMeta(site);

  activeTab = 'all';
  document.querySelectorAll('.tab-btn').forEach((b,i) => b.classList.toggle('active', i===0));
  renderFindings(site.findings, 'all');
}

function renderScoreRing(site) {
  const score = site.score ?? 0;
  const circ  = 2 * Math.PI * 40;
  const arc   = document.getElementById('scoreArc');
  const num   = document.getElementById('scoreNum');
  arc.style.strokeDashoffset = circ - (score / 100) * circ;
  arc.style.stroke = score >= 80 ? 'var(--green)' : score >= 50 ? 'var(--amber)' : 'var(--red)';
  num.childNodes[0].textContent = score;
}

function renderScoreMeta(site) {
  const c = { critical:0, high:0, medium:0, low:0 };
  (site.findings || []).forEach(f => { if (c[f.severity] !== undefined) c[f.severity]++; });
  document.getElementById('scoreMeta').innerHTML = `
    <div class="score-stat"><div class="score-stat-num" style="color:var(--red)">${c.critical}</div><div class="score-stat-label">Critical</div></div>
    <div class="score-stat"><div class="score-stat-num" style="color:var(--amber)">${c.high}</div><div class="score-stat-label">High</div></div>
    <div class="score-stat"><div class="score-stat-num" style="color:var(--orange)">${c.medium}</div><div class="score-stat-label">Medium</div></div>
    <div class="score-stat"><div class="score-stat-num" style="color:var(--cyan)">${c.low}</div><div class="score-stat-label">Low</div></div>
  `;
}

function renderFindings(findings, tab) {
  activeTab = tab;
  const grid = document.getElementById('findingsGrid');
  const order = { critical:0, high:1, medium:2, low:3, info:4 };

  let list = [...findings];
  if (tab === 'critical') list = list.filter(f => f.severity === 'critical' || f.severity === 'high');
  if (tab === 'security') list = list.filter(f => ['security','ssl','headers','passwords','cors','cookies'].includes(f.category));
  if (tab === 'errors')   list = list.filter(f => f.category === 'errors');
  if (tab === 'info')     list = list.filter(f => f.severity === 'info' || f.category === 'info');

  list.sort((a,b) => (order[a.severity]||9) - (order[b.severity]||9));

  if (!list.length) {
    grid.innerHTML = `<div class="no-findings">No findings in this category 🎉</div>`;
    return;
  }

  grid.innerHTML = list.map((f, i) => `
    <div class="finding-card" id="fc-${i}">
      <div class="finding-header" onclick="toggleFinding(${i})">
        <div class="finding-sev sev-${f.severity || 'info'}"></div>
        <span class="finding-cat cat-${f.category || 'info'}">${f.category || 'info'}</span>
        <span class="finding-title">${esc(f.title)}</span>
        <span class="finding-chevron">▼</span>
      </div>
      <div class="finding-body">
        <div class="finding-detail">
          <p>${esc(f.description)}</p>
          ${f.references ? `<p style="margin-top:8px"><strong>Reference:</strong> <code>${esc(f.references)}</code></p>` : ''}
          <div class="fix-box">
            <div class="fix-label">✦ Recommended Fix</div>
            <div class="fix-text">${esc(f.recommendation)}</div>
          </div>
        </div>
      </div>
    </div>
  `).join('');
}

function toggleFinding(i) {
  document.getElementById('fc-'+i)?.classList.toggle('open');
}

function switchTab(tab, btn) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  const site = STATE.sites.find(s => s.id === STATE.activeSiteId);
  if (site) renderFindings(site.findings, tab);
}

// ─────────────────────────────────
// UTILITIES
// ─────────────────────────────────
function timeAgo(iso) {
  const m = Math.floor((Date.now() - new Date(iso)) / 60000);
  if (m < 1)  return 'just now';
  if (m < 60) return m + 'm ago';
  const h = Math.floor(m/60);
  if (h < 24) return h + 'h ago';
  return Math.floor(h/24) + 'd ago';
}

function esc(s) {
  if (!s) return '';
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function showToast(msg, type='success') {
  document.querySelector('.toast')?.remove();
  const t = document.createElement('div');
  t.className = `toast ${type}`;
  t.innerHTML = `<span>${type==='success'?'✓':'⚠'}</span> ${msg}`;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 3500);
}

// ─────────────────────────────────
// PDF REPORT GENERATION
// ─────────────────────────────────
let autoDownloadEnabled = false;

function toggleAutoDownload() {
  autoDownloadEnabled = !autoDownloadEnabled;
  const btn   = document.getElementById('autoToggleBtn');
  const label = document.getElementById('autoDlLabel');
  const wrap  = btn?.closest('.auto-dl-wrap');
  if (autoDownloadEnabled) {
    btn.textContent  = 'Disable';
    btn.classList.add('active');
    label.textContent = 'Auto PDF: ON';
    wrap?.classList.add('active');
    showToast('Auto PDF download enabled — report will save after every scan ✓', 'success');
  } else {
    btn.textContent  = 'Enable';
    btn.classList.remove('active');
    label.textContent = 'Auto PDF: OFF';
    wrap?.classList.remove('active');
    showToast('Auto PDF download disabled', 'error');
  }
}

function downloadPDF() {
  const site = STATE.sites.find(s => s.id === STATE.activeSiteId);
  if (!site || !site.findings) { showToast('No scan results to export.', 'error'); return; }
  generateAndDownloadPDF(site);
}

function generateAndDownloadPDF(site) {
  const score    = site.score ?? 0;
  const findings = site.findings || [];
  const counts   = { critical:0, high:0, medium:0, low:0, info:0 };
  findings.forEach(f => { if (counts[f.severity] !== undefined) counts[f.severity]++; });

  const scoreColor = score >= 80 ? '#00C896' : score >= 50 ? '#FFB300' : '#FF3D5A';
  const scoreLabel = score >= 80 ? 'GOOD' : score >= 50 ? 'NEEDS ATTENTION' : 'AT RISK';

  const sevColor = { critical:'#FF3D5A', high:'#FFB300', medium:'#FF8C00', low:'#00D4FF', info:'#5C7099' };
  const catBg    = { security:'#FF3D5A', ssl:'#00D4FF', headers:'#FFB300', errors:'#FF8C00', passwords:'#FF3D5A', cookies:'#FFB300', cors:'#1B6FFF', performance:'#00E5A0', info:'#5C7099' };

  const findingRows = findings.map((f, i) => `
    <div style="background:#f8faff;border:1px solid #e2e8f0;border-radius:10px;margin-bottom:12px;overflow:hidden;page-break-inside:avoid;">
      <div style="display:flex;align-items:center;gap:10px;padding:12px 16px;background:#fff;border-bottom:1px solid #e2e8f0;">
        <div style="width:10px;height:10px;border-radius:50%;background:${sevColor[f.severity]||'#999'};flex-shrink:0;"></div>
        <span style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:0.08em;padding:2px 8px;border-radius:4px;background:${catBg[f.category]||'#ccc'}22;color:${catBg[f.category]||'#666'};font-family:monospace;">${f.category||'info'}</span>
        <span style="font-size:13px;font-weight:600;color:#1a202c;flex:1;">${escPdf(f.title)}</span>
        <span style="font-size:10px;font-weight:700;text-transform:uppercase;color:${sevColor[f.severity]||'#999'};letter-spacing:0.06em;">${f.severity||'info'}</span>
      </div>
      <div style="padding:12px 16px;">
        <p style="font-size:12px;color:#4a5568;line-height:1.7;margin-bottom:10px;">${escPdf(f.description)}</p>
        ${f.references ? `<p style="font-size:11px;color:#718096;margin-bottom:10px;"><strong>Reference:</strong> ${escPdf(f.references)}</p>` : ''}
        <div style="background:#f0fff8;border:1px solid #9ae6b4;border-radius:6px;padding:10px 12px;">
          <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:0.08em;color:#276749;margin-bottom:4px;font-family:monospace;">✦ RECOMMENDED FIX</div>
          <div style="font-size:12px;color:#1a202c;line-height:1.65;">${escPdf(f.recommendation)}</div>
        </div>
      </div>
    </div>
  `).join('');

  const html = `<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8"/>
<title>Security Report — ${site.hostname}</title>
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Syne:wght@700;800&family=IBM+Plex+Mono:wght@400;600&display=swap" rel="stylesheet"/>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'DM Sans', sans-serif; background: #fff; color: #1a202c; }
  @page { margin: 20mm 15mm; }
  @media print {
    .no-print { display: none !important; }
    body { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  }
</style>
</head>
<body>

<!-- PRINT BUTTON -->
<div class="no-print" style="position:fixed;top:16px;right:16px;z-index:999;display:flex;gap:10px;">
  <button onclick="window.print()" style="background:#1B6FFF;color:#fff;border:none;padding:10px 20px;border-radius:8px;font-size:14px;font-weight:700;cursor:pointer;font-family:'DM Sans',sans-serif;">🖨 Print / Save PDF</button>
  <button onclick="window.close()" style="background:#eee;color:#333;border:none;padding:10px 20px;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;font-family:'DM Sans',sans-serif;">✕ Close</button>
</div>

<!-- HEADER -->
<div style="background:linear-gradient(135deg,#080C18 0%,#0D1933 100%);color:white;padding:40px 48px 36px;margin-bottom:0;">
  <div style="display:flex;align-items:center;gap:12px;margin-bottom:28px;">
    <div style="width:32px;height:32px;background:linear-gradient(135deg,#1B6FFF,#00D4FF);border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:16px;">🛡</div>
    <span style="font-family:'Syne',sans-serif;font-size:20px;font-weight:800;letter-spacing:-0.02em;">SentinelScan</span>
    <span style="margin-left:auto;font-size:11px;color:#5C7099;font-family:'IBM Plex Mono',monospace;">SECURITY REPORT</span>
  </div>

  <div style="display:grid;grid-template-columns:1fr auto;gap:20px;align-items:start;">
    <div>
      <h1 style="font-family:'Syne',sans-serif;font-size:28px;font-weight:800;letter-spacing:-0.02em;margin-bottom:8px;">${site.hostname}</h1>
      <div style="font-family:'IBM Plex Mono',monospace;font-size:12px;color:#00D4FF;margin-bottom:6px;">${site.url}</div>
      <div style="font-size:12px;color:#5C7099;">Scanned: ${site.lastScan ? new Date(site.lastScan).toLocaleString() : 'Unknown'}</div>
    </div>
    <div style="text-align:center;background:rgba(255,255,255,0.06);border:1px solid rgba(255,255,255,0.1);border-radius:14px;padding:20px 28px;">
      <div style="font-family:'Syne',sans-serif;font-size:48px;font-weight:800;color:${scoreColor};line-height:1;">${score}</div>
      <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:0.1em;color:${scoreColor};margin-top:4px;">${scoreLabel}</div>
      <div style="font-size:10px;color:#5C7099;margin-top:2px;">Security Score</div>
    </div>
  </div>
</div>

<!-- SUMMARY STATS -->
<div style="background:#f7f9fc;border-bottom:1px solid #e2e8f0;padding:20px 48px;display:grid;grid-template-columns:repeat(5,1fr);gap:16px;">
  <div style="text-align:center;">
    <div style="font-family:'Syne',sans-serif;font-size:26px;font-weight:800;color:#FF3D5A;">${counts.critical}</div>
    <div style="font-size:11px;color:#718096;margin-top:2px;">Critical</div>
  </div>
  <div style="text-align:center;">
    <div style="font-family:'Syne',sans-serif;font-size:26px;font-weight:800;color:#FFB300;">${counts.high}</div>
    <div style="font-size:11px;color:#718096;margin-top:2px;">High</div>
  </div>
  <div style="text-align:center;">
    <div style="font-family:'Syne',sans-serif;font-size:26px;font-weight:800;color:#FF8C00;">${counts.medium}</div>
    <div style="font-size:11px;color:#718096;margin-top:2px;">Medium</div>
  </div>
  <div style="text-align:center;">
    <div style="font-family:'Syne',sans-serif;font-size:26px;font-weight:800;color:#00D4FF;">${counts.low}</div>
    <div style="font-size:11px;color:#718096;margin-top:2px;">Low</div>
  </div>
  <div style="text-align:center;">
    <div style="font-family:'Syne',sans-serif;font-size:26px;font-weight:800;color:#5C7099;">${counts.info}</div>
    <div style="font-size:11px;color:#718096;margin-top:2px;">Info</div>
  </div>
</div>

<!-- FINDINGS -->
<div style="padding:32px 48px;">
  <h2 style="font-family:'Syne',sans-serif;font-size:16px;font-weight:800;letter-spacing:-0.01em;margin-bottom:20px;color:#1a202c;text-transform:uppercase;letter-spacing:0.06em;">
    Security Findings
    <span style="font-size:12px;font-weight:500;color:#718096;text-transform:none;letter-spacing:0;margin-left:8px;">(${findings.length} total)</span>
  </h2>
  ${findingRows || '<p style="color:#718096;font-size:13px;">No findings recorded.</p>'}
</div>

<!-- FOOTER -->
<div style="border-top:1px solid #e2e8f0;padding:16px 48px;display:flex;justify-content:space-between;align-items:center;font-size:11px;color:#a0aec0;">
  <span>Generated by SentinelScan • Powered by Groq AI</span>
  <span>${new Date().toLocaleDateString()}</span>
</div>

<script>
  // Auto-open print dialog
  window.onload = () => setTimeout(() => {}, 500);
</script>
</body>
</html>`;

  // Open in new tab and trigger print
  const win = window.open('', '_blank');
  win.document.write(html);
  win.document.close();
  win.onload = () => {
    setTimeout(() => win.print(), 800);
  };

  showToast(`PDF report ready for ${site.hostname}`, 'success');
}

function escPdf(s) {
  if (!s) return '';
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
