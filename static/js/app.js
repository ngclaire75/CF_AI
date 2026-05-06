/* CF_AI Security Platform — Dashboard JS */

// ── State ─────────────────────────────────────────────────────────────────
const S = {
  sites: [],
  findings: [],
  scans: {},
  logs: [],
  selectedPlatform: 'auto',
};

// ── WST Coverage Data ────────────────────────────────────────────────────
const WST = [
  { cat: 'WSTG-INFO', label: 'Information Gathering', items: [
    { id: 'WSTG-INFO-01', name: 'Search Engine Discovery & Recon', covered: false },
    { id: 'WSTG-INFO-02', name: 'Fingerprint Web Server', covered: true },
    { id: 'WSTG-INFO-03', name: 'Review Webserver Metafiles', covered: false },
    { id: 'WSTG-INFO-04', name: 'Enumerate Applications on Webserver', covered: false },
    { id: 'WSTG-INFO-05', name: 'Review Webpage Content for Info Leakage', covered: false },
    { id: 'WSTG-INFO-06', name: 'Identify Application Entry Points', covered: true },
    { id: 'WSTG-INFO-07', name: 'Map Execution Paths', covered: true },
    { id: 'WSTG-INFO-08', name: 'Fingerprint Web Application Framework', covered: true },
    { id: 'WSTG-INFO-09', name: 'Fingerprint Web Application', covered: true },
    { id: 'WSTG-INFO-10', name: 'Map Application Architecture', covered: true },
  ]},
  { cat: 'WSTG-CONF', label: 'Configuration & Deploy Management', items: [
    { id: 'WSTG-CONF-01', name: 'Test Network Infrastructure Configuration', covered: true },
    { id: 'WSTG-CONF-02', name: 'Test Application Platform Configuration', covered: false },
    { id: 'WSTG-CONF-03', name: 'Test File Extension Handling', covered: false },
    { id: 'WSTG-CONF-04', name: 'Review Backup & Unreferenced Files', covered: false },
    { id: 'WSTG-CONF-05', name: 'Enumerate Admin Interfaces', covered: false },
    { id: 'WSTG-CONF-06', name: 'Test HTTP Methods', covered: false },
    { id: 'WSTG-CONF-07', name: 'Test HTTP Strict Transport Security', covered: false },
    { id: 'WSTG-CONF-10', name: 'Test for Subdomain Takeover', covered: true },
    { id: 'WSTG-CONF-12', name: 'Testing for Content Security Policy', covered: false },
  ]},
  { cat: 'WSTG-IDNT', label: 'Identity Management', items: [
    { id: 'WSTG-IDNT-01', name: 'Test Role Definitions', covered: true },
    { id: 'WSTG-IDNT-02', name: 'Test User Registration Process', covered: true },
    { id: 'WSTG-IDNT-03', name: 'Test Account Provisioning', covered: true },
    { id: 'WSTG-IDNT-04', name: 'Account Enumeration & Guessable Users', covered: true },
    { id: 'WSTG-IDNT-05', name: 'Weak or Unenforced Username Policy', covered: true },
  ]},
  { cat: 'WSTG-ATHN', label: 'Authentication Testing', items: [
    { id: 'WSTG-ATHN-01', name: 'Credentials over Encrypted Channel', covered: true },
    { id: 'WSTG-ATHN-02', name: 'Default Credentials', covered: true },
    { id: 'WSTG-ATHN-03', name: 'Weak Lock Out Mechanism', covered: true },
    { id: 'WSTG-ATHN-04', name: 'Bypassing Authentication Schema', covered: true },
    { id: 'WSTG-ATHN-05', name: 'Vulnerable Remember Password', covered: false },
    { id: 'WSTG-ATHN-07', name: 'Weak Password Policy', covered: true },
    { id: 'WSTG-ATHN-08', name: 'Weak Security Question Answer', covered: true },
    { id: 'WSTG-ATHN-09', name: 'Weak Password Change/Reset', covered: true },
    { id: 'WSTG-ATHN-10', name: 'Weaker Authentication in Alt Channel', covered: true },
    { id: 'WSTG-ATHN-11', name: 'Multi-Factor Authentication (MFA)', covered: true },
  ]},
  { cat: 'WSTG-ATHZ', label: 'Authorization Testing', items: [
    { id: 'WSTG-ATHZ-01', name: 'Directory Traversal / File Include', covered: true },
    { id: 'WSTG-ATHZ-02', name: 'Bypassing Authorization Schema', covered: true },
    { id: 'WSTG-ATHZ-03', name: 'Privilege Escalation', covered: true },
    { id: 'WSTG-ATHZ-04', name: 'Insecure Direct Object References (IDOR)', covered: true },
    { id: 'WSTG-ATHZ-05', name: 'OAuth Weaknesses', covered: true },
  ]},
  { cat: 'WSTG-SESS', label: 'Session Management', items: [
    { id: 'WSTG-SESS-01', name: 'Session Management Schema', covered: true },
    { id: 'WSTG-SESS-02', name: 'Cookies Attributes', covered: true },
    { id: 'WSTG-SESS-03', name: 'Session Fixation', covered: true },
    { id: 'WSTG-SESS-05', name: 'Cross Site Request Forgery (CSRF)', covered: true },
    { id: 'WSTG-SESS-06', name: 'Logout Functionality', covered: true },
    { id: 'WSTG-SESS-07', name: 'Session Timeout', covered: true },
    { id: 'WSTG-SESS-10', name: 'JSON Web Tokens (JWT)', covered: true },
  ]},
  { cat: 'WSTG-INPV', label: 'Input Validation', items: [
    { id: 'WSTG-INPV-01', name: 'Reflected Cross Site Scripting', covered: true },
    { id: 'WSTG-INPV-02', name: 'Stored Cross Site Scripting', covered: true },
    { id: 'WSTG-INPV-05', name: 'SQL Injection', covered: true },
    { id: 'WSTG-INPV-11', name: 'Code Injection', covered: true },
    { id: 'WSTG-INPV-12', name: 'Command Injection', covered: true },
    { id: 'WSTG-INPV-18', name: 'Server-Side Template Injection (SSTI)', covered: true },
    { id: 'WSTG-INPV-19', name: 'Server-Side Request Forgery (SSRF)', covered: true },
  ]},
  { cat: 'WSTG-CRYP', label: 'Cryptography', items: [
    { id: 'WSTG-CRYP-01', name: 'Weak Transport Layer Security', covered: true },
    { id: 'WSTG-CRYP-03', name: 'Sensitive Info over Unencrypted Channels', covered: true },
  ]},
  { cat: 'WSTG-CLIENT', label: 'Client-Side Testing', items: [
    { id: 'WSTG-CLNT-01', name: 'DOM Based XSS', covered: true },
    { id: 'WSTG-CLNT-02', name: 'JavaScript Execution', covered: true },
    { id: 'WSTG-CLNT-03', name: 'HTML Injection', covered: true },
    { id: 'WSTG-CLNT-04', name: 'Client-Side URL Redirect', covered: true },
    { id: 'WSTG-CLNT-12', name: 'Browser Storage', covered: true },
    { id: 'WSTG-CLNT-13', name: 'Cross Site Script Inclusion', covered: true },
  ]},
  { cat: 'WSTG-APIT', label: 'API Testing', items: [
    { id: 'WSTG-APIT-01', name: 'API Reconnaissance', covered: true },
    { id: 'WSTG-APIT-02', name: 'API Broken Object Level Authorization', covered: true },
    { id: 'WSTG-APIT-99', name: 'GraphQL Security Testing', covered: true },
  ]},
];

// ── Init ──────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initTabs();
  renderWST();
  loadSites();
  startLogStream();
  setInterval(pollScans, 5000);
  setInterval(loadStats, 10000);
});

// ── Tab Switching ─────────────────────────────────────────────────────────
function initTabs() {
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => switchTab(btn.dataset.tab));
  });
}

function switchTab(name) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.toggle('active', b.dataset.tab === name));
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.toggle('active', p.id === `tab-${name}`));
}

// ── API helpers ───────────────────────────────────────────────────────────
async function api(path, opts = {}) {
  try {
    const r = await fetch(path, {
      headers: { 'Content-Type': 'application/json' },
      ...opts,
    });
    return await r.json();
  } catch (e) {
    addLog(`[ERROR] API call failed: ${e.message}`, 'error');
    return null;
  }
}

// ── Sites ─────────────────────────────────────────────────────────────────
async function loadSites() {
  const data = await api('/api/sites');
  if (!data) return;
  S.sites = data.sites || [];
  renderSidebar();
  renderSiteGrid();
  loadFindings();
  loadStats();
  loadAutoFix();
}

function renderSidebar() {
  const el = document.getElementById('sidebar-sites');
  if (!S.sites.length) {
    el.innerHTML = `<div class="empty-state" style="padding:30px 10px">
      <div class="empty-state-icon">🌐</div>
      <div class="empty-state-title">No sites yet</div>
      <div class="empty-state-sub">Click "+ Add Site" below</div>
    </div>`;
    return;
  }
  el.innerHTML = S.sites.map(s => `
    <div class="site-item" onclick="focusSite('${s.id}')">
      <div class="site-favicon">${platformIcon(s.platform)}</div>
      <div class="site-info">
        <div class="site-name">${s.name || domain(s.url)}</div>
        <div class="site-meta">${domain(s.url)}</div>
      </div>
      ${severityBadge(s.worst_severity)}
    </div>
  `).join('');
}

function renderSiteGrid() {
  const el = document.getElementById('sites-grid');
  if (!S.sites.length) {
    el.innerHTML = `<div class="card" style="padding:40px;text-align:center;color:var(--text-3);grid-column:1/-1">
      <div style="font-size:32px;margin-bottom:10px">🌐</div>
      <div style="font-size:13px;font-weight:600;color:var(--text-2)">No sites connected</div>
      <div style="font-size:12px;margin-top:4px">Click "Add Site" to connect your first website</div>
    </div>`;
    return;
  }
  el.innerHTML = S.sites.map(s => `
    <div class="site-card">
      <div class="site-card-header">
        <div class="site-card-favicon">${platformIcon(s.platform)}</div>
        <div class="site-card-info">
          <div class="site-card-name">${s.name || domain(s.url)}</div>
          <div class="site-card-url">${s.url}</div>
          <div class="site-card-platform">${(s.platform || 'unknown').toUpperCase()}</div>
        </div>
        <button class="btn-icon" onclick="removeSite('${s.id}')" title="Remove site">✕</button>
      </div>
      <div class="site-card-stats">
        <div class="site-stat"><div class="site-stat-val critical">${s.findings_critical || 0}</div><div class="site-stat-key">Critical</div></div>
        <div class="site-stat"><div class="site-stat-val high">${s.findings_high || 0}</div><div class="site-stat-key">High</div></div>
        <div class="site-stat"><div class="site-stat-val medium">${s.findings_medium || 0}</div><div class="site-stat-key">Medium</div></div>
        <div class="site-stat"><div class="site-stat-val low">${s.findings_low || 0}</div><div class="site-stat-key">Low</div></div>
      </div>
      <div style="font-size:11px;color:var(--text-3)">
        Last scan: ${s.last_scan ? timeAgo(s.last_scan) : 'Never'}
      </div>
      <div class="site-card-actions">
        <button class="btn btn-ghost btn-sm" onclick="scanSite('${s.id}','${s.url}')">⚡ Scan</button>
        <button class="btn btn-success btn-sm" onclick="autoFixSite('${s.id}')">🛡 Auto-Fix</button>
        <button class="btn btn-ghost btn-sm" onclick="exportSiteReport('${s.id}')">📄 Report</button>
      </div>
    </div>
  `).join('');
}

function selectPlatform(btn) {
  document.querySelectorAll('.platform-btn').forEach(b => b.classList.remove('selected'));
  btn.classList.add('selected');
  S.selectedPlatform = btn.dataset.platform;
}

function openAddSite() {
  document.getElementById('new-site-url').value = '';
  document.getElementById('new-site-name').value = '';
  S.selectedPlatform = 'auto';
  document.querySelectorAll('.platform-btn').forEach(b => b.classList.remove('selected'));
  document.querySelector('[data-platform="auto"]').classList.add('selected');
  openModal('add-site-modal');
}

async function addSite() {
  const url = document.getElementById('new-site-url').value.trim();
  if (!url) { alert('Please enter a URL'); return; }
  const name = document.getElementById('new-site-name').value.trim();
  const freq = document.getElementById('new-site-freq').value;
  addLog(`[+] Adding site: ${url}`, 'info');
  const data = await api('/api/sites', {
    method: 'POST',
    body: JSON.stringify({ url, name, platform: S.selectedPlatform, scan_freq: freq }),
  });
  if (data && data.site) {
    closeModal('add-site-modal');
    addLog(`[+] Site added: ${url} (${data.site.platform})`, 'success');
    await loadSites();
    if (confirm(`Site added! Run initial security scan now?`)) {
      scanSite(data.site.id, url);
    }
  } else {
    addLog(`[!] Failed to add site`, 'error');
  }
}

async function removeSite(id) {
  if (!confirm('Remove this site and all its findings?')) return;
  await api(`/api/sites/${id}`, { method: 'DELETE' });
  addLog(`[-] Site removed`, 'warning');
  await loadSites();
}

async function scanSite(id, url) {
  addLog(`[⚡] Starting scan: ${url}`, 'info');
  S.scans[id] = { url, phase: 'Initializing...', progress: 0 };
  updateActiveScans();
  const data = await api(`/api/sites/${id}/scan`, { method: 'POST' });
  if (data) {
    addLog(`[+] Scan started for ${url}`, 'success');
    pollScanStatus(id);
  }
}

async function pollScanStatus(id) {
  const data = await api(`/api/sites/${id}/scan/status`);
  if (!data) return;
  S.scans[id] = { ...S.scans[id], ...data };
  updateActiveScans();
  if (data.status === 'running') {
    setTimeout(() => pollScanStatus(id), 3000);
  } else {
    addLog(`[✓] Scan complete for ${S.scans[id]?.url}`, 'success');
    delete S.scans[id];
    updateActiveScans();
    await loadSites();
    await loadFindings();
  }
}

async function pollScans() {
  Object.keys(S.scans).forEach(id => pollScanStatus(id));
}

function updateActiveScans() {
  const list = document.getElementById('active-scans-list');
  const count = document.getElementById('scan-count');
  const active = Object.entries(S.scans);
  document.getElementById('stat-scans').textContent = active.length;
  if (!active.length) {
    list.innerHTML = '<div class="text-muted" style="text-align:center;padding:16px 0">No scans running</div>';
    count.textContent = 'None running';
    return;
  }
  count.textContent = `${active.length} running`;
  list.innerHTML = active.map(([id, sc]) => `
    <div class="scan-item">
      <div class="spinner"></div>
      <div class="scan-info">
        <div class="scan-target">${sc.url || id}</div>
        <div class="scan-phase">${sc.phase || 'Scanning...'}</div>
      </div>
      <div class="scan-progress-wrap">
        <div style="font-size:10px;color:var(--text-3);text-align:right">${sc.progress || 0}%</div>
        <div class="scan-progress"><div class="scan-progress-fill" style="width:${sc.progress||0}%"></div></div>
      </div>
    </div>
  `).join('');
}

async function openScanAll() {
  if (!S.sites.length) { alert('Add a site first'); return; }
  if (!confirm(`Scan all ${S.sites.length} site(s)?`)) return;
  for (const s of S.sites) scanSite(s.id, s.url);
}

// ── Findings ──────────────────────────────────────────────────────────────
async function loadFindings() {
  const data = await api('/api/findings');
  if (!data) return;
  S.findings = data.findings || [];
  renderFindings();
  renderRecentFindings();
  loadStats();
  loadAutoFix();
}

function renderFindings() {
  const siteFilter = document.getElementById('findings-filter-site').value;
  const sevFilter  = document.getElementById('findings-filter-sev').value;
  let list = S.findings;
  if (siteFilter) list = list.filter(f => f.site_id === siteFilter);
  if (sevFilter)  list = list.filter(f => f.severity === sevFilter);

  // update filter dropdown
  const sel = document.getElementById('findings-filter-site');
  const cur = sel.value;
  sel.innerHTML = '<option value="">All Sites</option>' +
    S.sites.map(s => `<option value="${s.id}" ${s.id===cur?'selected':''}>${s.name || domain(s.url)}</option>`).join('');
  sel.value = cur;

  const tbody = document.getElementById('findings-body');
  if (!list.length) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text-3);padding:32px">No findings</td></tr>';
    return;
  }
  tbody.innerHTML = list.sort((a,b) => sevOrder(b.severity) - sevOrder(a.severity)).map(f => `
    <tr onclick="openFinding('${f.id}')" style="cursor:pointer">
      <td class="text-main">${f.site_name || domain(f.site_url || '')}</td>
      <td><span class="sev sev-${f.severity}">${f.severity}</span></td>
      <td class="monospace" style="font-size:10px;color:var(--text-3)">${f.wst_id || '—'}</td>
      <td class="text-main">${f.title}</td>
      <td style="color:var(--text-3)">${timeAgo(f.discovered)}</td>
      <td>
        ${f.autofix_available
          ? `<button class="btn btn-success btn-sm" onclick="event.stopPropagation();applyFix('${f.id}')">🛡 Fix</button>`
          : `<button class="btn btn-ghost btn-sm" onclick="event.stopPropagation();openFinding('${f.id}')">PoC</button>`}
      </td>
    </tr>
  `).join('');
}

function renderRecentFindings() {
  const tbody = document.getElementById('recent-findings-body');
  const recent = [...S.findings]
    .sort((a,b) => new Date(b.discovered) - new Date(a.discovered))
    .slice(0, 8);
  if (!recent.length) {
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-3);padding:24px">No findings yet — run a scan</td></tr>';
    return;
  }
  tbody.innerHTML = recent.map(f => `
    <tr onclick="openFinding('${f.id}')" style="cursor:pointer">
      <td class="text-main">${f.site_name || domain(f.site_url || '')}</td>
      <td><span class="sev sev-${f.severity}">${f.severity}</span></td>
      <td style="color:var(--text-3);font-size:11px">${f.wst_id || f.category || '—'}</td>
      <td class="text-main">${f.title}</td>
      <td>
        ${f.autofix_available
          ? `<button class="btn btn-success btn-sm" onclick="event.stopPropagation();applyFix('${f.id}')">🛡 Fix</button>`
          : `<button class="btn btn-ghost btn-sm" onclick="event.stopPropagation();openFinding('${f.id}')">View</button>`}
      </td>
    </tr>
  `).join('');
}

function openFinding(id) {
  const f = S.findings.find(x => x.id === id);
  if (!f) return;
  document.getElementById('drawer-title').textContent = f.title;
  document.getElementById('drawer-content').innerHTML = `
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px">
      <span class="sev sev-${f.severity}">${f.severity}</span>
      ${f.wst_id ? `<span class="sev" style="background:var(--accent-dim);color:var(--accent)">${f.wst_id}</span>` : ''}
      ${f.category ? `<span class="sev sev-info">${f.category}</span>` : ''}
    </div>
    <div style="font-size:12px;color:var(--text-2);line-height:1.7;margin-bottom:16px">${f.description || 'No description'}</div>
    ${f.poc ? `
      <div style="font-size:11px;font-weight:600;color:var(--text-2);margin-bottom:6px">Proof of Concept</div>
      <div class="poc-block">${escHtml(f.poc)}</div>
    ` : ''}
    ${f.recommendation ? `
      <div style="font-size:11px;font-weight:600;color:var(--text-2);margin:14px 0 6px">Recommendation</div>
      <div style="font-size:12px;color:var(--text-2);line-height:1.6">${f.recommendation}</div>
    ` : ''}
    ${f.autofix_available ? `
      <button class="btn btn-success" style="margin-top:16px;width:100%;justify-content:center" onclick="applyFix('${f.id}')">
        🛡 Apply Auto-Fix
      </button>
    ` : ''}
  `;
  document.getElementById('drawer-backdrop').classList.add('open');
  document.getElementById('finding-drawer').classList.add('open');
}

function closeDrawer() {
  document.getElementById('drawer-backdrop').classList.remove('open');
  document.getElementById('finding-drawer').classList.remove('open');
}

// ── Auto-Fix ──────────────────────────────────────────────────────────────
async function loadAutoFix() {
  const fixable = S.findings.filter(f => f.autofix_available);
  const el = document.getElementById('autofix-list');
  document.getElementById('stat-fixes').textContent = fixable.length;
  document.getElementById('ov-fixes').textContent = fixable.length;

  if (!fixable.length) {
    el.innerHTML = `<div class="empty-state">
      <div class="empty-state-icon">🛡️</div>
      <div class="empty-state-title">No fixes queued</div>
      <div class="empty-state-sub">Run a scan to find vulnerabilities with auto-fix support</div>
    </div>`;
    return;
  }

  el.innerHTML = fixable.map(f => `
    <div class="fix-item" id="fix-${f.id}">
      <div class="fix-icon ${f.severity}">
        ${f.severity === 'critical' ? '🔴' : f.severity === 'high' ? '🟠' : '🟡'}
      </div>
      <div class="fix-content">
        <div class="fix-title">${f.title}</div>
        <div class="fix-desc">${f.description || ''}</div>
        ${f.fix_command ? `<div class="fix-cmd">${escHtml(f.fix_command)}</div>` : ''}
      </div>
      <div class="fix-actions">
        <button class="btn btn-success btn-sm" onclick="applyFix('${f.id}')">Apply Fix</button>
        <button class="btn btn-ghost btn-sm" onclick="openFinding('${f.id}')">Details</button>
      </div>
    </div>
  `).join('');
}

async function applyFix(findingId) {
  if (!confirm('Apply this auto-fix? This will execute the remediation command on the target.')) return;
  addLog(`[⚡] Applying auto-fix for finding ${findingId}...`, 'info');
  const data = await api('/api/autofix', {
    method: 'POST',
    body: JSON.stringify({ finding_id: findingId }),
  });
  if (data && data.success) {
    addLog(`[✓] Auto-fix applied: ${data.message || 'Done'}`, 'success');
    document.getElementById(`fix-${findingId}`)?.remove();
    await loadFindings();
  } else {
    addLog(`[!] Fix failed: ${data?.error || 'Unknown error'}`, 'error');
  }
}

async function autoFixSite(siteId) {
  const fixable = S.findings.filter(f => f.site_id === siteId && f.autofix_available);
  if (!fixable.length) { alert('No auto-fixes available for this site'); return; }
  if (!confirm(`Apply ${fixable.length} auto-fix(es) for this site?`)) return;
  for (const f of fixable) await applyFix(f.id);
}

// ── Stats ─────────────────────────────────────────────────────────────────
function loadStats() {
  const critical = S.findings.filter(f => f.severity === 'critical').length;
  const high     = S.findings.filter(f => f.severity === 'high').length;
  document.getElementById('stat-sites').textContent = S.sites.length;
  document.getElementById('stat-critical').textContent = critical;
  document.getElementById('ov-sites').textContent = S.sites.length;
  document.getElementById('ov-critical').textContent = critical;
  document.getElementById('ov-high').textContent = high;
}

// ── AI Analysis ───────────────────────────────────────────────────────────
async function aiAnalyze() {
  const el = document.getElementById('ai-response');
  el.textContent = 'Analyzing...';
  const data = await api('/api/ai/analyze', {
    method: 'POST',
    body: JSON.stringify({
      sites: S.sites.length,
      findings: S.findings.length,
      critical: S.findings.filter(f => f.severity === 'critical').length,
      high: S.findings.filter(f => f.severity === 'high').length,
      top_findings: S.findings.slice(0, 5).map(f => ({ title: f.title, severity: f.severity, site: f.site_name })),
    }),
  });
  if (data && data.analysis) {
    el.textContent = data.analysis;
  } else {
    el.textContent = 'AI analysis unavailable. Check ANTHROPIC_API_KEY in .env';
  }
}

// ── WST Checklist ─────────────────────────────────────────────────────────
function renderWST() {
  const all    = WST.flatMap(c => c.items);
  const covered = all.filter(i => i.covered).length;
  document.getElementById('wst-covered-count').textContent = covered;
  document.getElementById('wst-total-count').textContent = all.length;
  document.getElementById('wst-progress-fill').style.width = `${Math.round(covered/all.length*100)}%`;

  const el = document.getElementById('wst-list');
  el.innerHTML = WST.map(cat => {
    const catCovered = cat.items.filter(i => i.covered).length;
    return `
      <div class="wst-category">
        <div class="wst-category-header" onclick="this.parentElement.classList.toggle('collapsed')">
          <div class="wst-category-title">${cat.cat} — ${cat.label}</div>
          <div class="wst-category-count">${catCovered}/${cat.items.length} covered</div>
        </div>
        ${cat.items.map(item => `
          <div class="wst-row">
            <div class="wst-id">${item.id}</div>
            <div class="wst-name">${item.name}</div>
            <div class="wst-status">
              ${item.covered
                ? '<span class="wst-check">✅</span>'
                : '<span class="wst-dash">—</span>'}
            </div>
          </div>
        `).join('')}
      </div>
    `;
  }).join('');
}

// ── Logs ──────────────────────────────────────────────────────────────────
function addLog(msg, level = 'info') {
  const ts = new Date().toLocaleTimeString();
  const entry = { ts, msg, level };
  S.logs.push(entry);
  if (S.logs.length > 500) S.logs.shift();
  appendLog(entry);
}

function appendLog({ ts, msg, level }) {
  const el = document.getElementById('log-output');
  const filter = document.getElementById('log-level-filter').value;
  if (filter && level !== filter) return;
  const line = document.createElement('span');
  line.className = `log-line ${level}`;
  line.textContent = `${ts}  ${msg}`;
  el.appendChild(line);
  el.appendChild(document.createTextNode('\n'));
  el.scrollTop = el.scrollHeight;
}

function filterLogs() {
  const el = document.getElementById('log-output');
  el.innerHTML = '';
  const filter = document.getElementById('log-level-filter').value;
  S.logs
    .filter(l => !filter || l.level === filter)
    .forEach(l => appendLog(l));
}

function clearLogs() {
  S.logs = [];
  document.getElementById('log-output').innerHTML = '';
}

function startLogStream() {
  const es = new EventSource('/api/logs/stream');
  es.onmessage = e => {
    try {
      const d = JSON.parse(e.data);
      addLog(d.msg, d.level || 'info');
    } catch (_) {}
  };
  es.onerror = () => {};
}

// ── Export ────────────────────────────────────────────────────────────────
function exportFindings() {
  const csv = ['Site,Severity,Category,Finding,Discovered']
    .concat(S.findings.map(f =>
      `"${f.site_name||''}","${f.severity}","${f.wst_id||f.category||''}","${f.title}","${f.discovered||''}"`)
    ).join('\n');
  download('cfai_findings.csv', csv, 'text/csv');
}

async function exportSiteReport(siteId) {
  addLog(`[*] Generating report...`, 'info');
  const data = await api(`/api/sites/${siteId}/report`, { method: 'POST' });
  if (data && data.report) {
    download(`cfai_report_${siteId}.txt`, data.report, 'text/plain');
    addLog(`[✓] Report downloaded`, 'success');
  }
}

function download(name, content, type) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([content], { type }));
  a.download = name;
  a.click();
}

// ── Modals ────────────────────────────────────────────────────────────────
function openModal(id) { document.getElementById(id).classList.add('open'); }
function closeModal(id) { document.getElementById(id).classList.remove('open'); }

document.addEventListener('keydown', e => {
  if (e.key === 'Escape') {
    document.querySelectorAll('.modal-backdrop.open').forEach(m => m.classList.remove('open'));
    closeDrawer();
  }
});

// ── Helpers ───────────────────────────────────────────────────────────────
function domain(url) {
  try { return new URL(url).hostname; } catch { return url; }
}

function platformIcon(p) {
  const icons = { wordpress: '🟦', shopify: '🟩', laravel: '🔴', nextjs: '⬛', django: '🟢', rails: '💎', auto: '🔍', other: '🌐' };
  return icons[p] || '🌐';
}

function severityBadge(s) {
  if (!s || s === 'none') return '<span class="site-badge badge-ok">✓ Clean</span>';
  return `<span class="site-badge badge-${s}">${s.toUpperCase()}</span>`;
}

function sevOrder(s) {
  return { critical: 4, high: 3, medium: 2, low: 1, info: 0 }[s] || 0;
}

function timeAgo(iso) {
  if (!iso) return 'Never';
  const d = new Date(iso);
  const diff = (Date.now() - d) / 1000;
  if (diff < 60) return 'just now';
  if (diff < 3600) return `${Math.floor(diff/60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff/3600)}h ago`;
  return `${Math.floor(diff/86400)}d ago`;
}

function escHtml(s) {
  return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function focusSite(id) {
  switchTab('sites');
}

function refreshAll() {
  addLog('[*] Refreshing...', 'info');
  loadSites();
}
