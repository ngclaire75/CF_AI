/* CF_AI Dashboard — Enhanced Frontend */

let isSending = false;
let reportText = '';
let sidebarOpen = true;

document.addEventListener('DOMContentLoaded', () => {
  const input = document.getElementById('user-input');
  const sendBtn = document.getElementById('send-btn');

  input.addEventListener('keydown', e => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  });

  sendBtn.addEventListener('click', sendMessage);

  // Set today's date in WP report form
  const dateField = document.getElementById('report-date');
  if (dateField) dateField.value = new Date().toISOString().split('T')[0];

  loadSystemStatus();
  setInterval(loadSystemStatus, 30000);
});

// ── Tab Switching ────────────────────────────────────────────────────────

function showTab(name) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

  const tab = document.getElementById(`tab-${name}`);
  const content = document.getElementById(`content-${name}`);
  if (tab) tab.classList.add('active');
  if (content) content.classList.add('active');

  // Remove active from all tool items then highlight wp if that tab
  document.querySelectorAll('.tool-item').forEach(i => i.classList.remove('active'));
  if (name === 'wordpress') {
    document.querySelectorAll('.tool-item').forEach(i => {
      if (i.textContent.includes('WordPress')) i.classList.add('active');
    });
  }
}

function toggleSidebar() {
  const sidebar = document.getElementById('sidebar');
  if (window.innerWidth <= 768) {
    sidebar.classList.toggle('open');
  } else {
    sidebar.classList.toggle('hidden');
  }
}

// ── Chat ─────────────────────────────────────────────────────────────────

function sendMessage() {
  if (isSending) return;

  const input = document.getElementById('user-input');
  const message = input.value.trim();
  if (!message) return;

  input.value = '';
  isSending = true;

  const sendBtn = document.getElementById('send-btn');
  sendBtn.disabled = true;

  appendMessage('user', message);
  const typingId = showTyping();

  fetch('/api/chat', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message })
  })
    .then(r => r.json())
    .then(data => {
      removeTyping(typingId);
      if (data.blocked) {
        appendMessage('bot', data.response || 'Request blocked by injection protection.', { blocked: true });
      } else if (data.success) {
        appendMessage('bot', data.response, {
          suggestedTools: data.suggested_tools || [],
          executed: !!data.executed,
        });
      } else {
        appendMessage('bot', 'Error: ' + (data.error || 'Unknown error'));
      }
    })
    .catch(err => {
      removeTyping(typingId);
      appendMessage('bot', 'Network error: ' + err.message);
    })
    .finally(() => {
      isSending = false;
      sendBtn.disabled = false;
      document.getElementById('user-input').focus();
    });
}

function appendMessage(role, text, opts = {}) {
  const container = document.getElementById('chat-messages');
  const isUser = role === 'user';

  const msg = document.createElement('div');
  msg.className = `message ${isUser ? 'user' : 'bot'}${opts.blocked ? ' blocked' : ''}`;

  const avatar = document.createElement('div');
  avatar.className = 'msg-avatar';
  avatar.textContent = isUser ? 'YOU' : 'AI';

  const body = document.createElement('div');
  body.className = 'msg-body';

  const textDiv = document.createElement('div');
  textDiv.className = 'msg-text';

  if (!isUser && opts.executed) {
    textDiv.innerHTML = formatExecutedOutput(text);
  } else {
    textDiv.innerHTML = formatText(text);
  }

  const meta = document.createElement('div');
  meta.className = 'msg-meta';
  meta.textContent = isUser ? 'You · ' + timeNow() : 'CF_AI · ' + timeNow();

  body.appendChild(textDiv);

  if (!isUser && opts.suggestedTools && opts.suggestedTools.length > 0) {
    const chips = document.createElement('div');
    chips.className = 'suggested-tools';
    opts.suggestedTools.forEach(tool => {
      const chip = document.createElement('span');
      chip.className = 'tool-chip';
      chip.textContent = tool;
      chip.onclick = () => fillInput(tool);
      chips.appendChild(chip);
    });
    body.appendChild(chips);
  }

  body.appendChild(meta);
  msg.appendChild(avatar);
  msg.appendChild(body);
  container.appendChild(msg);
  container.scrollTop = container.scrollHeight;
}

function showTyping() {
  const container = document.getElementById('chat-messages');
  const id = 'typing-' + Date.now();

  const msg = document.createElement('div');
  msg.className = 'message bot typing-indicator';
  msg.id = id;

  const avatar = document.createElement('div');
  avatar.className = 'msg-avatar';
  avatar.textContent = 'AI';

  const body = document.createElement('div');
  body.className = 'msg-body';

  const textDiv = document.createElement('div');
  textDiv.className = 'msg-text';
  [1, 2, 3].forEach(() => {
    const dot = document.createElement('div');
    dot.className = 'typing-dot';
    textDiv.appendChild(dot);
  });

  body.appendChild(textDiv);
  msg.appendChild(avatar);
  msg.appendChild(body);
  container.appendChild(msg);
  container.scrollTop = container.scrollHeight;
  return id;
}

function removeTyping(id) {
  const el = document.getElementById(id);
  if (el) el.remove();
}

function formatText(text) {
  if (!text) return '';
  let s = text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
  s = s.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  s = s.replace(/`([^`\n]+)`/g, '<code>$1</code>');
  s = s.replace(/^[•\-]\s+(.+)$/gm, '<span style="display:block;padding-left:12px">• $1</span>');
  s = s.replace(/\n/g, '<br>');
  return s;
}

function formatExecutedOutput(text) {
  if (!text) return '';
  // Split on ``` blocks
  const parts = text.split(/```/);
  let html = '';
  parts.forEach((part, i) => {
    if (i % 2 === 0) {
      // normal text
      let s = part
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
      s = s.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
      s = s.replace(/`([^`\n]+)`/g, '<code>$1</code>');
      s = s.replace(/\n/g, '<br>');
      html += s;
    } else {
      // terminal output block
      const escaped = part
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .trim();
      html += `<pre>${escaped}</pre>`;
    }
  });
  return html;
}

function timeNow() {
  return new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function fillInput(text) {
  const input = document.getElementById('user-input');
  if (input) {
    input.value = text;
    input.focus();
  }
}

function askCategory(desc) {
  fillInput(desc);
  showTab('chat');
}

function clearChat() {
  if (!confirm('Clear conversation history?')) return;
  fetch('/api/chat/clear', { method: 'POST' });
  const container = document.getElementById('chat-messages');
  container.innerHTML = '';
  appendMessage('bot', 'Conversation cleared. How can I help you?');
}

// ── System Status ─────────────────────────────────────────────────────────

function loadSystemStatus() {
  fetch('/health')
    .then(r => r.json())
    .then(data => {
      const dot = document.getElementById('server-dot');
      const label = document.getElementById('server-status-label');
      if (dot) { dot.className = 'status-dot online'; }
      if (label) label.textContent = 'Online';

      setStatus('st-status', 'Healthy', 'good');
      setStatus('st-version', data.version || '6.0.0', '');
      setStatus('st-tools', `${data.total_tools_available}/${data.total_tools_count}`, '');
      setStatus('st-uptime', formatUptime(data.uptime || 0), '');
      setStatus(
        'st-essential',
        data.all_essential_tools_available ? 'All OK' : 'Some Missing',
        data.all_essential_tools_available ? 'good' : 'warn'
      );
    })
    .catch(() => {
      const dot = document.getElementById('server-dot');
      const label = document.getElementById('server-status-label');
      if (dot) dot.className = 'status-dot offline';
      if (label) label.textContent = 'Offline';
      setStatus('st-status', 'Unreachable', 'bad');
    });
}

function setStatus(id, text, cls) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = text;
  el.className = 'status-val' + (cls ? ` status-${cls}` : '');
}

function formatUptime(seconds) {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

// ── WordPress Report ───────────────────────────────────────────────────────

function generateWordpressReport() {
  const siteUrl  = document.getElementById('site-url').value.trim();
  const scope    = document.getElementById('report-scope').value.trim();
  const notes    = document.getElementById('report-notes').value.trim();
  const company  = document.getElementById('company-name').value.trim();
  const assessor = document.getElementById('assessor-name').value.trim();
  const certs    = document.getElementById('cert-type').value.trim();
  const date     = document.getElementById('report-date').value;
  const aiTools  = document.querySelector('input[name="ai-tools"]:checked')?.value || 'yes';

  if (!siteUrl) {
    alert('Please enter the target site URL.');
    return;
  }

  const btn = document.getElementById('generate-report-btn');
  btn.disabled = true;
  btn.textContent = 'Generating...';

  const fullNotes = [
    notes,
    company  ? `Assessor firm: ${company}` : '',
    assessor ? `Lead assessor: ${assessor}` : '',
    certs    ? `Certifications: ${certs}` : '',
    date     ? `Report date: ${date}` : '',
    `AI tools: ${aiTools === 'yes' ? 'Acceptable' : 'Manual only'}`,
  ].filter(Boolean).join('\n');

  fetch('/api/wordpress/report', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      site_url: siteUrl,
      scope: scope || 'WordPress security assessment',
      notes: fullNotes,
    })
  })
    .then(r => r.json())
    .then(data => {
      if (data.success) {
        reportText = data.report;
        const resultEl = document.getElementById('wp-result');
        const outputEl = document.getElementById('wp-report-output');
        outputEl.textContent = data.report;
        resultEl.style.display = 'block';
        resultEl.scrollIntoView({ behavior: 'smooth' });

        showTab('chat');
        showTab('wordpress');
      } else {
        alert('Error: ' + (data.error || 'Unknown error'));
      }
    })
    .catch(err => alert('Network error: ' + err.message))
    .finally(() => {
      btn.disabled = false;
      btn.innerHTML = '<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/></svg> Generate Formal Security Report';
    });
}

function copyReport() {
  if (!reportText) return;
  navigator.clipboard.writeText(reportText)
    .then(() => showToast('Report copied to clipboard'))
    .catch(() => {
      const ta = document.createElement('textarea');
      ta.value = reportText;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
      showToast('Report copied');
    });
}

function downloadReport() {
  if (!reportText) return;
  const siteUrl = document.getElementById('site-url').value || 'report';
  const filename = 'cfai-wp-report-' + siteUrl.replace(/[^a-z0-9]/gi, '_') + '.doc';

  // Convert plain-text report into a Word-compatible HTML document
  const lines = reportText.split('\n');
  let bodyHtml = '';

  lines.forEach(line => {
    const trimmed = line.trim();
    // Section dividers
    if (/^[━=]{10,}$/.test(trimmed)) return;
    // Numbered section headings (e.g. "1. EXECUTIVE SUMMARY")
    if (/^\d+\.\s+[A-Z &\/\-]+$/.test(trimmed)) {
      bodyHtml += `<h2>${escW(trimmed)}</h2>`;
    // All-caps headings (e.g. "EXECUTIVE SUMMARY")
    } else if (/^[A-Z][A-Z\s&\/\-:]{6,}$/.test(trimmed) && trimmed.length < 60) {
      bodyHtml += `<h2>${escW(trimmed)}</h2>`;
    // Report header key-value lines
    } else if (/^(Target|Scan Date|Duration|Scope|WordPress|Server|HTTPS|Overall Risk|Total Findings)\s*:/.test(trimmed)) {
      const [key, ...rest] = trimmed.split(':');
      bodyHtml += `<p class="meta"><strong>${escW(key.trim())}:</strong> ${escW(rest.join(':').trim())}</p>`;
    // Finding severity lines like "[HIGH] F-001 — Title"
    } else if (/^\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]/.test(trimmed)) {
      const sev = trimmed.match(/\[(.*?)\]/)[1];
      const cls = sev.toLowerCase();
      bodyHtml += `<p class="finding-title ${cls}">${escW(trimmed)}</p>`;
    // Indented detail lines
    } else if (/^(Description|Evidence|Remediation)\s*:/.test(trimmed)) {
      const [key, ...rest] = trimmed.split(':');
      bodyHtml += `<p class="detail"><strong>${escW(key.trim())}:</strong> ${escW(rest.join(':').trim())}</p>`;
    // Bullet / numbered list items
    } else if (/^[\d]+\.\s/.test(trimmed) || /^[•\-]\s/.test(trimmed)) {
      bodyHtml += `<p class="list-item">${escW(trimmed)}</p>`;
    // Empty lines → small gap
    } else if (trimmed === '') {
      bodyHtml += '<br>';
    } else {
      bodyHtml += `<p>${escW(trimmed)}</p>`;
    }
  });

  const docHtml = `
<html xmlns:o="urn:schemas-microsoft-com:office:office"
      xmlns:w="urn:schemas-microsoft-com:office:word"
      xmlns="http://www.w3.org/TR/REC-html40">
<head>
<meta charset="UTF-8">
<!--[if gte mso 9]>
<xml><w:WordDocument><w:View>Print</w:View><w:Zoom>100</w:Zoom></w:WordDocument></xml>
<![endif]-->
<style>
  @page { size: A4; margin: 2.5cm 2cm; }
  body { font-family: Calibri, Arial, sans-serif; font-size: 11pt; color: #1a3a1a; line-height: 1.5; }
  h1 { font-size: 18pt; color: #1b5e20; border-bottom: 2px solid #1b5e20; padding-bottom: 6pt; margin-bottom: 12pt; }
  h2 { font-size: 13pt; color: #1b5e20; margin-top: 18pt; margin-bottom: 6pt; border-bottom: 1px solid #b2d8b2; padding-bottom: 3pt; }
  p { margin: 3pt 0; }
  p.meta { font-size: 10pt; color: #333; margin: 2pt 0; }
  p.detail { margin: 2pt 0 2pt 16pt; font-size: 10pt; color: #444; }
  p.list-item { margin: 2pt 0 2pt 20pt; }
  p.finding-title { font-weight: bold; margin-top: 10pt; padding: 4pt 8pt; border-left: 4px solid #888; }
  p.finding-title.critical { border-color: #b71c1c; background: #fff5f5; color: #b71c1c; }
  p.finding-title.high     { border-color: #e65100; background: #fff8f5; color: #e65100; }
  p.finding-title.medium   { border-color: #f57f17; background: #fffde7; color: #f57f17; }
  p.finding-title.low      { border-color: #388e3c; background: #f1f8f1; color: #388e3c; }
  p.finding-title.info     { border-color: #0277bd; background: #f0f8ff; color: #0277bd; }
  .report-header-box { background: #f4f9f4; border: 1px solid #b2d8b2; border-radius: 4pt; padding: 10pt 14pt; margin-bottom: 16pt; }
</style>
</head>
<body>
<h1>CF_AI — WordPress Security Assessment Report</h1>
<div class="report-header-box">${bodyHtml.substring(0, bodyHtml.indexOf('<h2>'))}</div>
${bodyHtml.substring(bodyHtml.indexOf('<h2>'))}
</body>
</html>`;

  const blob = new Blob([docHtml], { type: 'application/msword' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
  showToast('Report downloaded as Word document');
}

function escW(str) {
  return (str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

// ── Toast Notifications ────────────────────────────────────────────────────

function showToast(msg) {
  const toast = document.createElement('div');
  toast.textContent = msg;
  Object.assign(toast.style, {
    position: 'fixed',
    bottom: '24px',
    right: '24px',
    background: '#1b5e20',
    border: '1px solid #2e7d32',
    color: '#ffffff',
    padding: '10px 16px',
    borderRadius: '8px',
    fontSize: '12px',
    fontFamily: 'Inter, system-ui, sans-serif',
    zIndex: '9999',
    boxShadow: '0 4px 16px rgba(27,94,32,0.2)',
    transition: 'opacity 0.3s',
  });
  document.body.appendChild(toast);
  setTimeout(() => { toast.style.opacity = '0'; }, 2000);
  setTimeout(() => toast.remove(), 2400);
}
