/* ── App Logic: IDS Dashboard ───────────────────────────────────────────── */
/* ── Snort3 Integration ──────────────────────────────────────────────────── */

// Colour map for Snort3 alert types
const SNORT_TYPE_COLORS = {
  "DDoS":       { bg: "rgba(255,71,87,0.15)", text: "#ff6584", border: "rgba(255,71,87,0.3)" },
  "DoS":        { bg: "rgba(255,165,0,0.15)", text: "#ffa500", border: "rgba(255,165,0,0.3)" },
  "PortScan":   { bg: "rgba(255,209,102,0.15)", text: "#ffd166", border: "rgba(255,209,102,0.3)" },
  "BruteForce": { bg: "rgba(255,99,132,0.15)", text: "#ff6384", border: "rgba(255,99,132,0.3)" },
  "Bot":        { bg: "rgba(153,102,255,0.15)", text: "#9966ff", border: "rgba(153,102,255,0.3)" },
  "WebAttack":  { bg: "rgba(255,159,64,0.15)", text: "#ff9f40", border: "rgba(255,159,64,0.3)" },
  "Unknown":    { bg: "rgba(255,255,255,0.06)", text: "#888", border: "rgba(255,255,255,0.1)" },
};

let currentSnortFilter = "ALL";
let snortAlertCount = 0;

async function refreshSnortStatus() {
  try {
    const res = await fetch('/api/snort/status');
    const data = await res.json();
    const dot = document.getElementById('snortDot');
    const statusText = document.getElementById('snortStatusText');

    if (data.running) {
      dot.className = 'dot on';
      statusText.textContent = `Snort3: Running | Alerts: ${data.alert_count}`;
    } else if (data.simulation) {
      dot.className = 'dot sim';
      statusText.textContent = `Snort3: Simulation | Alerts: ${data.alert_count}`;
    } else {
      dot.className = 'dot off';
      statusText.textContent = `Snort3: Not running | Alerts: ${data.alert_count}`;
    }
    return data;
  } catch (e) {
    console.warn('Snort3 status check failed:', e);
    return { running: false, simulation: false, alert_count: 0 };
  }
}

async function loadSnortAlerts() {
  try {
    const type = currentSnortFilter;
    const res = await fetch(`/api/snort/alerts?type=${type}&limit=100`);
    const alerts = await res.json();
    renderSnortAlerts(alerts);
    updateSnortStats(alerts);
  } catch (e) {
    console.error('Failed to load Snort alerts:', e);
  }
}

function renderSnortAlerts(alerts) {
  const container = document.getElementById('snortAlertList');
  if (!alerts || alerts.length === 0) {
    container.innerHTML = '<div style="text-align:center; padding: 30px; color: #666;">' +
      (currentSnortFilter === 'ALL' ? 'No Snort3 alerts received yet.' : `No ${currentSnortFilter} alerts.`) +
      '</div>';
    return;
  }
  snortAlertCount = alerts.length;
  container.innerHTML = alerts.map(a => {
    const colors = SNORT_TYPE_COLORS[a.type] || SNORT_TYPE_COLORS['Unknown'];
    const time = a.timestamp ? formatSnortTime(a.timestamp) : '--';
    const srcStr = a.src_ip ? `${a.src_ip}:${a.src_port || ''}` : '--';
    return `
      <div class="snort3-alert-row">
        <span class="alert-type-badge type-${a.type}" style="background:${colors.bg};color:${colors.text};border-color:${colors.border}">${a.type || 'UNK'}</span>
        <span class="snort-alert-msg">${a.msg || a.type + ' detected'}</span>
        <span class="snort-alert-ip">${srcStr}</span>
        <span class="snort-alert-src">${a.source === 'snort3_sim' ? 'SIM' : 'SNORT3'}</span>
        <span class="snort-alert-time">${time}</span>
      </div>`;
  }).join('');
}

function formatSnortTime(ts) {
  try {
    const d = new Date(ts);
    return d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  } catch (e) {
    return ts;
  }
}

function updateSnortStats(alerts) {
  const counts = { total: alerts.length };
  const types = ['DDoS', 'DoS', 'PortScan', 'BruteForce', 'Bot', 'WebAttack'];
  types.forEach(t => { counts[t] = 0; });
  alerts.forEach(a => { if (counts[a.type] !== undefined) counts[a.type]++; });

  document.getElementById('snortTotalAlerts').textContent = counts.total;
  types.forEach(t => {
    const el = document.getElementById('snort' + t);
    if (el) el.textContent = counts[t];
  });
}

function filterSnortAlerts(type, btn) {
  currentSnortFilter = type;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  loadSnortAlerts();
}

async function startSnortSimulation() {
  try {
    const res = await fetch('/api/snort/simulate', { method: 'POST' });
    const data = await res.json();
    if (data.success) {
      showNotice('Snort3 simulation started');
      refreshSnortStatus();
    } else {
      showAlert('Failed: ' + data.message);
    }
  } catch (e) {
    showAlert('Error: ' + e.message);
  }
}

async function stopSnortSimulation() {
  try {
    const res = await fetch('/api/snort/simulate/stop', { method: 'POST' });
    const data = await res.json();
    if (data.success) {
      showNotice('Snort3 simulation stopped');
      refreshSnortStatus();
    }
  } catch (e) {
    showAlert('Error: ' + e.message);
  }
}

// ── Remote Sensors ──────────────────────────────────────────────────────────
async function loadSensors() {
  try {
    const res = await fetch('/api/snort/sensors');
    const sensors = await res.json();
    const grid = document.getElementById('sensorGrid');
    if (!sensors || sensors.length === 0) {
      grid.innerHTML = '<div style="text-align:center; padding: 10px; color: #666;">No remote sensors connected</div>';
      return;
    }
    grid.innerHTML = sensors.map(s => {
      const alive = s.alive ? 'alive' : 'dead';
      const time = s.last_alert ? formatSnortTime(s.last_alert) : '--';
      const sourceType = s.source || s.type || 'unknown';
      const typeColor = sourceType === 'live_agent' ? '#00C9A7' : sourceType === 'snort3_remote' ? '#6C63FF' : '#FFD166';
      return `
        <div class="sensor-card">
          <div class="sensor-name">${s.name || s.sensor_id}</div>
          <div class="sensor-host">${s.hostname || 'unknown'} · ${s.sensor_id}</div>
          <div class="sensor-time">Last: ${time}</div>
          <div style="display:flex; gap:0.5rem; align-items:center; margin-top:0.2rem;">
            <span class="sensor-status ${alive}" style="font-size:0.6rem;">${alive.toUpperCase()}</span>
            <span style="font-size:0.6rem; color:${typeColor};">${sourceType}</span>
          </div>
        </div>`;
    }).join('');
  } catch (e) {
    console.warn('Sensor load failed:', e);
  }
}

function showNotice(msg) {
  const banner = document.getElementById('alertBanner');
  banner.innerHTML = 'ℹ️ ' + msg;
  banner.style.display = 'block';
  banner.style.background = 'rgba(46,213,115,0.12)';
  banner.style.borderColor = 'rgba(46,213,115,0.35)';
  banner.style.color = '#2ed573';
  setTimeout(() => { banner.style.display = 'none'; }, 5000);
}

// Override showAlert to handle multiple styles
const _origShowAlert = window.showAlert;
window.showAlert = function(msg) {
  const banner = document.getElementById('alertBanner');
  banner.innerHTML = msg;
  banner.style.display = 'block';
  banner.style.background = '';  // reset to CSS default
  banner.style.borderColor = '';
  banner.style.color = '';
};

const MODEL_COLORS = {
  "KNN"          : "#6C63FF",
  "Random Forest": "#00C9A7",
  "SVM (Linear)" : "#FF6584",
};

// Key features to show in predict form (subset of 78 for UX)
const KEY_FEATURES = [
  { key: "Destination Port",      label: "Destination Port",     default_normal: 80,       default_ddos: 80       },
  { key: "Flow Duration",         label: "Flow Duration (µs)",   default_normal: 500000,   default_ddos: 100      },
  { key: "Total Fwd Packets",     label: "Fwd Packets (Total)",  default_normal: 10,       default_ddos: 1000     },
  { key: "Total Backward Packets",label: "Bwd Packets (Total)",  default_normal: 8,        default_ddos: 1        },
  { key: "Flow Bytes/s",          label: "Flow Bytes/s",         default_normal: 50000,    default_ddos: 9000000  },
  { key: "Flow Packets/s",        label: "Flow Packets/s",       default_normal: 200,      default_ddos: 50000    },
  { key: "SYN Flag Count",        label: "SYN Flags",            default_normal: 1,        default_ddos: 500      },
  { key: "ACK Flag Count",        label: "ACK Flags",            default_normal: 8,        default_ddos: 0        },
  { key: "RST Flag Count",        label: "RST Flags",            default_normal: 0,        default_ddos: 450      },
  { key: "Packet Length Mean",    label: "Pkt Length Mean",      default_normal: 512,      default_ddos: 60       },
  { key: "Packet Length Variance",label: "Pkt Length Variance",  default_normal: 8000,     default_ddos: 100      },
  { key: "Average Packet Size",   label: "Avg Packet Size",      default_normal: 512,      default_ddos: 60       },
];

// ── Init ─────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  renderFeatureFields();
  loadStatus();
  loadResults();
  refreshSnortStatus();
  loadSnortAlerts();
  loadSensors();
  loadConnectedAgents();
  setInterval(loadSnortAlerts, 5000);
  setInterval(refreshSnortStatus, 10000);
  setInterval(loadSensors, 15000);
  setInterval(loadConnectedAgents, 5000);
});

// ── API: Status ───────────────────────────────────────────────────────────────
async function loadStatus() {
  try {
    const res  = await fetch('/api/status');
    const data = await res.json();
    const chip = document.getElementById('chipModels');
    const dot  = chip.querySelector('.dot');

    if (data.results_ready) {
      dot.classList.remove('loading');
      chip.innerHTML = `<span class="dot"></span> ${data.models_loaded.length} models ready`;
    } else {
      chip.innerHTML = `<span class="dot loading"></span> Training required`;
      showAlert('⚠️ Models not trained yet. Please run <code>python src/train.py</code> first, then restart the server.');
    }
  } catch(e) {
    console.warn('Status check failed:', e);
  }
}

function showAlert(msg) {
  const el = document.getElementById('alertBanner');
  el.innerHTML = msg;
  el.style.display = 'block';
}

// ── API: Results ──────────────────────────────────────────────────────────────
async function loadResults() {
  try {
    const res  = await fetch('/api/results');
    if (!res.ok) {
      document.getElementById('comparisonContent').innerHTML =
        '<p style="color:#888;font-size:.875rem;padding:.5rem 0;">Run <code>python src/train.py</code> to see results.</p>';
      return;
    }
    const data = await res.json();
    renderComparisonTable(data);
  } catch(e) {
    console.error('Failed to load results:', e);
  }
}

function renderComparisonTable(results) {
  if (!results || results.length === 0) return;

  const bestF1 = Math.max(...results.map(r => r.f1_weighted));

  const rows = results.map(r => {
    const isBest   = r.f1_weighted === bestF1;
    const color    = MODEL_COLORS[r.model] || '#aaa';
    const bestTag  = isBest ? '<span class="best-badge">🏆 BEST</span>' : '';
    const mkVal    = (v, topVal) =>
      `<span class="metric-val${v === topVal ? ' top' : ''}">${v}%</span>`;

    const maxAcc  = Math.max(...results.map(x => x.accuracy));
    const maxPrec = Math.max(...results.map(x => x.precision_w));
    const maxRec  = Math.max(...results.map(x => x.recall_w));
    const maxF1   = Math.max(...results.map(x => x.f1_weighted));

    return `
      <tr class="${isBest ? 'best-row' : ''}">
        <td>
          <div class="model-name">
            <span class="model-dot" style="background:${color}"></span>
            ${r.model} ${bestTag}
          </div>
        </td>
        <td>${mkVal(r.accuracy, maxAcc)}</td>
        <td>${mkVal(r.precision_w, maxPrec)}</td>
        <td>${mkVal(r.recall_w, maxRec)}</td>
        <td>${mkVal(r.f1_weighted, maxF1)}</td>
        <td><span class="time-mono">${r.train_time}s</span></td>
      </tr>`;
  }).join('');

  document.getElementById('comparisonContent').innerHTML = `
    <div style="overflow-x:auto">
      <table class="comparison-table">
        <thead>
          <tr>
            <th>Algorithm</th>
            <th>Accuracy</th>
            <th>Precision</th>
            <th>Recall</th>
            <th>F1-Score</th>
            <th>Train Time</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

// ── Feature Fields ────────────────────────────────────────────────────────────
function renderFeatureFields() {
  const grid = document.getElementById('featuresGrid');
  grid.innerHTML = KEY_FEATURES.map(f => `
    <div class="feature-field">
      <label for="feat_${sanitizeId(f.key)}">${f.label}</label>
      <input type="number" id="feat_${sanitizeId(f.key)}"
             data-key="${f.key}"
             value="${f.default_normal}" step="any" min="0"/>
    </div>`).join('');
}

function sanitizeId(s) { return s.replace(/[^a-zA-Z0-9]/g, '_'); }

function loadPreset(type) {
  KEY_FEATURES.forEach(f => {
    const input = document.getElementById(`feat_${sanitizeId(f.key)}`);
    if (input) input.value = type === 'ddos' ? f.default_ddos : f.default_normal;
  });
}

function clearForm() {
  KEY_FEATURES.forEach(f => {
    const input = document.getElementById(`feat_${sanitizeId(f.key)}`);
    if (input) input.value = 0;
  });
  document.getElementById('predictResult').style.display = 'none';
}

// ── Predict ───────────────────────────────────────────────────────────────────
async function runPredict() {
  const btn     = document.getElementById('btnPredict');
  const btnText = document.getElementById('btnPredictText');
  const model   = document.getElementById('selectModel').value;

  // Build feature object: only KEY_FEATURES, rest = 0
  const features = {};
  KEY_FEATURES.forEach(f => {
    const input = document.getElementById(`feat_${sanitizeId(f.key)}`);
    features[f.key] = input ? parseFloat(input.value) || 0 : 0;
  });

  btn.disabled   = true;
  btnText.textContent = '⏳ Detecting...';

  try {
    const res  = await fetch('/api/predict', {
      method : 'POST',
      headers: { 'Content-Type': 'application/json' },
      body   : JSON.stringify({ model, features }),
    });
    const data = await res.json();

    if (data.error) {
      showAlert('❌ ' + data.error);
    } else {
      renderPredictResult(data);
    }
  } catch(e) {
    showAlert('❌ Server error: ' + e.message);
  } finally {
    btn.disabled   = false;
    btnText.textContent = '🚀 Run Detection';
  }
}

function renderPredictResult(data) {
  const resultEl = document.getElementById('predictResult');
  const isDDoS   = data.prediction === 'DDoS';

  document.getElementById('resultIcon').textContent   = isDDoS ? '🚨' : '✅';
  const labelEl = document.getElementById('resultLabel');
  labelEl.textContent      = isDDoS ? 'DDoS ATTACK DETECTED' : 'BENIGN TRAFFIC';
  labelEl.className        = 'result-label ' + (isDDoS ? 'ddos' : 'benign');

  const conf = data.confidence ? `${data.confidence}% confidence · ${data.selected_model}` : data.selected_model;
  document.getElementById('resultConfidence').textContent = conf;

  // All model results
  const allResults = data.all_results || {};
  const chipsHtml  = Object.entries(allResults).map(([name, r]) => {
    const isD = r.label === 'DDoS';
    const confStr = r.confidence ? `${r.confidence}%` : '';
    return `
      <div class="model-result-chip">
        <div class="chip-name">${name}</div>
        <div class="chip-label ${isD ? 'ddos' : 'benign'}">${isD ? '🚨 DDoS' : '✅ BENIGN'}</div>
        ${confStr ? `<div class="chip-conf">${confStr} confidence</div>` : ''}
      </div>`;
  }).join('');

  document.getElementById('allModelResults').innerHTML = chipsHtml;
  resultEl.style.display = 'block';
  resultEl.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// ── Connected Machine Monitoring ──────────────────────────────────────────────
let currentAgentId = null;
let activeTab = 'info';

async function loadConnectedAgents() {
  try {
    const res = await fetch('/api/agents');
    const agents = await res.json();
    const grid = document.getElementById('agentGrid');
    if (!agents || agents.length === 0) {
      grid.innerHTML = '<div style="text-align:center; padding: 20px; color: #666;">Waiting for agents to connect...</div>';
      return;
    }
    grid.innerHTML = agents.map(a => {
      const alive = a.alive ? 'alive' : 'dead';
      const time = a.last_seen ? formatAgentTime(a.last_seen) : '--';
      const cpuStyle = a.cpu > 80 ? '#ff6584' : a.cpu > 50 ? '#ffd166' : '#2ed573';
      return `
        <div class="agent-card ${alive} ${currentAgentId === a.agent_id ? 'selected' : ''}" onclick="loadAgentDetail('${a.agent_id}')">
          <div class="agent-card-header">
            <span class="agent-status-dot ${alive}"></span>
            <span class="agent-name">${a.hostname || a.agent_id}</span>
          </div>
          <div class="agent-card-body">
            <div class="agent-card-info"><span class="acl">IP</span> ${a.ip || '--'}</div>
            <div class="agent-card-info"><span class="acl">OS</span> ${a.os || '--'}</div>
            <div class="agent-card-info"><span class="acl">CPU</span> <span style="color:${cpuStyle}">${a.cpu ?? '--'}%</span></div>
            <div class="agent-card-info"><span class="acl">MEM</span> ${a.memory ?? '--'}%</div>
          </div>
          <div class="agent-card-footer">
            <span class="agent-time">${time}</span>
            <span class="agent-source-badge">${a.source || 'agent'}</span>
          </div>
        </div>`;
    }).join('');
  } catch (e) {
    console.warn('Failed to load agents:', e);
  }
}

async function loadAgentDetail(agentId) {
  currentAgentId = agentId;
  const panel = document.getElementById('agentDetail');
  panel.style.display = 'block';

  try {
    const res = await fetch(`/api/agents/${agentId}`);
    const agent = await res.json();
    if (agent.error) { closeAgentDetail(); return; }

    document.getElementById('detailAgentName').textContent = agent.hostname || agent.agent_id;
    document.getElementById('detailAgentHostname').textContent = agent.agent_id;
    document.getElementById('detOs').textContent = agent.os || '--';
    document.getElementById('detIp').textContent = agent.ip || '--';

    const cpu = agent.cpu ?? 0;
    document.getElementById('detCpu').textContent = `${cpu}%`;
    document.getElementById('detCpuFill').style.width = `${Math.min(cpu, 100)}%`;

    const mem = agent.memory ?? 0;
    document.getElementById('detMem').textContent = `${mem}%`;
    document.getElementById('detMemFill').style.width = `${Math.min(mem, 100)}%`;

    const disk = agent.disk ?? 0;
    document.getElementById('detDisk').textContent = `${disk}%`;
    document.getElementById('detDiskFill').style.width = `${Math.min(disk, 100)}%`;

    document.getElementById('detUptime').textContent = agent.uptime ? formatUptime(agent.uptime) : '--';
    document.getElementById('detFirstSeen').textContent = agent.first_seen ? formatAgentTime(agent.first_seen) : '--';
    document.getElementById('detLastSeen').textContent = agent.last_seen ? formatAgentTime(agent.last_seen) : '--';

    // Processes
    const procs = agent.processes || [];
    const procSection = document.getElementById('procSection');
    const procBody = document.getElementById('procBody');
    if (procs.length > 0) {
      procSection.style.display = 'block';
      procBody.innerHTML = procs.slice(0, 15).map(p => `
        <tr><td>${p.pid || '--'}</td><td>${p.name || '--'}</td><td>${(p.cpu_percent || 0).toFixed(1)}</td><td>${(p.memory_percent || 0).toFixed(1)}</td></tr>
      `).join('');
    } else {
      procSection.style.display = 'none';
    }

    // Connections tab
    loadAgentConnections(agentId);

    // Highlight card
    document.querySelectorAll('.agent-card').forEach(c => c.classList.remove('selected'));
    const card = document.querySelector(`.agent-card[onclick*="'${agentId}'"]`);
    if (card) card.classList.add('selected');

  } catch (e) {
    console.warn('Agent detail error:', e);
  }
}

async function loadAgentConnections(agentId) {
  try {
    const res = await fetch(`/api/agents/${agentId}/connections`);
    const data = await res.json();
    const connections = data.connections || [];
    const summary = document.getElementById('connSummary');
    const detail = document.getElementById('connDetail');

    if (connections.length > 0) {
      const c = connections[0];
      summary.innerHTML = `
        <span class="conn-stat"><span class="conn-num">${c.total || 0}</span> Total</span>
        <span class="conn-stat"><span class="conn-num">${c.established || 0}</span> Established</span>
        <span class="conn-stat"><span class="conn-num">${c.syn_sent || 0}</span> SYN_SENT</span>
        <span class="conn-stat"><span class="conn-num">${(c.ports || []).length}</span> Active Ports</span>
      `;
      detail.textContent = `Active ports: ${(c.ports || []).join(', ') || 'none'}`;
    } else {
      summary.innerHTML = '<span style="color:var(--text-muted)">No connection data</span>';
      detail.textContent = 'No connection data available.';
    }
  } catch (e) {
    console.warn('Connection load error:', e);
  }
}

function switchAgentTab(tab, btn) {
  activeTab = tab;
  document.querySelectorAll('.agent-tab').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.agent-tab-content').forEach(c => c.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById('tab' + tab.charAt(0).toUpperCase() + tab.slice(1)).classList.add('active');

  if (tab === 'screen' && currentAgentId) {
    loadAgentScreen(currentAgentId);
  }
  if (tab === 'connections' && currentAgentId) {
    loadAgentConnections(currentAgentId);
  }
}

async function loadAgentScreen(agentId) {
  const img = document.getElementById('screenImage');
  const status = document.getElementById('screenStatus');
  try {
    const res = await fetch(`/api/agents/${agentId}/screen`);
    const data = await res.json();
    if (data.image) {
      img.src = 'data:image/png;base64,' + data.image;
      img.style.display = 'block';
      status.textContent = `Last update: ${formatAgentTime(data.timestamp)}`;
    } else {
      img.style.display = 'none';
      status.textContent = 'No screenshot available yet. Screen capture sent every ~60s.';
    }
  } catch (e) {
    img.style.display = 'none';
    status.textContent = 'Failed to load screenshot.';
  }
}

function refreshScreen() {
  if (currentAgentId) loadAgentScreen(currentAgentId);
}

function closeAgentDetail() {
  document.getElementById('agentDetail').style.display = 'none';
  currentAgentId = null;
  document.querySelectorAll('.agent-card').forEach(c => c.classList.remove('selected'));
}

function formatAgentTime(ts) {
  try {
    const d = new Date(ts * 1000);
    return d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  } catch (e) {
    return ts;
  }
}

function formatUptime(seconds) {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const parts = [];
  if (d > 0) parts.push(d + 'd');
  if (h > 0) parts.push(h + 'h');
  parts.push(m + 'm');
  return parts.join(' ');
}
