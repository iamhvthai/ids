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
  setInterval(loadSnortAlerts, 5000);
  setInterval(refreshSnortStatus, 10000);
  setInterval(loadSensors, 15000);
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

  const bestF1 = Math.max(...results.map(r => r.f1));

  const rows = results.map(r => {
    const isBest   = r.f1 === bestF1;
    const color    = MODEL_COLORS[r.model] || '#aaa';
    const bestTag  = isBest ? '<span class="best-badge">🏆 BEST</span>' : '';
    const mkVal    = (v, topVal) =>
      `<span class="metric-val${v === topVal ? ' top' : ''}">${v}%</span>`;

    const maxAcc  = Math.max(...results.map(x => x.accuracy));
    const maxPrec = Math.max(...results.map(x => x.precision));
    const maxRec  = Math.max(...results.map(x => x.recall));
    const maxF1   = Math.max(...results.map(x => x.f1));

    return `
      <tr class="${isBest ? 'best-row' : ''}">
        <td>
          <div class="model-name">
            <span class="model-dot" style="background:${color}"></span>
            ${r.model} ${bestTag}
          </div>
        </td>
        <td>${mkVal(r.accuracy, maxAcc)}</td>
        <td>${mkVal(r.precision, maxPrec)}</td>
        <td>${mkVal(r.recall, maxRec)}</td>
        <td>${mkVal(r.f1, maxF1)}</td>
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

  // Build feature object — only KEY_FEATURES, rest = 0
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
