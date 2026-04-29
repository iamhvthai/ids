/* ── App Logic: IDS Dashboard ───────────────────────────────────────────── */

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
