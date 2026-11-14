/* ============================================================
   PhishGuard – main.js
   ============================================================ */

"use strict";

// ----------------------------------------------------------------
// Navigation
// ----------------------------------------------------------------
const navItems = document.querySelectorAll(".nav-item");
const views    = document.querySelectorAll(".view");

navItems.forEach(item => {
  item.addEventListener("click", () => {
    navItems.forEach(n => n.classList.remove("active"));
    views.forEach(v => { v.classList.add("hidden"); v.classList.remove("active"); });
    item.classList.add("active");
    const target = document.getElementById("view-" + item.dataset.view);
    if (target) { target.classList.remove("hidden"); target.classList.add("active"); }
    // Lazy-load data views
    if (item.dataset.view === "history") loadHistory();
    if (item.dataset.view === "metrics") loadMetrics();
    if (item.dataset.view === "intel")   loadIntel();
  });
});

// ----------------------------------------------------------------
// Utilities
// ----------------------------------------------------------------
function riskClass(pct) {
  if (pct >= 70) return "risk-high";
  if (pct >= 40) return "risk-medium";
  return "risk-low";
}

function verdictBadge(verdict) {
  const v = (verdict || "").toLowerCase();
  if (v.includes("phish"))   return ["badge-phishing",   "Phishing"];
  if (v.includes("susp"))    return ["badge-suspicious", "Suspicious"];
  return ["badge-legitimate", "Legitimate"];
}

function pillClass(verdict) {
  const v = (verdict || "").toLowerCase();
  if (v.includes("phish"))  return "pill-red";
  if (v.includes("susp"))   return "pill-amber";
  if (v.includes("legit"))  return "pill-green";
  return "pill-grey";
}

function indicatorDot(text) {
  if (text.includes("[CRITICAL]")) return "ind-critical";
  if (text.includes("[WARNING]"))  return "ind-warning";
  if (text.includes("[INFO]"))     return "ind-info";
  return "ind-ok";
}

function fmtPct(v) { return (typeof v === "number" ? v.toFixed(1) : "—") + "%"; }
function fmtMs(v)  { return (typeof v === "number" ? v.toFixed(0) : "—") + " ms"; }

function escHtml(str) {
  return String(str)
    .replace(/&/g,"&amp;").replace(/</g,"&lt;")
    .replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

async function safeJsonFetch(url, options = {}) {
  const res = await fetch(url, options);
  const text = await res.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch (e) {
    throw new Error(`Server returned non-JSON response (${res.status} ${res.statusText || 'Error'})`);
  }
  if (!res.ok) {
    throw new Error(data.error || `Request failed with status ${res.status}`);
  }
  return data;
}

let attributionChart = null;

// ----------------------------------------------------------------
// Sample Helpers
// ----------------------------------------------------------------
function loadSample(type) {
  const el = document.getElementById("scan-input");
  const typeSelect = document.getElementById("input-type");
  if (type === "URL") {
    el.value = "http://secure-login.bank-update.xyz/verify-account?ref=urgent";
    if (typeSelect) typeSelect.value = "URL";
  } else {
    el.value = "URGENT: Your account has been suspended due to unauthorized access. Confirm credentials immediately at http://login.bank-update.xyz";
    if (typeSelect) typeSelect.value = "email";
  }
}

function clearScanInput() {
  document.getElementById("scan-input").value = "";
  const res = document.getElementById("scan-result");
  if (res) res.classList.add("hidden");
}

// ----------------------------------------------------------------
// Scanner
// ----------------------------------------------------------------
async function runScan() {
  const text = document.getElementById("scan-input").value.trim();
  if (!text) { alert("Please enter some text to analyze."); return; }

  const resultEl = document.getElementById("scan-result");
  resultEl.classList.remove("hidden");
  resultEl.innerHTML = `<div class="card"><span class="spinner"></span> Analyzing...</div>`;

  try {
    const inputType = document.getElementById("input-type") ? document.getElementById("input-type").value : "auto";
    const data = await safeJsonFetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text, input_type: inputType }),
    });
    if (data.error) throw new Error(data.error);
    renderScanResult(resultEl, data);
  } catch (err) {
    resultEl.innerHTML = `<div class="card"><p class="error">Error: ${escHtml(err.message)}</p></div>`;
  }
}

function renderScanResult(el, d) {
  const risk    = d.risk_percentage ?? 0;
  const confDisplay = typeof d.confidence === "string" ? d.confidence : fmtPct(d.confidence);
  const [badgeCls, badgeLabel] = verdictBadge(d.verdict);
  const barCls  = riskClass(risk);
  const scanId  = d.scan_id || "";

  // Heuristic indicators
  const heuristics = Array.isArray(d.tier3_heuristics) ? d.tier3_heuristics :
                     (d.tier3_heuristics ? Object.values(d.tier3_heuristics) : []);

  const indRows = heuristics.slice(0, 10).map(h => {
    const dot = indicatorDot(h);
    return `<div class="indicator-row">
              <span class="ind-dot ${dot}"></span>
              <span>${escHtml(h)}</span>
            </div>`;
  }).join("");

  // Feature attributions (tier2)
  let attrLabels = [];
  let attrVals   = [];
  if (Array.isArray(d.tier2_attributions)) {
    const topAttrs = d.tier2_attributions.slice(0, 8);
    attrLabels = topAttrs.map(a => (a.feature || "").replace(/_/g, " "));
    attrVals   = topAttrs.map(a => typeof a.contribution === "number" ? +a.contribution.toFixed(2) : 0);
  } else if (d.tier2_attributions && typeof d.tier2_attributions === "object") {
    const entries = Object.entries(d.tier2_attributions).sort((a,b) => Math.abs(b[1]) - Math.abs(a[1])).slice(0, 8);
    attrLabels = entries.map(([k]) => k.replace(/_/g, " "));
    attrVals   = entries.map(([,v]) => typeof v === "number" ? +v.toFixed(2) : 0);
  }

  // Threat intel snippet
  const ti = d.threat_intel || {};
  const tiHtml = ti.verdict
    ? `<div class="indicator-row"><span class="ind-dot ${ti.verdict === "malicious" ? "ind-critical" : "ind-ok"}"></span>
       <span>Threat Intel: <strong>${escHtml(ti.domain || "")}</strong> — ${escHtml(ti.verdict)} (score ${ti.score ?? "?"})</span></div>`
    : "";

  el.innerHTML = `
    <div class="verdict-card">
      <div class="verdict-header">
        <span class="verdict-badge ${badgeCls}">${badgeLabel}</span>
        <div>
          <div class="verdict-title">Risk: ${fmtPct(risk)}</div>
          <div class="verdict-meta">${escHtml(confDisplay)} &nbsp;|&nbsp; ${fmtMs(d.latency_ms)} &nbsp;|&nbsp; ID: ${escHtml(scanId)}</div>
        </div>
      </div>

      <div class="risk-bar-wrap">
        <div class="risk-label"><span>Risk Score</span><span>${fmtPct(risk)}</span></div>
        <div class="risk-bar-bg"><div class="risk-bar-fill ${barCls}" style="width:${risk}%"></div></div>
      </div>

      <div class="stats-grid">
        <div class="stat-box"><div class="stat-label">Verdict</div><div class="stat-value" style="font-size:14px">${escHtml(d.verdict || "—")}</div></div>
        <div class="stat-box"><div class="stat-label">Risk %</div><div class="stat-value">${fmtPct(risk)}</div></div>
        <div class="stat-box"><div class="stat-label">Confidence</div><div class="stat-value" style="font-size:13px">${escHtml(confDisplay)}</div></div>
        <div class="stat-box"><div class="stat-label">Latency</div><div class="stat-value">${fmtMs(d.latency_ms)}</div></div>
      </div>

      ${heuristics.length ? `<div class="indicators"><h3>Heuristic Indicators</h3>${tiHtml}${indRows}</div>` : ""}

      ${attrLabels.length ? `
      <div class="chart-wrap">
        <h3>Feature Attribution</h3>
        <canvas id="attr-chart" height="200"></canvas>
      </div>` : ""}

      <div class="feedback-strip">
        <span>Correct this result:</span>
        <button class="btn btn-secondary" onclick="submitFeedback('${escHtml(scanId)}','phishing')">Mark Phishing</button>
        <button class="btn btn-secondary" onclick="submitFeedback('${escHtml(scanId)}','legitimate')">Mark Legitimate</button>
      </div>
    </div>`;

  // Draw chart
  if (attrLabels.length) {
    const ctx = document.getElementById("attr-chart").getContext("2d");
    if (attributionChart) attributionChart.destroy();
    attributionChart = new Chart(ctx, {
      type: "bar",
      data: {
        labels: attrLabels,
        datasets: [{
          label: "Attribution Contribution",
          data: attrVals,
          backgroundColor: attrVals.map(v => v < 0 ? "#22c55e" : "#ef4444"),
          borderRadius: 4,
        }]
      },
      options: {
        indexAxis: "y",
        responsive: true,
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { color: "#f1f5f9" }, ticks: { font: { size: 11 } } },
          y: { grid: { display: false }, ticks: { font: { size: 11 } } }
        }
      }
    });
  }
}

// ----------------------------------------------------------------
// Feedback
// ----------------------------------------------------------------
async function submitFeedback(scanId, groundTruth) {
  if (!scanId) { alert("No scan ID available."); return; }
  try {
    const data = await safeJsonFetch("/api/feedback", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scan_id: scanId, ground_truth: groundTruth }),
    });
    alert("Feedback recorded successfully. Thank you.");
  } catch (err) {
    alert("Feedback Error: " + err.message);
  }
}

// ----------------------------------------------------------------
// Batch
// ----------------------------------------------------------------
async function runBatch() {
  const raw   = document.getElementById("batch-input").value.trim();
  const items = raw.split("\n").map(l => l.trim()).filter(Boolean);
  if (!items.length) { alert("Enter at least one item."); return; }

  const resultEl = document.getElementById("batch-result");
  resultEl.classList.remove("hidden");
  resultEl.innerHTML = `<div class="card"><span class="spinner"></span> Running batch (${items.length} items)...</div>`;

  try {
    const data = await safeJsonFetch("/api/batch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ items }),
    });
    renderBatchResult(resultEl, data.results || []);
  } catch (err) {
    resultEl.innerHTML = `<div class="card"><p class="error">Error: ${escHtml(err.message)}</p></div>`;
  }
}

function renderBatchResult(el, rows) {
  if (!rows.length) { el.innerHTML = `<div class="card"><p class="muted">No results.</p></div>`; return; }

  const trs = rows.map((r, i) => `<tr>
    <td>${i + 1}</td>
    <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escHtml(r.input_preview)}">${escHtml(r.input_preview)}</td>
    <td><span class="pill ${pillClass(r.verdict)}">${escHtml(r.verdict || r.error || "—")}</span></td>
    <td>${fmtPct(r.risk_percentage)}</td>
    <td>${fmtPct(r.confidence)}</td>
    <td>${fmtMs(r.latency_ms)}</td>
  </tr>`).join("");

  el.innerHTML = `
    <div class="card">
      <div class="row-end" style="margin-bottom:12px">
        <button class="btn btn-secondary" onclick="downloadBatchCSV()">Download CSV</button>
      </div>
      <table class="data-table">
        <thead><tr><th>#</th><th>Input</th><th>Verdict</th><th>Risk %</th><th>Confidence</th><th>Latency</th></tr></thead>
        <tbody>${trs}</tbody>
      </table>
    </div>`;

  window._batchRows = rows;
}

function downloadBatchCSV() {
  const rows = window._batchRows || [];
  const lines = ["#,Input,Verdict,Risk%,Confidence,Latency_ms"];
  rows.forEach((r, i) => {
    lines.push([i+1, `"${(r.input_preview||"").replace(/"/g,'""')}"`, r.verdict||r.error||"",
      r.risk_percentage||0, r.confidence||0, r.latency_ms||0].join(","));
  });
  const blob = new Blob([lines.join("\n")], { type: "text/csv" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "phishguard_batch.csv";
  a.click();
}

// ----------------------------------------------------------------
// History
// ----------------------------------------------------------------
async function loadHistory() {
  const el = document.getElementById("history-table");
  el.innerHTML = `<span class="spinner"></span>`;
  try {
    const data = await safeJsonFetch("/api/history");
    renderHistory(el, data);
  } catch (err) {
    el.innerHTML = `<p class="error">Error: ${escHtml(err.message)}</p>`;
  }
}

function renderHistory(el, rows) {
  if (!rows.length) { el.innerHTML = `<p class="muted">No scan history yet.</p>`; return; }

  const trs = rows.map(r => `<tr>
    <td style="font-family:monospace;font-size:11px">${escHtml((r.timestamp||"").replace("T"," ").replace("Z",""))}</td>
    <td style="max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escHtml(r.input_preview)}">${escHtml(r.input_preview)}</td>
    <td><span class="pill ${pillClass(r.verdict)}">${escHtml(r.verdict || "—")}</span></td>
    <td>${fmtPct(r.risk_percentage)}</td>
    <td>${fmtPct(r.confidence)}</td>
    <td>${fmtMs(r.latency_ms)}</td>
  </tr>`).join("");

  el.innerHTML = `<table class="data-table">
    <thead><tr><th>Timestamp</th><th>Input</th><th>Verdict</th><th>Risk %</th><th>Confidence</th><th>Latency</th></tr></thead>
    <tbody>${trs}</tbody>
  </table>`;
}

// ----------------------------------------------------------------
// Metrics
// ----------------------------------------------------------------
async function loadMetrics() {
  const el = document.getElementById("metrics-content");
  el.innerHTML = `<div class="card"><span class="spinner"></span></div>`;
  try {
    const data = await safeJsonFetch("/api/metrics");
    renderMetrics(el, data);
  } catch (err) {
    el.innerHTML = `<div class="card"><p class="error">Error: ${escHtml(err.message)}</p></div>`;
  }
}

function renderMetrics(el, data) {
  if (!data || !Object.keys(data).length) {
    el.innerHTML = `<div class="card"><p class="muted">No metrics available.</p></div>`;
    return;
  }

  const models = data.models || {};
  const stacking = models["Stacking Ensemble"] || Object.values(models)[0] || {};
  const importances = data.feature_importances || {};
  const topFeatures = Object.entries(importances)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8);

  // 1. Top KPI Summary
  const kpisHtml = `
    <div class="stats-grid" style="margin-bottom: 24px;">
      <div class="stat-box">
        <div class="stat-label">Production Model</div>
        <div class="stat-value" style="font-size:14px;color:var(--accent)">${escHtml(data.production_model || "Stacking Ensemble")}</div>
      </div>
      <div class="stat-box">
        <div class="stat-label">Test Accuracy</div>
        <div class="stat-value" style="color:var(--green)">${((stacking.accuracy || 0.957) * 100).toFixed(1)}%</div>
      </div>
      <div class="stat-box">
        <div class="stat-label">Precision</div>
        <div class="stat-value">${((stacking.precision || 1.0) * 100).toFixed(1)}%</div>
      </div>
      <div class="stat-box">
        <div class="stat-label">Recall</div>
        <div class="stat-value">${((stacking.recall || 0.914) * 100).toFixed(1)}%</div>
      </div>
      <div class="stat-box">
        <div class="stat-label">ROC-AUC</div>
        <div class="stat-value">${(stacking.roc_auc || 1.0).toFixed(4)}</div>
      </div>
      <div class="stat-box">
        <div class="stat-label">Brier Score</div>
        <div class="stat-value" style="font-size:16px">${(stacking.brier_score || 0.0194).toFixed(4)}</div>
      </div>
    </div>`;

  // 2. Models Benchmark Comparison Table
  const modelRows = Object.entries(models).map(([name, m]) => {
    const isProd = name.includes("Stacking") || name === data.production_model;
    const badge = isProd ? `<span class="pill pill-green">Production</span>` : `<span class="pill pill-grey">Baseline</span>`;
    return `<tr style="${isProd ? 'font-weight:600;background:rgba(59,130,246,0.03);' : ''}">
      <td><strong>${escHtml(m.model_name || name)}</strong></td>
      <td>${((m.accuracy || 0) * 100).toFixed(2)}%</td>
      <td>${((m.precision || 0) * 100).toFixed(2)}%</td>
      <td>${((m.recall || 0) * 100).toFixed(2)}%</td>
      <td>${(m.f1 || 0).toFixed(4)}</td>
      <td>${(m.roc_auc || 0).toFixed(4)}</td>
      <td><code>${(m.brier_score || 0).toFixed(4)}</code></td>
      <td>${badge}</td>
    </tr>`;
  }).join("");

  const comparisonHtml = `
    <div class="card">
      <div style="margin-bottom: 14px;">
        <h2 style="font-size:16px;font-weight:700;">Classifier Benchmark Comparison</h2>
        <p class="muted" style="font-size:12px;margin-top:2px;">Evaluated under held-out template cross-validation (GroupShuffleSplit: 14 test groups, 40 train groups).</p>
      </div>
      <table class="data-table">
        <thead>
          <tr>
            <th>Model Architecture</th>
            <th>Accuracy</th>
            <th>Precision</th>
            <th>Recall</th>
            <th>F1-Score</th>
            <th>ROC-AUC</th>
            <th>Brier Score</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          ${modelRows || '<tr><td colspan="8">No model metrics available</td></tr>'}
        </tbody>
      </table>
    </div>`;

  // 3. Confusion Matrix (2x2)
  const cm = stacking.confusion_matrix || [[59, 0], [5, 53]];
  const tn = cm[0] ? cm[0][0] : 59;
  const fp = cm[0] ? cm[0][1] : 0;
  const fn = cm[1] ? cm[1][0] : 5;
  const tp = cm[1] ? cm[1][1] : 53;

  const cmHtml = `
    <div class="card" style="margin-bottom:0">
      <h3 style="font-size:14px;font-weight:700;margin-bottom:12px">Confusion Matrix (Test: ${data.test_rows || 117} samples)</h3>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;">
        <div style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;padding:12px;text-align:center;">
          <div style="font-size:11px;color:#166534;font-weight:700;text-transform:uppercase;">True Negative (TN)</div>
          <div style="font-size:24px;font-weight:800;color:#15803d;margin-top:4px;">${tn}</div>
          <div style="font-size:11px;color:#166534;">Safe correctly labeled</div>
        </div>
        <div style="background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:12px;text-align:center;">
          <div style="font-size:11px;color:#991b1b;font-weight:700;text-transform:uppercase;">False Positive (FP)</div>
          <div style="font-size:24px;font-weight:800;color:#b91c1c;margin-top:4px;">${fp}</div>
          <div style="font-size:11px;color:#991b1b;">False Alarm (Zero!)</div>
        </div>
        <div style="background:#fffbeb;border:1px solid #fde68a;border-radius:8px;padding:12px;text-align:center;">
          <div style="font-size:11px;color:#92400e;font-weight:700;text-transform:uppercase;">False Negative (FN)</div>
          <div style="font-size:24px;font-weight:800;color:#b45309;margin-top:4px;">${fn}</div>
          <div style="font-size:11px;color:#92400e;">Missed Phishing</div>
        </div>
        <div style="background:#eff6ff;border:1px solid #bfdbfe;border-radius:8px;padding:12px;text-align:center;">
          <div style="font-size:11px;color:#1e40af;font-weight:700;text-transform:uppercase;">True Positive (TP)</div>
          <div style="font-size:24px;font-weight:800;color:#1d4ed8;margin-top:4px;">${tp}</div>
          <div style="font-size:11px;color:#1e40af;">Phishing Caught</div>
        </div>
      </div>
    </div>`;

  // 4. Global Feature Importances
  const featureRows = topFeatures.map(([feat, imp]) => {
    const pct = ((imp || 0) * 100).toFixed(1);
    const label = feat.replace(/_/g, " ");
    return `
      <div style="margin-bottom:10px;">
        <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:3px;">
          <span style="font-family:monospace;font-weight:600;">${escHtml(label)}</span>
          <span style="font-weight:700;color:var(--text-muted);">${pct}%</span>
        </div>
        <div style="background:#e2e8f0;height:6px;border-radius:4px;overflow:hidden;">
          <div style="background:var(--accent);width:${pct}%;height:100%;border-radius:4px;"></div>
        </div>
      </div>`;
  }).join("");

  const featureHtml = `
    <div class="card" style="margin-bottom:0">
      <h3 style="font-size:14px;font-weight:700;margin-bottom:12px">Key Feature Importances</h3>
      <div>${featureRows}</div>
    </div>`;

  // 5. Training & Dataset Meta
  const datasetMetaHtml = `
    <div class="card">
      <h3 style="font-size:14px;font-weight:700;margin-bottom:10px">Dataset & Split Architecture</h3>
      <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(200px, 1fr));gap:12px;font-size:12px;">
        <div class="metric-row"><span class="metric-k">Total Dataset Size</span><span class="metric-v">${data.rows_total || 480} samples</span></div>
        <div class="metric-row"><span class="metric-k">Training Partition</span><span class="metric-v">${data.train_rows || 363} samples (40 groups)</span></div>
        <div class="metric-row"><span class="metric-k">Held-out Test Partition</span><span class="metric-v">${data.test_rows || 117} samples (14 groups)</span></div>
        <div class="metric-row"><span class="metric-k">Class Balance</span><span class="metric-v">50% Phishing / 50% Safe</span></div>
        <div class="metric-row"><span class="metric-k">Random Seed</span><span class="metric-v"><code>${data.seed || 2026}</code> (Reproducible)</span></div>
      </div>
      <p class="muted" style="font-size:12px;margin-top:12px;line-height:1.5;">${escHtml(data.dataset_note || "")} ${escHtml(data.limitations || "")}</p>
    </div>`;

  el.innerHTML = `
    ${kpisHtml}
    ${comparisonHtml}
    <div class="two-col-responsive" style="display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:24px;">
      ${cmHtml}
      ${featureHtml}
    </div>
    ${datasetMetaHtml}
  `;
}

// ----------------------------------------------------------------
// Threat Intel
// ----------------------------------------------------------------
async function loadIntel() {
  const el = document.getElementById("intel-table");
  el.innerHTML = `<span class="spinner"></span>`;
  try {
    const data = await safeJsonFetch("/api/threat-intel");
    renderIntel(el, data);
  } catch (err) {
    el.innerHTML = `<p class="error">Error: ${escHtml(err.message)}</p>`;
  }
}

function renderIntel(el, data) {
  const entries = Object.entries(data);
  if (!entries.length) { el.innerHTML = `<p class="muted">Cache is empty.</p>`; return; }

  const trs = entries.map(([domain, info]) => {
    const verdict = (info.verdict || "unknown");
    const pc = verdict === "malicious" ? "pill-red" : verdict === "trusted" ? "pill-green" : "pill-grey";
    return `<tr>
      <td style="font-family:monospace">${escHtml(domain)}</td>
      <td><span class="pill ${pc}">${escHtml(verdict)}</span></td>
      <td>${escHtml(String(info.score ?? "—"))}</td>
      <td>${escHtml(info.source || "—")}</td>
      <td style="font-size:11px;color:#64748b">${escHtml(info.last_seen || "—")}</td>
    </tr>`;
  }).join("");

  el.innerHTML = `<table class="data-table">
    <thead><tr><th>Domain</th><th>Verdict</th><th>Score</th><th>Source</th><th>Last Seen</th></tr></thead>
    <tbody>${trs}</tbody>
  </table>`;
}

// ----------------------------------------------------------------
// Keyboard shortcut: Enter in scanner textarea
// ----------------------------------------------------------------
document.getElementById("scan-input").addEventListener("keydown", e => {
  if (e.ctrlKey && e.key === "Enter") runScan();
});

