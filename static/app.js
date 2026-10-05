/**
 * AEGIS-XAI: SOC Analyst & Explainable Threat Intelligence Client Application
 * Includes custom vanilla HTML5 Canvas Force-Directed Physics Engine.
 */

// Application State
const state = {
  events: [],
  detections: [],
  clusters: [],
  explanations: [],
  threatIntel: {},
  evidenceGraphs: {},
  reports: {},
  activeClusterId: null,
  mitreDb: [],
  activeTechniqueIds: new Set(),
  graphNodes: [],
  graphEdges: [],
  selectedNode: null,
  hoveredNode: null,
  transform: { x: 0, y: 0, scale: 1.0 },
  isDraggingCanvas: false,
  draggedNode: null,
  dragStart: { x: 0, y: 0 }
};

// Canvas & Physics Configuration
const canvas = document.getElementById('threatCanvas');
const ctx = canvas.getContext('2d');
let animationFrameId = null;

function resizeCanvas() {
  const rect = canvas.parentElement.getBoundingClientRect();
  canvas.width = rect.width;
  canvas.height = rect.height - 45; // subtract header
}
window.addEventListener('resize', () => {
  resizeCanvas();
  renderGraph();
});

// Physics parameters
const PHYSICS = {
  repulsion: 800,
  springLength: 85,
  springStrength: 0.05,
  centering: 0.015,
  damping: 0.88,
  minVelocity: 0.02
};

// Attack Presets Data
const PRESETS = {
  syn_flood: {
    modality: "network",
    data: {
      src_ip: "185.220.101.5",
      dst_ip: "192.168.1.100",
      duration: 0.02,
      src_bytes: 0,
      dst_bytes: 0,
      count: 450,
      srv_count: 5,
      same_srv_rate: 0.02,
      diff_srv_rate: 0.98,
      dst_host_srv_count: 2,
      protocol_type: "tcp",
      service: "private",
      flag: "S0"
    }
  },
  phish_email: {
    modality: "message",
    data: {
      sender: "security-team@login-update-auth-service.com",
      subject: "URGENT: Corporate Account Verification Notice",
      body: "Security alert: unauthorized login detected. Verify your credentials immediately or access is terminated: https://login-update-auth-service.com/login",
      has_attachment: true
    }
  },
  c2_beacon: {
    modality: "url",
    data: {
      url: "http://185.220.101.5:8080/beacon/stage2.bin",
      referrer: "https://login-update-auth-service.com/login"
    }
  },
  ssh_brute: {
    modality: "log",
    data: {
      log_line: "Failed password for root from 185.220.101.5 port 58922 ssh2. Sudo privileges requested with whoami probe.",
      failed_auth_count: 35,
      user: "root",
      severity: 1
    }
  },
  benign_web: {
    modality: "network",
    data: {
      src_ip: "192.168.1.45",
      dst_ip: "142.250.190.46",
      duration: 1.25,
      src_bytes: 350,
      dst_bytes: 3200,
      count: 4,
      srv_count: 5,
      same_srv_rate: 1.0,
      diff_srv_rate: 0.0,
      dst_host_srv_count: 150,
      protocol_type: "tcp",
      service: "http",
      flag: "SF"
    }
  }
};

// Initialization
document.addEventListener('DOMContentLoaded', async () => {
  resizeCanvas();
  setupNavigation();
  setupFormModalityHandlers();
  setupCanvasInteraction();
  await loadMitreTechniques();
  await checkHealthAndStats();
  await loadHistory();
  startPhysicsLoop();

  // Run initial demo on startup for instant hackathon showcase
  await runDemo();
});

// Tab Navigation
function setupNavigation() {
  const tabs = document.querySelectorAll('.tab-btn');
  tabs.forEach(btn => {
    btn.addEventListener('click', () => {
      tabs.forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
      btn.classList.add('active');
      const targetPane = document.getElementById(btn.dataset.tab);
      if (targetPane) targetPane.classList.add('active');
      if (btn.dataset.tab === 'tab-graph') {
        setTimeout(resizeCanvas, 50);
      }
    });
  });

  // Demo Button
  document.getElementById('btn-run-demo').addEventListener('click', runDemo);
  // Copy Report Button
  document.getElementById('btn-copy-report').addEventListener('click', copyReport);
  // Refresh History
  document.getElementById('btn-refresh-history').addEventListener('click', loadHistory);
}

// Check Health & DB Stats
async function checkHealthAndStats() {
  try {
    const res = await fetch('/api/health');
    const health = await res.json();
    if (health.status === 'healthy') {
      document.getElementById('pipeline-status').innerText = 'Core Pipeline Online (XAI Ready)';
    }

    const sRes = await fetch('/api/stats');
    const stats = await sRes.json();
    document.getElementById('kpi-events').innerText = stats.total_events || 0;
    document.getElementById('kpi-incidents').innerText = stats.total_incidents || 0;
    document.getElementById('kpi-iocs').innerText = stats.tracked_malicious_iocs || 0;
  } catch (err) {
    console.warn("Status check notice:", err);
  }
}

// Load MITRE ATT&CK Matrix
async function loadMitreTechniques() {
  try {
    const res = await fetch('/api/mitre');
    const data = await res.json();
    state.mitreDb = data.techniques || [];
    renderMitreGrid();
  } catch (err) {
    console.error("Failed to load MITRE techniques:", err);
  }
}

function renderMitreGrid() {
  const grid = document.getElementById('mitre-grid');
  if (!grid) return;
  grid.innerHTML = '';

  state.mitreDb.forEach(t => {
    const isActive = state.activeTechniqueIds.has(t.technique_id);
    const card = document.createElement('div');
    card.className = `mitre-card ${isActive ? 'active-technique' : ''}`;
    card.innerHTML = `
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.4rem;">
        <span style="font-weight:700; color:var(--text-main); font-family:var(--font-mono);">${t.technique_id}</span>
        <span class="mitre-tactic-badge">${t.tactic}</span>
      </div>
      <div style="font-weight:600; font-size:0.85rem; margin-bottom:0.4rem; color:${isActive ? '#fbbf24' : 'var(--text-main)'};">${t.technique_name}</div>
      <p style="font-size:0.75rem; color:var(--text-muted); line-height:1.4;">${t.description}</p>
    `;
    grid.appendChild(card);
  });
}

// Setup Form Modality Switcher
function setupFormModalityHandlers() {
  const select = document.getElementById('event-modality');
  select.addEventListener('change', () => renderFormFields(select.value));
  renderFormFields('network');

  // Preset Buttons
  document.querySelectorAll('.preset-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const preset = PRESETS[btn.dataset.preset];
      if (preset) {
        select.value = preset.modality;
        renderFormFields(preset.modality, preset.data);
      }
    });
  });

  // Submit Button
  document.getElementById('btn-submit-event').addEventListener('click', submitCustomEvent);
}

function renderFormFields(modality, data = {}) {
  const container = document.getElementById('dynamic-form-fields');
  if (modality === 'network') {
    container.innerHTML = `
      <div class="form-row">
        <div class="form-group"><label>Source IP</label><input id="net-src-ip" class="form-control" value="${data.src_ip || '185.220.101.5'}"></div>
        <div class="form-group"><label>Destination IP</label><input id="net-dst-ip" class="form-control" value="${data.dst_ip || '10.0.0.12'}"></div>
      </div>
      <div class="form-row">
        <div class="form-group"><label>Duration (s)</label><input type="number" id="net-duration" class="form-control" value="${data.duration ?? 0.05}"></div>
        <div class="form-group"><label>Connection Count (past 2s)</label><input type="number" id="net-count" class="form-control" value="${data.count ?? 380}"></div>
      </div>
      <div class="form-row">
        <div class="form-group"><label>Source Bytes</label><input type="number" id="net-src-bytes" class="form-control" value="${data.src_bytes ?? 0}"></div>
        <div class="form-group"><label>Destination Bytes</label><input type="number" id="net-dst-bytes" class="form-control" value="${data.dst_bytes ?? 0}"></div>
      </div>
      <div class="form-row">
        <div class="form-group"><label>Same Service Rate (0-1)</label><input type="number" step="0.01" id="net-same-srv" class="form-control" value="${data.same_srv_rate ?? 0.05}"></div>
        <div class="form-group"><label>Diff Service Rate (0-1)</label><input type="number" step="0.01" id="net-diff-srv" class="form-control" value="${data.diff_srv_rate ?? 0.95}"></div>
      </div>
    `;
  } else if (modality === 'message') {
    container.innerHTML = `
      <div class="form-group"><label>Sender Email</label><input id="msg-sender" class="form-control" value="${data.sender || 'security@login-update-auth-service.com'}"></div>
      <div class="form-group"><label>Subject</label><input id="msg-subject" class="form-control" value="${data.subject || 'URGENT: Password Expiration Notice'}"></div>
      <div class="form-group"><label>Body Content</label><textarea id="msg-body" class="form-control" rows="3">${data.body || 'Immediate verification required. Verify password here: https://login-update-auth-service.com/login'}</textarea></div>
    `;
  } else if (modality === 'url') {
    container.innerHTML = `
      <div class="form-group"><label>URL Target</label><input id="url-target" class="form-control" value="${data.url || 'http://185.220.101.5:8080/beacon.ps1'}"></div>
      <div class="form-group"><label>Referrer</label><input id="url-referrer" class="form-control" value="${data.referrer || 'https://login-update-auth-service.com'}"></div>
    `;
  } else if (modality === 'log') {
    container.innerHTML = `
      <div class="form-group"><label>Raw Log Line</label><textarea id="log-line" class="form-control" rows="2">${data.log_line || 'Failed password for root from 185.220.101.5 port 45212 ssh2'}</textarea></div>
      <div class="form-row">
        <div class="form-group"><label>Failed Auth Attempts</label><input type="number" id="log-failed-count" class="form-control" value="${data.failed_auth_count ?? 25}"></div>
        <div class="form-group"><label>Target User</label><input id="log-user" class="form-control" value="${data.user || 'root'}"></div>
      </div>
    `;
  } else if (modality === 'file') {
    container.innerHTML = `
      <div class="form-group"><label>Filename</label><input id="file-name" class="form-control" value="${data.file_name || 'invoice.pdf.exe'}"></div>
      <div class="form-row">
        <div class="form-group"><label>Entropy (0.0 - 8.0)</label><input type="number" step="0.1" id="file-entropy" class="form-control" value="${data.entropy ?? 7.6}"></div>
        <div class="form-group"><label>SHA256 Hash</label><input id="file-hash" class="form-control" value="${data.hash || '44d88612fea8a8f36de82e1278abb02f'}"></div>
      </div>
    `;
  }
}

// Ingestion Submission
async function submitCustomEvent() {
  const modality = document.getElementById('event-modality').value;
  let rawEvent = { event_type: modality };

  if (modality === 'network') {
    rawEvent = {
      ...rawEvent,
      src_ip: document.getElementById('net-src-ip').value,
      dst_ip: document.getElementById('net-dst-ip').value,
      duration: parseFloat(document.getElementById('net-duration').value),
      count: parseFloat(document.getElementById('net-count').value),
      src_bytes: parseFloat(document.getElementById('net-src-bytes').value),
      dst_bytes: parseFloat(document.getElementById('net-dst-bytes').value),
      same_srv_rate: parseFloat(document.getElementById('net-same-srv').value),
      diff_srv_rate: parseFloat(document.getElementById('net-diff-srv').value),
      srv_count: 5,
      dst_host_srv_count: 10
    };
  } else if (modality === 'message') {
    rawEvent = {
      ...rawEvent,
      sender: document.getElementById('msg-sender').value,
      subject: document.getElementById('msg-subject').value,
      body: document.getElementById('msg-body').value,
      has_attachment: true
    };
  } else if (modality === 'url') {
    rawEvent = {
      ...rawEvent,
      url: document.getElementById('url-target').value,
      referrer: document.getElementById('url-referrer').value
    };
  } else if (modality === 'log') {
    rawEvent = {
      ...rawEvent,
      log_line: document.getElementById('log-line').value,
      failed_auth_count: parseFloat(document.getElementById('log-failed-count').value),
      user: document.getElementById('log-user').value
    };
  } else if (modality === 'file') {
    rawEvent = {
      ...rawEvent,
      file_name: document.getElementById('file-name').value,
      entropy: parseFloat(document.getElementById('file-entropy').value),
      hash: document.getElementById('file-hash').value
    };
  }

  try {
    const res = await fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ events: [rawEvent] })
    });
    const result = await res.json();
    processAnalysisResponse(result);
    // Switch to graph tab
    document.querySelector('[data-tab="tab-graph"]').click();
  } catch (err) {
    alert("Analysis failed: " + err.message);
  }
}

// Run Multi-Stage Attack Demo
async function runDemo() {
  try {
    const btn = document.getElementById('btn-run-demo');
    btn.innerHTML = '<span>⏳ Simulating Attack...</span>';
    btn.disabled = true;

    const res = await fetch('/api/demo');
    const result = await res.json();
    processAnalysisResponse(result);

    btn.innerHTML = '<span>⚡ Run Multi-Stage Attack Demo</span>';
    btn.disabled = false;
  } catch (err) {
    console.error("Demo failed:", err);
  }
}

// Process Pipeline Response
function processAnalysisResponse(data) {
  state.events = data.events || [];
  state.detections = data.detections || [];
  state.clusters = data.clusters || [];
  state.explanations = data.explanations || [];
  state.threatIntel = data.threat_intel || {};
  state.evidenceGraphs = data.evidence_graphs || {};
  state.reports = data.reports || {};

  // Update KPIs
  document.getElementById('kpi-events').innerText = state.events.length;
  document.getElementById('kpi-incidents').innerText = state.clusters.length;

  let malIocs = 0;
  Object.values(state.threatIntel).forEach(t => { if (t.is_malicious) malIocs++; });
  document.getElementById('kpi-iocs').innerText = malIocs;

  // Track active MITRE techniques
  state.activeTechniqueIds.clear();
  state.clusters.forEach(c => {
    c.mitre_techniques.forEach(t => state.activeTechniqueIds.add(t.technique_id));
  });
  renderMitreGrid();

  // Update Pipeline Feed
  renderPipelineFeed();

  // Populate Graph
  buildCanvasGraph(data.threat_graph);

  // Update XAI drawer & cluster list
  renderClusterList();

  // Default select first critical incident
  if (state.clusters.length > 0) {
    selectCluster(state.clusters[0].cluster_id);
  }

  // Refresh DB history
  loadHistory();
}

function renderPipelineFeed() {
  const feed = document.getElementById('pipeline-feed');
  feed.innerHTML = '';

  const detMap = {};
  state.detections.forEach(d => detMap[d.event_id] = d);

  state.events.forEach(ev => {
    const det = detMap[ev.event_id];
    const isMal = det ? det.is_malicious : false;
    const item = document.createElement('div');
    item.style.padding = '0.75rem';
    item.style.borderRadius = '6px';
    item.style.marginBottom = '0.5rem';
    item.style.backgroundColor = 'var(--bg-secondary)';
    item.style.borderLeft = `4px solid ${isMal ? 'var(--threat-critical)' : 'var(--threat-clean)'}`;
    item.innerHTML = `
      <div style="display:flex; justify-content:space-between; margin-bottom:0.25rem;">
        <strong style="font-size:0.8rem; text-transform:uppercase;">${ev.event_type}</strong>
        <span style="font-size:0.75rem; color:${isMal ? 'var(--threat-critical)' : 'var(--threat-clean)'}; font-weight:700;">
          ${det ? det.severity : 'CLEAN'} (${det ? (det.confidence * 100).toFixed(0) : 100}%)
        </span>
      </div>
      <div style="font-size:0.75rem; color:var(--text-muted); font-family:var(--font-mono);">${ev.event_id}</div>
      <div style="font-size:0.78rem; margin-top:0.25rem;">${det ? det.explanation_summary : 'Telemetry baseline normal'}</div>
    `;
    feed.appendChild(item);
  });
}

function renderClusterList() {
  const list = document.getElementById('cluster-list');
  list.innerHTML = '';

  state.clusters.forEach(c => {
    const item = document.createElement('div');
    item.className = 'xai-card';
    item.style.cursor = 'pointer';
    item.style.borderLeft = `4px solid ${c.risk_score > 0.6 ? 'var(--threat-critical)' : 'var(--threat-high)'}`;
    item.innerHTML = `
      <div style="display:flex; justify-content:space-between; align-items:center;">
        <strong>${c.cluster_id}</strong>
        <span class="badge" style="color:var(--threat-critical); font-weight:700;">Risk: ${(c.risk_score * 100).toFixed(0)}%</span>
      </div>
      <p style="font-size:0.8rem; margin-top:0.4rem; color:var(--text-muted);">${c.attack_summary}</p>
    `;
    item.addEventListener('click', () => selectCluster(c.cluster_id));
    list.appendChild(item);
  });
}

function selectCluster(clusterId) {
  state.activeClusterId = clusterId;
  const cluster = state.clusters.find(c => c.cluster_id === clusterId);
  if (!cluster) return;

  // Report view
  const reportView = document.getElementById('report-view');
  reportView.innerText = state.reports[clusterId] || "Report generating...";

  // Alibi Rules
  const alibiContainer = document.getElementById('alibi-rules-container');
  alibiContainer.innerHTML = '';
  const expMap = {};
  state.explanations.forEach(x => expMap[x.event_id] = x);

  cluster.event_ids.forEach(eid => {
    const exp = expMap[eid];
    if (exp && exp.anchor_rules && exp.anchor_rules.length > 0) {
      exp.anchor_rules.forEach(rule => {
        const div = document.createElement('div');
        div.className = 'anchor-rule-tag';
        div.innerHTML = `<strong>[Event ${eid.slice(0, 8)}] IF</strong> ${rule} <strong>-> ${exp.prediction_label.toUpperCase()}</strong> (Precision: ${(exp.anchor_precision * 100).toFixed(0)}%)`;
        alibiContainer.appendChild(div);
      });
    }
  });

  // DiCE Counterfactuals
  const diceContainer = document.getElementById('dice-cf-container');
  diceContainer.innerHTML = '';
  cluster.event_ids.forEach(eid => {
    const exp = expMap[eid];
    if (exp && exp.counterfactuals && exp.counterfactuals.length > 0) {
      exp.counterfactuals.forEach(cf => {
        const box = document.createElement('div');
        box.className = 'cf-box';
        let rows = `<div style="font-weight:600; margin-bottom:0.3rem; color:var(--accent-cyan);">${cf.explanation}</div>`;
        for (const [feat, diff] of Object.entries(cf.feature_changes || {})) {
          rows += `
            <div class="cf-delta-row">
              <span>${feat}</span>
              <span>${diff.original} ➔ <strong>${diff.required_to_flip}</strong> (Δ ${diff.delta > 0 ? '+' : ''}${diff.delta})</span>
            </div>
          `;
        }
        box.innerHTML = rows;
        diceContainer.appendChild(box);
      });
    }
  });
}

function copyReport() {
  const text = document.getElementById('report-view').innerText;
  navigator.clipboard.writeText(text).then(() => {
    alert("Incident report markdown copied to clipboard!");
  });
}

async function loadHistory() {
  try {
    const res = await fetch('/api/incidents');
    const data = await res.json();
    const tbody = document.getElementById('history-table-body');
    tbody.innerHTML = '';

    if (!data.incidents || data.incidents.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" class="placeholder-text">No incidents recorded in database.</td></tr>`;
      return;
    }

    data.incidents.forEach(inc => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td style="font-family:var(--font-mono); font-weight:700;">${inc.incident_id}</td>
        <td style="font-size:0.75rem;">${new Date(inc.created_at).toLocaleTimeString()}</td>
        <td><span style="color:${inc.risk_score > 0.6 ? 'var(--threat-critical)' : 'var(--threat-high)'}; font-weight:700;">${(inc.risk_score * 100).toFixed(0)}%</span></td>
        <td>${inc.event_ids.length}</td>
        <td>${inc.shared_iocs.length}</td>
        <td style="font-size:0.75rem; max-width:280px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${inc.attack_summary}</td>
        <td><button class="btn btn-xs btn-outline" onclick="viewHistoryReport('${inc.incident_id}')">Inspect</button></td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error("Failed to load history:", err);
  }
}

window.viewHistoryReport = async function(incidentId) {
  try {
    const res = await fetch(`/api/incidents/${incidentId}`);
    const inc = await res.json();
    document.querySelector('[data-tab="tab-xai"]').click();
    document.getElementById('report-view').innerText = inc.report_markdown;
  } catch (err) {
    alert("Could not load report");
  }
};

// ==========================================
// FORCE-DIRECTED CANVAS GRAPH PHYSICS ENGINE
// ==========================================

function buildCanvasGraph(rawGraph) {
  state.graphNodes = [];
  state.graphEdges = [];
  const nodeMap = new Map();

  const centerX = canvas.width / 2;
  const centerY = canvas.height / 2;

  (rawGraph.nodes || []).forEach((n, idx) => {
    const angle = (idx / rawGraph.nodes.length) * Math.PI * 2;
    const radius = 120 + Math.random() * 80;

    let color = '#06b6d4';
    let size = 10;
    if (n.node_type === 'cluster') { color = '#f97316'; size = 18; }
    else if (n.node_type === 'event') { color = n.is_malicious ? '#ef4444' : '#10b981'; size = 14; }
    else if (n.node_type === 'ioc') { color = n.is_malicious ? '#ef4444' : '#06b6d4'; size = 11; }
    else if (n.node_type === 'mitre') { color = '#fbbf24'; size = 12; }
    else if (n.node_type === 'explanation') { color = '#a855f7'; size = 10; }

    const node = {
      id: n.id,
      label: n.label || n.id,
      type: n.node_type || 'node',
      color: color,
      radius: size,
      x: centerX + Math.cos(angle) * radius,
      y: centerY + Math.sin(angle) * radius,
      vx: 0,
      vy: 0,
      data: n
    };
    nodeMap.set(n.id, node);
    state.graphNodes.push(node);
  });

  (rawGraph.edges || []).forEach(e => {
    const source = nodeMap.get(e.source);
    const target = nodeMap.get(e.target);
    if (source && target) {
      state.graphEdges.push({
        source,
        target,
        relation: e.relation || ''
      });
    }
  });

  state.transform = { x: 0, y: 0, scale: 1.0 };
}

function updatePhysics() {
  const nodes = state.graphNodes;
  const edges = state.graphEdges;
  const centerX = canvas.width / 2;
  const centerY = canvas.height / 2;

  // 1. Node Repulsion
  for (let i = 0; i < nodes.length; i++) {
    for (let j = i + 1; j < nodes.length; j++) {
      const n1 = nodes[i];
      const n2 = nodes[j];
      const dx = n2.x - n1.x;
      const dy = n2.y - n1.y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 1;
      const force = (PHYSICS.repulsion * 50) / (dist * dist);
      const fx = (dx / dist) * force;
      const fy = (dy / dist) * force;

      n1.vx -= fx;
      n1.vy -= fy;
      n2.vx += fx;
      n2.vy += fy;
    }
  }

  // 2. Edge Spring Attraction
  for (let i = 0; i < edges.length; i++) {
    const e = edges[i];
    const dx = e.target.x - e.source.x;
    const dy = e.target.y - e.source.y;
    const dist = Math.sqrt(dx * dx + dy * dy) || 1;
    const displacement = dist - PHYSICS.springLength;
    const force = displacement * PHYSICS.springStrength;
    const fx = (dx / dist) * force;
    const fy = (dy / dist) * force;

    e.source.vx += fx;
    e.source.vy += fy;
    e.target.vx -= fx;
    e.target.vy -= fy;
  }

  // 3. Center Gravity & Position update
  for (let i = 0; i < nodes.length; i++) {
    const n = nodes[i];
    if (n === state.draggedNode) continue;

    n.vx += (centerX - n.x) * PHYSICS.centering;
    n.vy += (centerY - n.y) * PHYSICS.centering;

    n.vx *= PHYSICS.damping;
    n.vy *= PHYSICS.damping;

    n.x += n.vx;
    n.y += n.vy;
  }
}

function renderGraph() {
  ctx.save();
  ctx.clearRect(0, 0, canvas.width, canvas.height);

  // Apply pan & zoom transform
  ctx.translate(state.transform.x, state.transform.y);
  ctx.scale(state.transform.scale, state.transform.scale);

  // Draw Edges
  state.graphEdges.forEach(e => {
    ctx.beginPath();
    ctx.moveTo(e.source.x, e.source.y);
    ctx.lineTo(e.target.x, e.target.y);
    ctx.strokeStyle = 'rgba(75, 95, 130, 0.4)';
    ctx.lineWidth = 1.5;
    ctx.stroke();

    // Draw relation badge if long enough
    const midX = (e.source.x + e.target.x) / 2;
    const midY = (e.source.y + e.target.y) / 2;
    if (e.relation) {
      ctx.fillStyle = 'rgba(148, 163, 184, 0.6)';
      ctx.font = '9px "JetBrains Mono"';
      ctx.textAlign = 'center';
      ctx.fillText(e.relation, midX, midY - 3);
    }
  });

  // Draw Nodes
  state.graphNodes.forEach(n => {
    const isSelected = (state.selectedNode === n);
    const isHovered = (state.hoveredNode === n);

    // Glow effect
    if (isSelected || isHovered) {
      ctx.beginPath();
      ctx.arc(n.x, n.y, n.radius + 6, 0, Math.PI * 2);
      ctx.fillStyle = n.color + '44';
      ctx.fill();
    }

    // Node body
    ctx.beginPath();
    ctx.arc(n.x, n.y, n.radius, 0, Math.PI * 2);
    ctx.fillStyle = n.color;
    ctx.fill();
    ctx.strokeStyle = isSelected ? '#ffffff' : '#0a0d14';
    ctx.lineWidth = isSelected ? 2.5 : 1.5;
    ctx.stroke();

    // Node label
    ctx.fillStyle = '#e2e8f0';
    ctx.font = '11px "Inter", sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText(n.label.slice(0, 20), n.x, n.y + n.radius + 14);
  });

  ctx.restore();
}

function startPhysicsLoop() {
  function loop() {
    updatePhysics();
    renderGraph();
    animationFrameId = requestAnimationFrame(loop);
  }
  loop();
}

// Canvas Interaction (Pan, Zoom, Drag, Inspect)
function setupCanvasInteraction() {
  document.getElementById('btn-zoom-in').addEventListener('click', () => {
    state.transform.scale = Math.min(2.5, state.transform.scale * 1.2);
  });
  document.getElementById('btn-zoom-out').addEventListener('click', () => {
    state.transform.scale = Math.max(0.4, state.transform.scale / 1.2);
  });
  document.getElementById('btn-reset-graph').addEventListener('click', () => {
    state.transform = { x: 0, y: 0, scale: 1.0 };
  });

  canvas.addEventListener('wheel', e => {
    e.preventDefault();
    const zoomFactor = e.deltaY < 0 ? 1.1 : 0.9;
    state.transform.scale = Math.max(0.3, Math.min(3.0, state.transform.scale * zoomFactor));
  });

  canvas.addEventListener('mousedown', e => {
    const mousePos = getCanvasMousePos(e);
    const hit = findNodeAt(mousePos.x, mousePos.y);

    if (hit) {
      state.draggedNode = hit;
      state.selectedNode = hit;
      inspectNode(hit);
    } else {
      state.isDraggingCanvas = true;
      state.dragStart = { x: e.clientX - state.transform.x, y: e.clientY - state.transform.y };
    }
  });

  window.addEventListener('mousemove', e => {
    if (state.draggedNode) {
      const mousePos = getCanvasMousePos(e);
      state.draggedNode.x = mousePos.x;
      state.draggedNode.y = mousePos.y;
      state.draggedNode.vx = 0;
      state.draggedNode.vy = 0;
    } else if (state.isDraggingCanvas) {
      state.transform.x = e.clientX - state.dragStart.x;
      state.transform.y = e.clientY - state.dragStart.y;
    } else {
      const mousePos = getCanvasMousePos(e);
      state.hoveredNode = findNodeAt(mousePos.x, mousePos.y);
    }
  });

  window.addEventListener('mouseup', () => {
    state.draggedNode = null;
    state.isDraggingCanvas = false;
  });
}

function getCanvasMousePos(e) {
  const rect = canvas.getBoundingClientRect();
  const rawX = e.clientX - rect.left;
  const rawY = e.clientY - rect.top;
  return {
    x: (rawX - state.transform.x) / state.transform.scale,
    y: (rawY - state.transform.y) / state.transform.scale
  };
}

function findNodeAt(x, y) {
  for (let i = state.graphNodes.length - 1; i >= 0; i--) {
    const n = state.graphNodes[i];
    const dx = n.x - x;
    const dy = n.y - y;
    if (dx * dx + dy * dy <= (n.radius + 5) * (n.radius + 5)) {
      return n;
    }
  }
  return null;
}

function inspectNode(node) {
  const badge = document.getElementById('insp-type');
  const body = document.getElementById('insp-content');
  badge.innerText = node.type.toUpperCase();

  let html = `<h4 style="color:${node.color}; margin-bottom:0.5rem;">${node.label}</h4>`;
  const d = node.data || {};

  if (node.type === 'event') {
    html += `
      <p><strong>Modality:</strong> ${d.modality || 'network'}</p>
      <p><strong>Classification:</strong> ${d.is_malicious ? '🔴 MALICIOUS' : '🟢 BENIGN'}</p>
      <p><strong>Confidence:</strong> ${(d.confidence * 100).toFixed(1)}%</p>
      <p><strong>Severity:</strong> ${d.severity || 'INFO'}</p>
    `;
  } else if (node.type === 'ioc') {
    const intel = state.threatIntel[d.ioc] || {};
    html += `
      <p><strong>IOC Value:</strong> <code>${d.ioc}</code></p>
      <p><strong>Reputation:</strong> ${(d.reputation_score * 100).toFixed(0)}%</p>
      <p><strong>Status:</strong> ${d.is_malicious ? '🔴 CONFIRMED MALICIOUS' : '🟢 CLEAN'}</p>
      <p><strong>Source:</strong> ${d.source || 'Threat Intel'}</p>
      ${intel.country ? `<p><strong>Country:</strong> ${intel.country}</p>` : ''}
      ${intel.isp_or_owner ? `<p><strong>ISP / Owner:</strong> ${intel.isp_or_owner}</p>` : ''}
    `;
  } else if (node.type === 'mitre') {
    html += `
      <p><strong>Technique ID:</strong> ${d.technique_id}</p>
      <p><strong>Tactic:</strong> ${d.tactic}</p>
      <p><strong>Kill Chain Stage:</strong> Phase ${d.kill_chain_stage || 1}</p>
    `;
  } else if (node.type === 'explanation') {
    html += `
      <p><strong>Alibi Anchor Rule:</strong></p>
      <div class="anchor-rule-tag">${d.full_rule || node.label}</div>
      <p><strong>Rule Precision:</strong> ${(d.precision * 100).toFixed(0)}%</p>
    `;
  } else if (node.type === 'cluster') {
    html += `
      <p><strong>Campaign Risk:</strong> ${(d.risk_score * 100).toFixed(0)}%</p>
      <p><strong>Summary:</strong> ${d.summary || 'Correlated attack'}</p>
    `;
  }

  body.innerHTML = html;
}
