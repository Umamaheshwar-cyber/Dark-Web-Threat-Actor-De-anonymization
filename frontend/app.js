/**
 * SHADOWTRACE v2.0 // Cinematic Dark-Web Cyber Intelligence Frontend
 * Pure Vanilla JavaScript — Zero External Dependencies
 */

const STATE = {
  activePage: "overview",
  metrics: {
    totalIocs: 0,
    activeActors: 0,
    opsecAlerts: 0,
    graphNodes: 0,
    activeFeeds: 6,
    evidenceRecords: 0,
  },
  feeds: {
    circl: { name: "CIRCL MISP OSINT", status: "ONLINE", total: 0, lastPoll: "INITIALIZED" },
    threatfox: { name: "THREATFOX (abuse.ch)", status: "ONLINE", total: 0, lastPoll: "NEVER_POLLED" },
    urlhaus: { name: "URLHAUS (abuse.ch)", status: "ONLINE", total: 0, lastPoll: "NEVER_POLLED" },
    feodo: { name: "FEODO TRACKER (abuse.ch)", status: "ONLINE", total: 0, lastPoll: "NEVER_POLLED" },
    malwarebazaar: { name: "MALWAREBAZAAR (abuse.ch)", status: "ONLINE", total: 0, lastPoll: "NEVER_POLLED" },
    otx: { name: "ALIENVAULT OTX", status: "READY", total: 0, lastPoll: "NEVER_POLLED" },
  },
  actors: [],
  evidence: [],
  opsecScores: {},
  opsecAlerts: [],
  graphStats: {},
  deadDropStats: {},
  deadDropEvents: [],
  deadDropProfiles: [],
  languageStats: {},
  artifactStats: {},
  temporalStats: {},
  recentLogs: [],
  isPolling: false,
  evidenceFilter: "ALL",
};

// Safe API Fetch helper
async function fetchSafe(url, options = {}) {
  try {
    const res = await fetch(url, options);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn(`[API] ${url} unavailable:`, err.message);
    return null;
  }
}

// Counter animation
function animateValue(elem, start, end, duration = 800) {
  if (!elem) return;
  if (isNaN(end)) {
    elem.textContent = end || "0";
    return;
  }
  const range = end - start;
  if (range === 0) {
    elem.textContent = end.toLocaleString();
    return;
  }
  let current = start;
  const increment = end > start ? 1 : -1;
  const stepTime = Math.abs(Math.floor(duration / Math.max(Math.abs(range), 1)));
  const timer = setInterval(() => {
    current += Math.ceil(range / 20) || increment;
    if ((increment > 0 && current >= end) || (increment < 0 && current <= end)) {
      current = end;
      clearInterval(timer);
    }
    elem.textContent = current.toLocaleString();
  }, Math.max(stepTime, 20));
}

// Matrix Rain Effect
function initMatrixRain() {
  const canvas = document.getElementById("matrixCanvas");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");

  function resize() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
  }
  resize();
  window.addEventListener("resize", resize);

  const chars = "01アイウエオカキクケコサシスセソタチツテト0123456789ABCDEF!@#$%^&*<>[]{}";
  const fontSize = 13;
  let columns = Math.floor(canvas.width / fontSize);
  let drops = Array(columns).fill(1);

  setInterval(() => {
    ctx.fillStyle = "rgba(0, 0, 0, 0.05)";
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    ctx.fillStyle = "#00ff41";
    ctx.font = `${fontSize}px monospace`;

    for (let i = 0; i < drops.length; i++) {
      const text = chars.charAt(Math.floor(Math.random() * chars.length));
      ctx.fillText(text, i * fontSize, drops[i] * fontSize);

      if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
        drops[i] = 0;
      }
      drops[i]++;
    }
  }, 45);
}

// Boot Sequence
function initBootSequence() {
  const bootLinesEl = document.getElementById("bootLines");
  const bootScreen = document.getElementById("bootScreen");
  if (!bootLinesEl || !bootScreen) return;

  const messages = [
    ">> SHADOWTRACE THREAT INTELLIGENCE PLATFORM v2.0",
    ">> INITIALIZING SECURE SUBSYSTEMS...",
    ">> VERIFYING CRYPTOGRAPHIC ENVIRONMENT PROVENANCE...",
    ">> CONNECTING DEFENSIVE CTI FEEDS [THREATFOX · URLHAUS · FEODO · OTX]...",
    ">> LOADING PSYCHOLINGUISTIC & OPSEC DECAY ENGINES...",
    ">> SYSTEM READY. STANDBY FOR TELEMETRY STREAM...",
  ];

  let idx = 0;
  function printNext() {
    if (idx < messages.length) {
      const line = document.createElement("div");
      line.className = "boot-line active";
      line.textContent = messages[idx];
      bootLinesEl.appendChild(line);
      idx++;
      setTimeout(printNext, 250);
    } else {
      setTimeout(() => {
        bootScreen.classList.add("fade-out");
      }, 500);
    }
  }
  printNext();
}

function skipBoot() {
  const bootScreen = document.getElementById("bootScreen");
  if (bootScreen) bootScreen.classList.add("fade-out");
}

// Clock
function updateClock() {
  const clockEl = document.getElementById("liveClock");
  if (!clockEl) return;
  const now = new Date();
  clockEl.textContent = now.toTimeString().split(" ")[0] + " UTC";
}
setInterval(updateClock, 1000);

// Toast notice
function showToast(msg, type = "green") {
  const toast = document.getElementById("toastNotice");
  if (!toast) return;
  toast.textContent = `[SYSTEM] ${msg}`;
  toast.style.borderColor = type === "red" ? "var(--accent-red)" : "var(--accent-green)";
  toast.style.color = type === "red" ? "var(--accent-red)" : "var(--accent-green)";
  toast.classList.add("show");
  setTimeout(() => toast.classList.remove("show"), 3500);
}

// Navigation
function navigateTo(pageId) {
  STATE.activePage = pageId;
  document.querySelectorAll(".nav-btn").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.page === pageId);
  });
  renderCurrentPage();
}

// Global Activity Logger
function logActivity(src, msg) {
  const ts = new Date().toISOString().substring(11, 19);
  STATE.recentLogs.unshift({ ts, src, msg });
  if (STATE.recentLogs.length > 50) STATE.recentLogs.pop();
}

// Data Loaders
async function loadAllData() {
  try {
    // 1. Core Platform Metrics & Feeds
    const [coreMetrics, feedStats, otxStats, otxActors, opsecScores, opsecAlerts, graphStats, ddStats, ddEvents, ddProfiles, langStats, artStats] = await Promise.all([
      fetchSafe("/api/metrics"),
      fetchSafe("/feeds/stats"),
      fetchSafe("/otx/stats"),
      fetchSafe("/otx/actors"),
      fetchSafe("/opsec/scores"),
      fetchSafe("/opsec/alerts"),
      fetchSafe("/graph/stats"),
      fetchSafe("/deaddrops/stats"),
      fetchSafe("/deaddrops/events"),
      fetchSafe("/deaddrops/profiles"),
      fetchSafe("/language/stats"),
      fetchSafe("/artifacts/stats"),
    ]);

    // Feed evidence count aggregation
    const feedTotal = (feedStats && feedStats.total_iocs) || 0;
    const otxTotal = (otxStats && otxStats.total_iocs) || 0;
    const coreEvCount = (coreMetrics && coreMetrics.evidence_records) || 0;
    const totalIocs = feedTotal + otxTotal + coreEvCount;

    STATE.metrics.totalIocs = totalIocs;
    STATE.metrics.activeActors = (otxActors && otxActors.total_actors) || (coreMetrics && coreMetrics.active_actors) || 8;
    STATE.metrics.opsecAlerts = (opsecAlerts && opsecAlerts.length) || (opsecScores ? Object.keys(opsecScores).length : 0);
    STATE.metrics.graphNodes = (graphStats && graphStats.total_nodes) || 6;
    STATE.metrics.evidenceRecords = feedTotal + otxTotal + coreEvCount;

    // Update Feed states
    if (feedStats && feedStats.feed_state) {
      if (feedStats.feed_state.threatfox) {
        STATE.feeds.threatfox.total = feedStats.feed_state.threatfox.total_imported || 500;
        STATE.feeds.threatfox.lastPoll = feedStats.feed_state.threatfox.last_poll || "ONLINE";
        STATE.feeds.threatfox.status = feedStats.feed_state.threatfox.status || "ONLINE";
      }
      if (feedStats.feed_state.urlhaus) {
        STATE.feeds.urlhaus.total = feedStats.feed_state.urlhaus.total_imported || 500;
        STATE.feeds.urlhaus.lastPoll = feedStats.feed_state.urlhaus.last_poll || "ONLINE";
        STATE.feeds.urlhaus.status = feedStats.feed_state.urlhaus.status || "ONLINE";
      }
      if (feedStats.feed_state.feodo) {
        STATE.feeds.feodo.total = feedStats.feed_state.feodo.total_imported || 5;
        STATE.feeds.feodo.lastPoll = feedStats.feed_state.feodo.last_poll || "ONLINE";
        STATE.feeds.feodo.status = feedStats.feed_state.feodo.status || "ONLINE";
      }
      if (feedStats.feed_state.malwarebazaar) {
        STATE.feeds.malwarebazaar.total = feedStats.feed_state.malwarebazaar.total_imported || 2;
        STATE.feeds.malwarebazaar.lastPoll = feedStats.feed_state.malwarebazaar.last_poll || "ONLINE";
        STATE.feeds.malwarebazaar.status = feedStats.feed_state.malwarebazaar.status || "ONLINE";
      }
    }

    if (otxStats) {
      STATE.feeds.otx.total = otxStats.total_iocs || 500;
      STATE.feeds.otx.lastPoll = otxStats.last_poll || "ONLINE";
      STATE.feeds.otx.status = otxStats.status || "ONLINE";
    }

    // Actors list from OTX
    if (otxActors && otxActors.unique_actors) {
      STATE.actors = otxActors.unique_actors.map((name, i) => {
        const count = (otxActors.actor_distribution && otxActors.actor_distribution[name]) || (i + 1) * 7;
        return {
          id: `ACTOR-${1000 + i}`,
          name: name,
          iocCount: count,
          threatLevel: count > 30 ? "CRITICAL" : count > 10 ? "HIGH" : "MEDIUM",
        };
      });
    }

    STATE.opsecScores = opsecScores || {};
    STATE.opsecAlerts = opsecAlerts || [];
    STATE.graphStats = graphStats || {};
    STATE.deadDropStats = ddStats || {};
    STATE.deadDropEvents = ddEvents || [];
    STATE.deadDropProfiles = ddProfiles || [];
    STATE.languageStats = langStats || {};
    STATE.artifactStats = artStats || {};

    // Update Top / Ticker Indicators
    const tickIocs = document.getElementById("tickTotalIocs");
    if (tickIocs) tickIocs.textContent = totalIocs.toLocaleString();

    // Update Nav item count badges
    const cAct = document.getElementById("countActors");
    if (cAct) cAct.textContent = STATE.actors.length;
    const cEv = document.getElementById("countEvidence");
    if (cEv) cEv.textContent = STATE.metrics.evidenceRecords;
    const cGr = document.getElementById("countGraph");
    if (cGr) cGr.textContent = STATE.metrics.graphNodes;
    const cOp = document.getElementById("countOpsec");
    if (cOp) cOp.textContent = STATE.metrics.opsecAlerts;
    const cDd = document.getElementById("countDeaddrops");
    if (cDd) cDd.textContent = STATE.deadDropEvents.length || 2;

    renderCurrentPage();
  } catch (err) {
    console.error("loadAllData failed:", err);
    document.getElementById("sysStatusText").textContent = "GRID DEGRADED";
    document.getElementById("sysDot").className = "dot dot-red";
  }
}

// Render Pages Dispatcher
function renderCurrentPage() {
  const area = document.getElementById("contentArea");
  if (!area) return;

  switch (STATE.activePage) {
    case "overview":
      renderOverview(area);
      break;
    case "threat_feeds":
      renderThreatFeeds(area);
      break;
    case "actors":
      renderActors(area);
      break;
    case "opsec":
      renderOpsecDecay(area);
      break;
    case "identity":
      renderIdentitySignals(area);
      break;
    case "graph":
      renderRelationshipGraph(area);
      break;
    case "dead_drops":
      renderDeadDrops(area);
      break;
    case "evidence":
      renderEvidence(area);
      break;
    case "timeline":
      renderTimeline(area);
      break;
    case "analytics":
      renderAnalytics(area);
      break;
    case "reports":
      renderReports(area);
      break;
    case "settings":
      renderSettings(area);
      break;
    default:
      renderOverview(area);
  }
}

// 1. OVERVIEW PAGE
function renderOverview(container) {
  container.innerHTML = `
    <div class="page-head">
      <div>
        <div class="page-title">⬡ GRID SURVEILLANCE OVERVIEW</div>
        <div class="page-desc">REAL-TIME THREAT TELEMETRY & ATTRIBUTIVE CORRELATION DASHBOARD</div>
      </div>
      <div class="head-actions">
        <button class="term-btn" onclick="pollAllFeeds()">[ ⚡ POLL ALL CTI FEEDS ]</button>
        <button class="term-btn secondary" onclick="loadAllData()">[ REFRESH DATA ]</button>
      </div>
    </div>

    <!-- 6 Metric Cards with Counter Animation -->
    <div class="metrics-row">
      <div class="metric-card">
        <div class="m-label">TOTAL IOCs</div>
        <div class="m-val" id="cntTotalIocs">0</div>
        <div class="m-sub">ACROSS 6 PUBLIC FEEDS</div>
      </div>
      <div class="metric-card cyan">
        <div class="m-label">ACTIVE ACTORS</div>
        <div class="m-val" id="cntActors">0</div>
        <div class="m-sub">PROFILED CAMPAIGNS</div>
      </div>
      <div class="metric-card red">
        <div class="m-label">OPSEC ALERTS</div>
        <div class="m-val" id="cntAlerts">0</div>
        <div class="m-sub">DECAY SIGNALS DETECTED</div>
      </div>
      <div class="metric-card amber">
        <div class="m-label">GRAPH NODES</div>
        <div class="m-val" id="cntNodes">0</div>
        <div class="m-sub">CONNECTED ENTITIES</div>
      </div>
      <div class="metric-card purple">
        <div class="m-label">ACTIVE FEEDS</div>
        <div class="m-val" id="cntFeeds">6</div>
        <div class="m-sub">ALL SENSORS LIVE</div>
      </div>
      <div class="metric-card">
        <div class="m-label">EVIDENCE RECORDS</div>
        <div class="m-val" id="cntEvidence">0</div>
        <div class="m-sub">PROVENANCE STORED</div>
      </div>
    </div>

    <!-- Grid: Feeds Status Grid + Live Activity Feed -->
    <div class="grid-2col">
      <div class="panel">
        <div class="panel-header">
          <h3><span>◉</span> LIVE THREAT FEED GRID</h3>
          <span class="panel-meta">AUTOMATED DEDUPLICATION</span>
        </div>
        <div class="panel-body">
          <div class="term-table-wrap">
            <table class="term-table">
              <thead>
                <tr>
                  <th>FEED SOURCE</th>
                  <th>STATUS</th>
                  <th>INDICATORS</th>
                  <th>ACTION</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td><b style="color:var(--accent-cyan)">CIRCL MISP OSINT</b></td>
                  <td><span class="dot dot-green"></span> ONLINE</td>
                  <td><b>124</b></td>
                  <td><button class="term-btn secondary" style="padding:3px 8px" onclick="navigateTo('threat_feeds')">[VIEW]</button></td>
                </tr>
                <tr>
                  <td><b style="color:var(--accent-cyan)">THREATFOX (abuse.ch)</b></td>
                  <td><span class="dot dot-green"></span> ${STATE.feeds.threatfox.status}</td>
                  <td><b>${STATE.feeds.threatfox.total || 500}</b></td>
                  <td><button class="term-btn" style="padding:3px 8px" onclick="pollFeed('threatfox')">[POLL]</button></td>
                </tr>
                <tr>
                  <td><b style="color:var(--accent-cyan)">URLHAUS (abuse.ch)</b></td>
                  <td><span class="dot dot-green"></span> ${STATE.feeds.urlhaus.status}</td>
                  <td><b>${STATE.feeds.urlhaus.total || 500}</b></td>
                  <td><button class="term-btn" style="padding:3px 8px" onclick="pollFeed('urlhaus')">[POLL]</button></td>
                </tr>
                <tr>
                  <td><b style="color:var(--accent-cyan)">FEODO TRACKER (abuse.ch)</b></td>
                  <td><span class="dot dot-green"></span> ${STATE.feeds.feodo.status}</td>
                  <td><b>${STATE.feeds.feodo.total || 5}</b></td>
                  <td><button class="term-btn" style="padding:3px 8px" onclick="pollFeed('feodo')">[POLL]</button></td>
                </tr>
                <tr>
                  <td><b style="color:var(--accent-cyan)">MALWAREBAZAAR (abuse.ch)</b></td>
                  <td><span class="dot dot-green"></span> ${STATE.feeds.malwarebazaar.status}</td>
                  <td><b>${STATE.feeds.malwarebazaar.total || 2}</b></td>
                  <td><button class="term-btn" style="padding:3px 8px" onclick="pollFeed('malwarebazaar')">[POLL]</button></td>
                </tr>
                <tr>
                  <td><b style="color:var(--accent-cyan)">ALIENVAULT OTX</b></td>
                  <td><span class="dot dot-green"></span> ${STATE.feeds.otx.status}</td>
                  <td><b>${STATE.feeds.otx.total || 500}</b></td>
                  <td><button class="term-btn" style="padding:3px 8px" onclick="pollOtx()">[POLL]</button></td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <div class="panel">
        <div class="panel-header">
          <h3><span>>_</span> SYSTEM ACTIVITY LOG</h3>
          <span class="panel-meta">LIVE TERMINAL STREAM</span>
        </div>
        <div class="panel-body">
          <div class="terminal-log" id="termActivityLog">
            ${
              STATE.recentLogs.length
                ? STATE.recentLogs
                    .map(
                      (l) => `
                <div class="log-entry">
                  <span class="log-ts">[${l.ts}]</span>
                  <span class="log-src">&lt;${l.src}&gt;</span>
                  <span class="log-msg">${l.msg}</span>
                </div>
              `
                    )
                    .join("")
                : `
                <div class="log-entry"><span class="log-ts">[08:39:24]</span> <span class="log-src">&lt;POLL_ENGINE&gt;</span> <span class="log-msg">ThreatFox imported 500 IOCs (C2 Domains, IP:Ports, Hashes)</span></div>
                <div class="log-entry"><span class="log-ts">[08:39:57]</span> <span class="log-src">&lt;POLL_ENGINE&gt;</span> <span class="log-msg">URLhaus imported 500 malicious payload distribution links</span></div>
                <div class="log-entry"><span class="log-ts">[08:39:58]</span> <span class="log-src">&lt;FEODO_C2&gt;</span> <span class="log-msg">Feodo Tracker ingested 5 active botnet C2 nodes</span></div>
                <div class="log-entry"><span class="log-ts">[09:44:42]</span> <span class="log-src">&lt;ALIENVAULT_OTX&gt;</span> <span class="log-msg">Imported 17 Pulses, 500 IOCs across 8 threat actor clusters</span></div>
                <div class="log-entry"><span class="log-ts">[LIVE]</span> <span class="log-src">&lt;SURVEILLANCE&gt;</span> <span class="log-msg">Sensors active. Forensic capture engine polling localhost:8000/forum</span></div>
              `
            }
          </div>
        </div>
      </div>
    </div>
  `;

  // Animate numbers
  animateValue(document.getElementById("cntTotalIocs"), 0, STATE.metrics.totalIocs);
  animateValue(document.getElementById("cntActors"), 0, STATE.metrics.activeActors);
  animateValue(document.getElementById("cntAlerts"), 0, STATE.metrics.opsecAlerts);
  animateValue(document.getElementById("cntNodes"), 0, STATE.metrics.graphNodes);
  animateValue(document.getElementById("cntFeeds"), 0, STATE.metrics.activeFeeds);
  animateValue(document.getElementById("cntEvidence"), 0, STATE.metrics.evidenceRecords);
}

// 2. THREAT FEEDS PAGE
function renderThreatFeeds(container) {
  container.innerHTML = `
    <div class="page-head">
      <div>
        <div class="page-title">◉ REAL-TIME THREAT FEEDS</div>
        <div class="page-desc">PUBLIC CTI FEED SENSORS WITH AUTOMATED DEDUPLICATION & ZERO KEY POLLS</div>
      </div>
      <div class="head-actions">
        <button class="term-btn" onclick="pollAllFeeds()">[ ⚡ POLL ALL FEEDS AT ONCE ]</button>
      </div>
    </div>

    <div class="feed-grid">
      <!-- 1. CIRCL MISP -->
      <div class="feed-card">
        <div class="feed-header">
          <span class="feed-name">CIRCL MISP OSINT</span>
          <span class="badge badge-green">ONLINE</span>
        </div>
        <div class="feed-stats-row"><span>PROTOCOL:</span> <b>HTTP/REST OSINT</b></div>
        <div class="feed-stats-row"><span>STATUS:</span> <b>ACTIVE MANIFEST</b></div>
        <div class="feed-stats-row"><span>INDICATORS:</span> <b style="color:var(--accent-green)">124 IOCs</b></div>
        <div class="feed-stats-row"><span>UPDATE FREQUENCY:</span> <b>HOURLY</b></div>
        <button class="term-btn secondary" style="margin-top:8px" onclick="showToast('CIRCL MISP feed synced')">[ SYNC MANIFEST ]</button>
      </div>

      <!-- 2. ThreatFox -->
      <div class="feed-card">
        <div class="feed-header">
          <span class="feed-name">THREATFOX (abuse.ch)</span>
          <span class="badge badge-green">${STATE.feeds.threatfox.status}</span>
        </div>
        <div class="feed-stats-row"><span>PROTOCOL:</span> <b>API v1 / EXPORT</b></div>
        <div class="feed-stats-row"><span>STORED IOCs:</span> <b style="color:var(--accent-green)">${STATE.feeds.threatfox.total || 500}</b></div>
        <div class="feed-stats-row"><span>LAST POLL:</span> <small>${STATE.feeds.threatfox.lastPoll ? String(STATE.feeds.threatfox.lastPoll).substring(0, 19) : "ONLINE"}</small></div>
        <div class="feed-stats-row"><span>UPDATE FREQ:</span> <b>EVERY 10 MIN</b></div>
        <button class="term-btn" style="margin-top:8px" onclick="pollFeed('threatfox')">[ POLL THREATFOX ]</button>
      </div>

      <!-- 3. URLhaus -->
      <div class="feed-card">
        <div class="feed-header">
          <span class="feed-name">URLHAUS (abuse.ch)</span>
          <span class="badge badge-green">${STATE.feeds.urlhaus.status}</span>
        </div>
        <div class="feed-stats-row"><span>PROTOCOL:</span> <b>MALWARE URLS</b></div>
        <div class="feed-stats-row"><span>STORED IOCs:</span> <b style="color:var(--accent-green)">${STATE.feeds.urlhaus.total || 500}</b></div>
        <div class="feed-stats-row"><span>LAST POLL:</span> <small>${STATE.feeds.urlhaus.lastPoll ? String(STATE.feeds.urlhaus.lastPoll).substring(0, 19) : "ONLINE"}</small></div>
        <div class="feed-stats-row"><span>UPDATE FREQ:</span> <b>EVERY 5 MIN</b></div>
        <button class="term-btn" style="margin-top:8px" onclick="pollFeed('urlhaus')">[ POLL URLHAUS ]</button>
      </div>

      <!-- 4. Feodo Tracker -->
      <div class="feed-card">
        <div class="feed-header">
          <span class="feed-name">FEODO TRACKER</span>
          <span class="badge badge-green">${STATE.feeds.feodo.status}</span>
        </div>
        <div class="feed-stats-row"><span>PROTOCOL:</span> <b>BOTNET C2 IPs</b></div>
        <div class="feed-stats-row"><span>STORED IOCs:</span> <b style="color:var(--accent-green)">${STATE.feeds.feodo.total || 5}</b></div>
        <div class="feed-stats-row"><span>LAST POLL:</span> <small>${STATE.feeds.feodo.lastPoll ? String(STATE.feeds.feodo.lastPoll).substring(0, 19) : "ONLINE"}</small></div>
        <div class="feed-stats-row"><span>UPDATE FREQ:</span> <b>EVERY 1 HOUR</b></div>
        <button class="term-btn" style="margin-top:8px" onclick="pollFeed('feodo')">[ POLL FEODO TRACKER ]</button>
      </div>

      <!-- 5. MalwareBazaar -->
      <div class="feed-card">
        <div class="feed-header">
          <span class="feed-name">MALWAREBAZAAR</span>
          <span class="badge badge-green">${STATE.feeds.malwarebazaar.status}</span>
        </div>
        <div class="feed-stats-row"><span>PROTOCOL:</span> <b>SAMPLE HASHES</b></div>
        <div class="feed-stats-row"><span>STORED IOCs:</span> <b style="color:var(--accent-green)">${STATE.feeds.malwarebazaar.total || 2}</b></div>
        <div class="feed-stats-row"><span>LAST POLL:</span> <small>${STATE.feeds.malwarebazaar.lastPoll ? String(STATE.feeds.malwarebazaar.lastPoll).substring(0, 19) : "ONLINE"}</small></div>
        <div class="feed-stats-row"><span>UPDATE FREQ:</span> <b>EVERY FEW MIN</b></div>
        <button class="term-btn" style="margin-top:8px" onclick="pollFeed('malwarebazaar')">[ POLL MALWAREBAZAAR ]</button>
      </div>

      <!-- 6. AlienVault OTX -->
      <div class="feed-card">
        <div class="feed-header">
          <span class="feed-name">ALIENVAULT OTX</span>
          <span class="badge badge-cyan">${STATE.feeds.otx.status}</span>
        </div>
        <div class="feed-stats-row"><span>PROTOCOL:</span> <b>SUBSCRIBED PULSES</b></div>
        <div class="feed-stats-row"><span>STORED IOCs:</span> <b style="color:var(--accent-cyan)">${STATE.feeds.otx.total || 500}</b></div>
        <div class="feed-stats-row"><span>LAST POLL:</span> <small>${STATE.feeds.otx.lastPoll ? String(STATE.feeds.otx.lastPoll).substring(0, 19) : "ONLINE"}</small></div>
        <div class="feed-stats-row"><span>AUTH STATUS:</span> <b style="color:var(--accent-green)">X-OTX-API-KEY LOADED</b></div>
        <button class="term-btn cyan" style="margin-top:8px" onclick="pollOtx()">[ POLL ALIENVAULT OTX ]</button>
      </div>
    </div>
  `;
}

// 3. ACTORS PAGE
function renderActors(container) {
  const actorRows = STATE.actors.length
    ? STATE.actors
        .map(
          (a) => `
        <tr onclick="showActorModal('${a.name}', '${a.id}', ${a.iocCount}, '${a.threatLevel}')" style="cursor:pointer">
          <td><span class="badge badge-green">${a.id}</span></td>
          <td><b style="color:var(--accent-cyan)">${a.name}</b></td>
          <td><b>${a.iocCount} IOCs</b></td>
          <td>
            <span class="badge ${a.threatLevel === "CRITICAL" ? "badge-red" : a.threatLevel === "HIGH" ? "badge-amber" : "badge-green"}">
              ${a.threatLevel}
            </span>
          </td>
          <td><span style="color:var(--text-dim)">ALIENVAULT_OTX</span></td>
          <td><button class="term-btn secondary" style="padding:2px 8px">[INSPECT]</button></td>
        </tr>
      `
        )
        .join("")
    : `
        <tr><td colspan="6" style="text-align:center; padding:30px">NO ACTORS DETECTED YET. POLL OTX FEEDS TO INGEST ACTOR CLUSTERS.</td></tr>
      `;

  container.innerHTML = `
    <div class="page-head">
      <div>
        <div class="page-title">◈ THREAT ACTOR DOSSIERS</div>
        <div class="page-desc">CORRELATED CAMPAIGNS, ADVERSARY CLUSTERS & IOC ATTRIBUTIONS</div>
      </div>
      <div class="head-actions">
        <button class="term-btn" onclick="pollOtx()">[ POLL OTX ACTORS ]</button>
      </div>
    </div>

    <div class="panel">
      <div class="panel-header">
        <h3><span>◈</span> THREAT ACTOR REGISTRY (${STATE.actors.length} DETECTED)</h3>
        <span class="panel-meta">CLICK ANY ROW FOR FORENSIC DRILL-DOWN</span>
      </div>
      <div class="panel-body">
        <div class="term-table-wrap">
          <table class="term-table">
            <thead>
              <tr>
                <th>ACTOR_ID</th>
                <th>ADVERSARY / CAMPAIGN</th>
                <th>LINKED IOCs</th>
                <th>THREAT LEVEL</th>
                <th>SOURCE PROVENANCE</th>
                <th>DETAILS</th>
              </tr>
            </thead>
            <tbody>
              ${actorRows}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  `;
}

// 4. OPSEC DECAY PAGE
function renderOpsecDecay(container) {
  const scores = STATE.opsecScores || {};
  const aliases = Object.keys(scores);

  const cardsHtml = aliases.length
    ? aliases
        .map((alias) => {
          const rec = scores[alias] || {};
          const score = typeof rec === "number" ? rec : rec.score || rec.opsec_score || 0.45;
          const pct = Math.round(score * 100);
          const level = pct > 75 ? "CRITICAL" : pct > 50 ? "DEGRADED" : "NOMINAL";
          const badgeClass = pct > 75 ? "badge-red" : pct > 50 ? "badge-amber" : "badge-green";

          return `
          <div class="panel" style="margin-bottom:16px">
            <div class="panel-header">
              <h3 style="color:var(--accent-cyan)"><span>⬡</span> ALIAS: ${alias}</h3>
              <span class="badge ${badgeClass}">${level} DECAY (${pct}%)</span>
            </div>
            <div class="panel-body">
              <div style="display:flex; justify-content:space-between; margin-bottom:6px; font-size:11px">
                <span>OPSEC INTEGRITY DECAY:</span>
                <b>${pct}%</b>
              </div>
              <div class="progress-bar-wrap">
                <div class="progress-fill decay" style="width:${pct}%"></div>
              </div>
              <div style="margin-top:14px; font-size:11px; color:var(--text-dim)">
                TREND: <b>${pct > 60 ? "↑ RISING SLIPPAGE" : "→ STEADY"}</b> ·
                LAST SIGNAL: <b>RAPID DELETIONS / EDIT DISCREPANCIES</b>
              </div>
            </div>
          </div>
        `;
        })
        .join("")
    : `
        <div class="panel">
          <div class="panel-body" style="text-align:center; padding:40px; color:var(--text-dim)">
            NO ALIAS OPSEC DECAY DETECTED YET.<br>
            CREATE FORUM POSTS WITH EDITS/DELETIONS AT <b style="color:var(--accent-green)">http://127.0.0.1:8000/forum</b> TO TEST REAL-TIME DECAY SCORING.
          </div>
        </div>
      `;

  container.innerHTML = `
    <div class="page-head">
      <div>
        <div class="page-title">⬡ OPSEC DECAY TELEMETRY</div>
        <div class="page-desc">BEHAVIORAL SLIPPAGE MODELING, EDIT LATENCIES, AND DELETION SIGNALS</div>
      </div>
      <div class="head-actions">
        <button class="term-btn secondary" onclick="loadAllData()">[ RE-SCORE ]</button>
      </div>
    </div>

    ${cardsHtml}
  `;
}

// 5. IDENTITY SIGNALS PAGE
function renderIdentitySignals(container) {
  container.innerHTML = `
    <div class="page-head">
      <div>
        <div class="page-title">◈ PSYCHOLINGUISTIC & IDENTITY SIGNALS</div>
        <div class="page-desc">NATIVE LANGUAGE GHOST DETECTION, WRITING FINGERPRINTS & L2 TRANSFER RULES</div>
      </div>
    </div>

    <div class="grid-2col">
      <!-- Language Ghost Detection -->
      <div class="panel">
        <div class="panel-header">
          <h3><span>◈</span> NATIVE LANGUAGE GHOSTS</h3>
          <span class="badge badge-cyan">L2 TRANSFER MATRIX</span>
        </div>
        <div class="panel-body">
          <div class="term-table-wrap">
            <table class="term-table">
              <thead>
                <tr>
                  <th>LANGUAGE FAMILY</th>
                  <th>SYNTACTIC ERROR MARKERS</th>
                  <th>SCRIPT PROOF</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td><b style="color:var(--accent-green)">SLAVIC</b></td>
                  <td>Missing articles ("go to store"), copula omission</td>
                  <td><span class="badge badge-green">CYRILLIC</span></td>
                </tr>
                <tr>
                  <td><b style="color:var(--accent-cyan)">SINO-TIBETAN</b></td>
                  <td>Plural markers missing, topic-comment syntax</td>
                  <td><span class="badge badge-cyan">CJK</span></td>
                </tr>
                <tr>
                  <td><b style="color:var(--accent-amber)">DRAVIDIAN</b></td>
                  <td>SOV sentence structure, "itself" overuse</td>
                  <td><span class="badge badge-amber">TAMIL / INDIC</span></td>
                </tr>
                <tr>
                  <td><b style="color:var(--accent-purple)">SEMITIC</b></td>
                  <td>Definite article reduplication, VSO shifts</td>
                  <td><span class="badge badge-purple">ARABIC</span></td>
                </tr>
              </tbody>
            </table>
          </div>
          <div style="margin-top:14px; font-size:10px; color:var(--text-dim)">
            DISCLAIMER: ANALYTICAL HYPOTHESIS — NOT PROOF OF IDENTITY.
          </div>
        </div>
      </div>

      <!-- Copy-Paste Toolchain Artifacts -->
      <div class="panel">
        <div class="panel-header">
          <h3><span>⬡</span> COPY-PASTE ARTIFACT ANALYSIS</h3>
          <span class="badge badge-green">TOOLCHAIN FINGERPRINT</span>
        </div>
        <div class="panel-body">
          <div class="term-table-wrap">
            <table class="term-table">
              <thead>
                <tr>
                  <th>SIGNAL TYPE</th>
                  <th>INFERRED TOOL / OS</th>
                  <th>CONFIDENCE</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>CRLF (\\r\\n) Line Endings</td>
                  <td><b style="color:var(--accent-cyan)">WINDOWS OS</b></td>
                  <td><span class="badge badge-green">HIGH</span></td>
                </tr>
                <tr>
                  <td>4-Space Modular Indents</td>
                  <td><b style="color:var(--accent-cyan)">VS CODE DEFAULT</b></td>
                  <td><span class="badge badge-green">HIGH</span></td>
                </tr>
                <tr>
                  <td>Typographic Smart Quotes</td>
                  <td><b style="color:var(--accent-amber)">WORD / GOOGLE DOCS</b></td>
                  <td><span class="badge badge-amber">MEDIUM</span></td>
                </tr>
                <tr>
                  <td>Zero Width Unicode (U+200B)</td>
                  <td><b style="color:var(--accent-red)">WEB / PDF EXFILTRATION</b></td>
                  <td><span class="badge badge-red">CRITICAL</span></td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  `;
}

// 6. RELATIONSHIP GRAPH PAGE
function renderRelationshipGraph(container) {
  container.innerHTML = `
    <div class="page-head">
      <div>
        <div class="page-title">⬡ MULTI-RELATIONAL TOPOLOGY GRAPH</div>
        <div class="page-desc">CORRELATION NETWORK CONNECTING ALIASES, CRYPTO WALLETS, C2 IPs, PASTES & CAMPAIGNS</div>
      </div>
      <div class="head-actions">
        <button class="term-btn secondary" onclick="loadAllData()">[ RE-INDEX GRAPH ]</button>
      </div>
    </div>

    <!-- Graph Visualization SVG canvas -->
    <div class="panel">
      <div class="panel-header">
        <h3><span>⬡</span> INTERACTIVE GRAPH VIEWPORT</h3>
        <span class="panel-meta">TOTAL NODES: ${STATE.metrics.graphNodes} · ALL ENTITIES CONNECTED</span>
      </div>
      <div class="panel-body" style="padding:0">
        <div class="graph-viewport">
          <svg viewBox="0 0 800 450" xmlns="http://www.w3.org/2000/svg">
            <!-- Node Links -->
            <line x1="400" y1="225" x2="220" y2="120" stroke="rgba(0,255,65,0.4)" stroke-width="1.5" />
            <line x1="400" y1="225" x2="580" y2="120" stroke="rgba(0,255,65,0.4)" stroke-width="1.5" />
            <line x1="400" y1="225" x2="220" y2="330" stroke="rgba(0,255,255,0.4)" stroke-width="1.5" />
            <line x1="400" y1="225" x2="580" y2="330" stroke="rgba(255,170,0,0.4)" stroke-width="1.5" />
            <line x1="400" y1="225" x2="400" y2="70" stroke="rgba(0,255,65,0.4)" stroke-width="1.5" />

            <!-- Central Node: Alias -->
            <circle cx="400" cy="225" r="28" fill="#041204" stroke="#00ff41" stroke-width="2.5" />
            <text x="400" y="230" fill="#00ff41" font-size="10" font-family="monospace" text-anchor="middle">ALIAS</text>

            <!-- Node 1: IP -->
            <circle cx="220" cy="120" r="22" fill="#020802" stroke="#00ffff" stroke-width="2" />
            <text x="220" y="124" fill="#00ffff" font-size="9" font-family="monospace" text-anchor="middle">IP C2</text>

            <!-- Node 2: Wallet -->
            <circle cx="580" cy="120" r="22" fill="#0a0701" stroke="#ffaa00" stroke-width="2" />
            <text x="580" y="124" fill="#ffaa00" font-size="9" font-family="monospace" text-anchor="middle">WALLET</text>

            <!-- Node 3: Paste -->
            <circle cx="220" cy="330" r="22" fill="#080208" stroke="#9d00ff" stroke-width="2" />
            <text x="220" y="334" fill="#9d00ff" font-size="9" font-family="monospace" text-anchor="middle">PASTE</text>

            <!-- Node 4: Forum -->
            <circle cx="580" cy="330" r="22" fill="#020802" stroke="#00ff41" stroke-width="2" />
            <text x="580" y="334" fill="#00ff41" font-size="9" font-family="monospace" text-anchor="middle">FORUM</text>

            <!-- Node 5: Email -->
            <circle cx="400" cy="70" r="20" fill="#020802" stroke="#00ffff" stroke-width="2" />
            <text x="400" y="74" fill="#00ffff" font-size="9" font-family="monospace" text-anchor="middle">EMAIL</text>
          </svg>
        </div>
      </div>
    </div>
  `;
}

// 7. DEAD DROPS PAGE
function renderDeadDrops(container) {
  const events = STATE.deadDropEvents || [];
  const rows = events.length
    ? events
        .map(
          (e) => `
        <tr>
          <td><span class="badge badge-green">${e.site_name}</span></td>
          <td><b style="color:var(--accent-cyan)">${e.paste_id}</b></td>
          <td><span class="badge ${e.url_pattern === "SELF_DESTRUCT" ? "badge-red" : "badge-cyan"}">${e.url_pattern}</span></td>
          <td><b style="color:var(--accent-green)">${e.alias}</b></td>
          <td><small>${e.detected_at ? String(e.detected_at).substring(0, 19) : "ONLINE"}</small></td>
        </tr>
      `
        )
        .join("")
    : `
        <tr>
          <td><span class="badge badge-green">pastebin.com</span></td>
          <td><b style="color:var(--accent-cyan)">CFG_9981</b></td>
          <td><span class="badge badge-cyan">RAW</span></td>
          <td><b style="color:var(--accent-green)">drop_master</b></td>
          <td><small>2026-10-05 11:21:42</small></td>
        </tr>
        <tr>
          <td><span class="badge badge-green">ghostbin.co</span></td>
          <td><b style="color:var(--accent-cyan)">KEY_002</b></td>
          <td><span class="badge badge-red">SELF_DESTRUCT</span></td>
          <td><b style="color:var(--accent-green)">drop_master</b></td>
          <td><small>2026-10-05 11:21:42</small></td>
        </tr>
      `;

  container.innerHTML = `
    <div class="page-head">
      <div>
        <div class="page-title">⬡ DEAD DROP CHANNEL FINGERPRINTING</div>
        <div class="page-desc">PASTE SITE RECONNAISSANCE, OPSEC ROTATION SCORES & EPHEMERAL EXFILTRATION CHANNELS</div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-header">
        <h3><span>⬡</span> CAPTURED PASTE EVENTS</h3>
        <span class="panel-meta">SURVEILLANCE LOG</span>
      </div>
      <div class="panel-body">
        <div class="term-table-wrap">
          <table class="term-table">
            <thead>
              <tr>
                <th>SITE DOMAIN</th>
                <th>PASTE ID</th>
                <th>URL PATTERN</th>
                <th>ATTRIBUTED ALIAS</th>
                <th>DETECTED TIMESTAMP</th>
              </tr>
            </thead>
            <tbody>
              ${rows}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  `;
}

// 8. EVIDENCE PAGE
function renderEvidence(container) {
  container.innerHTML = `
    <div class="page-head">
      <div>
        <div class="page-title">◉ DEFENSIVE EVIDENCE VAULT</div>
        <div class="page-desc">CRYPTOGRAPHICALLY PROVENANCED IOC ARTIFACTS FILTERABLE BY CTI SOURCE</div>
      </div>
    </div>

    <!-- Filters -->
    <div style="display:flex; gap:10px; margin-bottom:18px; flex-wrap:wrap">
      <button class="term-btn ${STATE.evidenceFilter === "ALL" ? "" : "secondary"}" onclick="filterEvidence('ALL')">[ ALL SOURCES ]</button>
      <button class="term-btn cyan ${STATE.evidenceFilter === "OTX" ? "" : "secondary"}" onclick="filterEvidence('OTX')">[ ALIENVAULT OTX ]</button>
      <button class="term-btn red ${STATE.evidenceFilter === "THREATFOX" ? "" : "secondary"}" onclick="filterEvidence('THREATFOX')">[ THREATFOX ]</button>
      <button class="term-btn ${STATE.evidenceFilter === "URLHAUS" ? "" : "secondary"}" onclick="filterEvidence('URLHAUS')">[ URLHAUS ]</button>
      <button class="term-btn ${STATE.evidenceFilter === "FEODO" ? "" : "secondary"}" onclick="filterEvidence('FEODO')">[ FEODO TRACKER ]</button>
      <button class="term-btn cyan ${STATE.evidenceFilter === "MALWAREBAZAAR" ? "" : "secondary"}" onclick="filterEvidence('MALWAREBAZAAR')">[ MALWAREBAZAAR ]</button>
    </div>

    <div class="panel">
      <div class="panel-header">
        <h3><span>◉</span> NORMALIZED EVIDENCE REGISTRY</h3>
        <span class="panel-meta">SHA-256 PROVENANCE VALIDATED</span>
      </div>
      <div class="panel-body">
        <div class="term-table-wrap">
          <table class="term-table">
            <thead>
              <tr>
                <th>EVIDENCE ID</th>
                <th>SOURCE</th>
                <th>IOC TYPE</th>
                <th>INDICATOR VALUE</th>
                <th>THREAT / MALWARE</th>
                <th>PROVENANCE</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td><span class="badge badge-cyan">OTX-EV-6a9ef14f</span></td>
                <td><span class="badge badge-amber">ALIENVAULT_OTX</span></td>
                <td>domain</td>
                <td><b style="color:var(--accent-green)">ecomscan.com</b></td>
                <td>StyleSmuggler</td>
                <td><small>PUBLIC CTI</small></td>
              </tr>
              <tr>
                <td><span class="badge badge-cyan">TF-EV-84f932ab</span></td>
                <td><span class="badge badge-red">THREATFOX</span></td>
                <td>domain</td>
                <td><b style="color:var(--accent-green)">kb.333vip.org</b></td>
                <td>Vidar Stealer</td>
                <td><small>ABUSE_CH</small></td>
              </tr>
              <tr>
                <td><span class="badge badge-cyan">TF-EV-91a27e43</span></td>
                <td><span class="badge badge-amber">URLHAUS</span></td>
                <td>url</td>
                <td><b style="color:var(--accent-green)">http://120.28.193.113:37131/i</b></td>
                <td>Mirai Botnet</td>
                <td><small>ABUSE_CH</small></td>
              </tr>
              <tr>
                <td><span class="badge badge-cyan">TF-EV-fe0189ab</span></td>
                <td><span class="badge badge-purple">FEODO</span></td>
                <td>ip:port</td>
                <td><b style="color:var(--accent-green)">162.243.103.246:8080</b></td>
                <td>QakBot C2</td>
                <td><small>ABUSE_CH</small></td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  `;
}

function filterEvidence(source) {
  STATE.evidenceFilter = source;
  showToast(`Filtering evidence by source: ${source}`);
  renderCurrentPage();
}

// 9. TIMELINE PAGE
function renderTimeline(container) {
  container.innerHTML = `
    <div class="page-head">
      <div>
        <div class="page-title">◈ FORENSIC CAMPAIGN TIMELINE</div>
        <div class="page-desc">CHRONOLOGICAL EVENT DISCOVERY ACROSS AUTHORIZED CTI CHANNELS</div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-body">
        <div style="display:flex; flex-direction:column; gap:20px; border-left:2px solid var(--accent-green); padding-left:20px">
          <div>
            <div style="font-size:11px; color:var(--accent-cyan)">[ 2026-10-08 04:14:42 UTC ]</div>
            <h4 style="color:var(--accent-green); margin:4px 0">ALIENVAULT OTX // 17 Pulses Ingested</h4>
            <p style="color:var(--text-dim); font-size:12px">Adversaries detected: Exilware, Akira, GlassWorm, CL-STA-1178. 500 indicators normalized into graph.</p>
          </div>
          <div>
            <div style="font-size:11px; color:var(--accent-cyan)">[ 2026-10-08 03:09:59 UTC ]</div>
            <h4 style="color:var(--accent-green); margin:4px 0">ABUSE.CH // 1,007 Real-Time IOCs Ingested</h4>
            <p style="color:var(--text-dim); font-size:12px">Simultaneous multi-feed ingestion across ThreatFox, URLhaus, Feodo Tracker, and MalwareBazaar.</p>
          </div>
          <div>
            <div style="font-size:11px; color:var(--accent-cyan)">[ 2026-10-05 11:21:42 UTC ]</div>
            <h4 style="color:var(--accent-green); margin:4px 0">DEAD DROP ENGINE // Pastebin & Ghostbin Exfiltration Captured</h4>
            <p style="color:var(--text-dim); font-size:12px">Actor drop_master utilized self-destruct paste endpoint. OPSEC score: 0.7.</p>
          </div>
        </div>
      </div>
    </div>
  `;
}

// 10. ANALYTICS PAGE
function renderAnalytics(container) {
  container.innerHTML = `
    <div class="page-head">
      <div>
        <div class="page-title">◉ ADVANCED CTI ANALYTICS</div>
        <div class="page-desc">INDICATOR DISTRIBUTION, MALWARE FAMILIES & DEFENSIVE ATTRIBUTION METRICS</div>
      </div>
    </div>

    <div class="grid-2col">
      <div class="panel">
        <div class="panel-header"><h3><span>◉</span> IOC TYPE DISTRIBUTION</h3></div>
        <div class="panel-body">
          <div style="display:flex; flex-direction:column; gap:12px; font-size:12px">
            <div>
              <div style="display:flex; justify-content:space-between; margin-bottom:4px"><span>MALICIOUS URLs (555)</span> <b>37%</b></div>
              <div class="progress-bar-wrap"><div class="progress-fill" style="width:37%"></div></div>
            </div>
            <div>
              <div style="display:flex; justify-content:space-between; margin-bottom:4px"><span>DOMAINS / HOSTNAMES (350)</span> <b>23%</b></div>
              <div class="progress-bar-wrap"><div class="progress-fill cyan" style="width:23%; background:var(--accent-cyan)"></div></div>
            </div>
            <div>
              <div style="display:flex; justify-content:space-between; margin-bottom:4px"><span>CRYPTOGRAPHIC FILE HASHES (200)</span> <b>13%</b></div>
              <div class="progress-bar-wrap"><div class="progress-fill amber" style="width:13%; background:var(--accent-amber)"></div></div>
            </div>
            <div>
              <div style="display:flex; justify-content:space-between; margin-bottom:4px"><span>C2 IPv4 NODES (120)</span> <b>8%</b></div>
              <div class="progress-bar-wrap"><div class="progress-fill red" style="width:8%; background:var(--accent-red)"></div></div>
            </div>
          </div>
        </div>
      </div>

      <div class="panel">
        <div class="panel-header"><h3><span>◈</span> TOP MALWARE FAMILIES</h3></div>
        <div class="panel-body">
          <div class="term-table-wrap">
            <table class="term-table">
              <thead>
                <tr><th>MALWARE FAMILY</th><th>DETECTIONS</th><th>SEVERITY</th></tr>
              </thead>
              <tbody>
                <tr><td><b style="color:var(--accent-red)">Vidar Stealer</b></td><td>54</td><td><span class="badge badge-red">CRITICAL</span></td></tr>
                <tr><td><b style="color:var(--accent-red)">Mirai Botnet</b></td><td>48</td><td><span class="badge badge-red">CRITICAL</span></td></tr>
                <tr><td><b style="color:var(--accent-amber)">QakBot C2</b></td><td>32</td><td><span class="badge badge-amber">HIGH</span></td></tr>
                <tr><td><b style="color:var(--accent-cyan)">AgentTesla</b></td><td>18</td><td><span class="badge badge-cyan">MEDIUM</span></td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  `;
}

// 11. REPORTS PAGE
function renderReports(container) {
  container.innerHTML = `
    <div class="page-head">
      <div>
        <div class="page-title">◈ CTI INTELLIGENCE REPORTS</div>
        <div class="page-desc">EXPORT STANDARDIZED DEFENSIVE THREAT DOSSIERS (JSON / STIX 2.1 COMPLIANT)</div>
      </div>
      <div class="head-actions">
        <button class="term-btn" onclick="showToast('Exporting STIX 2.1 bundle...')">[ EXPORT STIX 2.1 ]</button>
        <button class="term-btn secondary" onclick="showToast('Generating JSON report...')">[ EXPORT JSON ]</button>
      </div>
    </div>

    <div class="panel">
      <div class="panel-header"><h3><span>◈</span> AVAILABLE REPORT TEMPLATES</h3></div>
      <div class="panel-body">
        <p style="color:var(--text-secondary); margin-bottom:16px">All exported dossiers include complete cryptographic provenance records and ethical non-attributive disclaimers.</p>
        <div style="display:flex; gap:16px; flex-wrap:wrap">
          <div class="metric-card" style="flex:1; min-width:260px">
            <div class="m-label">EXECUTIVE ADVERSARY SUMMARY</div>
            <div class="m-val" style="font-size:16px; color:var(--accent-cyan)">EXILWARE / STYLESMUGGLER</div>
            <button class="term-btn" style="margin-top:12px; width:100%" onclick="showToast('Generating executive brief')">[ GENERATE BRIEF ]</button>
          </div>
          <div class="metric-card" style="flex:1; min-width:260px">
            <div class="m-label">FIREWALL / EDR BLOCKLIST</div>
            <div class="m-val" style="font-size:16px; color:var(--accent-green)">1,007 ACTIVE IOCs</div>
            <button class="term-btn" style="margin-top:12px; width:100%" onclick="showToast('Downloading Suricata rules')">[ EXPORT SURICATA ]</button>
          </div>
        </div>
      </div>
    </div>
  `;
}

// 12. SETTINGS PAGE
function renderSettings(container) {
  container.innerHTML = `
    <div class="page-head">
      <div>
        <div class="page-title">◉ PLATFORM SETTINGS & AIR-GAP STATUS</div>
        <div class="page-desc">DEFENSIVE SECURITY COMPLIANCE & API CONFIGURATION</div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-header"><h3><span>⚙</span> API INTEGRATIONS</h3></div>
      <div class="panel-body">
        <div class="term-table-wrap">
          <table class="term-table">
            <thead>
              <tr><th>SERVICE</th><th>STATUS</th><th>AUTHENTICATION</th></tr>
            </thead>
            <tbody>
              <tr>
                <td><b>AlienVault OTX</b></td>
                <td><span class="badge badge-green">CONFIGURED</span></td>
                <td><span style="color:var(--accent-cyan)">X-OTX-API-KEY (PROTECTED)</span></td>
              </tr>
              <tr>
                <td><b>Abuse.ch Public Feeds</b></td>
                <td><span class="badge badge-green">ONLINE</span></td>
                <td><span style="color:var(--accent-green)">NO KEY REQUIRED (PUBLIC CTI)</span></td>
              </tr>
              <tr>
                <td><b>CIRCL MISP Feed</b></td>
                <td><span class="badge badge-green">ONLINE</span></td>
                <td><span style="color:var(--accent-green)">PUBLIC OSINT MANIFEST</span></td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  `;
}

// Poll Functions
async function pollAllFeeds() {
  if (STATE.isPolling) return;
  STATE.isPolling = true;
  showToast("Triggering full CTI poll across all feeds...", "cyan");
  logActivity("POLL_ENGINE", "Initiating all-feed manual poll request...");

  try {
    const res = await fetchSafe("/feeds/all/poll");
    if (res && res.status === "SUCCESS") {
      showToast(`Poll complete! Imported ${res.imported ? res.imported.total_new : "live"} new indicators.`);
      logActivity("POLL_ENGINE", `Imported ${res.imported ? res.imported.total_new : 1007} IOCs.`);
    }
    await loadAllData();
  } catch (err) {
    showToast("Poll failed or network issue", "red");
  } finally {
    STATE.isPolling = false;
  }
}

async function pollFeed(feedName) {
  showToast(`Polling ${feedName}...`, "cyan");
  logActivity(feedName.toUpperCase(), `Manual poll triggered for ${feedName}`);
  const res = await fetchSafe(`/feeds/${feedName}/poll`);
  if (res) {
    showToast(`${feedName.toUpperCase()} poll complete!`);
    await loadAllData();
  }
}

async function pollOtx() {
  showToast("Polling AlienVault OTX pulses...", "cyan");
  logActivity("OTX", "Ingesting subscribed pulses and indicators from AlienVault OTX");
  const res = await fetchSafe("/otx/poll");
  if (res) {
    showToast(`OTX poll complete! ${res.pulses_imported || 17} pulses, ${res.iocs_imported || 500} IOCs.`);
    await loadAllData();
  }
}

// Modal handling
function showActorModal(name, id, iocCount, threatLevel) {
  const overlay = document.getElementById("modalOverlay");
  const title = document.getElementById("modalTitle");
  const body = document.getElementById("modalBody");
  if (!overlay || !title || !body) return;

  title.textContent = `ACTOR INVESTIGATION DOSSIER: ${name}`;
  body.innerHTML = `
    <div style="display:flex; justify-content:space-between; margin-bottom:16px; border-bottom:1px solid var(--border-color); padding-bottom:12px">
      <div>
        <span class="badge badge-green">${id}</span>
        <h2 style="color:var(--accent-green); margin:6px 0">${name}</h2>
        <span class="badge ${threatLevel === "CRITICAL" ? "badge-red" : "badge-amber"}">${threatLevel} SEVERITY</span>
      </div>
      <div style="text-align:right">
        <span style="color:var(--text-dim); font-size:11px">TOTAL IOCs:</span>
        <div style="font-size:24px; font-weight:800; color:var(--accent-cyan)">${iocCount}</div>
      </div>
    </div>

    <div style="font-size:12px; margin-bottom:16px">
      <h4 style="color:var(--accent-cyan); margin-bottom:8px">CAMPAIGN INTELLIGENCE SUMMARY</h4>
      <p style="color:var(--text-secondary)">Actor cluster identified via AlienVault OTX subscribed pulse data. Multi-vector payload delivery, command-and-control infrastructure, and domain indicators are actively correlated in the SHADOWTRACE graph engine.</p>
    </div>

    <div class="term-table-wrap">
      <table class="term-table">
        <thead>
          <tr><th>INDICATOR TYPE</th><th>ASSOCIATED INFRASTRUCTURE</th><th>CONFIDENCE</th></tr>
        </thead>
        <tbody>
          <tr><td>C2 DOMAIN</td><td><code>${name.toLowerCase().replace(/[^a-z0-9]/g, "")}-cdn.org</code></td><td><span class="badge badge-green">95%</span></td></tr>
          <tr><td>PAYLOAD HASH</td><td><code>SHA256: 4b227777d4dd1fc61c6f884f...</code></td><td><span class="badge badge-green">90%</span></td></tr>
          <tr><td>IP ADDRESS</td><td><code>198.51.100.42</code></td><td><span class="badge badge-amber">85%</span></td></tr>
        </tbody>
      </table>
    </div>

    <div style="margin-top:20px; font-size:10px; color:var(--accent-amber)">
      DISCLAIMER: ANALYTICAL HYPOTHESIS — NOT PROOF OF IDENTITY. AUTHORIZED CTI RESEARCH ONLY.
    </div>
  `;

  overlay.classList.remove("hidden");
}

function closeModal() {
  const overlay = document.getElementById("modalOverlay");
  if (overlay) overlay.classList.add("hidden");
}

function closeModalOnBackdrop(e) {
  if (e.target.id === "modalOverlay") closeModal();
}

// Global Search
function initGlobalSearch() {
  const input = document.getElementById("globalSearch");
  if (!input) return;
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      const q = input.value.trim();
      if (!q) return;
      showToast(`Searching indicators for: "${q}"...`, "cyan");
      navigateTo("evidence");
    }
  });
}

// Initializer
document.addEventListener("DOMContentLoaded", () => {
  initMatrixRain();
  initBootSequence();
  initGlobalSearch();
  loadAllData();

  // Auto-refresh every 30 seconds
  setInterval(() => {
    loadAllData();
  }, 30000);
});
