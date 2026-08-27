/**
 * ObsidianTrace — Enterprise Network Troubleshooting Platform
 * Application Logic & Controller
 */

let state = {
  cases: [],
  presets: [],
  reviews: {},
  stats: {},
  responsibleAiLog: [],
  currentCase: null,
  currentDiagnosis: null,
  assistantDiagnosis: null,
  charts: {},
  settings: {
    provider: localStorage.getItem('obsidiantrace_provider') || localStorage.getItem('netsage_provider') || 'groq',
    groqModel: ['llama-3.3-70b-versatile', 'llama-3.1-8b-instant', 'openai/gpt-oss-120b', 'openai/gpt-oss-20b'].includes(localStorage.getItem('obsidiantrace_groq_model') || localStorage.getItem('netsage_groq_model'))
      ? (localStorage.getItem('obsidiantrace_groq_model') || localStorage.getItem('netsage_groq_model'))
      : 'openai/gpt-oss-120b',
    apiKey: localStorage.getItem('obsidiantrace_groq_api_key') || localStorage.getItem('netsage_groq_api_key') || '',
    reviewerName: localStorage.getItem('obsidiantrace_reviewer') || localStorage.getItem('netsage_reviewer') || 'Alex Rivera (Lead Network Engineer)'
  }
};

const PAGE_TITLES = {
  'page-assistant': 'Troubleshooting',
  'page-explorer': 'Case Explorer',
  'page-overview': 'Overview & Analytics',
  'page-review': 'Human Review',
  'page-responsible': 'Responsible AI Log',
};

document.addEventListener('DOMContentLoaded', () => {
  initApp();
});

async function initApp() {
  setupNavigation();
  setupMobileMenu();
  setupEventListeners();
  loadSavedSettingsIntoUI();
  await loadInitialData();
  renderAllViews();
}

/* ==========================================================================
   Data Fetching
   ========================================================================== */

async function loadInitialData() {
  try {
    const [casesRes, presetsRes, reviewsRes, statsRes, respAiRes] = await Promise.all([
      fetch('/api/cases').then(r => r.json()),
      fetch('/api/presets').then(r => r.json()).catch(() => []),
      fetch('/api/reviews').then(r => r.json()),
      fetch('/api/stats').then(r => r.json()),
      fetch('/api/responsible-ai-log').then(r => r.json())
    ]);

    state.cases = casesRes;
    state.presets = presetsRes;
    state.reviews = reviewsRes;
    state.stats = statsRes;
    state.responsibleAiLog = respAiRes;

    if (state.cases.length > 0) {
      state.currentCase = state.cases[0];
    }

    const countEl = document.getElementById('sidebarCaseCount');
    if (countEl) countEl.textContent = state.cases.length;
    const navCountEl = document.getElementById('navCaseCount');
    if (navCountEl) navCountEl.textContent = state.cases.length;
    const heroCases = document.getElementById('heroCases');
    if (heroCases) heroCases.textContent = state.cases.length;

    renderPresets();
    checkGroqStatus();
  } catch (err) {
    console.error('Failed to load initial data:', err);
  }
}

function loadSavedSettingsIntoUI() {
  const providerEl = document.getElementById('settingProvider');
  const modelEl = document.getElementById('settingAiModel');
  const keyEl = document.getElementById('settingApiKey');
  const reviewerEl = document.getElementById('settingReviewerName');

  if (providerEl) providerEl.value = state.settings.provider;
  if (modelEl) modelEl.value = state.settings.groqModel;
  if (keyEl && state.settings.apiKey) keyEl.value = state.settings.apiKey;
  if (reviewerEl) reviewerEl.value = state.settings.reviewerName;
}

/* ==========================================================================
   Navigation — Sidebar
   ========================================================================== */

function setupNavigation() {
  const sidebarItems = document.querySelectorAll('.sidebar-item');
  const navLinks = document.querySelectorAll('.nav-link');
  const allNav = [...sidebarItems, ...navLinks];
  function activate(targetId) {
    sidebarItems.forEach(i => i.classList.toggle('active', i.getAttribute('data-target') === targetId));
    navLinks.forEach(n => n.classList.toggle('active', n.getAttribute('data-target') === targetId));
    document.querySelectorAll('.page').forEach(p => p.classList.toggle('active', p.id === targetId));
    const breadcrumb = document.getElementById('headerBreadcrumb');
    if (breadcrumb) {
      const t = PAGE_TITLES[targetId] || targetId;
      breadcrumb.innerHTML = `<strong>${t}</strong> — Cisco Packet Tracer troubleshooting`;
    }
    document.getElementById('sidebar').classList.remove('open');
    document.getElementById('sidebarOverlay').classList.remove('active');
  }
  allNav.forEach(item => {
    item.addEventListener('click', () => activate(item.getAttribute('data-target')));
  });
  // expose for footer/hero
  window._activateNav = activate;
}

function setupMobileMenu() {
  const menuBtn = document.getElementById('mobileMenuBtn');
  const sidebar = document.getElementById('sidebar');
  const overlay = document.getElementById('sidebarOverlay');

  if (menuBtn) {
    menuBtn.addEventListener('click', () => {
      sidebar.classList.toggle('open');
      overlay.classList.toggle('active');
    });
  }

  if (overlay) {
    overlay.addEventListener('click', () => {
      sidebar.classList.remove('open');
      overlay.classList.remove('active');
    });
  }
}

function navigateToPage(targetId) {
  if (window._activateNav) return window._activateNav(targetId);
  const items = document.querySelectorAll('.sidebar-item');
  const navLinks = document.querySelectorAll('.nav-link');
  items.forEach(i => i.classList.toggle('active', i.getAttribute('data-target')===targetId));
  navLinks.forEach(n => n.classList.toggle('active', n.getAttribute('data-target')===targetId));
  document.querySelectorAll('.page').forEach(p => p.classList.toggle('active', p.id===targetId));
  const breadcrumb = document.getElementById('headerBreadcrumb');
  if (breadcrumb) breadcrumb.innerHTML = `<strong>${PAGE_TITLES[targetId]||targetId}</strong> — Cisco Packet Tracer troubleshooting`;
  document.getElementById('sidebar').classList.remove('open');
  document.getElementById('sidebarOverlay').classList.remove('active');
}

/* ==========================================================================
   Event Listeners
   ========================================================================== */

function setupEventListeners() {
  // Assistant Tab Buttons
  const btnRunAsst = document.getElementById('btnRunAssistantDiagnosis');
  if (btnRunAsst) btnRunAsst.addEventListener('click', runAssistantDiagnosis);

  const btnClearAsst = document.getElementById('btnClearAssistant');
  if (btnClearAsst) btnClearAsst.addEventListener('click', clearAssistantFields);

  // Assistant Action Buttons
  const btnAsstReview = document.getElementById('btnAssistantToReview');
  if (btnAsstReview) {
    btnAsstReview.addEventListener('click', () => {
      if (!state.assistantDiagnosis) return;
      openReviewModalFromAssistant();
    });
  }

  // Command Template Inserter
  const cmdButtons = document.querySelectorAll('.cmd-template-btn');
  cmdButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const cmd = btn.getAttribute('data-cmd');
      const cliArea = document.getElementById('assistantPastedCli');
      if (cliArea) {
        const snippet = `Router# ${cmd}\n! (Insert Packet Tracer terminal output here)\n\n`;
        cliArea.value = (cliArea.value ? cliArea.value.trim() + '\n\n' : '') + snippet;
        cliArea.focus();
      }
    });
  });

  // Case Explorer Filters
  const searchInput = document.getElementById('caseSearchInput');
  const layerFilter = document.getElementById('layerFilter');
  const severityFilter = document.getElementById('severityFilter');

  if (searchInput) searchInput.addEventListener('input', filterCases);
  if (layerFilter) layerFilter.addEventListener('change', filterCases);
  if (severityFilter) severityFilter.addEventListener('change', filterCases);

  // Human Review Modal
  const btnOpenReview = document.getElementById('btnOpenReviewModal');
  const modal = document.getElementById('reviewModal');
  const btnCloseReview = document.getElementById('btnCloseReviewModal');
  const btnCancelReview = document.getElementById('btnCancelReview');
  const btnSubmitReview = document.getElementById('btnSubmitReviewFinal');

  if (btnOpenReview) {
    btnOpenReview.addEventListener('click', () => {
      if (!state.currentCase) return;
      openReviewModal();
    });
  }

  if (btnCloseReview) btnCloseReview.addEventListener('click', () => modal.classList.remove('active'));
  if (btnCancelReview) btnCancelReview.addEventListener('click', () => modal.classList.remove('active'));
  if (btnSubmitReview) btnSubmitReview.addEventListener('click', submitReviewVerdict);

  // Modal decision radio changes
  const radios = document.querySelectorAll('input[name="modalDecision"]');
  const editFields = document.getElementById('modalEditFields');
  radios.forEach(r => {
    r.addEventListener('change', () => {
      if (r.value === 'Edited' || r.value === 'Rejected') {
        editFields.style.display = 'block';
      } else {
        editFields.style.display = 'none';
      }
    });
  });

}

/* ==========================================================================
   Toast Notification
   ========================================================================== */

function showToast(message, type) {
  const existing = document.querySelector('.toast');
  if (existing) existing.remove();

  const toast = document.createElement('div');
  toast.className = 'toast';
  toast.style.cssText = `
    position: fixed; bottom: 24px; right: 24px; z-index: 300;
    padding: 10px 18px; border-radius: 8px; font-size: 13px; font-weight: 600;
    font-family: var(--font-sans); box-shadow: 0 4px 12px rgba(0,0,0,0.1);
    animation: toastIn 0.2s ease-out;
  `;

  if (type === 'error') {
    toast.style.background = '#fef2f2'; toast.style.border = '1px solid #fecaca';
    toast.style.color = '#991b1b';
  } else {
    toast.style.background = '#ecfdf5'; toast.style.border = '1px solid #a7f3d0';
    toast.style.color = '#065f46';
  }

  toast.textContent = message;
  document.body.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transition = 'opacity 0.2s';
    setTimeout(() => toast.remove(), 200);
  }, 2500);
}

/* ==========================================================================
   Render All Views
   ========================================================================== */

function renderAllViews() {
  updateKpiBanner();
  renderAnalyticsCharts();
  renderCaseTable();
  renderReviewTable();
  renderResponsibleAiLog();
}

function updateKpiBanner() {
  const totalEl = document.getElementById('kpi-total-cases');
  if (totalEl) totalEl.textContent = state.cases.length;
  const heroAgree = document.getElementById('heroAgree');
  if (state.stats) {
    const agreeEl = document.getElementById('kpi-agreement-rate');
    const editEl = document.getElementById('kpi-human-edits');
    const pct = `${state.stats.ai_human_agreement_rate_pct || 80.0}%`;
    if (agreeEl) agreeEl.textContent = pct;
    if (heroAgree) heroAgree.textContent = pct;
    if (editEl) editEl.textContent = (state.stats.edited || 0) + (state.stats.rejected || 0);
  }
}

/* ==========================================================================
   Analytics Charts (Light Theme)
   ========================================================================== */

function renderAnalyticsCharts() {
  const chartColors = {
    bg: ['#0a0a0a', '#27272a', '#52525b', '#71717a', '#a1a1aa', '#d4d4d8'],
    text: '#52525b',
    grid: '#e4e4e7'
  };

  // 1. Layer Chart
  const layerCtx = document.getElementById('layerChart')?.getContext('2d');
  if (layerCtx) {
    const layerCounts = state.stats?.layer_distribution || {
      "Layer 1 (Physical)": 1, "Layer 2 (Data Link)": 8, "Layer 3 (Network)": 18,
      "Layer 4 (Transport)": 5, "Layer 7 (Application)": 3
    };
    if (state.charts.layer) state.charts.layer.destroy();
    state.charts.layer = new Chart(layerCtx, {
      type: 'doughnut',
      data: {
        labels: Object.keys(layerCounts),
        datasets: [{
          data: Object.values(layerCounts),
          backgroundColor: chartColors.bg,
          borderColor: '#ffffff',
          borderWidth: 2
        }]
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: {
          legend: { position: 'right', labels: { color: chartColors.text, font: { family: 'Inter', size: 11 }, padding: 12 } }
        }
      }
    });
  }

  // 2. Verdict Chart — monochrome
  const verdictCtx = document.getElementById('verdictChart')?.getContext('2d');
  if (verdictCtx) {
    const accepted = state.stats?.accepted || 10;
    const edited = state.stats?.edited || 8;
    const rejected = state.stats?.rejected || 2;
    const pending = state.stats?.pending || 15;
    if (state.charts.verdict) state.charts.verdict.destroy();
    state.charts.verdict = new Chart(verdictCtx, {
      type: 'bar',
      data: {
        labels: ['Accepted', 'Edited', 'Rejected', 'Pending'],
        datasets: [{
          label: 'Cases',
          data: [accepted, edited, rejected, pending],
          backgroundColor: ['#0a0a0a', '#52525b', '#a1a1aa', '#e4e4e7'],
          borderColor: '#0a0a0a',
          borderWidth: 1,
          borderRadius: 0
        }]
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: chartColors.text }, grid: { display: false } },
          y: { ticks: { color: chartColors.text }, grid: { color: chartColors.grid } }
        }
      }
    });
  }

  // 3. Domain Chart
  const domainCtx = document.getElementById('domainChart')?.getContext('2d');
  if (domainCtx) {
    const domainCounts = state.stats?.domain_distribution || {};
    const topDomains = Object.entries(domainCounts).slice(0, 6);
    if (state.charts.domain) state.charts.domain.destroy();
    state.charts.domain = new Chart(domainCtx, {
      type: 'bar',
      data: {
        labels: topDomains.map(d => d[0]),
        datasets: [{
          label: 'Cases',
          data: topDomains.map(d => d[1]),
          backgroundColor: '#0a0a0a',
          borderColor: '#0a0a0a',
          borderWidth: 1,
          borderRadius: 0
        }]
      },
      options: {
        indexAxis: 'y', responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: chartColors.text }, grid: { color: chartColors.grid } },
          y: { ticks: { color: chartColors.text }, grid: { display: false } }
        }
      }
    });
  }

  // 4. Severity Chart
  const sevCtx = document.getElementById('severityChart')?.getContext('2d');
  if (sevCtx) {
    const sevCounts = state.stats?.severity_distribution || {
      "Critical": 6, "High": 18, "Medium": 11, "Low": 0
    };
    if (state.charts.severity) state.charts.severity.destroy();
    state.charts.severity = new Chart(sevCtx, {
      type: 'pie',
      data: {
        labels: Object.keys(sevCounts),
        datasets: [{
          data: Object.values(sevCounts),
          backgroundColor: ['#0a0a0a', '#52525b', '#71717a', '#a1a1aa'],
          borderColor: '#ffffff',
          borderWidth: 2
        }]
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: {
          legend: { position: 'right', labels: { color: chartColors.text, font: { family: 'Inter', size: 11 }, padding: 12 } }
        }
      }
    });
  }
}

/* ==========================================================================
   Case Explorer Table
   ========================================================================== */

function renderCaseTable() {
  const tbody = document.getElementById('caseTableBody');
  if (!tbody) return;
  tbody.innerHTML = '';

  state.cases.forEach(c => {
    const review = state.reviews[c.case_id];
    const status = review ? review.decision.toLowerCase() : 'pending';

    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><strong>${c.case_id}</strong></td>
      <td>${c.title}</td>
      <td><span class="badge badge-blue">${c.domain}</span></td>
      <td>${c.osi_layer}</td>
      <td><span class="badge badge-severity-${c.severity.toLowerCase()}">${c.severity}</span></td>
      <td><span class="badge badge-status-${status}">${status.charAt(0).toUpperCase() + status.slice(1)}</span></td>
      <td><button class="btn btn-primary btn-sm" onclick="goToAssistantCase('${c.case_id}')">Diagnose</button></td>
    `;
    tbody.appendChild(tr);
  });
}

function filterCases() {
  const query = document.getElementById('caseSearchInput').value.toLowerCase();
  const layer = document.getElementById('layerFilter').value;
  const sev = document.getElementById('severityFilter').value;

  const rows = document.querySelectorAll('#caseTableBody tr');
  state.cases.forEach((c, idx) => {
    const matchesSearch = c.case_id.toLowerCase().includes(query) ||
                          c.title.toLowerCase().includes(query) ||
                          c.symptom.toLowerCase().includes(query) ||
                          c.domain.toLowerCase().includes(query);
    const matchesLayer = !layer || c.osi_layer.includes(layer);
    const matchesSev = !sev || c.severity === sev;
    if (rows[idx]) {
      rows[idx].style.display = (matchesSearch && matchesLayer && matchesSev) ? '' : 'none';
    }
  });
}

function goToAssistantCase(caseId) {
  const c = state.cases.find(x => x.case_id === caseId);
  if (c) {
    document.getElementById('assistantSymptom').value = c.symptom || '';
    document.getElementById('assistantTopology').value = c.topology_note || '';
    document.getElementById('assistantPastedCli').value = Object.entries(c.show_outputs || {})
      .map(([command, output]) => `${command}\n${output}`).join('\n\n');
    navigateToPage('page-assistant');
  }
}

/* ==========================================================================
   Studio Logic
   ========================================================================== */

function populateStudioCaseDropdown() {
  const select = document.getElementById('studioCaseSelect');
  if (!select) return;
  select.innerHTML = '';
  state.cases.forEach(c => {
    const opt = document.createElement('option');
    opt.value = c.case_id;
    opt.textContent = `${c.case_id} - ${c.title}`;
    select.appendChild(opt);
  });
}

function selectCaseForStudio(c) {
  state.currentCase = c;
  const select = document.getElementById('studioCaseSelect');
  if (select) select.value = c.case_id;

  const symptomEl = document.getElementById('studioSymptom');
  const topoEl = document.getElementById('studioTopology');
  if (symptomEl) symptomEl.textContent = c.symptom;
  if (topoEl) topoEl.textContent = c.topology_note;

  const showContainer = document.getElementById('studioShowOutputs');
  showContainer.innerHTML = '';
  if (c.show_outputs) {
    for (const [cmd, out] of Object.entries(c.show_outputs)) {
      const block = document.createElement('div');
      block.className = 'terminal-block';
      block.innerHTML = `
        <div class="terminal-bar">
          <div class="terminal-bar-left">
            <div class="terminal-dots">
              <div class="terminal-dot red"></div>
              <div class="terminal-dot yellow"></div>
              <div class="terminal-dot green"></div>
            </div>
            <span class="terminal-title">${escapeHtml(cmd)}</span>
          </div>
        </div>
        <div class="terminal-body">${escapeHtml(out)}</div>
      `;
      showContainer.appendChild(block);
    }
  }

  document.getElementById('studioFaultSummary').textContent = 'Ready for diagnosis...';
  document.getElementById('studioRootCause').textContent = 'Click "Run AI Diagnosis" to analyze symptoms and CLI evidence.';
  document.getElementById('studioConfidenceBadge').textContent = 'Confidence: --';
  document.getElementById('studioConfidenceBadge').className = 'badge badge-gray';
  document.getElementById('studioEvidenceCitations').innerHTML = '';
  document.getElementById('studioNextCommands').innerHTML = '';
  document.getElementById('studioRemediationScript').textContent = '! Waiting for diagnosis...';
  document.getElementById('studioRuleEngineAlert').style.display = 'none';
  document.getElementById('simulatorResultBox').style.display = 'none';
}

async function runStudioDiagnosis() {
  if (!state.currentCase) return;

  const btn = document.getElementById('btnRunDiagnosis');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner" style="width:16px;height:16px;border-width:2px;"></span> Analyzing Evidence...';

  try {
    const res = await fetch('/api/diagnose', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        case_id: state.currentCase.case_id,
        use_llm: state.settings.provider !== 'local',
        provider: state.settings.provider,
        api_key: state.settings.apiKey
      })
    });
    const diag = await res.json();
    state.currentDiagnosis = diag;

    document.getElementById('studioFaultSummary').textContent = diag.fault_summary;
    document.getElementById('studioRootCause').textContent = diag.root_cause;

    const confBadge = document.getElementById('studioConfidenceBadge');
    confBadge.textContent = `Confidence: ${Math.round(diag.confidence * 100)}% (${diag.osi_layer})`;
    confBadge.className = 'badge badge-green';

    // Rule alert
    const ruleAlert = document.getElementById('studioRuleEngineAlert');
    if (diag.rule_checker_pre_scan?.has_violations) {
      const v = diag.rule_checker_pre_scan.violations[0];
      ruleAlert.style.display = 'block';
      ruleAlert.innerHTML = `
        <div class="alert alert-red mb-3">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="flex-shrink:0;margin-top:1px;"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
          <div><strong>Rule Hit:</strong> ${v.rule_name} (${v.rule_id}) — ${v.severity} Severity</div>
        </div>
      `;
    } else {
      ruleAlert.style.display = 'block';
      ruleAlert.innerHTML = `
        <div class="alert alert-green mb-3">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="flex-shrink:0;margin-top:1px;"><polyline points="20 6 9 17 4 12"/></svg>
          <div><strong>Pre-Check Passed:</strong> No static configuration violations detected.</div>
        </div>
      `;
    }

    // Evidence
    const citContainer = document.getElementById('studioEvidenceCitations');
    citContainer.innerHTML = '';
    diag.evidence_citations.forEach(c => {
      const box = document.createElement('div');
      box.className = 'citation-item';
      box.textContent = c;
      citContainer.appendChild(box);
    });

    // Next commands
    const nextContainer = document.getElementById('studioNextCommands');
    nextContainer.innerHTML = '';
    diag.next_recommended_commands.forEach(cmd => {
      const div = document.createElement('div');
      div.style.cssText = 'padding:5px 8px;margin-bottom:4px;background:#f8f9fb;border:1px solid var(--border-light);border-radius:4px;color:var(--cyan);';
      div.textContent = `# ${cmd}`;
      nextContainer.appendChild(div);
    });

    document.getElementById('studioRemediationScript').textContent = diag.remediation_cli_script;
    showToast('Diagnosis complete');

  } catch (err) {
    showToast('Failed to generate diagnosis: ' + err.message, 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg> Run AI Diagnosis & Rule Pre-Scan';
  }
}

/* ==========================================================================
   Human Review Modal
   ========================================================================== */

function openReviewModal() {
  const modal = document.getElementById('reviewModal');
  document.getElementById('modalCaseId').textContent = `${state.currentCase.case_id} - ${state.currentCase.title}`;

  if (state.currentDiagnosis) {
    document.getElementById('modalEditedRootCause').value = state.currentDiagnosis.root_cause;
    document.getElementById('modalEditedCliFix').value = state.currentDiagnosis.remediation_cli_script;
  }

  modal.classList.add('active');
}

async function submitReviewVerdict() {
  const decision = document.querySelector('input[name="modalDecision"]:checked').value;
  const reviewerNotes = document.getElementById('modalReviewerNotes').value;
  const editedRootCause = document.getElementById('modalEditedRootCause').value;
  const editedCliFix = document.getElementById('modalEditedCliFix').value;
  const errorCategory = document.getElementById('modalErrorCategory').value;

  const payload = {
    case_id: state.currentCase.case_id,
    reviewer: state.settings.reviewerName,
    decision: decision,
    ai_diagnosis: state.currentDiagnosis || {
      root_cause: state.currentCase.expected_fault,
      remediation_cli_script: state.currentCase.ground_truth_fix,
      confidence: 0.95
    },
    edited_root_cause: editedRootCause,
    edited_cli_fix: editedCliFix,
    reviewer_notes: reviewerNotes,
    error_category: errorCategory
  };

  try {
    const res = await fetch('/api/review', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const reviewRecord = await res.json();
    if (!res.ok || reviewRecord.error) {
      throw new Error(reviewRecord.error || `Review submission failed (HTTP ${res.status})`);
    }

    state.reviews[state.currentCase.case_id] = reviewRecord;
    document.getElementById('reviewModal').classList.remove('active');

    const statsRes = await fetch('/api/stats').then(r => r.json());
    state.stats = statsRes;
    updateKpiBanner();
    renderReviewTable();
    navigateToPage('page-review');
    showToast(`Review "${decision}" saved for ${state.currentCase.case_id}`);
  } catch (err) {
    showToast('Failed to submit review: ' + err.message, 'error');
  }
}

/* ==========================================================================
   Review Table
   ========================================================================== */

function renderReviewTable() {
  const tbody = document.getElementById('reviewTableBody');
  if (!tbody) return;
  tbody.innerHTML = '';

  const reviewsList = Object.values(state.reviews);
  if (reviewsList.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding:32px; color:var(--text-muted);">No reviews submitted yet.</td></tr>`;
    return;
  }

  reviewsList.forEach(r => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><strong>${r.case_id}</strong></td>
      <td>${r.reviewer}</td>
      <td><span class="badge badge-status-${r.decision.toLowerCase()}">${r.decision}</span></td>
      <td class="text-sm text-muted">${r.timestamp}</td>
      <td><span class="badge badge-blue">${r.error_category || 'None'}</span></td>
      <td class="text-sm">${r.reviewer_notes}</td>
    `;
    tbody.appendChild(tr);
  });
}

/* ==========================================================================
   Responsible AI Cards
   ========================================================================== */

function renderResponsibleAiLog() {
  const container = document.getElementById('responsibleAiCards');
  if (!container) return;
  container.innerHTML = '';

  state.responsibleAiLog.forEach(log => {
    const card = document.createElement('div');
    card.className = 'card';
    card.innerHTML = `
      <div class="flex justify-between items-center mb-3" style="flex-wrap:wrap; gap:8px;">
        <div class="flex items-center gap-2">
          <strong style="font-size:14px;">${log.case_id}: ${log.title}</strong>
          <span class="badge badge-amber">${log.error_taxonomy}</span>
        </div>
        <span class="badge badge-status-edited">Verdict: ${log.reviewer_verdict}</span>
      </div>

      <div style="display:grid; grid-template-columns:1fr 1fr; gap:14px; margin-bottom:12px;">
        <div style="background:var(--red-light); border-left:3px solid var(--red); padding:10px 12px; border-radius:0 6px 6px 0;">
          <div class="text-xs font-bold" style="color:var(--red); margin-bottom:4px;">Initial AI Failure Mode</div>
          <div class="text-sm" style="color:var(--text-secondary);">${log.ai_initial_diagnosis}</div>
        </div>
        <div style="background:var(--green-light); border-left:3px solid var(--green); padding:10px 12px; border-radius:0 6px 6px 0;">
          <div class="text-xs font-bold" style="color:var(--green); margin-bottom:4px;">Human Reviewer Correction</div>
          <div class="text-sm" style="color:var(--text-secondary);">${log.human_correction}</div>
        </div>
      </div>

      <div class="text-sm text-muted">
        <strong>Key Learning:</strong> ${log.key_learning}
      </div>
    `;
    container.appendChild(card);
  });
}

/* ==========================================================================
   Presets
   ========================================================================== */

function renderPresets() {
  const container = document.getElementById('ptPresetsList');
  if (!container) return;
  container.innerHTML = '';

  if (!state.presets || state.presets.length === 0) {
    container.innerHTML = '<span class="text-sm text-muted">No lab presets loaded.</span>';
    return;
  }

  state.presets.forEach(preset => {
    const chip = document.createElement('button');
    chip.className = 'preset-chip';
    chip.textContent = preset.title;
    chip.addEventListener('click', () => {
      document.querySelectorAll('.preset-chip').forEach(c => c.classList.remove('active'));
      chip.classList.add('active');
      loadPresetIntoAssistant(preset);
    });
    container.appendChild(chip);
  });
}

function loadPresetIntoAssistant(preset) {
  const symptomEl = document.getElementById('assistantSymptom');
  const topEl = document.getElementById('assistantTopology');
  const cliEl = document.getElementById('assistantPastedCli');

  if (symptomEl) symptomEl.value = preset.symptom || '';
  if (topEl) topEl.value = preset.topology || '';
  if (cliEl) cliEl.value = preset.pasted_cli || '';

  runAssistantDiagnosis();
}

function clearAssistantFields() {
  const symptomEl = document.getElementById('assistantSymptom');
  const topEl = document.getElementById('assistantTopology');
  const cliEl = document.getElementById('assistantPastedCli');
  const outContainer = document.getElementById('assistantOutputContainer');
  const ruleBanner = document.getElementById('assistantRuleBanner');
  const actionFooter = document.getElementById('assistantActionFooter');
  const providerBadge = document.getElementById('assistantProviderBadge');

  if (symptomEl) symptomEl.value = '';
  if (topEl) topEl.value = '';
  if (cliEl) cliEl.value = '';
  if (ruleBanner) ruleBanner.style.display = 'none';
  if (actionFooter) actionFooter.style.display = 'none';
  if (providerBadge) {
    providerBadge.textContent = 'Ready';
    providerBadge.className = 'badge badge-gray';
  }

  document.querySelectorAll('.preset-chip').forEach(c => c.classList.remove('active'));
  state.assistantDiagnosis = null;

  if (outContainer) {
    outContainer.innerHTML = `
      <div class="empty-state">
        <div class="empty-state-icon">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
        </div>
        <h4>Network Troubleshooter Ready</h4>
        <p>Select a preset scenario or enter your symptoms and show commands to get evidence-based root cause analysis and copy-pasteable Cisco IOS fixes.</p>
      </div>
    `;
  }
}

/* ==========================================================================
   Engine Status
   ========================================================================== */

async function checkGroqStatus() {
  const badge = document.getElementById('assistantEngineBadge');
  const text = document.getElementById('assistantEngineStatusText');
  if (!badge || !text) return;

  const key = state.settings.apiKey;
  if (!key) {
    badge.className = 'engine-status';
    text.textContent = 'AI Engine: Local CCIE Active';
    return;
  }

  try {
    const res = await fetch('/api/groq-status', {
      headers: { 'Authorization': `Bearer ${key}` }
    });
    const data = await res.json();
    if (data.connected) {
      badge.className = 'engine-status online';
      text.textContent = `Cloud AI Online`;
    } else {
      badge.className = 'engine-status';
      text.textContent = 'Local Engine Active';
    }
  } catch (err) {
    badge.className = 'engine-status';
    text.textContent = 'Local CCIE Engine Active';
  }
}

async function testGroqConnection() {
  const keyInput = document.getElementById('settingApiKey');
  const resultDiv = document.getElementById('apiKeyTestResult');
  if (!resultDiv) return;

  const key = keyInput ? keyInput.value.trim() : '';
  if (!key) {
    resultDiv.style.display = 'block';
    resultDiv.innerHTML = '<span style="color:var(--red);">Please enter an API Key to test.</span>';
    return;
  }

  resultDiv.style.display = 'block';
  resultDiv.innerHTML = '<span style="color:var(--cyan);">Testing connection...</span>';

  try {
    const res = await fetch('/api/groq-status', {
      headers: { 'Authorization': `Bearer ${key}` }
    });
    const data = await res.json();
    if (data.connected) {
      resultDiv.innerHTML = `<span style="color:var(--green);"><strong>Connected!</strong> Model: <code>${data.model_tested}</code></span>`;
      checkGroqStatus();
    } else {
      resultDiv.innerHTML = `<span style="color:var(--red);"><strong>Failed:</strong> ${data.error || 'Invalid API Key'}</span>`;
    }
  } catch (err) {
    resultDiv.innerHTML = `<span style="color:var(--red);"><strong>Error:</strong> ${err.message}</span>`;
  }
}

/* ==========================================================================
   Assistant Diagnosis
   ========================================================================== */

async function runAssistantDiagnosis() {
  const symptom = document.getElementById('assistantSymptom')?.value.trim() || '';
  const topology = document.getElementById('assistantTopology')?.value.trim() || '';
  const pastedCli = document.getElementById('assistantPastedCli')?.value.trim() || '';
  const outContainer = document.getElementById('assistantOutputContainer');
  const providerBadge = document.getElementById('assistantProviderBadge');
  const ruleBanner = document.getElementById('assistantRuleBanner');
  const actionFooter = document.getElementById('assistantActionFooter');

  if (!symptom && !pastedCli) {
    showToast('Enter a symptom or paste Cisco show-command output.', 'error');
    return;
  }

  if (outContainer) {
    outContainer.innerHTML = `
      <div style="text-align:center; padding:48px 24px;">
        <div class="spinner" style="width:28px;height:28px;border-width:3px;margin:0 auto 16px;"></div>
        <h4 style="font-size:14px; font-weight:600; color:var(--text-primary); margin-bottom:4px;">Analyzing Network Issue...</h4>
        <p class="text-sm text-muted">Running deterministic pre-scan & AI diagnostic reasoning</p>
      </div>
    `;
  }
  if (providerBadge) {
    providerBadge.textContent = 'Reasoning...';
    providerBadge.className = 'badge badge-blue';
  }

  const btn = document.getElementById('btnRunAssistantDiagnosis');
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner" style="width:16px;height:16px;border-width:2px;"></span> Analyzing...';
  }

  const payload = {
    case_id: 'PT-DIAG-' + Math.floor(1000 + Math.random() * 9000),
    title: symptom ? symptom.slice(0, 50) : 'Packet Tracer Troubleshooting Case',
    symptom: symptom,
    topology_note: topology || 'Cisco Packet Tracer Lab Topology',
    show_outputs: { pasted_cli: pastedCli },
    use_llm: true,
    api_key: state.settings.apiKey,
    provider: state.settings.provider || 'groq',
    model: state.settings.groqModel || 'llama-3.3-70b-versatile'
  };

  try {
    const res = await fetch('/api/diagnose', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const diag = await res.json();
    state.assistantDiagnosis = diag;

    renderAssistantDiagnosis(diag);

    if (actionFooter) actionFooter.style.display = 'flex';
    if (providerBadge) {
      providerBadge.textContent = diag.ai_provider_used || 'Cloud AI';
      providerBadge.className = 'badge badge-green';
    }

    showToast('Diagnosis complete');
  } catch (err) {
    if (outContainer) {
      outContainer.innerHTML = `
        <div class="alert alert-red">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="flex-shrink:0;margin-top:1px;"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
          <div><strong>Diagnosis Error:</strong> ${err.message}</div>
        </div>
      `;
    }
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg> Analyze Network Issue';
    }
  }
}

function renderAssistantDiagnosis(diag) {
  const outContainer = document.getElementById('assistantOutputContainer');
  const ruleBanner = document.getElementById('assistantRuleBanner');
  if (!outContainer) return;

  // Rule banner
  if (ruleBanner) {
    const findings = diag.rule_checker_pre_scan;
    if (findings && findings.has_violations && findings.violations.length > 0) {
      const v = findings.violations[0];
      ruleBanner.style.display = 'block';
      ruleBanner.innerHTML = `
        <div class="alert alert-red mb-3">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="flex-shrink:0;margin-top:1px;"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
          <div>
            <strong>Rule Pre-Scan Flag:</strong> [${v.rule_id}] ${v.rule_name}
            <div class="text-xs text-muted mt-1">${v.evidence}</div>
          </div>
          <span class="badge badge-amber" style="margin-left:auto;">${v.severity}</span>
        </div>
      `;
    } else {
      ruleBanner.style.display = 'none';
    }
  }

  // Citations
  let citationsHtml = '';
  if (diag.evidence_citations && diag.evidence_citations.length > 0) {
    citationsHtml = diag.evidence_citations.map(c => `
      <div class="citation-item">${escapeHtml(c)}</div>
    `).join('');
  }

  // Next commands
  let nextCmdsHtml = '';
  if (diag.next_recommended_commands && diag.next_recommended_commands.length > 0) {
    nextCmdsHtml = diag.next_recommended_commands.map(cmd => `
      <div style="padding:5px 8px;margin-bottom:4px;background:#f8f9fb;border:1px solid var(--border-light);border-radius:4px;font-family:var(--font-mono);font-size:12px;color:var(--cyan);"># ${escapeHtml(cmd)}</div>
    `).join('');
  }

  const fixScript = diag.remediation_cli_script || '! No configuration changes required';
  const encodedFix = encodeURIComponent(fixScript);

  outContainer.innerHTML = `
    <!-- Diagnosis Header -->
    <div class="flex justify-between items-center mb-3" style="flex-wrap:wrap; gap:8px;">
      <div>
        <div style="font-size:15px; font-weight:700; color:var(--text-primary);">${escapeHtml(diag.fault_summary)}</div>
        <div class="text-xs text-muted mt-1">Case: <strong>${diag.case_id}</strong> &middot; Concept: <span style="color:var(--purple);">${escapeHtml(diag.concept_tag)}</span></div>
      </div>
      <div class="flex gap-2">
        <span class="badge badge-blue">${escapeHtml(diag.osi_layer)}</span>
        <span class="badge badge-green">Confidence: ${Math.round(diag.confidence * 100)}%</span>
      </div>
    </div>

    <!-- Root Cause -->
    <div class="output-section-label">Root Cause Analysis</div>
    <div style="background:var(--bg-surface); border:1px solid var(--border); border-radius:var(--radius-md); padding:12px 14px; margin-bottom:16px; font-size:13.5px; color:var(--text-secondary); line-height:1.6;">
      ${escapeHtml(diag.root_cause)}
    </div>

    <!-- Evidence -->
    ${citationsHtml ? `
      <div class="output-section-label">Cited CLI Evidence</div>
      <div class="mb-3">${citationsHtml}</div>
    ` : ''}

    <!-- Verification Commands -->
    ${nextCmdsHtml ? `
      <div class="output-section-label">Verification Commands</div>
      <div class="mb-3">${nextCmdsHtml}</div>
    ` : ''}

    <!-- Cisco Fix -->
    <div class="output-section-label" style="display:flex; justify-content:space-between; align-items:center;">
      <span>Proposed Cisco IOS Fix</span>
      <button class="copy-btn" onclick="copyCiscoFixToClipboard(this, decodeURIComponent('${encodedFix}'))">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
        Copy
      </button>
    </div>
    <div class="terminal-block" style="margin-bottom:16px;">
      <div class="terminal-bar">
        <div class="terminal-bar-left">
          <div class="terminal-dots">
            <div class="terminal-dot red"></div>
            <div class="terminal-dot yellow"></div>
            <div class="terminal-dot green"></div>
          </div>
          <span class="terminal-title">Cisco IOS Config</span>
        </div>
        <span class="text-xs font-semibold" style="color:var(--amber);">Risk: ${diag.risk_level || 'Low'}</span>
      </div>
      <div class="terminal-body">${escapeHtml(fixScript)}</div>
    </div>

    <!-- Human Oversight -->
    <div class="alert alert-green">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="flex-shrink:0;margin-top:1px;"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
      <div><strong>Human Oversight Active:</strong> A human reviewer must verify and approve this diagnosis before applying changes to real networks.</div>
    </div>
  `;
}

function copyCiscoFixToClipboard(btn, text) {
  const doCopy = (t) => {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(t);
    } else {
      const ta=document.createElement('textarea'); ta.value=t; ta.style.position='fixed'; ta.style.opacity='0';
      document.body.appendChild(ta); ta.select();
      try { document.execCommand('copy'); return Promise.resolve(); } catch(e){ return Promise.reject(e); } finally { ta.remove(); }
    }
  };
  doCopy(text).then(() => {
    btn.classList.add('copied');
    const originalHTML = btn.innerHTML;
    btn.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg> Copied';
    setTimeout(() => {
      btn.classList.remove('copied');
      btn.innerHTML = originalHTML;
    }, 2000);
    showToast('Copied to clipboard');
  }).catch(() => {
    showToast('Failed to copy to clipboard', 'error');
  });
}

function openReviewModalFromAssistant() {
  if (!state.assistantDiagnosis) return;

  state.currentCase = {
    case_id: state.assistantDiagnosis.case_id || 'PT-CUSTOM',
    title: state.assistantDiagnosis.fault_summary || 'Custom Packet Tracer Diagnosis',
    expected_fault: state.assistantDiagnosis.root_cause || '',
    ground_truth_fix: state.assistantDiagnosis.remediation_cli_script || ''
  };
  state.currentDiagnosis = state.assistantDiagnosis;
  openReviewModal();
}

/* ==========================================================================
   Utilities
   ========================================================================== */

function escapeHtml(str) {
  if (!str) return '';
  return str.toString().replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
