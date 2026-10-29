const RULES = [
  { id: 'PY.SECRET.LITERAL', title: 'Possible hard-coded credential', scope: 'Python literals', description: 'Credential-like names with direct string values, including annotated assignments, dictionary keys, keyword arguments, and parameter defaults.', limitation: 'Name matching is heuristic. Values are intentionally omitted.' },
  { id: 'GEN.SECRET.LITERAL', title: 'Possible hard-coded credential', scope: '.env files', description: 'Credential-like keys assigned non-placeholder values in .env files.', limitation: 'The rule does not confirm whether the value is a real credential.' },
  { id: 'PY.SQL.UNTRUSTED', title: 'Request data may reach SQL execution', scope: 'SQL sinks', description: 'Request data passed to execute-like calls or tracked through simple local variables.', limitation: 'SQL library identity and parameterization semantics are not resolved.' },
  { id: 'PY.COMMAND.UNTRUSTED', title: 'Request data may reach a command', scope: 'Shell/process sinks', description: 'Request data reaching os.system, os.popen, asyncio.create_subprocess_shell, or shell-enabled process calls.', limitation: 'Method names are heuristic; sanitizers and library identity are not modeled.' },
  { id: 'PY.PATH.UNTRUSTED', title: 'Request data may reach a file path', scope: 'File paths', description: 'Request data passed to open() or a method named open.', limitation: 'Path containment and method identity are not evaluated.' },
  { id: 'PY.CODE.UNTRUSTED', title: 'Request data may reach Python code execution', scope: 'eval / exec', description: 'Request data passed to eval or exec, directly or through simple local flow.', limitation: 'Other aliases and name shadowing are not resolved.' },
  { id: 'PY.CRYPTO.WEAK', title: 'Weak digest may be used for security', scope: 'MD5 / SHA-1', description: 'Direct calls to common MD5 or SHA-1 constructors.', limitation: 'Purpose and module identity are heuristic; checksums can be legitimate.' },
  { id: 'PY.RANDOM.INSECURE', title: 'Non-cryptographic randomness may be security-sensitive', scope: 'Python random', description: 'Direct calls to common random-module functions.', limitation: 'Aliases and security context are not resolved.' },
];

const DEMO_REPORT = {
  schema_version: '1',
  complete: true,
  scanned_files: 24,
  errors: [],
  findings: [
    { id: 'demo-code-01', rule_id: 'PY.CODE.UNTRUSTED', title: 'Request data may reach Python code execution', severity: 'high', confidence: 0.72, path: 'app/routes/admin.py', start: { line: 84, column: 5 }, end: { line: 84, column: 34 }, message: 'Request-derived text appears in the first argument to an eval/exec-like call.', evidence: [{ path: 'app/routes/admin.py', line: 84, role: 'source', excerpt: 'Request-derived input marker; source text omitted.' }, { path: 'app/routes/admin.py', line: 84, role: 'sink', excerpt: 'Sensitive API call; argument text omitted.' }], trace: [{ path: 'app/routes/admin.py', line: 84, label: 'request input' }, { path: 'app/routes/admin.py', line: 84, label: 'Python code execution sink' }], limitations: ['Builtin identity and name shadowing are not resolved.'] },
    { id: 'demo-command-02', rule_id: 'PY.COMMAND.UNTRUSTED', title: 'Request data may reach a shell command', severity: 'high', confidence: 0.68, path: 'app/services/export.py', start: { line: 47, column: 9 }, end: { line: 47, column: 43 }, message: 'Request-derived text appears in a method-name-matched call that enables shell execution.', evidence: [{ path: 'app/services/export.py', line: 43, role: 'source', excerpt: 'Request-derived value tracked through a simple local assignment; source text omitted.' }, { path: 'app/services/export.py', line: 47, role: 'sink', excerpt: 'Sensitive API call; argument text omitted.' }], trace: [{ path: 'app/services/export.py', line: 43, label: 'request input' }, { path: 'app/services/export.py', line: 47, label: 'Shell-enabled process-like call' }], limitations: ['Library identity, aliases, sanitizers, and branch paths are not resolved.'] },
    { id: 'demo-secret-03', rule_id: 'PY.SECRET.LITERAL', title: 'Possible hard-coded credential', severity: 'high', confidence: 0.62, path: 'app/config/settings.py', start: { line: 18, column: 14 }, end: { line: 18, column: 22 }, message: 'A credential-like variable is assigned a string literal. Confirm whether it is a real secret.', evidence: [{ path: 'app/config/settings.py', line: 18, role: 'assignment', excerpt: 'Credential-like name assigned a literal; value intentionally omitted.' }], trace: [], limitations: ['Heuristic name matching; the value is omitted.'] },
    { id: 'demo-path-04', rule_id: 'PY.PATH.UNTRUSTED', title: 'Request data may reach a file path', severity: 'medium', confidence: 0.58, path: 'app/files/downloads.py', start: { line: 62, column: 11 }, end: { line: 62, column: 27 }, message: 'A locally tracked request-derived variable appears in a file open argument.', evidence: [{ path: 'app/files/downloads.py', line: 60, role: 'source', excerpt: 'Request-derived value tracked through a simple local assignment; source text omitted.' }, { path: 'app/files/downloads.py', line: 62, role: 'sink', excerpt: 'Sensitive API call; argument text omitted.' }], trace: [{ path: 'app/files/downloads.py', line: 60, label: 'request input' }, { path: 'app/files/downloads.py', line: 62, label: 'Filesystem sink' }], limitations: ['Path containment, aliases, and branch paths are not modeled.'] },
    { id: 'demo-sql-05', rule_id: 'PY.SQL.UNTRUSTED', title: 'Request data may reach a SQL query argument', severity: 'medium', confidence: 0.66, path: 'app/db/search.py', start: { line: 39, column: 8 }, end: { line: 39, column: 44 }, message: 'A locally tracked request-derived variable appears in the query argument of a SQL-like execution call.', evidence: [{ path: 'app/db/search.py', line: 35, role: 'source', excerpt: 'Request-derived value tracked through a simple local assignment; source text omitted.' }, { path: 'app/db/search.py', line: 39, role: 'sink', excerpt: 'Sensitive API call; argument text omitted.' }], trace: [{ path: 'app/db/search.py', line: 35, label: 'request input' }, { path: 'app/db/search.py', line: 39, label: 'SQL execution sink' }], limitations: ['SQL parameterization, aliases, and branch paths are not modeled.'] },
  ],
};

const elements = {
  scannerPanel: document.querySelector('#scannerPanel'),
  modeBadge: document.querySelector('#modeBadge'),
  workspaceTitle: document.querySelector('#workspaceTitle'),
  workspaceSubtitle: document.querySelector('#workspaceSubtitle'),
  pageSubtitle: document.querySelector('#pageSubtitle'),
  heroKicker: document.querySelector('#heroKicker'),
  reportInput: document.querySelector('#reportInput'),
  scanPathInput: document.querySelector('#scanPathInput'),
  apiTokenInput: document.querySelector('#apiTokenInput'),
  runScanButton: document.querySelector('#runScanButton'),
  scannerStatus: document.querySelector('#scannerStatus'),
  scanTelemetry: document.querySelector('#scanTelemetry'),
  scanLatency: document.querySelector('#scanLatency'),
  scanThroughput: document.querySelector('#scanThroughput'),
  importButton: document.querySelector('#importButton'),
  heroImportButton: document.querySelector('#heroImportButton'),
  reportState: document.querySelector('#reportState span'),
  navFindingCount: document.querySelector('#navFindingCount'),
  totalFindings: document.querySelector('#totalFindings'),
  highFindings: document.querySelector('#highFindings'),
  filesScanned: document.querySelector('#filesScanned'),
  rulesTriggered: document.querySelector('#rulesTriggered'),
  scanCompleteness: document.querySelector('#scanCompleteness'),
  severityChart: document.querySelector('#severityChart'),
  completenessPill: document.querySelector('#completenessPill'),
  healthRing: document.querySelector('#healthRing'),
  healthIcon: document.querySelector('#healthIcon'),
  healthTitle: document.querySelector('#healthTitle'),
  healthDescription: document.querySelector('#healthDescription'),
  healthFiles: document.querySelector('#healthFiles'),
  healthErrors: document.querySelector('#healthErrors'),
  errorList: document.querySelector('#errorList'),
  findingList: document.querySelector('#findingList'),
  findingDetail: document.querySelector('#findingDetail'),
  searchInput: document.querySelector('#searchInput'),
  toast: document.querySelector('#toast'),
  ruleGrid: document.querySelector('#ruleGrid'),
  breadcrumbCurrent: document.querySelector('#breadcrumbCurrent'),
};

const state = { report: DEMO_REPORT, origin: 'Demo preview', reportName: null, reportMode: 'demo', apiAvailable: false, filter: 'all', search: '', selected: null, toastTimer: null };

function configureHostingMode() {
  const loopbackHosts = new Set(['localhost', '127.0.0.1', '::1', '[::1]']);
  const localServer = location.protocol !== 'file:' && loopbackHosts.has(location.hostname);
  if (localServer) { state.apiAvailable = true; return; }

  elements.scannerPanel.hidden = true;
  elements.modeBadge.textContent = 'HOSTED REPORT VIEWER';
  elements.workspaceTitle.textContent = 'Hosted dashboard';
  elements.workspaceSubtitle.textContent = 'Report review only';
  elements.pageSubtitle.textContent = 'Import a SecuTron JSON report to review findings. Scans run on your own machine.';
  elements.heroKicker.textContent = 'LOCAL SCANS · HOSTED REVIEW';
  document.querySelector('.sidebar-bottom p').textContent = 'Imported reports stay in this browser. Source code is not uploaded.';
  document.querySelector('.privacy-indicator').lastChild.textContent = ' BROWSER ONLY';
}

function textNode(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  node.textContent = text ?? '';
  return node;
}

function severityOf(value) {
  const severity = String(value || 'info').toLowerCase();
  if (severity === 'critical' || severity === 'high' || severity === 'medium' || severity === 'low') return severity;
  return 'low';
}

function titleForRule(ruleId) {
  return RULES.find(rule => rule.id === ruleId)?.title || ruleId || 'Finding';
}

function findings() {
  return Array.isArray(state.report?.findings) ? state.report.findings : [];
}

function safeNumber(value) {
  const number = Number(value);
  return Number.isFinite(number) && number >= 0 ? number : 0;
}

function showToast(message) {
  elements.toast.textContent = message;
  elements.toast.classList.add('show');
  clearTimeout(state.toastTimer);
  state.toastTimer = setTimeout(() => elements.toast.classList.remove('show'), 3600);
}

function normalizeReport(value) {
  if (!value || typeof value !== 'object' || !Array.isArray(value.findings) || typeof value.complete !== 'boolean') {
    throw new Error('This file is not a SecuTron JSON scan report. Choose JSON output from `secutron scan … --format json`.');
  }
  const cleanedFindings = value.findings.map((finding, index) => {
    if (!finding || typeof finding !== 'object') throw new Error(`Finding ${index + 1} is malformed.`);
    const start = finding.start && typeof finding.start === 'object' ? finding.start : {};
    return {
      ...finding,
      id: String(finding.id || `${finding.rule_id || 'finding'}-${index}`),
      rule_id: String(finding.rule_id || 'UNKNOWN'),
      title: String(finding.title || titleForRule(finding.rule_id)),
      severity: severityOf(finding.severity),
      confidence: Number.isFinite(Number(finding.confidence)) ? Number(finding.confidence) : null,
      path: String(finding.path || '(unknown file)'),
      start: { line: safeNumber(start.line), column: safeNumber(start.column) },
      message: String(finding.message || 'No message provided.'),
      evidence: Array.isArray(finding.evidence) ? finding.evidence : [],
      trace: Array.isArray(finding.trace) ? finding.trace : [],
      limitations: Array.isArray(finding.limitations) ? finding.limitations : [],
    };
  });
  return {
    ...value,
    complete: value.complete,
    scanned_files: safeNumber(value.scanned_files),
    errors: Array.isArray(value.errors) ? value.errors : [],
    findings: cleanedFindings,
  };
}

function renderMetrics() {
  const reportFindings = findings();
  const high = reportFindings.filter(item => ['high', 'critical'].includes(severityOf(item.severity))).length;
  const ruleCount = new Set(reportFindings.map(item => item.rule_id)).size;
  const complete = state.report.complete === true;
  elements.totalFindings.textContent = String(reportFindings.length);
  elements.highFindings.textContent = String(high);
  elements.filesScanned.textContent = String(safeNumber(state.report.scanned_files));
  elements.rulesTriggered.textContent = String(ruleCount);
  elements.navFindingCount.textContent = String(reportFindings.length);
  elements.scanCompleteness.textContent = complete ? 'Scan report is complete' : 'Review the recorded scan errors';
  elements.reportState.textContent = state.origin;
  elements.completenessPill.className = `status-pill ${complete ? 'complete' : 'incomplete'}`;
  elements.completenessPill.querySelector('span').textContent = complete ? 'COMPLETE' : 'INCOMPLETE';
  elements.healthRing.className = `health-ring ${complete ? 'healthy' : 'warning'}`;
  elements.healthIcon.textContent = complete ? '✓' : '!';
  elements.healthTitle.textContent = complete ? 'Scan completed' : 'Scan is incomplete';
  const errorCount = Array.isArray(state.report.errors) ? state.report.errors.length : 0;
  elements.healthDescription.textContent = complete
    ? `${reportFindings.length} candidate finding${reportFindings.length === 1 ? '' : 's'} in the imported report.`
    : `${errorCount} recorded issue${errorCount === 1 ? '' : 's'} prevented a complete analysis.`;
  elements.healthFiles.textContent = String(safeNumber(state.report.scanned_files));
  elements.healthErrors.textContent = String(errorCount);
  elements.errorList.replaceChildren();
  elements.errorList.hidden = errorCount === 0;
  if (errorCount) {
    elements.errorList.append(textNode('div', 'error-list-title', 'Recorded scan errors'));
    for (const error of state.report.errors) {
      const row = textNode('div', 'error-item', '');
      row.append(textNode('strong', '', String(error?.path || '.')));
      row.append(textNode('span', '', String(error?.message || 'Scan issue recorded.')));
      elements.errorList.append(row);
    }
  }
  renderSeverityChart(reportFindings);
}

function renderSeverityChart(reportFindings) {
  const groups = [
    { label: 'Critical', key: 'critical', color: 'var(--critical)' },
    { label: 'High', key: 'high', color: 'var(--high)' },
    { label: 'Medium', key: 'medium', color: 'var(--medium)' },
    { label: 'Low / info', key: 'low', color: 'var(--low)' },
  ];
  const counts = Object.fromEntries(groups.map(group => [group.key, reportFindings.filter(item => severityOf(item.severity) === group.key || (group.key === 'low' && severityOf(item.severity) === 'info')).length]));
  const max = Math.max(1, ...Object.values(counts));
  elements.severityChart.replaceChildren();
  for (const group of groups) {
    const row = textNode('div', 'severity-row', '');
    row.append(textNode('span', '', group.label));
    const track = textNode('div', 'severity-track', '');
    const fill = textNode('div', 'severity-fill', '');
    fill.style.width = `${counts[group.key] ? Math.max(5, (counts[group.key] / max) * 100) : 0}%`;
    fill.style.background = group.color;
    track.append(fill);
    row.append(track, textNode('strong', 'severity-count', String(counts[group.key])));
    elements.severityChart.append(row);
  }
}

function filteredFindings() {
  const query = state.search.trim().toLowerCase();
  return findings().map((finding, index) => ({ finding, index })).filter(({ finding }) => {
    const severity = severityOf(finding.severity);
    const filterPass = state.filter === 'all' || (state.filter === 'high' ? severity === 'high' || severity === 'critical' : state.filter === 'low' ? severity === 'low' || severity === 'info' : severity === state.filter);
    const searchPass = !query || [finding.title, finding.rule_id, finding.path, finding.message].some(value => String(value || '').toLowerCase().includes(query));
    return filterPass && searchPass;
  });
}

function renderFindingList() {
  const visible = filteredFindings();
  elements.findingList.replaceChildren();
  if (visible.length === 0) {
    const message = findings().length === 0
      ? (state.report.complete ? 'No candidate findings in this report.' : 'No findings were recorded, but this scan is incomplete. Review the scan errors before treating it as clean.')
      : 'No findings match the current search and filters.';
    elements.findingList.append(textNode('div', 'empty-list', message));
    renderFindingDetail(null);
    state.selected = null;
    return;
  }
  if (!visible.some(({ index }) => index === state.selected)) state.selected = visible[0].index;
  for (const { finding, index } of visible) {
    const severity = severityOf(finding.severity);
    const button = document.createElement('button');
    button.type = 'button';
    button.className = `finding-row sev-${severity}${index === state.selected ? ' selected' : ''}`;
    button.setAttribute('aria-pressed', String(index === state.selected));
    button.addEventListener('click', () => { state.selected = index; renderFindingList(); });
    button.append(textNode('span', 'finding-accent', ''));
    const main = textNode('span', 'finding-row-main', '');
    const title = textNode('span', 'finding-title', '');
    title.append(textNode('span', '', String(finding.title || titleForRule(finding.rule_id))));
    title.append(textNode('span', 'finding-rule', String(finding.rule_id)));
    main.append(title);
    const meta = textNode('span', 'finding-meta', '');
    meta.append(textNode('span', 'finding-path', String(finding.path || '(unknown file)')));
    const line = safeNumber(finding.start?.line);
    meta.append(textNode('span', '', `L${line}`));
    main.append(meta);
    button.append(main, textNode('span', 'severity-label', severity));
    elements.findingList.append(button);
  }
  renderFindingDetail(findings()[state.selected]);
}

function renderFindingDetail(finding) {
  elements.findingDetail.replaceChildren();
  if (!finding) {
    const empty = textNode('div', 'detail-empty', '');
    const shield = textNode('div', 'detail-shield', '');
    shield.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3 20 6v5c0 5-3.4 8.3-8 10-4.6-1.7-8-5-8-10V6l8-3Z"/><path d="m8.5 12 2.2 2.2 4.8-5"/></svg>';
    empty.append(shield, textNode('h3', '', 'Select a finding'), textNode('p', '', 'Evidence, trace, and rule limitations will appear here.'));
    elements.findingDetail.append(empty);
    return;
  }
  const head = textNode('div', 'detail-header', '');
  const titleWrap = textNode('div', '', '');
  titleWrap.append(textNode('span', 'finding-rule', String(finding.rule_id)));
  titleWrap.append(textNode('h3', '', String(finding.title || titleForRule(finding.rule_id))));
  titleWrap.append(textNode('div', 'detail-id', `Finding ${String(finding.id).slice(0, 12)}`));
  head.append(titleWrap, textNode('span', 'severity-label', severityOf(finding.severity)));
  elements.findingDetail.append(head);

  const location = textNode('div', 'detail-location', '');
  location.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 21s7-4.4 7-11a7 7 0 1 0-14 0c0 6.6 7 11 7 11Z"/><circle cx="12" cy="10" r="2.2"/></svg>';
  location.append(textNode('span', '', `${String(finding.path)}:${safeNumber(finding.start?.line)}:${safeNumber(finding.start?.column)}`));
  elements.findingDetail.append(location, textNode('p', 'detail-message', String(finding.message || '')));

  if (state.reportMode !== 'demo') {
    const aiAction = textNode('div', 'ai-action', '');
    const actions = textNode('div', 'ai-action-buttons', '');
    const download = textNode('button', 'button button-secondary', 'Download report JSON');
    download.type = 'button';
    download.addEventListener('click', downloadReport);
    const copyCommand = textNode('button', 'button button-secondary', 'Copy CLI explain command');
    copyCommand.type = 'button';
    copyCommand.setAttribute('aria-label', `Copy CLI explanation command for ${String(finding.id)}`);
    copyCommand.addEventListener('click', () => copyExplainCommand(finding));
    actions.append(download, copyCommand);
    aiAction.append(actions, textNode('p', '', `${state.reportName ? `Imported ${state.reportName}.` : 'Save the local scan as JSON first.'} Replace the report-path placeholder, then run from the SecuTron project folder. The CLI asks before sending this finding to the configured provider.`));
    if (state.apiAvailable) {
      const explainButton = textNode('button', 'button button-secondary', 'Ask Nebius to explain');
      explainButton.type = 'button';
      const explanation = textNode('p', 'ai-explanation', '');
      const telemetry = textNode('div', 'ai-telemetry', '');
      explainButton.addEventListener('click', async () => {
        const token = elements.apiTokenInput.value.trim();
        if (!token) { explanation.textContent = 'Enter the local API token above first.'; return; }
        explainButton.disabled = true;
        explanation.textContent = 'Sending this finding’s allowlisted metadata and sanitized evidence to the configured Nebius provider…';
        telemetry.textContent = '';
        try {
          const response = await fetch('/api/explain', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
            body: JSON.stringify({ finding }),
          });
          const result = await response.json();
          if (!response.ok) throw new Error(String(result.error || `Local API returned HTTP ${response.status}.`));
          explanation.textContent = String(result.explanation || 'The provider returned no explanation.');
          const inputTokens = Number.isSafeInteger(result.input_tokens) ? result.input_tokens : '—';
          const outputTokens = Number.isSafeInteger(result.output_tokens) ? result.output_tokens : '—';
          telemetry.textContent = `${String(result.provider)} · ${String(result.model)} · ${Number(result.latency_ms).toFixed(0)} ms · ${inputTokens} input / ${outputTokens} output tokens`;
        } catch (error) {
          explanation.textContent = String(error.message || 'The provider request failed.');
        } finally { explainButton.disabled = false; }
      });
      actions.append(explainButton);
      aiAction.append(
        textNode('p', 'ai-disclosure', 'Clicking Ask sends only this finding’s allowlisted metadata, sanitized evidence, trace, and limitations. It does not send source files, the full report, or environment values.'),
        explanation,
        telemetry,
      );
    }
    elements.findingDetail.append(aiAction);
  }

  const evidence = Array.isArray(finding.evidence) ? finding.evidence : [];
  if (evidence.length) {
    const block = textNode('div', 'detail-block', '');
    block.append(textNode('div', 'detail-block-title', 'Evidence'));
    for (const item of evidence) {
      const row = textNode('div', 'evidence-item', '');
      row.append(textNode('span', 'evidence-role', String(item.role || 'evidence')));
      row.append(textNode('span', '', `${String(item.path || finding.path)}:${safeNumber(item.line)} · ${String(item.excerpt || '')}`));
      block.append(row);
    }
    elements.findingDetail.append(block);
  }

  const trace = Array.isArray(finding.trace) ? finding.trace : [];
  if (trace.length) {
    const block = textNode('div', 'detail-block', '');
    block.append(textNode('div', 'detail-block-title', 'Source-to-sink trace'));
    const list = textNode('div', 'trace-list', '');
    for (const step of trace) {
      const chip = textNode('span', 'trace-chip', '');
      chip.append(textNode('span', '', `L${safeNumber(step.line)}`), document.createTextNode(String(step.label || 'Trace step')));
      list.append(chip);
    }
    block.append(list);
    elements.findingDetail.append(block);
  }

  const limitations = Array.isArray(finding.limitations) ? finding.limitations : [];
  if (limitations.length) {
    const block = textNode('div', 'detail-block', '');
    block.append(textNode('div', 'detail-block-title', 'Rule limitations'));
    const list = document.createElement('ul');
    list.className = 'limitation-list';
    for (const limitation of limitations) list.append(textNode('li', '', String(limitation)));
    block.append(list);
    elements.findingDetail.append(block);
  }
}

function renderRules() {
  elements.ruleGrid.replaceChildren();
  for (const rule of RULES) {
    const card = textNode('article', 'rule-card', '');
    const head = textNode('div', 'rule-card-head', '');
    head.append(textNode('span', 'rule-id', rule.id), textNode('span', 'rule-state', 'IMPLEMENTED · HEURISTIC'));
    card.append(head, textNode('h3', '', rule.title), textNode('p', '', `${rule.scope}. ${rule.description} ${rule.limitation}`));
    elements.ruleGrid.append(card);
  }
}

function render() {
  renderMetrics();
  renderFindingList();
}

async function importReport(file) {
  if (!file) return;
  try {
    const parsed = JSON.parse(await file.text());
    state.report = normalizeReport(parsed);
    state.origin = `Imported · ${file.name}`;
    state.reportName = file.name;
    state.reportMode = 'imported';
    state.filter = 'all';
    state.search = '';
    state.selected = null;
    elements.searchInput.value = '';
    document.querySelectorAll('.filter-button').forEach(button => button.classList.toggle('active', button.dataset.filter === 'all'));
    render();
    showToast(`Loaded ${state.report.findings.length} finding${state.report.findings.length === 1 ? '' : 's'} from ${file.name}.`);
  } catch (error) {
    showToast(error instanceof SyntaxError ? 'Could not read this file as JSON.' : String(error.message || 'Could not load the scan report.'));
  } finally {
    elements.reportInput.value = '';
  }
}

async function copyExplainCommand(finding) {
  const quotedId = `'${String(finding.id).replaceAll("'", "''")}'`;
  const command = `cargo run -- explain '<path-to-scan-report.json>' ${quotedId}`;
  try {
    await navigator.clipboard.writeText(command);
    showToast('CLI command copied. Replace the report-path placeholder before running it.');
  } catch {
    window.prompt('Clipboard access was blocked. Copy this command and replace the report-path placeholder:', command);
  }
}

function downloadReport() {
  const blob = new Blob([JSON.stringify(state.report, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = 'secutron-scan-report.json';
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  showToast('Scan report downloaded to this device.');
}

async function runLocalScan() {
  const path = elements.scanPathInput.value.trim();
  const token = elements.apiTokenInput.value.trim();
  if (!path || !token) {
    elements.scannerStatus.textContent = 'Enter a repository folder and the token printed by secutron serve.';
    return;
  }
  elements.runScanButton.disabled = true;
  elements.scanTelemetry.hidden = true;
  elements.scannerStatus.textContent = 'Scanning locally…';
  try {
    if (location.protocol === 'file:') throw new Error('Open the local URL printed by `secutron serve` to use streamed scans.');
    const socketProtocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const report = await new Promise((resolve, reject) => {
      const socket = new WebSocket(`${socketProtocol}//${location.host}/api/scan/stream`);
      let settled = false;
      const fail = error => {
        if (settled) return;
        settled = true;
        socket.close();
        reject(error instanceof Error ? error : new Error(String(error)));
      };
      socket.addEventListener('open', () => socket.send(JSON.stringify({ token, path })));
      socket.addEventListener('message', event => {
        let message;
        try { message = JSON.parse(event.data); } catch { fail(new Error('Local scan stream returned invalid JSON.')); return; }
        if (message.type === 'started') {
          elements.scannerStatus.textContent = 'Scan started on the local SecuTron server…';
        } else if (message.type === 'running') {
          const seconds = (Number(message.elapsed_ms) / 1000).toFixed(1);
          elements.scannerStatus.textContent = `Scan running · ${seconds}s elapsed`;
        } else if (message.type === 'error') {
          fail(new Error(String(message.error || 'Local scan failed.')));
        } else if (message.type === 'complete') {
          settled = true;
          socket.close();
          resolve({ report: message.report, elapsedMs: Number(message.elapsed_ms) });
        }
      });
      socket.addEventListener('error', () => fail(new Error('Could not connect to the local SecuTron scan stream.')));
      socket.addEventListener('close', () => { if (!settled) fail(new Error('Local scan stream closed before the scan completed.')); });
    });
    state.report = normalizeReport(report.report);
    state.origin = `Local scan · ${path}`;
    state.reportName = null;
    state.reportMode = 'local';
    state.filter = 'all';
    state.search = '';
    state.selected = null;
    elements.searchInput.value = '';
    document.querySelectorAll('.filter-button').forEach(button => button.classList.toggle('active', button.dataset.filter === 'all'));
    render();
    const elapsedMs = Math.max(0, report.elapsedMs);
    const filesPerSecond = elapsedMs > 0 ? state.report.scanned_files / (elapsedMs / 1000) : 0;
    elements.scanLatency.textContent = `Scan time: ${elapsedMs.toFixed(1)} ms`;
    elements.scanThroughput.textContent = `Throughput: ${filesPerSecond.toFixed(1)} files/sec`;
    elements.scanTelemetry.hidden = false;
    elements.scannerStatus.textContent = `Scan returned ${state.report.findings.length} finding${state.report.findings.length === 1 ? '' : 's'} across ${state.report.scanned_files} file${state.report.scanned_files === 1 ? '' : 's'}.`;
    showToast(state.report.complete ? 'Local scan complete.' : 'Local scan ended with recorded errors; review completeness before treating it as clean.');
  } catch (error) {
    elements.scannerStatus.textContent = String(error.message || 'Could not connect to the local SecuTron API.');
    if (location.protocol === 'file:') elements.scannerStatus.textContent += ' Open the http://127.0.0.1 URL printed by `cargo run -- serve`.';
  } finally {
    elements.runScanButton.disabled = false;
  }
}

function showView(viewName) {
  const overview = document.querySelector('#overviewView');
  const rules = document.querySelector('#rulesView');
  const showRules = viewName === 'rules';
  overview.hidden = showRules;
  rules.hidden = !showRules;
  overview.classList.toggle('active', !showRules);
  rules.classList.toggle('active', showRules);
  elements.breadcrumbCurrent.textContent = showRules ? 'Rule coverage' : viewName === 'findings' ? 'Findings' : 'Overview';
  document.querySelectorAll('.nav-item[data-view]').forEach(button => {
    const active = button.dataset.view === (showRules ? 'rules' : viewName === 'findings' ? 'findings' : 'overview');
    button.classList.toggle('active', active);
    if (active) button.setAttribute('aria-current', 'page'); else button.removeAttribute('aria-current');
  });
  if (viewName === 'findings') document.querySelector('#findings').scrollIntoView({ behavior: 'smooth', block: 'start' });
  else window.scrollTo({ top: 0, behavior: 'smooth' });
}

elements.importButton.addEventListener('click', () => elements.reportInput.click());
elements.heroImportButton.addEventListener('click', () => elements.reportInput.click());
elements.reportInput.addEventListener('change', event => importReport(event.target.files?.[0]));
elements.runScanButton.addEventListener('click', runLocalScan);
elements.searchInput.addEventListener('input', event => { state.search = event.target.value; renderFindingList(); });
document.querySelectorAll('.filter-button').forEach(button => button.addEventListener('click', () => {
  state.filter = button.dataset.filter;
  document.querySelectorAll('.filter-button').forEach(item => item.classList.toggle('active', item === button));
  renderFindingList();
}));
document.querySelectorAll('[data-view]').forEach(button => button.addEventListener('click', () => showView(button.dataset.view)));
document.querySelector('#helpButton').addEventListener('click', () => showToast('Demo preview is illustrative. Import a SecuTron JSON report to inspect real scan results.'));

renderRules();
configureHostingMode();
render();


