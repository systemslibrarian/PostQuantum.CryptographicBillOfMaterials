import * as vscode from 'vscode';
import { CbomState } from './state';
import { CbomSummary } from './model';

/**
 * The PQC readiness dashboard — a single webview that visualizes the json-summary: readiness gauge,
 * severity breakdown, quantum/classical split, baseline delta, and prioritized actions. Content is fully
 * static HTML rendered from the summary (no scripts beyond a tiny message handler), under a strict CSP.
 */
export class DashboardPanel {
  private static current: DashboardPanel | undefined;
  private readonly panel: vscode.WebviewPanel;
  private readonly disposables: vscode.Disposable[] = [];

  static show(state: CbomState): void {
    if (DashboardPanel.current) {
      DashboardPanel.current.panel.reveal(vscode.ViewColumn.Active);
      DashboardPanel.current.render(state.latest?.summary);
      return;
    }
    DashboardPanel.current = new DashboardPanel(state);
  }

  private constructor(private readonly state: CbomState) {
    this.panel = vscode.window.createWebviewPanel(
      'cbomDashboard',
      'PQC Readiness',
      vscode.ViewColumn.Active,
      { enableScripts: true, retainContextWhenHidden: true },
    );
    this.panel.onDidDispose(() => this.dispose(), null, this.disposables);
    this.state.onDidChange((r) => this.render(r?.summary), null, this.disposables);
    this.panel.webview.onDidReceiveMessage((msg) => {
      if (msg?.command === 'scan') {
        vscode.commands.executeCommand('cbom.scan');
      }
    }, null, this.disposables);
    this.render(this.state.latest?.summary);
  }

  private render(summary: CbomSummary | undefined): void {
    const nonce = makeNonce();
    const csp =
      `default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}';`;
    this.panel.webview.html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="${csp}">
<style>${STYLES}</style>
</head>
<body>
${summary ? body(summary) : empty()}
<script nonce="${nonce}">
  const vscode = acquireVsCodeApi();
  const btn = document.getElementById('scan');
  if (btn) { btn.addEventListener('click', () => vscode.postMessage({ command: 'scan' })); }
</script>
</body>
</html>`;
  }

  private dispose(): void {
    DashboardPanel.current = undefined;
    while (this.disposables.length) {
      this.disposables.pop()?.dispose();
    }
    this.panel.dispose();
  }
}

function body(s: CbomSummary): string {
  const f = s.findings;
  const tone = s.findings.critical > 0 ? 'crit' : s.findings.high > 0 ? 'warn' : 'ok';
  const delta = s.baselineDelta
    ? `<div class="delta">Since baseline:
        <span class="up">+${s.baselineDelta.new} new</span> ·
        <span class="down">−${s.baselineDelta.fixed} fixed</span> ·
        <span>${s.baselineDelta.regressed} regressed</span></div>`
    : '<div class="delta muted">No baseline supplied — run with a baseline to see migration progress.</div>';

  const actions = s.topActions.length
    ? s.topActions.map((a) => `<tr>
        <td><span class="pill ${a.level.toLowerCase()}">${a.level}</span></td>
        <td><code>${esc(a.ruleId)}</code></td>
        <td>${esc(a.algorithm)}${a.occurrences > 1 ? ` <span class="muted">×${a.occurrences}</span>` : ''}</td>
        <td>${esc(a.action)}</td></tr>`).join('')
    : '<tr><td colspan="4" class="muted">No high-risk actions detected.</td></tr>';

  return `
  <header>
    <div class="gauge ${tone}">${s.readinessScore}<span>/100</span></div>
    <div class="head-meta">
      <h1>PQC Readiness</h1>
      <div class="muted">profile <code>${esc(s.policyProfile)}</code> · ${esc(s.tool)} ${esc(s.toolVersion)}
        · ${s.coverage.projectsAnalyzed} analyzed${s.coverage.projectsFailed ? `, ${s.coverage.projectsFailed} failed` : ''}</div>
      <button id="scan">Re-scan</button>
    </div>
  </header>

  <section class="cards">
    <div class="card crit"><b>${f.critical}</b><span>Critical</span></div>
    <div class="card warn"><b>${f.high}</b><span>High</span></div>
    <div class="card"><b>${f.medium}</b><span>Medium</span></div>
    <div class="card"><b>${s.quantumVulnerable}</b><span>Quantum-vulnerable</span></div>
    <div class="card"><b>${s.classicalWeaknesses}</b><span>Classical weaknesses</span></div>
    <div class="card"><b>${s.waived}</b><span>Waived</span></div>
  </section>

  ${delta}

  <h2>Top migration actions</h2>
  <table>
    <thead><tr><th>Risk</th><th>Rule</th><th>Algorithm</th><th>Action</th></tr></thead>
    <tbody>${actions}</tbody>
  </table>

  <p class="footnote">A clean scan means “no detectable issues in analyzed source,” not “quantum-safe.”
    Runs locally — no code leaves your machine.</p>`;
}

function empty(): string {
  return `<div class="empty">
    <h1>PostQuantum CBOM</h1>
    <p class="muted">No scan yet. Run a scan to compute your PQC readiness.</p>
    <button id="scan">Scan workspace</button>
  </div>`;
}

function esc(value: string): string {
  return value.replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c] as string));
}

function makeNonce(): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let out = '';
  for (let i = 0; i < 32; i++) {
    out += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return out;
}

const STYLES = `
  body { font-family: var(--vscode-font-family); color: var(--vscode-foreground); padding: 1.2rem 1.6rem; }
  h1 { margin: 0 0 .2rem; font-size: 1.4rem; } h2 { margin-top: 1.6rem; font-size: 1.05rem; }
  .muted { opacity: .7; } code { color: var(--vscode-textPreformat-foreground); }
  header { display: flex; gap: 1.2rem; align-items: center; }
  .gauge { width: 96px; height: 96px; border-radius: 50%; display: flex; align-items: center; justify-content: center;
    font-size: 1.9rem; font-weight: 700; border: 4px solid var(--vscode-charts-green); }
  .gauge span { font-size: .8rem; opacity: .7; font-weight: 400; }
  .gauge.warn { border-color: var(--vscode-charts-yellow); } .gauge.crit { border-color: var(--vscode-charts-red); }
  .head-meta button, .empty button { margin-top: .5rem; background: var(--vscode-button-background);
    color: var(--vscode-button-foreground); border: none; padding: .35rem .8rem; border-radius: 3px; cursor: pointer; }
  .cards { display: flex; flex-wrap: wrap; gap: .6rem; margin-top: 1.2rem; }
  .card { flex: 1 1 110px; background: var(--vscode-editorWidget-background); border: 1px solid var(--vscode-widget-border);
    border-radius: 6px; padding: .7rem .9rem; display: flex; flex-direction: column; }
  .card b { font-size: 1.6rem; } .card span { opacity: .7; font-size: .8rem; }
  .card.crit b { color: var(--vscode-charts-red); } .card.warn b { color: var(--vscode-charts-yellow); }
  .delta { margin-top: 1rem; } .delta .up { color: var(--vscode-charts-red); } .delta .down { color: var(--vscode-charts-green); }
  table { width: 100%; border-collapse: collapse; margin-top: .5rem; }
  th, td { text-align: left; padding: .4rem .5rem; border-bottom: 1px solid var(--vscode-widget-border); vertical-align: top; }
  th { opacity: .7; font-weight: 600; }
  .pill { padding: .1rem .45rem; border-radius: 10px; font-size: .75rem; }
  .pill.critical { background: var(--vscode-charts-red); color: #fff; } .pill.high { background: var(--vscode-charts-yellow); color: #000; }
  .pill.medium, .pill.low, .pill.informational { background: var(--vscode-badge-background); color: var(--vscode-badge-foreground); }
  .footnote { margin-top: 1.6rem; font-size: .8rem; opacity: .65; }
  .empty { text-align: center; margin-top: 4rem; }
`;
