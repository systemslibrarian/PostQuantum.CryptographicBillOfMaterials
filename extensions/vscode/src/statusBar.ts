import * as vscode from 'vscode';
import { CbomState } from './state';

/** A status-bar item showing the PQC readiness score, coloured by posture, that opens the dashboard. */
export function createStatusBar(state: CbomState): vscode.Disposable {
  const item = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  item.command = 'cbom.showDashboard';
  item.text = '$(shield) PQC: —';
  item.tooltip = 'PostQuantum CBOM — run a scan to compute readiness';
  item.show();

  const sub = state.onDidChange((result) => {
    if (!result) {
      item.text = '$(shield) PQC: —';
      item.backgroundColor = undefined;
      return;
    }
    const s = result.summary;
    item.text = `$(shield) PQC: ${s.readinessScore}/100`;
    item.tooltip =
      `PQC readiness ${s.readinessScore}/100 · ` +
      `${s.findings.critical} critical, ${s.findings.high} high · ` +
      `${s.quantumVulnerable} quantum-vulnerable\nClick to open the dashboard`;
    // Warn only when there is genuine risk, so a clean repo stays unobtrusive.
    item.backgroundColor =
      s.findings.critical > 0
        ? new vscode.ThemeColor('statusBarItem.errorBackground')
        : s.findings.high > 0
          ? new vscode.ThemeColor('statusBarItem.warningBackground')
          : undefined;
  });

  return vscode.Disposable.from(item, sub);
}
