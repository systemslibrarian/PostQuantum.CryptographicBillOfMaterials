import * as vscode from 'vscode';
import * as path from 'path';
import { CliRunner, CliError } from './cli';
import { CbomState } from './state';
import { CbomExplorerProvider } from './explorer';
import { DashboardPanel } from './dashboard';
import { createStatusBar } from './statusBar';
import { addGitHubAction } from './scaffold';

export function activate(context: vscode.ExtensionContext): void {
  const root = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  if (!root) {
    return; // No folder open — nothing to scan.
  }

  const state = new CbomState();
  const runner = new CliRunner(root);

  const explorer = new CbomExplorerProvider(state);
  context.subscriptions.push(
    state,
    vscode.window.registerTreeDataProvider('cbomExplorer', explorer),
    createStatusBar(state),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('cbom.scan', () => runScan(runner, state)),
    vscode.commands.registerCommand('cbom.refresh', () => runScan(runner, state)),
    vscode.commands.registerCommand('cbom.showDashboard', () => DashboardPanel.show(state)),
    vscode.commands.registerCommand('cbom.generateReport', () => openReport(state)),
    vscode.commands.registerCommand('cbom.addGitHubAction', () => guard(() => addGitHubAction(root))),
  );

  // Opt-in scan-on-save: quiet by default to honour the local-first, low-noise posture.
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((doc) => {
      const enabled = vscode.workspace.getConfiguration('cbom').get<boolean>('scanOnSave', false);
      if (enabled && doc.languageId === 'csharp') {
        runScan(runner, state, /* silent */ true);
      }
    }),
  );
}

export function deactivate(): void {
  // Subscriptions are disposed by VS Code via context.subscriptions.
}

async function runScan(runner: CliRunner, state: CbomState, silent = false): Promise<void> {
  await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: 'CBOM: scanning for crypto / PQC risk…', cancellable: true },
    async (_progress, token) => {
      try {
        const result = await runner.scan(token);
        state.set(result);
        if (!silent) {
          const s = result.summary;
          vscode.window.showInformationMessage(
            `PQC readiness ${s.readinessScore}/100 — ${s.findings.critical} critical, ${s.findings.high} high.`,
            'Open dashboard',
          ).then((choice) => {
            if (choice === 'Open dashboard') {
              DashboardPanel.show(state);
            }
          });
        }
      } catch (e) {
        reportError(e);
      }
    },
  );
}

async function openReport(state: CbomState): Promise<void> {
  const result = state.latest;
  if (!result) {
    vscode.window.showInformationMessage('Run a CBOM scan first.');
    return;
  }
  const html = vscode.Uri.file(path.join(result.outputDir, 'cbom.html'));
  try {
    await vscode.env.openExternal(html);
  } catch {
    vscode.window.showErrorMessage('Could not open the generated HTML report.');
  }
}

async function guard(action: () => Promise<void>): Promise<void> {
  try {
    await action();
  } catch (e) {
    reportError(e);
  }
}

function reportError(e: unknown): void {
  const message = e instanceof CliError ? e.message : (e as Error)?.message ?? String(e);
  vscode.window.showErrorMessage(`CBOM: ${message}`);
}
