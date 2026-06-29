import * as vscode from 'vscode';
import { CbomState } from './state';
import { MigrationAction } from './model';

type Node = SummaryNode | GroupNode | ActionNode | MessageNode;

interface SummaryNode { kind: 'summary'; label: string; description: string; }
interface GroupNode { kind: 'group'; label: string; }
interface ActionNode { kind: 'action'; action: MigrationAction; }
interface MessageNode { kind: 'message'; label: string; }

/**
 * The "Crypto inventory" tree: a readiness header, a severity breakdown, and the prioritized migration
 * actions. Clicking an action opens the rule documentation. The full inventory lives in the generated
 * CycloneDX/HTML reports; this view is the at-a-glance triage surface.
 */
export class CbomExplorerProvider implements vscode.TreeDataProvider<Node> {
  private readonly _onDidChangeTreeData = new vscode.EventEmitter<void>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  constructor(private readonly state: CbomState) {
    state.onDidChange(() => this._onDidChangeTreeData.fire());
  }

  getTreeItem(node: Node): vscode.TreeItem {
    switch (node.kind) {
      case 'summary': {
        const item = new vscode.TreeItem(node.label, vscode.TreeItemCollapsibleState.None);
        item.description = node.description;
        item.iconPath = new vscode.ThemeIcon('shield');
        return item;
      }
      case 'group': {
        const item = new vscode.TreeItem(node.label, vscode.TreeItemCollapsibleState.Expanded);
        item.iconPath = new vscode.ThemeIcon('list-unordered');
        return item;
      }
      case 'action': {
        const a = node.action;
        const item = new vscode.TreeItem(`${a.algorithm} — ${a.action}`, vscode.TreeItemCollapsibleState.None);
        item.description = `${a.ruleId} · ${a.level}${a.occurrences > 1 ? ` ×${a.occurrences}` : ''}`;
        item.tooltip = new vscode.MarkdownString(`**${a.ruleId} — ${a.algorithm}** (${a.level})\n\n${a.action}`);
        item.iconPath = new vscode.ThemeIcon(iconForLevel(a.level));
        item.command = {
          command: 'vscode.open',
          title: 'Open rule documentation',
          arguments: [vscode.Uri.parse(
            'https://github.com/systemslibrarian/PostQuantum.CryptographicBillOfMaterials/blob/main/docs/RULES.md')],
        };
        return item;
      }
      case 'message': {
        return new vscode.TreeItem(node.label, vscode.TreeItemCollapsibleState.None);
      }
    }
  }

  getChildren(node?: Node): Node[] {
    const result = this.state.latest;
    if (!result) {
      return node ? [] : [{ kind: 'message', label: 'Run "CBOM: Scan workspace" to begin' }];
    }
    const s = result.summary;

    if (!node) {
      const f = s.findings;
      return [
        { kind: 'summary', label: `PQC readiness ${s.readinessScore}/100`, description: `profile: ${s.policyProfile}` },
        {
          kind: 'summary',
          label: `${f.critical} critical · ${f.high} high · ${f.medium} medium`,
          description: `${s.quantumVulnerable} quantum-vulnerable`,
        },
        { kind: 'group', label: 'Top migration actions' },
      ];
    }

    if (node.kind === 'group') {
      if (s.topActions.length === 0) {
        return [{ kind: 'message', label: 'No high-risk actions — nice.' }];
      }
      return s.topActions.map((action) => ({ kind: 'action', action }));
    }

    return [];
  }
}

function iconForLevel(level: MigrationAction['level']): string {
  switch (level) {
    case 'Critical': return 'error';
    case 'High': return 'warning';
    default: return 'info';
  }
}
