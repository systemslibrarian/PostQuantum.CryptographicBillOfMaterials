import * as vscode from 'vscode';
import { ScanResult } from './cli';

/** Holds the latest scan result and notifies the UI (status bar, tree, dashboard) when it changes. */
export class CbomState {
  private _latest: ScanResult | undefined;
  private readonly _onDidChange = new vscode.EventEmitter<ScanResult | undefined>();

  /** Fires whenever a new scan completes (or the state is cleared). */
  readonly onDidChange = this._onDidChange.event;

  get latest(): ScanResult | undefined {
    return this._latest;
  }

  set(result: ScanResult | undefined): void {
    this._latest = result;
    this._onDidChange.fire(result);
  }

  dispose(): void {
    this._onDidChange.dispose();
  }
}
