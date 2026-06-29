import * as vscode from 'vscode';
import { execFile } from 'child_process';
import * as fs from 'fs/promises';
import * as os from 'os';
import * as path from 'path';
import { CbomSummary, SUPPORTED_SCHEMA_VERSION } from './model';

/** Thrown when the CLI can't be run or its output can't be understood — carries a user-facing message. */
export class CliError extends Error {}

export interface ScanResult {
  summary: CbomSummary;
  /** Absolute path to the output directory holding the generated reports (cbom.*). */
  outputDir: string;
}

/**
 * Drives the local `dotnet-cbom` CLI. Everything runs on the developer's machine — no network, no upload —
 * which is the whole trust proposition of this extension. We ask for the json-summary (typed contract) plus
 * the full CycloneDX and HTML so the dashboard and "open report" actions have what they need.
 */
export class CliRunner {
  constructor(private readonly workspaceRoot: string) {}

  private config<T>(key: string, fallback: T): T {
    return vscode.workspace.getConfiguration('cbom').get<T>(key, fallback);
  }

  /** Resolve the scan target: configured value (relative to the workspace) or the workspace root. */
  private resolveTarget(): string {
    const configured = this.config<string>('target', '').trim();
    return configured ? path.resolve(this.workspaceRoot, configured) : this.workspaceRoot;
  }

  async scan(token?: vscode.CancellationToken): Promise<ScanResult> {
    const cli = this.config<string>('cliPath', 'dotnet-cbom');
    const profile = this.config<string>('profile', 'general');
    const target = this.resolveTarget();
    const outputDir = await fs.mkdtemp(path.join(os.tmpdir(), 'cbom-'));

    const args = [
      'scan', target,
      '--format', 'json-summary,cyclonedx,html',
      '--profile', profile,
      '--fail-on', 'none', // the gate is a CI concern; in-editor we only report
      '--output', outputDir,
    ];

    await this.exec(cli, args, token);

    const summaryPath = path.join(outputDir, 'cbom.summary.json');
    let raw: string;
    try {
      raw = await fs.readFile(summaryPath, 'utf8');
    } catch {
      throw new CliError(`Scan finished but no summary was produced at ${summaryPath}.`);
    }

    let summary: CbomSummary;
    try {
      summary = JSON.parse(raw) as CbomSummary;
    } catch (e) {
      throw new CliError(`Could not parse the CBOM summary JSON: ${(e as Error).message}`);
    }

    if (summary.schemaVersion > SUPPORTED_SCHEMA_VERSION) {
      throw new CliError(
        `The CBOM CLI produced summary schema v${summary.schemaVersion}, but this extension understands ` +
        `v${SUPPORTED_SCHEMA_VERSION}. Update the extension.`,
      );
    }

    return { summary, outputDir };
  }

  private exec(cli: string, args: string[], token?: vscode.CancellationToken): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      const child = execFile(cli, args, { cwd: this.workspaceRoot, maxBuffer: 32 * 1024 * 1024 },
        (error, _stdout, stderr) => {
          if (error) {
            // dotnet-cbom exit codes: 1 = findings at/above gate (we pass --fail-on none, so unexpected),
            // 2 = partial analysis, 3 = usage/config, 4 = internal. ENOENT = CLI not installed.
            if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
              reject(new CliError(
                `Could not find '${cli}'. Install it with:\n` +
                `  dotnet tool install -g PostQuantum.CryptographicBillOfMaterials.Cli\n` +
                `or set "cbom.cliPath" in settings.`,
              ));
              return;
            }
            reject(new CliError(stderr?.trim() || error.message));
            return;
          }
          resolve();
        });

      token?.onCancellationRequested(() => {
        child.kill();
        reject(new CliError('Scan cancelled.'));
      });
    });
  }
}
