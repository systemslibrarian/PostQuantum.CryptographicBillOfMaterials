// Typed mirror of the `dotnet-cbom --format json-summary` contract (JsonSummaryReporter, schemaVersion 1).
// Keep in sync with that reporter; additive fields are safe, shape changes require a schemaVersion bump.

export interface CbomSummary {
  schemaVersion: number;
  tool: string;
  toolVersion: string;
  knowledgeBaseVersion: string | null;
  generatedAt: string;
  policyProfile: string;
  readinessScore: number;
  findings: FindingCounts;
  quantumVulnerable: number;
  classicalWeaknesses: number;
  waived: number;
  baselineDelta: BaselineDelta | null;
  coverage: Coverage;
  topActions: MigrationAction[];
  /**
   * Migration playbooks referenced by `topActions`, resolved and de-duplicated by the CLI.
   * Optional: the extension can be newer than the `dotnet-cbom` on PATH, and summaries written
   * before playbooks existed simply omit it. Treat absent and empty the same way.
   */
  playbooks?: MigrationPlaybook[];
}

export interface FindingCounts {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  informational: number;
}

export interface BaselineDelta {
  new: number;
  fixed: number;
  regressed: number;
}

export interface Coverage {
  projectsAnalyzed: number;
  projectsFailed: number;
}

export interface MigrationAction {
  project: string;
  algorithm: string;
  ruleId: string;
  level: 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';
  occurrences: number;
  action: string;
  /** Ids into {@link CbomSummary.playbooks}. Optional for the same back-compat reason. */
  playbookIds?: string[];
}

/**
 * A concrete migration guide for one class of quantum-vulnerable cryptography. The summary carries the
 * headline fields only — the worked code, library options and citations live in the Markdown and HTML
 * reports, which is where someone actually doing the migration should be sent.
 */
export interface MigrationPlaybook {
  id: string;
  title: string;
  appliesTo: string;
  target: string;
  steps: string[];
}

/** The supported schema version this extension understands. */
export const SUPPORTED_SCHEMA_VERSION = 1;
