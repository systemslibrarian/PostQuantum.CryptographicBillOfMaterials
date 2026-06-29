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
}

/** The supported schema version this extension understands. */
export const SUPPORTED_SCHEMA_VERSION = 1;
