export type GateVerdict = 'ALLOW' | 'REFUSE' | 'ESCALATE';

export interface GateDecision {
  allowed: boolean;
  verdict: GateVerdict;
  reason: string;
  rule?: number;
  requiresApproval?: boolean;
  approvalStatus?: 'pending' | 'approved' | 'refused' | 'not_requested';
  actionDigest?: string;
  receipt?: Record<string, unknown>;
}

export interface DirghaGateOptions {
  /**
   * Governance profile:
   * - 'developer': zero friction, log advisory only
   * - 'safe-dev': advisory logging with high-risk prompts
   * - 'strict': fail-closed, irreversible actions require approval
   */
  mode?: 'developer' | 'safe-dev' | 'strict';

  /**
   * Path to signed LOKAHI manifest JSON
   */
  manifestPath?: string;

  /**
   * Path to append-only audit ledger JSONL
   */
  ledgerPath?: string;

  /**
   * Explicit allowlist of tool names
   */
  allowedTools?: string[];

  /**
   * Explicit denylist of tool names or shell commands
   */
  forbiddenTools?: string[];

  /**
   * Custom approval handler for human-in-the-loop escalation
   */
  onApprovalRequest?: (action: { tool: string; args: Record<string, unknown>; reason: string }) => Promise<boolean>;
}
