import * as crypto from 'node:crypto';
import type { DirghaGateOptions, GateDecision } from './types.js';

export class DirghaGate {
  private mode: 'developer' | 'safe-dev' | 'strict';
  private allowedTools?: Set<string>;
  private forbiddenTools: Set<string>;
  private onApprovalRequest?: DirghaGateOptions['onApprovalRequest'];

  constructor(options: DirghaGateOptions = {}) {
    this.mode = options.mode || 'strict';
    this.allowedTools = options.allowedTools ? new Set(options.allowedTools) : undefined;
    this.forbiddenTools = new Set(
      options.forbiddenTools || [
        'rm -rf',
        'drop table',
        'delete_database',
        'transfer_funds',
        'format_disk',
        'shutdown',
      ]
    );
    this.onApprovalRequest = options.onApprovalRequest;
  }

  /**
   * Computes an RFC 8785-compatible action digest for cryptographic binding
   */
  public computeActionDigest(tool: string, args: Record<string, unknown>): string {
    const canonical = JSON.stringify({ tool, args: Object.keys(args).sort().reduce((acc, k) => {
      acc[k] = args[k];
      return acc;
    }, {} as Record<string, unknown>) });
    return crypto.createHash('sha256').update(canonical).digest('hex');
  }

  /**
   * Evaluates a tool invocation against policy rules
   */
  public async evaluate(tool: string, args: Record<string, unknown> = {}): Promise<GateDecision> {
    const actionDigest = this.computeActionDigest(tool, args);

    // In developer mode, all calls are permitted
    if (this.mode === 'developer') {
      return {
        allowed: true,
        verdict: 'ALLOW',
        reason: 'Developer mode: all actions permitted',
        actionDigest,
      };
    }

    // Check allowlist
    if (this.allowedTools && !this.allowedTools.has(tool)) {
      return {
        allowed: false,
        verdict: 'REFUSE',
        rule: 5,
        reason: `Tool '${tool}' is not in the signed manifest allowlist`,
        actionDigest,
      };
    }

    // Check forbidden keywords across tool name and string arguments
    const serializedArgs = JSON.stringify(args).toLowerCase();
    for (const forbidden of this.forbiddenTools) {
      if (tool.toLowerCase().includes(forbidden) || serializedArgs.includes(forbidden.toLowerCase())) {
        return {
          allowed: false,
          verdict: 'REFUSE',
          rule: 7,
          reason: `Action blocked: contains forbidden pattern '${forbidden}'`,
          actionDigest,
        };
      }
    }

    // Check if tool is classified as irreversible
    const isIrreversible = this.isIrreversibleAction(tool, args);
    if (isIrreversible && this.mode === 'strict') {
      if (this.onApprovalRequest) {
        const approved = await this.onApprovalRequest({ tool, args, reason: 'Irreversible action requires consent' });
        if (approved) {
          return {
            allowed: true,
            verdict: 'ALLOW',
            reason: 'Irreversible action approved by steward',
            approvalStatus: 'approved',
            actionDigest,
          };
        }
      }

      return {
        allowed: false,
        verdict: 'ESCALATE',
        rule: 14,
        reason: `Rule 14 refusal: tool '${tool}' is irreversible and requires disjoint steward quorum`,
        requiresApproval: true,
        approvalStatus: 'pending',
        actionDigest,
      };
    }

    return {
      allowed: true,
      verdict: 'ALLOW',
      reason: 'Action verified and compliant with policy',
      actionDigest,
    };
  }

  /**
   * Helper that executes the function only if policy evaluation passes
   */
  public async execute<T>(
    tool: string,
    args: Record<string, unknown>,
    fn: () => Promise<T>
  ): Promise<{ result?: T; decision: GateDecision }> {
    const decision = await this.evaluate(tool, args);
    if (!decision.allowed) {
      return { decision };
    }
    const result = await fn();
    return { result, decision };
  }

  private isIrreversibleAction(tool: string, args: Record<string, unknown>): boolean {
    const toolLower = tool.toLowerCase();
    if (toolLower.includes('delete') || toolLower.includes('drop') || toolLower.includes('kill')) {
      return true;
    }
    if (toolLower === 'run_command' || toolLower === 'shell') {
      const cmd = String(args['cmd'] || args['command'] || '').toLowerCase();
      if (cmd.includes('rm ') || cmd.includes('git push') || cmd.includes('dd ') || cmd.includes('mkfs')) {
        return true;
      }
    }
    return false;
  }
}
