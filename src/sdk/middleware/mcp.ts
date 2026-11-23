import type { DirghaGate } from '../gate.js';

export interface McpToolCallRequest {
  jsonrpc: '2.0';
  id: string | number;
  method: 'tools/call';
  params: {
    name: string;
    arguments?: Record<string, unknown>;
  };
}

export interface McpToolCallResponse {
  jsonrpc: '2.0';
  id: string | number;
  result?: unknown;
  error?: {
    code: number;
    message: string;
    data?: unknown;
  };
}

/**
 * Wraps an MCP JSON-RPC `tools/call` handler with LOKAHI policy evaluation.
 */
export function createMcpGate(gate: DirghaGate) {
  return async function handleMcpCall(
    request: McpToolCallRequest,
    executeRaw: (req: McpToolCallRequest) => Promise<McpToolCallResponse>
  ): Promise<McpToolCallResponse> {
    const { name, arguments: args = {} } = request.params;
    const decision = await gate.evaluate(name, args);

    if (!decision.allowed) {
      return {
        jsonrpc: '2.0',
        id: request.id,
        error: {
          code: -32000,
          message: `[LOKAHI GATE REFUSAL]: ${decision.reason}`,
          data: {
            allowed: false,
            rule: decision.rule,
            action_digest: decision.actionDigest,
            _meta: {
              approval_status: decision.approvalStatus || 'refused',
              input_required: decision.requiresApproval || false,
            },
          },
        },
      };
    }

    return executeRaw(request);
  };
}
