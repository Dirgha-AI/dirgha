import { describe, it, expect, vi } from 'vitest';
import {
  DirghaGate,
  DirghaStreamGuard,
  createMcpGate,
  createVercelAIMiddleware,
  type McpToolCallRequest,
} from '../index.js';

describe('Dirgha SDK: DirghaGate Core', () => {
  it('allows benign reads in strict mode', async () => {
    const gate = new DirghaGate({ mode: 'strict' });
    const decision = await gate.evaluate('read_file', { path: 'package.json' });

    expect(decision.allowed).toBe(true);
    expect(decision.verdict).toBe('ALLOW');
    expect(decision.actionDigest).toBeDefined();
    expect(decision.actionDigest).toHaveLength(64); // SHA-256 hex
  });

  it('refuses forbidden commands in strict mode (Rule 7)', async () => {
    const gate = new DirghaGate({ mode: 'strict' });
    const decision = await gate.evaluate('run_command', { cmd: 'rm -rf /' });

    expect(decision.allowed).toBe(false);
    expect(decision.verdict).toBe('REFUSE');
    expect(decision.rule).toBe(7);
    expect(decision.reason).toContain("contains forbidden pattern 'rm -rf'");
  });

  it('escalates irreversible actions when not pre-approved (Rule 14)', async () => {
    const gate = new DirghaGate({ mode: 'strict' });
    const decision = await gate.evaluate('run_command', { cmd: 'git push origin main' });

    expect(decision.allowed).toBe(false);
    expect(decision.verdict).toBe('ESCALATE');
    expect(decision.rule).toBe(14);
    expect(decision.requiresApproval).toBe(true);
    expect(decision.approvalStatus).toBe('pending');
  });

  it('approves irreversible action if custom approval handler consents', async () => {
    const onApproval = vi.fn().mockResolvedValue(true);
    const gate = new DirghaGate({ mode: 'strict', onApprovalRequest: onApproval });

    const decision = await gate.evaluate('run_command', { cmd: 'git push origin main' });

    expect(onApproval).toHaveBeenCalledOnce();
    expect(decision.allowed).toBe(true);
    expect(decision.verdict).toBe('ALLOW');
    expect(decision.approvalStatus).toBe('approved');
  });

  it('permits all actions in developer mode', async () => {
    const gate = new DirghaGate({ mode: 'developer' });
    const decision = await gate.evaluate('delete_database', { db: 'prod' });

    expect(decision.allowed).toBe(true);
    expect(decision.verdict).toBe('ALLOW');
  });

  it('enforces tool allowlist (Rule 5)', async () => {
    const gate = new DirghaGate({ mode: 'strict', allowedTools: ['read_file', 'write_file'] });

    const allowed = await gate.evaluate('read_file', { path: 'a.txt' });
    expect(allowed.allowed).toBe(true);

    const refused = await gate.evaluate('search_web', { query: 'test' });
    expect(refused.allowed).toBe(false);
    expect(refused.rule).toBe(5);
  });
});

describe('Dirgha SDK: DirghaStreamGuard', () => {
  it('passes through text chunks without interference', async () => {
    const gate = new DirghaGate({ mode: 'strict' });
    const guard = new DirghaStreamGuard(gate);

    const chunk = {
      choices: [{ delta: { content: 'Hello world' } }],
    };

    const res = await guard.inspectChunk(chunk);
    expect(res.blocked).toBe(false);
    expect(res.chunk).toEqual(chunk);
  });

  it('intercepts streaming tool calls and emits refusal when forbidden', async () => {
    const gate = new DirghaGate({ mode: 'strict' });
    const guard = new DirghaStreamGuard(gate);

    const toolChunk = {
      choices: [
        {
          delta: {
            tool_calls: [
              {
                index: 0,
                id: 'call_1',
                type: 'function',
                function: {
                  name: 'delete_database',
                  arguments: '{"db": "production"}',
                },
              },
            ],
          },
        },
      ],
    };

    const res = await guard.inspectChunk(toolChunk);
    expect(res.blocked).toBe(true);
    expect(res.refusalChunk?.choices?.[0]?.delta?.content).toContain('[LOKAHI GATE REFUSAL]');
    expect(res.decision?.allowed).toBe(false);
  });
});

describe('Dirgha SDK: MCP Gate Wrapper', () => {
  it('intercepts MCP JSON-RPC call and wraps response on refusal', async () => {
    const gate = new DirghaGate({ mode: 'strict' });
    const mcpGate = createMcpGate(gate);

    const rawReq: McpToolCallRequest = {
      jsonrpc: '2.0',
      id: 42,
      method: 'tools/call',
      params: {
        name: 'delete_database',
        arguments: {},
      },
    };

    const mockExecutor = vi.fn();
    const response = await mcpGate(rawReq, mockExecutor);

    expect(mockExecutor).not.toHaveBeenCalled();
    expect(response.id).toBe(42);
    expect(response.error).toBeDefined();
    expect(response.error?.code).toBe(-32000);
    expect(response.error?.message).toContain('[LOKAHI GATE REFUSAL]');
  });
});

describe('Dirgha SDK: Vercel AI SDK Middleware', () => {
  it('filters disallowed tools from parameters', async () => {
    const gate = new DirghaGate({ mode: 'strict', allowedTools: ['allowed_tool'] });
    const middleware = createVercelAIMiddleware(gate);

    const params = {
      tools: [
        { name: 'allowed_tool', description: 'test' },
        { name: 'disallowed_tool', description: 'test' },
      ],
    };

    const transformed = await middleware.transformParams({ params });
    expect(transformed.tools).toHaveLength(1);
    expect(transformed.tools[0].name).toBe('allowed_tool');
  });

  it('intercepts generated tool calls and throws on policy refusal', async () => {
    const gate = new DirghaGate({ mode: 'strict' });
    const middleware = createVercelAIMiddleware(gate);

    const doGenerate = vi.fn().mockResolvedValue({
      text: 'Executing...',
      toolCalls: [{ toolName: 'delete_database', args: {} }],
    });

    await expect(middleware.wrapGenerate({ doGenerate, params: {} })).rejects.toThrow(
      '[LOKAHI GATE REFUSAL]'
    );
  });
});
