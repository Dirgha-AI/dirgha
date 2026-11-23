import type { DirghaGate } from './gate.js';
import type { GateDecision } from './types.js';

export interface StreamChunk {
  choices?: Array<{
    delta?: {
      content?: string;
      tool_calls?: Array<{
        index: number;
        id?: string;
        type?: string;
        function?: {
          name?: string;
          arguments?: string;
        };
      }>;
    };
    finish_reason?: string | null;
  }>;
}

/**
 * Mid-stream guard that inspects streaming tool deltas from OpenAI/Anthropic
 * and truncates the stream with a LOKAHI refusal if an irreversible/forbidden action is detected.
 */
export class DirghaStreamGuard {
  private gate: DirghaGate;
  private activeToolCalls: Map<number, { name: string; argsJson: string }>;

  constructor(gate: DirghaGate) {
    this.gate = gate;
    this.activeToolCalls = new Map();
  }

  /**
   * Inspects a streaming chunk. Returns `{ blocked: false, chunk }` to forward,
   * or `{ blocked: true, refusalChunk, decision }` if policy refuses the call.
   */
  public async inspectChunk(
    chunk: StreamChunk
  ): Promise<{ blocked: boolean; chunk?: StreamChunk; refusalChunk?: StreamChunk; decision?: GateDecision }> {
    const toolCalls = chunk.choices?.[0]?.delta?.tool_calls;
    if (!toolCalls || toolCalls.length === 0) {
      return { blocked: false, chunk };
    }

    for (const call of toolCalls) {
      const idx = call.index ?? 0;
      const current = this.activeToolCalls.get(idx) || { name: '', argsJson: '' };

      if (call.function?.name) {
        current.name = call.function.name;
      }
      if (call.function?.arguments) {
        current.argsJson += call.function.arguments;
      }
      this.activeToolCalls.set(idx, current);

      // Pre-evaluate tool name as soon as it's known
      if (current.name) {
        let parsedArgs: Record<string, unknown> = {};
        try {
          if (current.argsJson.trim().endsWith('}')) {
            parsedArgs = JSON.parse(current.argsJson);
          }
        } catch {
          // Arguments still streaming in
        }

        const decision = await this.gate.evaluate(current.name, parsedArgs);
        if (!decision.allowed) {
          // Immediately generate refusal chunk
          const refusalChunk: StreamChunk = {
            choices: [
              {
                delta: {
                  content: `\n\n[LOKAHI GATE REFUSAL]: ${decision.reason}\n`,
                  tool_calls: [],
                },
                finish_reason: 'stop',
              },
            ],
          };
          return { blocked: true, refusalChunk, decision };
        }
      }
    }

    return { blocked: false, chunk };
  }
}
