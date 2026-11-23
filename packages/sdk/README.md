# @dirgha/sdk

> Deterministic LOKAHI runtime policy gate and real-time streaming tool interceptor for AI agents.

Enforce boundary policies, prevent prompt-injected file destruction (`rm -rf`), and require human disjoint quorum (Rule 14) before any autonomous agent executes irreversible actions.

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![MCP Compatible](https://img.shields.io/badge/protocol-MCP-purple.svg)](https://modelcontextprotocol.io)

---

## Installation

```bash
npm install @dirgha/sdk
```

---

## Quickstart (3 Lines of Code)

```typescript
import { DirghaGate } from '@dirgha/sdk';

const gate = new DirghaGate({ mode: 'strict' });

// Evaluates tool invocation before OS execution
const decision = await gate.evaluate('run_command', { cmd: 'rm -rf /' });
if (!decision.allowed) {
  console.error(decision.reason); // "[LOKAHI GATE REFUSAL]: Action blocked by Rule 7: contains forbidden pattern 'rm -rf'"
}
```

---

## 1. Vercel AI SDK Integration

Wrap any language model with the Dirgha guardrail middleware to automatically filter forbidden tools from the prompt and block dangerous model tool calls before they run:

```typescript
import { wrapLanguageModel } from 'ai';
import { openai } from '@ai-sdk/openai';
import { DirghaGate, createVercelAIMiddleware } from '@dirgha/sdk';

const gate = new DirghaGate({
  mode: 'strict',
  allowedTools: ['read_file', 'search_code', 'run_tests'],
});

export const safeModel = wrapLanguageModel({
  model: openai('gpt-4o'),
  middleware: createVercelAIMiddleware(gate),
});
```

---

## 2. Model Context Protocol (MCP) Server Wrapper

Protect any standard MCP server tool handler:

```typescript
import { DirghaGate, createMcpGate } from '@dirgha/sdk';

const gate = new DirghaGate({ mode: 'strict' });
const mcpGate = createMcpGate(gate);

// Inside your MCP JSON-RPC server router:
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  return mcpGate(request, async (req) => {
    // This inner handler only runs if LOKAHI policy allows it
    return executeTool(req.params.name, req.params.arguments);
  });
});
```

---

## 3. Real-Time Streaming Guard (OpenAI & Anthropic SSE)

Prevent runaway streaming generation from outputting malicious shell commands:

```typescript
import { DirghaGate, DirghaStreamGuard } from '@dirgha/sdk';

const guard = new DirghaStreamGuard(new DirghaGate({ mode: 'strict' }));

for await (const chunk of stream) {
  const { blocked, chunk: safeChunk, refusalChunk } = await guard.inspectChunk(chunk);
  if (blocked) {
    // Stream intercepted mid-sentence! Emit policy refusal and close stream.
    res.write(JSON.stringify(refusalChunk));
    res.end();
    break;
  }
  res.write(JSON.stringify(safeChunk));
}
```

---

## 4. Governance Profiles

- **`developer`**: Zero-friction mode. All tool calls and commands are permitted without prompts.
- **`safe-dev`**: Advisory mode. Logs security alerts for irreversible actions without blocking execution.
- **`strict` (Default)**: Fail-closed mode. Enforces Rule 14 disjoint quorum: irreversible actions require explicit human steward approval.

---

## License

Apache-2.0 © Salik Shah / Dirgha AI
