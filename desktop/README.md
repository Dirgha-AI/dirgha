# Dirgha Desktop (v2.0.0)

Dirgha Desktop is the native **Tauri v2 workbench** for Dirgha 2.0. It provides an interactive visual cockpit for Dirgha agents, sessions, models, skills, git review, terminal execution, and LOKAHI capability gate approvals.

Desktop is a visual client that connects directly to the sovereign Dirgha daemon and native Rust kernel (`crates/native-host`), with an ultra-lightweight footprint (<15MB RAM) and zero Electron bloat.

---

## Capabilities

* **Interactive Coding & Chat:** Run agents in one-shot, iterative chat, or fleet worktree mode.
* **Monaco Editor Integration:** In-window code inspection, diffing, and editing powered by Monaco Editor (`@monaco-editor/react`).
* **Streaming Terminal:** Embedded xterm emulator (`@xterm/xterm`) for command execution and live agent output.
* **LOKAHI Gate & Multi-Sig Approvals:** Visual popups for human-in-the-loop `S2` approval tickets and irreversible action confirmations.
* **Provider Switcher:** Switch between 235+ LLM providers, BYOK endpoints, or local Ollama / GGUF models.

---

## Development

Requires Node.js 22+, Rust toolchain, and Microsoft Edge WebView2 on Windows.

```bash
cd desktop
npm install
npm run dev           # Start Vite frontend in development mode
npm run tauri         # Launch native Tauri v2 desktop window
npm run build:web     # Build static frontend bundle
npm run tauri:build   # Build standalone native installer (.msi / .exe)
```
