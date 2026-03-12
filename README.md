# llm-prism

A local transparent proxy to redact secrets (API keys, PII) before they leave your machine.

---

| Feature | Direct Connection | With llm-prism |
| :--- | :--- | :--- |
| **Data Privacy** | Secrets sent to Cloud | **Redacted locally** |
| **Provider Sees** | `key: "sk-7d...363e"` | `key: "[REDACTED]"` |
| **Streaming** | Standard | **Real-time filtering** |

---

## Quick Start

### 1. Install
```bash
go install github.com/wangyihang/llm-prism@latest
```

### 2. Setup Rules
Update your local redirection rules from the official Gitleaks repository:
```bash
llm-prism sync
```

### 3. Run
```bash
export LLM_PRISM_API_KEY=sk-your-real-key
llm-prism run
```

---

## Integration

Point your LLM client's base URL to `http://localhost:4000`.

### Claude Code
```bash
export ANTHROPIC_BASE_URL=http://localhost:4000
claude
```

### Cursor / Aider / OpenAI SDK
Set the API base URL in your configuration to `http://localhost:4000`.

---

## Core Features

- **Automatic Redaction**: Detects 100+ secret types using Gitleaks-compatible rules.
- **Zero-Latency Streaming**: Intercepts and filters SSE streams in real-time.
- **Deep JSON Scanning**: Recursively traverses nested structures (e.g., Anthropic content blocks).
- **Local Audit**: Records detected leaks to `llm-prism-detections.jsonl`.

---

## License
MIT
