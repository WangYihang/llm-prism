# LLM-Redactor

A local transparent proxy to redact secrets (API keys, PII) before they leave your machine.

| Feature | Direct Connection | With **LLM-Redactor** |
| :--- | :--- | :--- |
| Data Privacy | Secrets sent to Cloud | **Redacted locally** |
| Provider Sees | `Prompt: "Fix this: API_KEY=sk-123..."` | `Prompt: "Fix this: API_KEY=[REDACTED]"` |
| Streaming | Standard | **Real-time filtering** |

## Core Features

- Automatic Redaction: Detects 100+ secret types using Gitleaks-compatible rules.
- Zero Configuration: No need to modify your existing workflows.
- Zero-Latency Streaming: Intercepts and filters SSE streams in real-time.
- Deep JSON Scanning: Recursively traverses nested structures (e.g., Anthropic content blocks).
- Local Audit: Records detected leaks to `detections.jsonl`.


## Use Case 1: Execute Command with Redaction (Recommended)

This is the easiest way to use LLM-Redactor. Just prepend the command to your existing CLI tool. It will automatically set up the proxy and configure environment variables for the session.

### Install
```bash
go install github.com/wangyihang/llm-redactor/cmd/llm-redactor-exec@latest
```

### Usage
Prepend `llm-redactor-exec --` to your existing command:
```bash
llm-redactor-exec -- claude
llm-redactor-exec -- gemini
llm-redactor-exec -- codex
```

Upon exiting the session, a comprehensive audit summary will be displayed.

## Use Case 2: Standalone Redacting Proxy

Use this if you want to run a persistent proxy server that multiple tools or background processes can use.

### Install
```bash
go install github.com/wangyihang/llm-redactor/cmd/llm-redactor-proxy@latest
```

### Usage
1. Start the proxy server:
   ```bash
   llm-redactor-proxy --port 4000
   ```

2. Configure your environment or tools to use the proxy:
   ```bash
   export HTTP_PROXY=http://localhost:4000
   export HTTPS_PROXY=http://localhost:4000
   # Now run your tools normally
   claude
   ```

## Audit & Logs

All detected leaks are logged to `detections.jsonl` with full metadata for post-session review.

![Summary](./figures/summary.png)
