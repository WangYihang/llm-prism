# llm-prism

A lightweight, transparent reverse proxy for LLM API observability and security. It captures full HTTP request/response lifecycles while automatically redacting sensitive information like API keys and tokens.

> **Note**: Optimized for DeepSeek and Anthropic-style APIs, but designed to be provider-agnostic.

## Features

- **🛡️ Automatic Secret Redaction**: Automatically detects and redacts secrets (API keys, tokens, etc.) from request bodies and streaming responses using Gitleaks-compatible rules.
- **🔄 Recursive JSON Traversal**: Deep-scans nested JSON structures (including Anthropic-style content blocks) to ensure no sensitive string escapes detection.
- **⚡ Zero-Latency Streaming**: Wraps `http.Flusher` to ensure Server-Sent Events (SSE) are forwarded instantly without buffering delay.
- **🔍 Faithful Capture**: Records raw payloads with automatic Gzip decompression and JSON normalization for clear logging.
- **📊 Dual-Channel Logging**:
  - **Data Logs (`llm-prism.jsonl`)**: Full traffic analysis for debugging and auditing.
  - **Detection Logs (`llm-prism-detections.jsonl`)**: Dedicated security audit trail for leaked secrets.

## Install

```bash
go install github.com/wangyihang/llm-prism@latest
```

## Usage

### 1. Sync Redactor Rules
Update your local redirection rules from the official Gitleaks repository:
```bash
llm-prism sync
```

### 2. Start the Proxy
```bash
$ llm-prism run --help
Usage: llm-prism run --api-key=STRING [flags]

Run proxy

Flags:
  -h, --help                               Show context-sensitive help.
      --log-file="llm-prism.jsonl"         Log file ($LLM_PRISM_LOG_FILE)
      --detection-log-file="llm-prism-detections.jsonl"
                                           Detection log file ($LLM_PRISM_DETECTION_LOG_FILE)
      --redactor-rules="redactor_rules.toml"
                                           Redactor rules file (TOML or JSON) ($LLM_PRISM_REDACTOR_RULES)

      --api-url="https://api.deepseek.com/anthropic"
                                           API URL ($LLM_PRISM_API_URL)
      --api-key=STRING                     API Key ($LLM_PRISM_API_KEY)
      --provider="deepseek"                Provider ($LLM_PRISM_PROVIDER)
      --host="0.0.0.0"                     Host ($LLM_PRISM_HOST)
      --port=4000                          Port ($LLM_PRISM_PORT)
```

#### Example: Running with DeepSeek
```bash
export LLM_PRISM_API_URL=https://api.deepseek.com/anthropic
export LLM_PRISM_API_KEY=sk-your-deepseek-key
export LLM_PRISM_PROVIDER=deepseek
llm-prism run
```

### 3. Connect your Client (e.g., Claude Code)
Point your LLM client to the proxy:
```bash
export ANTHROPIC_BASE_URL=http://localhost:4000
export ANTHROPIC_AUTH_TOKEN=anything  # The proxy handles the real authentication
claude
```

## Security & Redaction

`llm-prism` uses a recursive redaction engine that handles:
- **Standard JSON**: Replaces sensitive strings in any field.
- **Complex Payloads**: Supports Anthropic's `content` array of objects (multi-modal/thinking blocks).
- **Streaming (SSE)**: Redacts secrets on-the-fly as they are streamed from the assistant.

### Example Detection Log
When a secret is detected (e.g., you accidentally paste a key into a chat), it is logged to `llm-prism-detections.jsonl`:
```json
{
  "level": "info",
  "rule_id": "deepseek-api-key",
  "description": "DeepSeek API Key",
  "masked_content": "sk-7d...363e",
  "match_length": 35,
  "path": "/v1/messages",
  "method": "POST",
  "source": "request",
  "time": "2026-03-12T17:22:06.190Z",
  "message": "secret detected"
}
```

## Architecture

- **Recursive Redactor**: A traversal engine that visits every node of a JSON tree to identify sensitive strings without breaking the JSON schema.
- **SSE Spy**: Intercepts and modifies text/event-streams in real-time.
- **Provider Adapters**: Normalize headers and authentication for different backends while providing a unified local interface.
