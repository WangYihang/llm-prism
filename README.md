# llm-prism

A lightweight, transparent reverse proxy for LLM API observability. It captures full HTTP request/response lifecycles (including streaming/SSE) without latency impact.

> **Note**: Currently optimized for the DeepSeek API. The design is provider-agnostic and can be extended to other LLM providers in the future.

## Features

- **Zero-Latency Streaming**: Wraps `http.Flusher` to ensure Server-Sent Events (SSE) are forwarded instantly.
- **Faithful Capture**: Records raw payloads. Automatically handles Gzip decompression and JSON validation for logging.
- **Log Separation**:
  - **System Logs**: Console (Stderr) for operational status.
  - **Data Logs**: File (JSONL) for traffic analysis.

## Install

```bash
go install github.com/wangyihang/llm-prism@latest
```

## Usage

```bash
$ llm-prism run --help
Usage: llm-prism run --api-key=STRING [flags]

Run proxy

Flags:
  -h, --help                                            Show context-sensitive help.
      --log-file="llm-prism.jsonl"                      Log file ($LLM_PRISM_LOG_FILE)

      --api-url="https://api.deepseek.com/anthropic"    API URL ($LLM_PRISM_API_URL, currently DeepSeek-only)
      --api-key=STRING                                  API Key ($LLM_PRISM_API_KEY)
      --host="0.0.0.0"                                  Host ($LLM_PRISM_HOST)
      --port=4000                                       Port ($LLM_PRISM_PORT)
```

```bash
# Basic usage
LLM_PRISM_API_KEY=sk-deepseek-sample-api-key llm-prism run
```

## Log Format

Data logs are stored in JSONL format. Each line represents a completed HTTP interaction.  
The example below shows a DeepSeek chat completion, but the schema is generic enough to support other providers later.

```json
{
  "level": "info",
  "time": "2023-10-27T10:00:00.123Z",
  "duration": 150.5,
  "http": {
    "request": {
      "method": "POST",
      "path": "/v1/chat/completions",
      "body": {
        "model": "deepseek-chat",
        "messages": [...]
      }
    },
    "response": {
      "status": 200,
      "body": "data: {...}\n\ndata: [DONE]" // Raw string for SSE streams
    }
  }
}
```

## Architecture

- **Provider-Agnostic Core**: Core proxy and logging pipeline are independent of any specific LLM provider.
- **DeepSeek Adapter (current)**: Request/response examples focus on DeepSeek endpoints and models.
- **Future Providers**: Additional adapters can be added to normalize request/response shapes for other providers while keeping the logging format stable.
