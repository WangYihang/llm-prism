package proxy

import (
	"context"
	"io"

	"github.com/coder/websocket"
)

// ContentRedactor defines the redaction capabilities required by the proxy layer.
type ContentRedactor interface {
	RedactRequest(ctx context.Context, body []byte) ([]byte, bool, error)
	RedactWebSocket(ctx context.Context, messageType websocket.MessageType, data []byte) ([]byte, bool, error)
	// UnredactResponse restores pseudonymized values (e.g. fake IPs → real IPs)
	// in a buffered LLM response body.
	UnredactResponse(body []byte) ([]byte, bool, error)
	// WrapStreamUnredactor wraps a streaming response body so that
	// pseudonymized values are restored as each chunk is read.
	WrapStreamUnredactor(body io.ReadCloser) io.ReadCloser
}
