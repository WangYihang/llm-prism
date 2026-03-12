package proxy

import (
	"context"

	"github.com/coder/websocket"
)

// ContentRedactor defines the redaction capabilities required by the proxy layer.
type ContentRedactor interface {
	RedactRequest(ctx context.Context, body []byte) ([]byte, bool, error)
	RedactWebSocket(ctx context.Context, messageType websocket.MessageType, data []byte) ([]byte, bool, error)
}
