package proxy

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/coder/websocket"
	"github.com/rs/zerolog"
	"github.com/wangyihang/llm-redactor/pkg/utils/ctxkeys"
)

func TestContextKeys(t *testing.T) {
	ctx := context.Background()
	id := ctxkeys.GetString(ctx, ctxkeys.RequestID)
	if id != "" {
		t.Errorf("Expected empty request ID, got %s", id)
	}

	ctx = context.WithValue(ctx, ctxkeys.RequestID, "test-id")
	id = ctxkeys.GetString(ctx, ctxkeys.RequestID)
	if id != "test-id" {
		t.Errorf("Expected test-id, got %s", id)
	}
}

func TestNew(t *testing.T) {
	p, closeRelay := New(nil, zerolog.Nop(), zerolog.Nop(), zerolog.Nop(), "/tmp")
	if p == nil {
		t.Fatal("Expected proxy, got nil")
	}
	_ = closeRelay(context.Background())
}

type chunkRedactor struct {
	changed bool
	lastIn  []byte
}

func (f *chunkRedactor) RedactRequest(ctx context.Context, body []byte) ([]byte, bool, error) {
	f.lastIn = body
	if f.changed {
		return []byte(`{"redacted":true}`), true, nil
	}
	return body, false, nil
}

func (f *chunkRedactor) RedactWebSocket(ctx context.Context, messageType websocket.MessageType, data []byte) ([]byte, bool, error) {
	return data, false, nil
}

func (f *chunkRedactor) UnredactResponse(body []byte) ([]byte, bool, error) {
	return body, false, nil
}

func (f *chunkRedactor) WrapStreamUnredactor(body io.ReadCloser) io.ReadCloser {
	return body
}

func TestRedactRequestBody_RedactsChunkedBodies(t *testing.T) {
	rdr := &chunkRedactor{changed: true}

	body := io.NopCloser(strings.NewReader(`{"secret":"123"}`))
	req, _ := http.NewRequest(http.MethodPost, "http://example.com", body)
	req.ContentLength = -1

	_ = redactRequestBody(rdr, "req-1", req)

	if string(rdr.lastIn) != `{"secret":"123"}` {
		t.Fatalf("unexpected redactor input: %s", string(rdr.lastIn))
	}
	if req.ContentLength != int64(len(`{"redacted":true}`)) {
		t.Fatalf("expected content length updated, got %d", req.ContentLength)
	}

	readBack, _ := io.ReadAll(req.Body)
	if string(readBack) != `{"redacted":true}` {
		t.Fatalf("unexpected request body: %s", string(readBack))
	}
}
