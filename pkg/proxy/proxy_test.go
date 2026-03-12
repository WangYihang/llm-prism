package proxy

import (
	"context"
	"testing"

	"github.com/rs/zerolog"
	"github.com/wangyihang/llm-prism/pkg/utils/ctxkeys"
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
