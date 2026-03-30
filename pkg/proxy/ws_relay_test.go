package proxy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/coder/websocket"
	"github.com/rs/zerolog"
	"github.com/wangyihang/llm-redactor/pkg/utils/ctxkeys"
)

func TestParseRelayTarget(t *testing.T) {
	makeReq := func(target string) *http.Request {
		req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
		req.Header.Set(wsRelayTargetHeader, target)
		return req
	}

	t.Run("missing", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
		_, _, err := parseRelayTarget(req)
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("http->ws", func(t *testing.T) {
		_, wsTarget, err := parseRelayTarget(makeReq("http://api.example.com/ws"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if wsTarget.Scheme != "ws" {
			t.Fatalf("expected ws scheme, got %q", wsTarget.Scheme)
		}
	})

	t.Run("https->wss", func(t *testing.T) {
		_, wsTarget, err := parseRelayTarget(makeReq("https://api.example.com/ws"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if wsTarget.Scheme != "wss" {
			t.Fatalf("expected wss scheme, got %q", wsTarget.Scheme)
		}
	})

	t.Run("ws stays", func(t *testing.T) {
		_, wsTarget, err := parseRelayTarget(makeReq("ws://api.example.com/ws"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if wsTarget.Scheme != "ws" {
			t.Fatalf("expected ws scheme, got %q", wsTarget.Scheme)
		}
	})

	t.Run("unsupported scheme", func(t *testing.T) {
		_, _, err := parseRelayTarget(makeReq("ftp://api.example.com/ws"))
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("invalid url", func(t *testing.T) {
		_, _, err := parseRelayTarget(makeReq(":/bad"))
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestParseWebSocketSubprotocols(t *testing.T) {
	header := http.Header{}
	header.Add("Sec-WebSocket-Protocol", "v1, v2")
	header.Add("Sec-WebSocket-Protocol", "v3")

	got := parseWebSocketSubprotocols(header)
	if len(got) != 3 {
		t.Fatalf("expected 3 subprotocols, got %d", len(got))
	}
	if got[0] != "v1" || got[1] != "v2" || got[2] != "v3" {
		t.Fatalf("unexpected subprotocols: %#v", got)
	}
}

func TestFilterWebSocketDialHeaders(t *testing.T) {
	header := http.Header{}
	header.Set("Upgrade", "websocket")
	header.Set("Connection", "Upgrade")
	header.Set("Sec-WebSocket-Key", "key")
	header.Set("Sec-WebSocket-Version", "13")
	header.Set("Sec-WebSocket-Protocol", "proto")
	header.Set(wsRelayTargetHeader, "http://target")
	header.Set(wsRelayTokenHeader, "token")
	header.Set("Authorization", "Bearer abc")
	header.Set("User-Agent", "ua")

	filtered := filterWebSocketDialHeaders(header)
	if filtered.Get("Authorization") == "" || filtered.Get("User-Agent") == "" {
		t.Fatal("expected non-websocket headers to be preserved")
	}
	if filtered.Get("Upgrade") != "" || filtered.Get("Connection") != "" || filtered.Get("Sec-WebSocket-Key") != "" {
		t.Fatal("expected websocket handshake headers to be stripped")
	}
	if filtered.Get(wsRelayTokenHeader) != "" {
		t.Fatal("expected relay token header to be stripped")
	}
}

func TestIsWebSocketUpgrade(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
	req.Header.Set("Upgrade", "websocket")
	if !isWebSocketUpgrade(req) {
		t.Fatal("expected websocket upgrade to be true without Connection header")
	}

	req.Header.Set("Connection", "keep-alive")
	if isWebSocketUpgrade(req) {
		t.Fatal("expected websocket upgrade to be false when Connection lacks upgrade")
	}

	req.Header.Set("Connection", "keep-alive, Upgrade")
	if !isWebSocketUpgrade(req) {
		t.Fatal("expected websocket upgrade to be true when Connection includes upgrade")
	}
}

func TestRewriteRequest(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "http://example.com/ws", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")

	relay := &WebSocketRelay{addr: "127.0.0.1:1234", sysLog: zerolog.Nop(), relayToken: "token-1"}
	if !relay.RewriteRequest(req, "req-1") {
		t.Fatal("expected rewrite to succeed")
	}
	if req.URL.Host != relay.addr || req.URL.Scheme != "http" {
		t.Fatalf("unexpected rewrite target: %s", req.URL.String())
	}
	if req.Header.Get(wsRelayTargetHeader) != "http://example.com/ws" {
		t.Fatalf("unexpected relay header: %s", req.Header.Get(wsRelayTargetHeader))
	}
	if req.Header.Get(wsRelayTokenHeader) != "token-1" {
		t.Fatalf("unexpected relay token header: %s", req.Header.Get(wsRelayTokenHeader))
	}
}

func TestHeaderHasToken(t *testing.T) {
	if !headerHasToken("keep-alive, Upgrade", "upgrade") {
		t.Fatal("expected token match")
	}
	if headerHasToken("keep-alive", "upgrade") {
		t.Fatal("expected token miss")
	}
}

func TestValidateRelayToken(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "http://example.com/ws", nil)
	relay := &WebSocketRelay{relayToken: "token-1"}
	if relay.validateRelayToken(req) {
		t.Fatal("expected token check to fail without header")
	}
	req.Header.Set(wsRelayTokenHeader, "token-1")
	if !relay.validateRelayToken(req) {
		t.Fatal("expected token check to succeed")
	}
}

func TestBuildRelayContext(t *testing.T) {
	base := buildRelayContext(context.Background(), "req-1", mustParseURL(t, "http://example.com/path"))
	if ctxkeys.GetString(base, ctxkeys.RequestID) != "req-1" {
		t.Fatal("expected request id")
	}
	if ctxkeys.GetString(base, ctxkeys.Host) != "example.com" {
		t.Fatal("expected host")
	}
	if ctxkeys.GetString(base, ctxkeys.Path) != "/path" {
		t.Fatal("expected path")
	}
	if ctxkeys.GetString(base, ctxkeys.Method) != "WEBSOCKET" {
		t.Fatal("expected method")
	}
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return u
}

type fakeWSConn struct {
	reads  []wsRead
	writes []wsWrite
}

type wsRead struct {
	typ  websocket.MessageType
	data []byte
	err  error
}

type wsWrite struct {
	typ  websocket.MessageType
	data []byte
}

func (f *fakeWSConn) Read(ctx context.Context) (websocket.MessageType, []byte, error) {
	if len(f.reads) == 0 {
		return websocket.MessageText, nil, io.EOF
	}
	r := f.reads[0]
	f.reads = f.reads[1:]
	return r.typ, r.data, r.err
}

func (f *fakeWSConn) Write(ctx context.Context, typ websocket.MessageType, data []byte) error {
	f.writes = append(f.writes, wsWrite{typ: typ, data: data})
	return nil
}

type fakeRedactor struct {
	changed bool
	err     error
	lastCtx context.Context
}

func (f *fakeRedactor) RedactRequest(ctx context.Context, body []byte) ([]byte, bool, error) {
	return body, false, nil
}

func (f *fakeRedactor) RedactWebSocket(ctx context.Context, messageType websocket.MessageType, data []byte) ([]byte, bool, error) {
	f.lastCtx = ctx
	if f.err != nil {
		return data, false, f.err
	}
	if f.changed {
		return []byte("redacted"), true, nil
	}
	return data, false, nil
}

func (f *fakeRedactor) UnredactResponse(body []byte) ([]byte, bool, error) {
	return body, false, nil
}

func (f *fakeRedactor) WrapStreamUnredactor(body io.ReadCloser) io.ReadCloser {
	return body
}

func TestPipeWebSocket_NoRedactor(t *testing.T) {
	src := &fakeWSConn{
		reads: []wsRead{{typ: websocket.MessageText, data: []byte("hello")}},
	}
	dst := &fakeWSConn{}
	errChan := make(chan error, 1)

	pipeWebSocket(context.Background(), nil, src, dst, "client->server", errChan)

	if len(dst.writes) != 1 {
		t.Fatalf("expected 1 write, got %d", len(dst.writes))
	}
	if string(dst.writes[0].data) != "hello" {
		t.Fatalf("unexpected data: %s", string(dst.writes[0].data))
	}
}

func TestPipeWebSocket_Redacted(t *testing.T) {
	src := &fakeWSConn{
		reads: []wsRead{{typ: websocket.MessageText, data: []byte("secret")}},
	}
	dst := &fakeWSConn{}
	errChan := make(chan error, 1)
	rdr := &fakeRedactor{changed: true}

	pipeWebSocket(context.Background(), rdr, src, dst, "server->client", errChan)

	if len(dst.writes) != 1 {
		t.Fatalf("expected 1 write, got %d", len(dst.writes))
	}
	if string(dst.writes[0].data) != "redacted" {
		t.Fatalf("unexpected data: %s", string(dst.writes[0].data))
	}
	if ctxkeys.GetString(rdr.lastCtx, ctxkeys.Source) != "server->client" {
		t.Fatal("expected ctx to include source")
	}
}

func TestPipeWebSocket_RedactorError(t *testing.T) {
	src := &fakeWSConn{
		reads: []wsRead{{typ: websocket.MessageText, data: []byte("secret")}},
	}
	dst := &fakeWSConn{}
	errChan := make(chan error, 1)
	rdr := &fakeRedactor{err: errors.New("boom")}

	pipeWebSocket(context.Background(), rdr, src, dst, "client->server", errChan)

	if len(dst.writes) != 1 {
		t.Fatalf("expected 1 write, got %d", len(dst.writes))
	}
	if string(dst.writes[0].data) != "secret" {
		t.Fatalf("unexpected data: %s", string(dst.writes[0].data))
	}
}

func TestCloseWebSocketSilently_Nil(t *testing.T) {
	closeWebSocketSilently(nil, websocket.StatusNormalClosure, "ok")
}
