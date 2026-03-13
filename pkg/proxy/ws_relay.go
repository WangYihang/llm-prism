package proxy

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/wangyihang/llm-redactor/pkg/utils/ctxkeys"
)

const (
	wsRelayTargetHeader = "X-LLM-Redactor-WS-Target"
	wsRelayTokenHeader  = "X-LLM-Redactor-WS-Token"
)

type WebSocketRelay struct {
	addr       string
	rdr        ContentRedactor
	sysLog     zerolog.Logger
	server     *http.Server
	sessions   sync.Map
	relayToken string
}

func NewWebSocketRelay(rdr ContentRedactor, sysLog zerolog.Logger) (*WebSocketRelay, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}

	relay := &WebSocketRelay{
		addr:       ln.Addr().String(),
		rdr:        rdr,
		sysLog:     sysLog,
		relayToken: uuid.NewString(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", relay.handle)

	relay.server = &http.Server{Handler: mux}
	go func() {
		if err := relay.server.Serve(ln); err != nil && err != http.ErrServerClosed {
			sysLog.Error().Err(err).Msg("internal websocket relay server error")
		}
	}()

	sysLog.Info().Str("addr", relay.addr).Msg("internal websocket relay started")
	return relay, nil
}

func (r *WebSocketRelay) RewriteRequest(req *http.Request, requestID string) bool {
	if r == nil || r.addr == "" || !isWebSocketUpgrade(req) {
		return false
	}

	req.Header.Set(wsRelayTargetHeader, req.URL.String())
	req.Header.Set(wsRelayTokenHeader, r.relayToken)
	req.URL.Scheme = "http"
	req.URL.Host = r.addr
	r.sysLog.Info().Str("id", requestID).Str("host", req.Host).Str("path", req.URL.Path).Str("relay", r.addr).Msg("routing websocket to internal relay")
	return true
}

func (r *WebSocketRelay) Close(ctx context.Context) error {
	if r == nil || r.server == nil {
		return nil
	}
	r.sessions.Range(func(_, value interface{}) bool {
		if cancel, ok := value.(context.CancelFunc); ok {
			cancel()
		}
		return true
	})
	return r.server.Shutdown(ctx)
}

func (r *WebSocketRelay) handle(w http.ResponseWriter, req *http.Request) {
	if !r.validateRelayToken(req) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	requestID := uuid.New().String()
	targetURL, wsTarget, err := parseRelayTarget(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	sessionCtx, cancel := context.WithCancel(context.Background())
	r.sessions.Store(requestID, cancel)
	defer func() {
		r.sessions.Delete(requestID)
		cancel()
	}()

	subprotocols := parseWebSocketSubprotocols(req.Header)
	clientWS, err := r.acceptClientWebSocket(w, req, requestID, subprotocols)
	if err != nil {
		return
	}
	defer closeWebSocketSilently(clientWS, websocket.StatusInternalError, "relay error")

	backendWS, err := r.dialBackendWebSocket(sessionCtx, wsTarget, requestID, subprotocols, req.Header)
	if err != nil {
		return
	}
	defer closeWebSocketSilently(backendWS, websocket.StatusInternalError, "relay error")

	r.sysLog.Info().Str("id", requestID).Str("target", wsTarget.String()).Msg("internal websocket relay established")

	baseCtx := buildRelayContext(sessionCtx, requestID, targetURL)

	errChan := make(chan error, 2)
	go pipeWebSocket(baseCtx, r.rdr, clientWS, backendWS, "client->server", errChan)
	go pipeWebSocket(baseCtx, r.rdr, backendWS, clientWS, "server->client", errChan)

	err = <-errChan
	if err != nil && err != io.EOF && websocket.CloseStatus(err) != websocket.StatusNormalClosure && websocket.CloseStatus(err) != websocket.StatusGoingAway {
		r.sysLog.Debug().Err(err).Str("id", requestID).Msg("internal relay websocket closed with error")
	} else {
		r.sysLog.Info().Str("id", requestID).Msg("internal relay websocket closed normally")
	}
}

func (r *WebSocketRelay) acceptClientWebSocket(w http.ResponseWriter, req *http.Request, requestID string, subprotocols []string) (*websocket.Conn, error) {
	clientWS, err := websocket.Accept(w, req, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
		Subprotocols:       subprotocols,
	})
	if err != nil {
		r.sysLog.Error().Err(err).Str("id", requestID).Msg("internal relay failed to accept websocket")
		return nil, err
	}
	clientWS.SetReadLimit(-1)
	return clientWS, nil
}

func (r *WebSocketRelay) dialBackendWebSocket(ctx context.Context, wsTarget *url.URL, requestID string, subprotocols []string, header http.Header) (*websocket.Conn, error) {
	dialHeaders := filterWebSocketDialHeaders(header)
	dialOptions := &websocket.DialOptions{
		HTTPHeader:   dialHeaders,
		Subprotocols: subprotocols,
		HTTPClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}

	backendWS, _, err := websocket.Dial(ctx, wsTarget.String(), dialOptions)
	if err != nil {
		r.sysLog.Error().Err(err).Str("id", requestID).Str("url", wsTarget.String()).Msg("internal relay failed to dial backend websocket")
		return nil, err
	}
	backendWS.SetReadLimit(-1)
	return backendWS, nil
}

func buildRelayContext(sessionCtx context.Context, requestID string, targetURL *url.URL) context.Context {
	baseCtx := sessionCtx
	if baseCtx == nil {
		baseCtx = context.Background()
	}
	baseCtx = context.WithValue(baseCtx, ctxkeys.RequestID, requestID)
	baseCtx = context.WithValue(baseCtx, ctxkeys.Host, targetURL.Host)
	baseCtx = context.WithValue(baseCtx, ctxkeys.Path, targetURL.Path)
	baseCtx = context.WithValue(baseCtx, ctxkeys.Method, "WEBSOCKET")
	return baseCtx
}

func closeWebSocketSilently(conn *websocket.Conn, status websocket.StatusCode, reason string) {
	if conn == nil {
		return
	}
	_ = conn.Close(status, reason)
}

func parseRelayTarget(req *http.Request) (*url.URL, *url.URL, error) {
	targetStr := req.Header.Get(wsRelayTargetHeader)
	if targetStr == "" {
		return nil, nil, errBadRelayTarget("missing relay target")
	}

	targetURL, err := url.Parse(targetStr)
	if err != nil || targetURL.Host == "" {
		return nil, nil, errBadRelayTarget("invalid relay target")
	}

	wsTarget := *targetURL
	switch wsTarget.Scheme {
	case "http":
		wsTarget.Scheme = "ws"
	case "https":
		wsTarget.Scheme = "wss"
	case "ws", "wss":
	default:
		return nil, nil, errBadRelayTarget("unsupported relay target scheme")
	}

	return targetURL, &wsTarget, nil
}

type errBadRelayTarget string

func (e errBadRelayTarget) Error() string { return string(e) }

func isWebSocketUpgrade(req *http.Request) bool {
	if !strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
		return false
	}
	// Some clients omit Connection, but if it's present it must include "upgrade".
	conn := req.Header.Get("Connection")
	if conn == "" {
		return true
	}
	return headerHasToken(conn, "upgrade")
}

func headerHasToken(value, token string) bool {
	for _, part := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(part), token) {
			return true
		}
	}
	return false
}

type webSocketConn interface {
	Read(ctx context.Context) (websocket.MessageType, []byte, error)
	Write(ctx context.Context, typ websocket.MessageType, data []byte) error
}

func pipeWebSocket(ctx context.Context, rdr ContentRedactor, src, dst webSocketConn, direction string, errChan chan error) {
	for {
		typ, data, err := src.Read(ctx)
		if err != nil {
			errChan <- err
			return
		}

		data = redactWebSocketPayload(ctx, rdr, direction, typ, data)

		err = dst.Write(ctx, typ, data)
		if err != nil {
			errChan <- err
			return
		}
	}
}

func redactWebSocketPayload(ctx context.Context, rdr ContentRedactor, direction string, typ websocket.MessageType, data []byte) []byte {
	if rdr == nil {
		return data
	}
	redactCtx := context.WithValue(ctx, ctxkeys.Source, direction)
	redacted, changed, err := rdr.RedactWebSocket(redactCtx, typ, data)
	if err == nil && changed {
		return redacted
	}
	return data
}

func parseWebSocketSubprotocols(header http.Header) []string {
	values := header.Values("Sec-WebSocket-Protocol")
	if len(values) == 0 {
		return nil
	}
	var subprotocols []string
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				subprotocols = append(subprotocols, trimmed)
			}
		}
	}
	return subprotocols
}

func filterWebSocketDialHeaders(header http.Header) http.Header {
	res := make(http.Header)
	for k, vv := range header {
		kLower := strings.ToLower(k)
		if kLower == "upgrade" || kLower == "connection" || kLower == "proxy-connection" ||
			kLower == "sec-websocket-key" || kLower == "sec-websocket-version" ||
			kLower == "sec-websocket-extensions" || kLower == "sec-websocket-protocol" ||
			kLower == strings.ToLower(wsRelayTargetHeader) || kLower == strings.ToLower(wsRelayTokenHeader) {
			continue
		}
		for _, v := range vv {
			res.Add(k, v)
		}
	}
	return res
}

func (r *WebSocketRelay) validateRelayToken(req *http.Request) bool {
	if r == nil {
		return false
	}
	return req.Header.Get(wsRelayTokenHeader) == r.relayToken
}
