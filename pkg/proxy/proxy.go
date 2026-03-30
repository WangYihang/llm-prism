package proxy

import (
	"bytes"
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/wangyihang/llm-redactor/pkg/utils/ctxkeys"
)

// proxyLogWriter implements io.Writer to adapt standard library log to zerolog.
type proxyLogWriter struct {
	logger zerolog.Logger
}

func (w *proxyLogWriter) Write(p []byte) (n int, err error) {
	return len(p), nil
}

// New creates a new goproxy.ProxyHttpServer configured for LLM traffic interception.
// It returns the proxy and a cleanup function for internal services.
func New(rdr ContentRedactor, sysLog, sysFileLog, trafficLog zerolog.Logger, sessionDir string) (*goproxy.ProxyHttpServer, func(context.Context) error) {
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = true
	proxy.Logger = log.New(&proxyLogWriter{logger: sysFileLog}, "", 0)

	caPath, err := GenerateAndSetCA(sessionDir)
	if err != nil {
		sysLog.Warn().Err(err).Msg("failed to generate session CA certificate")
	} else {
		sysLog.Info().Str("path", caPath).Msg("session CA certificate generated and applied")
	}

	// Intercept only known LLM domains to avoid breaking binary updates and other non-LLM traffic
	llmDomains := []string{
		"anthropic.com",
		"openai.com",
		"chatgpt.com",
		"googleapis.com",
		"deepseek.com",
		"moonshot.cn",
		"mistral.ai",
		"groq.com",
		"openrouter.ai",
		"together.xyz",
		"perplex.ity",
		"perplexity.ai",
	}

	proxy.OnRequest().HandleConnectFunc(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		hostname, _, err := net.SplitHostPort(host)
		if err != nil {
			hostname = host
		}
		hostname = strings.ToLower(hostname)

		shouldIntercept := false
		for _, domain := range llmDomains {
			if hostname == domain || strings.HasSuffix(hostname, "."+domain) {
				shouldIntercept = true
				break
			}
		}

		if shouldIntercept {
			sysLog.Debug().Str("host", host).Msg("intercepting LLM traffic (MITM)")
			return goproxy.MitmConnect, host
		}

		sysLog.Debug().Str("host", host).Msg("passing through non-LLM traffic (Tunnel)")
		return goproxy.OkConnect, host
	})

	wsLog, closeWSLog := newWebSocketLogger(sessionDir, sysLog)
	var wsRelay *WebSocketRelay
	wsRelay, err = NewWebSocketRelay(rdr, wsLog)
	if err != nil {
		sysLog.Warn().Err(err).Msg("failed to start internal websocket relay; websocket traffic will not be redacted")
	}
	closeRelay := func(ctx context.Context) error {
		defer closeWSLog()
		if wsRelay == nil {
			return nil
		}
		return wsRelay.Close(ctx)
	}

	proxy.OnRequest().DoFunc(func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		// Recovery from http.ErrAbortHandler to avoid log noise in goproxy
		defer func() {
			if rec := recover(); rec != nil {
				if rec != http.ErrAbortHandler {
					sysLog.Error().Interface("panic", rec).Msg("recovered from panic in OnRequest")
				}
			}
		}()

		requestID := uuid.New().String()
		ctx.UserData = map[string]interface{}{
			"request_id": requestID,
			"start_time": time.Now(),
		}

		// WebSocket interception: rewrite to internal relay for safe redaction.
		if wsRelay != nil {
			wsRelay.RewriteRequest(r, requestID)
		}

		// Handle normal HTTP Request redaction
		requestBody := redactRequestBody(rdr, requestID, r)

		ctx.UserData.(map[string]interface{})["request_body"] = requestBody
		return r, nil
	})

	proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		// Short-circuit for hijacked/aborted requests
		if resp == nil || resp.StatusCode == http.StatusSwitchingProtocols {
			return resp
		}

		userData := ctx.UserData.(map[string]interface{})
		requestID := userData["request_id"].(string)
		startTime := userData["start_time"].(time.Time)
		requestBody, _ := userData["request_body"].([]byte)

		var responseBody []byte
		contentType := strings.ToLower(resp.Header.Get("Content-Type"))
		isStream := strings.Contains(contentType, "text/event-stream") ||
			strings.Contains(contentType, "application/x-ndjson") ||
			strings.Contains(contentType, "application/stream+json") ||
			strings.Contains(contentType, "application/jsonl")

		if resp.Body != nil && !isStream {
			const maxLogSize = 1024 * 1024
			limitReader := io.LimitReader(resp.Body, maxLogSize)
			var err error
			responseBody, err = io.ReadAll(limitReader)
			if err == nil {
				// Restore pseudonymized values (e.g. fake IPs → real IPs) before
				// returning the response to the client.
				if rdr != nil {
					if unredacted, changed, uerr := rdr.UnredactResponse(responseBody); uerr == nil && changed {
						responseBody = unredacted
					}
				}
				resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(responseBody), resp.Body))
				resp.ContentLength = int64(len(responseBody))
			}
		} else if isStream && resp.Body != nil && rdr != nil {
			// For streaming responses (SSE/NDJSON), wrap the body so that
			// pseudonymized values are restored chunk-by-chunk as data flows.
			resp.Body = rdr.WrapStreamUnredactor(resp.Body)
			resp.ContentLength = -1 // length unknown after transform
		}

		reqEvt := zerolog.Dict().Str("id", requestID).Str("method", ctx.Req.Method).Str("path", ctx.Req.URL.Path).Str("host", ctx.Req.Host)
		EnrichLogEvent(reqEvt, requestBody, ctx.Req.Header, sysLog)

		resEvt := zerolog.Dict().Int("status", resp.StatusCode)
		EnrichLogEvent(resEvt, responseBody, resp.Header, sysLog)

		trafficLog.Info().
			Str("id", requestID).
			Dur("duration", time.Since(startTime)).
			Dict("http", zerolog.Dict().Dict("request", reqEvt).Dict("response", resEvt)).
			Msg("")

		return resp
	})

	return proxy, closeRelay
}

func redactRequestBody(rdr ContentRedactor, requestID string, r *http.Request) []byte {
	if r == nil || r.Body == nil || r.ContentLength >= 10*1024*1024 {
		return nil
	}
	requestBody, err := io.ReadAll(r.Body)
	if err != nil {
		return nil
	}

	reqCtx := context.Background()
	reqCtx = context.WithValue(reqCtx, ctxkeys.RequestID, requestID)
	reqCtx = context.WithValue(reqCtx, ctxkeys.Source, "request")
	reqCtx = context.WithValue(reqCtx, ctxkeys.Host, r.Host)
	reqCtx = context.WithValue(reqCtx, ctxkeys.Path, r.URL.Path)
	reqCtx = context.WithValue(reqCtx, ctxkeys.Method, r.Method)

	if rdr != nil {
		redacted, changed, err := rdr.RedactRequest(reqCtx, requestBody)
		if err == nil && changed {
			r.Body = io.NopCloser(bytes.NewReader(redacted))
			r.ContentLength = int64(len(redacted))
			return redacted
		}
	}

	r.Body = io.NopCloser(bytes.NewReader(requestBody))
	return requestBody
}
