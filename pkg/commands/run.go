package commands

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/wangyihang/llm-prism/pkg/config"
	"github.com/wangyihang/llm-prism/pkg/proxy"
	"github.com/wangyihang/llm-prism/pkg/redactor"
	"github.com/wangyihang/llm-prism/pkg/utils/logging"
)

func Run(cli *config.CLI, logs *logging.Loggers) {
	_, _, err := StartProxy(cli, logs, cli.Run.Host, cli.Run.Port, cli.Run.ApiURL, cli.Run.ApiKey, cli.Run.Provider)
	if err != nil {
		logs.System.Fatal().Err(err).Msg("failed to start proxy")
	}
	// Run indefinitely
	select {}
}

func StartProxy(cli *config.CLI, logs *logging.Loggers, host string, port int, apiURL, apiKey, provider string) (string, context.CancelFunc, error) {
	rdr, err := redactor.New(cli.RedactorRules, logs.Detection)
	if err != nil {
		logs.System.Warn().Err(err).Msg("failed to load redactor rules, skipping redaction")
	}

	// We need to pass the dynamic parameters to Setup
	// Let's modify Setup to accept these explicitly or use a temporary config
	tempCLI := *cli
	tempCLI.Run.ApiURL = apiURL
	tempCLI.Run.ApiKey = apiKey
	tempCLI.Run.Provider = provider

	rp, err := proxy.Setup(&tempCLI, rdr, logs)
	if err != nil {
		return "", nil, fmt.Errorf("failed to setup reverse proxy: %w", err)
	}

	addr := fmt.Sprintf("%s:%d", host, port)
	server := &http.Server{
		Addr: addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t := time.Now()
			requestID := uuid.New().String()
			rb := new(bytes.Buffer)
			if r.Body != nil {
				r.Body = io.NopCloser(io.TeeReader(r.Body, rb))
			}
			sw := &proxy.Spy{ResponseWriter: w, Buf: new(bytes.Buffer), Code: http.StatusOK}

			r = r.WithContext(proxy.WithRequestID(r.Context(), requestID))
			rp.ServeHTTP(sw, r)

			reqEvt := zerolog.Dict().Str("id", requestID).Str("method", r.Method).Str("path", r.URL.Path)
			proxy.EnrichLogEvent(reqEvt, rb.Bytes(), r.Header, logs.System)

			resEvt := zerolog.Dict().Int("status", sw.Code)
			proxy.EnrichLogEvent(resEvt, sw.Buf.Bytes(), sw.Header(), logs.System)

			logs.Data.Info().
				Str("id", requestID).
				Dur("duration", time.Since(t)).
				Dict("http", zerolog.Dict().Dict("request", reqEvt).Dict("response", resEvt)).
				Msg("")
		}),
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", nil, err
	}

	go func() {
		if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
			logs.System.Error().Err(err).Msg("proxy server error")
		}
	}()

	logs.System.Info().Str("addr", addr).Msg("proxy started")

	return addr, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}, nil
}
