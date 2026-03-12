package commands

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/wangyihang/llm-prism/pkg/config"
	"github.com/wangyihang/llm-prism/pkg/proxy"
	"github.com/wangyihang/llm-prism/pkg/redactor"
	"github.com/wangyihang/llm-prism/pkg/utils/logging"
)

func Run(cli *config.CLI, logs *logging.Loggers) {
	rdr, _, _, err := StartProxy(cli, logs, cli.Run.Host, cli.Run.Port)
	if err != nil {
		logs.System.Fatal().Err(err).Msg("failed to start proxy")
	}

	// Handle signals for graceful shutdown and summary
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	if rdr != nil {
		fmt.Println(rdr.Summary())
	}
}

func StartProxy(cli *config.CLI, logs *logging.Loggers, host string, port int) (*redactor.Redactor, string, context.CancelFunc, error) {
	rdr, err := redactor.New(cli.RedactorRules, logs.System, logs.Detection)
	if err != nil {
		logs.System.Warn().Err(err).Msg("failed to load redactor rules, skipping redaction")
		rdr = nil
	} else {
		rdr.SetLogPaths(cli.AppLogFile, cli.TrafficLogFile, cli.DetectionLogFile)
	}

	var contentRedactor proxy.ContentRedactor
	if rdr != nil {
		contentRedactor = rdr
	}

	sessionDir := filepath.Dir(cli.AppLogFile)
	p := proxy.New(contentRedactor, logs.System, logs.SystemFile, logs.Traffic, sessionDir)

	addr := fmt.Sprintf("%s:%d", host, port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, "", nil, err
	}
	actualAddr := ln.Addr().String()

	server := &http.Server{
		Handler: p,
	}

	go func() {
		if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
			logs.System.Error().Err(err).Msg("proxy server error")
		}
	}()

	logs.System.Info().Str("addr", actualAddr).Msg("proxy started")

	return rdr, actualAddr, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		_ = server.Shutdown(ctx)
	}, nil
}
