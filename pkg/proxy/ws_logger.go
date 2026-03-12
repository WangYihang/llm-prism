package proxy

import (
	"io"
	"os"
	"path/filepath"

	"github.com/rs/zerolog"
)

func newWebSocketLogger(sessionDir string, sysLog zerolog.Logger) (zerolog.Logger, func()) {
	path := filepath.Join(sessionDir, "websocket.jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		sysLog.Warn().Err(err).Str("path", path).Msg("failed to open websocket log file; disabling websocket logging")
		return zerolog.New(io.Discard).With().Timestamp().Logger(), func() {}
	}

	logger := zerolog.New(f).
		Level(zerolog.DebugLevel).
		With().
		Timestamp().
		Logger()

	return logger, func() {
		_ = f.Close()
	}
}
