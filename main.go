package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/alecthomas/kong"
	"github.com/google/uuid"
	"github.com/wangyihang/llm-prism/pkg/commands"
	"github.com/wangyihang/llm-prism/pkg/config"
	"github.com/wangyihang/llm-prism/pkg/utils"
	"github.com/wangyihang/llm-prism/pkg/utils/logging"
	"github.com/wangyihang/llm-prism/pkg/utils/version"
)

func main() {
	var cli config.CLI
	ctx := kong.Parse(&cli, kong.Name("llm-prism"), kong.UsageOnError())

	// Session Setup
	sessionID := fmt.Sprintf("%s-%s", time.Now().Format("20060102-150405"), uuid.New().String()[:8])
	baseDir := utils.ExpandTilde(cli.BaseLogDir)
	sessionDir := filepath.Join(baseDir, sessionID)

	if err := os.MkdirAll(sessionDir, 0755); err != nil {
		fmt.Printf("Failed to create log directory: %v\n", err)
		os.Exit(1)
	}

	appLogPath := filepath.Join(sessionDir, cli.AppLogFile)
	trafficLogPath := filepath.Join(sessionDir, cli.TrafficLogFile)
	detectionLogPath := filepath.Join(sessionDir, cli.DetectionLogFile)

	logs := logging.New(appLogPath, trafficLogPath, detectionLogPath)
	logs.System.Info().Str("session_id", sessionID).Str("log_dir", sessionDir).Msg("session started")

	cli.AppLogFile = appLogPath
	cli.TrafficLogFile = trafficLogPath
	cli.DetectionLogFile = detectionLogPath

	switch strings.Split(ctx.Command(), " ")[0] {
	case "version":
		fmt.Println(version.GetVersionInfo().JSON())
	case "sync":
		commands.Sync(&cli, logs)
	case "run":
		commands.Run(&cli, logs)
	case "exec":
		commands.Exec(&cli, logs)
	}
}
