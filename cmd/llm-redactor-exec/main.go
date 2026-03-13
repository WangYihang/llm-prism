package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/alecthomas/kong"
	"github.com/google/uuid"
	"github.com/wangyihang/llm-redactor/pkg/commands"
	"github.com/wangyihang/llm-redactor/pkg/config"
	"github.com/wangyihang/llm-redactor/pkg/utils"
	"github.com/wangyihang/llm-redactor/pkg/utils/logging"
	"github.com/wangyihang/llm-redactor/pkg/utils/version"
)

func main() {
	var cli config.ExecCLI
	kong.Parse(&cli, kong.Name("llm-redactor-exec"), kong.UsageOnError())

	if cli.Version {
		fmt.Println(version.GetVersionInfo().JSON())
		return
	}

	if len(cli.Command) == 0 {
		fmt.Println("Error: command is required")
		fmt.Println("Usage: llm-redactor-exec [options] -- <command> [args...]")
		os.Exit(1)
	}

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

	commands.Exec(&cli, logs)
}
