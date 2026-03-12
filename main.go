package main

import (
	"fmt"

	"github.com/alecthomas/kong"
	"github.com/wangyihang/llm-prism/pkg/commands"
	"github.com/wangyihang/llm-prism/pkg/config"
	"github.com/wangyihang/llm-prism/pkg/utils/logging"
	"github.com/wangyihang/llm-prism/pkg/utils/version"
)

func main() {
	var cli config.CLI
	ctx := kong.Parse(&cli, kong.Name("llm-prism"), kong.UsageOnError())
	logs := logging.New(cli.LogFile, cli.DetectionLogFile)

	switch ctx.Command() {
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
