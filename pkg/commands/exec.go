package commands

import (
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/wangyihang/llm-prism/pkg/config"
	"github.com/wangyihang/llm-prism/pkg/utils/logging"
)

func Exec(cli *config.CLI, logs *logging.Loggers) {
	// Start the proxy
	addr, closeProxy, err := StartProxy(cli, logs, cli.Exec.Host, cli.Exec.Port, cli.Exec.ApiURL, cli.Exec.ApiKey, cli.Exec.Provider)
	if err != nil {
		logs.System.Fatal().Err(err).Msg("failed to start proxy")
	}
	defer closeProxy()

	// Handle signals to ensure proxy is closed
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		closeProxy()
		os.Exit(0)
	}()

	// Determine the proxy URL for the sub-process
	proxyHost := cli.Exec.Host
	if proxyHost == "0.0.0.0" {
		proxyHost = "127.0.0.1"
	}
	proxyURL := "http://" + proxyHost + ":" + os.Getenv("LLM_PRISM_PORT")
	if os.Getenv("LLM_PRISM_PORT") == "" {
		proxyURL = "http://" + proxyHost + ":" + strings.Split(addr, ":")[len(strings.Split(addr, ":"))-1]
	}

	// Prepare environment variables for common tools
	env := os.Environ()
	proxyEnvs := map[string]string{
		"ANTHROPIC_BASE_URL": proxyURL,
		"OPENAI_BASE_URL":    proxyURL + "/v1",
		"OPENAI_API_BASE":    proxyURL + "/v1",
		"DEEPSEEK_BASE_URL":  proxyURL,
	}

	for k, v := range proxyEnvs {
		env = append(env, k+"="+v)
	}

	// Execute the command
	cmdName := cli.Exec.Command[0]
	cmdArgs := cli.Exec.Command[1:]
	cmd := exec.Command(cmdName, cmdArgs...)
	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	logs.System.Info().
		Str("command", strings.Join(cli.Exec.Command, " ")).
		Interface("env_injected", proxyEnvs).
		Msg("executing command")

	err = cmd.Run()

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		logs.System.Fatal().Err(err).Msg("command failed")
	}
}
