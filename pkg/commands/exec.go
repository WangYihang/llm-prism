package commands

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/wangyihang/llm-prism/pkg/config"
	"github.com/wangyihang/llm-prism/pkg/utils/logging"
)

func Exec(cli *config.CLI, logs *logging.Loggers) {
	if len(cli.Exec.Command) == 0 {
		fmt.Println("Usage: llm-prism exec -- <command> [args...]")
		os.Exit(1)
	}

	// Start the proxy
	rdr, addr, closeProxy, err := StartProxy(cli, logs, cli.Exec.Host, cli.Exec.Port)
	if err != nil {
		logs.System.Fatal().Err(err).Msg("failed to start proxy")
	}
	defer func() {
		closeProxy()
		if rdr != nil {
			rdr.Close()
			fmt.Println(rdr.Summary())
		}
	}()

	// Wait a bit for the proxy to be ready
	time.Sleep(200 * time.Millisecond)

	// Determine the proxy URL
	proxyHost := cli.Exec.Host
	if proxyHost == "0.0.0.0" || proxyHost == "127.0.0.1" || proxyHost == "::1" {
		proxyHost = "localhost"
	}
	// addr might be [::]:port or 0.0.0.0:port
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		port = strings.Split(addr, ":")[len(strings.Split(addr, ":"))-1]
	}
	proxyURL := fmt.Sprintf("http://%s:%s", proxyHost, port)

	// Prepare environment variables
	env := os.Environ()
	sessionDir := filepath.Dir(cli.AppLogFile)
	caPath := filepath.Join(sessionDir, "ca.crt")
	proxyEnvs := map[string]string{
		// Node.js specific CA certs
		"NODE_EXTRA_CA_CERTS": caPath,

		// OpenSSL, Curl, and Python requests CA certs
		"SSL_CERT_FILE":      caPath,
		"CURL_CA_BUNDLE":     caPath,
		"REQUESTS_CA_BUNDLE": caPath,

		// Standard proxy environment variables
		"HTTP_PROXY":  proxyURL,
		"HTTPS_PROXY": proxyURL,
		"http_proxy":  proxyURL,
		"https_proxy": proxyURL,
	}

	for k, v := range proxyEnvs {
		env = append(env, k+"="+v)
	}

	// Prepare the command
	cmdName := cli.Exec.Command[0]
	cmdArgs := cli.Exec.Command[1:]

	path, err := exec.LookPath(cmdName)
	if err != nil {
		fmt.Printf("Error: command not found: %s\n", cmdName)
		os.Exit(127)
	}

	cmd := exec.Command(path, cmdArgs...)
	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	logs.System.Info().
		Str("command", strings.Join(cli.Exec.Command, " ")).
		Str("proxy", proxyURL).
		Msg("executing")

	// Final check: handle signals properly
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		for sig := range sigChan {
			if cmd.Process != nil {
				if err := cmd.Process.Signal(sig); err != nil {
					logs.System.Warn().Err(err).Msg("failed to forward signal to child process")
				}
			} else {
				closeProxy()
				os.Exit(0)
			}
		}
	}()

	err = cmd.Run()

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		logs.System.Fatal().Err(err).Msg("command failed")
	}
}
