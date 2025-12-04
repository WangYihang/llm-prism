package main

import (
	"fmt"
	"net/http"
	"net/http/httputil"

	"github.com/WangYihang/http-grab/pkg/model"
	"github.com/alecthomas/kong"
	"github.com/wangyihang/llm-prism/pkg/llms/providers"
	"github.com/wangyihang/llm-prism/pkg/version"
)

type CLI struct {
	Run struct {
		ApiURL string `help:"The API base URL." env:"LLM_PRISM_API_URL" default:"https://api.deepseek.com/anthropic"`
		ApiKey string `help:"The API key." env:"LLM_PRISM_API_KEY" required:""`
		Host   string `help:"The host to listen on." env:"LLM_PRISM_HOST" default:"0.0.0.0"`
		Port   int    `help:"The port to listen on." env:"LLM_PRISM_PORT" default:"4000"`
	} `cmd:"" help:"Run the proxy server."`
	Version struct {
	} `cmd:"" help:"Print version information."`
}

func main() {
	var cli CLI
	ctx := kong.Parse(&cli,
		kong.Name("llm-prism"),
		kong.Description("A proxy server for LLM API requests."),
		kong.UsageOnError(),
	)

	switch ctx.Command() {
	case "run":
		runProxy(cli.Run.ApiURL, cli.Run.ApiKey, cli.Run.Host, cli.Run.Port)
	case "version":
		fmt.Println(version.GetVersionInfo().JSON())
	}
}

func runProxy(apiURL, apiKey, host string, port int) {
	deepseekProvider := providers.NewDeepseekProvider(apiURL, apiKey)
	proxy := httputil.NewSingleHostReverseProxy(deepseekProvider.Target())
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req = deepseekProvider.Director(req)
		httpRequest, err := model.NewHTTPRequest(req)
		if err != nil {
			fmt.Println(">>>> error: ", err)
			return
		}
		fmt.Println(">>>> request: ", httpRequest)
	}
	proxy.ModifyResponse = func(resp *http.Response) error {
		dump, _ := httputil.DumpResponse(resp, true)
		fmt.Println(">>>> response: ", string(dump))
		httpResponse, err := model.NewHTTPResponse(resp)
		if err != nil {
			fmt.Println(">>>> error: ", err)
			return nil
		}
		fmt.Println(">>>> response: ", httpResponse)
		return nil
	}
	addr := fmt.Sprintf("%s:%d", host, port)
	fmt.Printf("Starting proxy server on %s\n", addr)
	err := http.ListenAndServe(addr, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(w, r)
	}))
	if err != nil {
		fmt.Println(">>>> error: ", err)
		return
	}
}
