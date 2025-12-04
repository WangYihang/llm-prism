package main

import (
	"fmt"
	"net/http"
	"net/http/httputil"

	"github.com/WangYihang/http-grab/pkg/model"
	"github.com/wangyihang/llm-prism/pkg/llms/providers"
)

func main() {
	deepseekProvider := providers.NewDeepseekProvider("https://api.deepseek.com/anthropic", "sk-3a197085316e44f596cad242c914905e")
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
	err := http.ListenAndServe(":4000", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(w, r)
	}))
	if err != nil {
		fmt.Println(">>>> error: ", err)
		return
	}
}
