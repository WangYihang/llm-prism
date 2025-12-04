package providers

import (
	"net/http"
	"net/url"
)

type DeepseekProvider struct {
	BaseURL string
	APIKey  string
}

func NewDeepseekProvider(baseURL, apiKey string) *DeepseekProvider {
	return &DeepseekProvider{
		BaseURL: baseURL,
		APIKey:  apiKey,
	}
}

func (p *DeepseekProvider) Director(req *http.Request) *http.Request {
	req.Host = p.Target().Host
	req.Header.Set("Authorization", "Bearer "+p.APIKey)
	return req
}

func (p *DeepseekProvider) Target() *url.URL {
	target, _ := url.Parse(p.BaseURL)
	return target
}
