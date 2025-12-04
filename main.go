package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/alecthomas/kong"
	"github.com/rs/zerolog"
	"github.com/wangyihang/llm-prism/pkg/llms/providers"
	"github.com/wangyihang/llm-prism/pkg/utils/logging"
	"github.com/wangyihang/llm-prism/pkg/utils/version"
)

type CLI struct {
	LogFile string `help:"Log file" env:"LLM_PRISM_LOG_FILE" default:"llm-prism.jsonl"`
	Run     struct {
		ApiURL string `help:"API URL" env:"LLM_PRISM_API_URL" default:"https://api.deepseek.com/anthropic"`
		ApiKey string `help:"API Key" env:"LLM_PRISM_API_KEY" required:""`
		Host   string `help:"Host" env:"LLM_PRISM_HOST" default:"0.0.0.0"`
		Port   int    `help:"Port" env:"LLM_PRISM_PORT" default:"4000"`
	} `cmd:"" help:"Run proxy"`
	Version struct{} `cmd:"" help:"Version"`
}

type spy struct {
	http.ResponseWriter
	buf  *bytes.Buffer
	code int
}

func (w *spy) Write(b []byte) (int, error) { w.buf.Write(b); return w.ResponseWriter.Write(b) }
func (w *spy) WriteHeader(c int)           { w.code = c; w.ResponseWriter.WriteHeader(c) }
func (w *spy) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func main() {
	var cli CLI
	ctx := kong.Parse(&cli, kong.Name("llm-prism"), kong.UsageOnError())
	log := logging.GetLogger(cli.LogFile)

	if ctx.Command() == "version" {
		fmt.Println(version.GetVersionInfo().JSON())
		return
	}

	u, _ := url.Parse(cli.Run.ApiURL)
	p := providers.NewDeepseekProvider(u, cli.Run.ApiKey)
	rp := httputil.NewSingleHostReverseProxy(p.BaseURL)
	d := rp.Director
	rp.Director = func(r *http.Request) { d(r); p.Director(r) }

	addr := fmt.Sprintf("%s:%d", cli.Run.Host, cli.Run.Port)
	log.Info().Str("addr", addr).Msg("started")

	err := http.ListenAndServe(addr, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t := time.Now()
		rb := new(bytes.Buffer)
		r.Body = io.NopCloser(io.TeeReader(r.Body, rb))
		sw := &spy{ResponseWriter: w, buf: new(bytes.Buffer), code: 200}

		rp.ServeHTTP(sw, r)

		enrich := func(e *zerolog.Event, b []byte, h http.Header) {
			if strings.Contains(h.Get("Content-Encoding"), "gzip") {
				if z, err := gzip.NewReader(bytes.NewReader(b)); err == nil {
					if d, _ := io.ReadAll(z); d != nil {
						b = d
					}
					_ = z.Close()
				}
			}
			if json.Valid(b) {
				e.RawJSON("body", b)
			} else {
				e.Str("body", string(b))
			}
		}

		reqEvt := zerolog.Dict().Str("method", r.Method).Str("path", r.URL.Path)
		enrich(reqEvt, rb.Bytes(), r.Header)

		resEvt := zerolog.Dict().Int("status", sw.code)
		enrich(resEvt, sw.buf.Bytes(), sw.Header())

		log.Info().
			Dur("duration", time.Since(t)).
			Dict("http", zerolog.Dict().Dict("request", reqEvt).Dict("response", resEvt)).
			Msg("interaction")
	}))

	if err != nil {
		log.Fatal().Err(err).Msg("failed")
	}
}
