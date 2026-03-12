package detectors

import (
	"context"
	"regexp"
)

type DeepSeekDetector struct {
	regex *regexp.Regexp
}

func NewDeepSeekDetector() *DeepSeekDetector {
	return &DeepSeekDetector{
		regex: regexp.MustCompile(`sk-[a-f0-9]{32}`),
	}
}

func (d *DeepSeekDetector) Type() string {
	return "deepseek"
}

func (d *DeepSeekDetector) Redact(ctx context.Context, content string, callback RedactionCallback) string {
	return d.regex.ReplaceAllStringFunc(content, func(match string) string {
		return callback(match, "deepseek-api-key", "DeepSeek API Key")
	})
}
