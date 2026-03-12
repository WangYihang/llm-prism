package detectors

import (
	"context"
	"regexp"
)

type RegexRule struct {
	ID          string
	Description string
	Regex       *regexp.Regexp
}

type RegexDetector struct {
	rules []RegexRule
}

func NewRegexDetector(rules []RegexRule) *RegexDetector {
	return &RegexDetector{rules: rules}
}

func (d *RegexDetector) Type() string {
	return "regex"
}

func (d *RegexDetector) Redact(ctx context.Context, content string, callback RedactionCallback) string {
	for _, rule := range d.rules {
		content = rule.Regex.ReplaceAllStringFunc(content, func(match string) string {
			if len(match) == 0 {
				return match
			}
			return callback(match, rule.ID, rule.Description)
		})
	}
	return content
}
