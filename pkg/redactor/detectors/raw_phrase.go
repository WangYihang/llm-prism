package detectors

import (
	"bufio"
	"context"
	"os"
	"regexp"
	"strings"

	"github.com/wangyihang/llm-redactor/pkg/utils"
)

// RawRule is one entry from the raw rules file: either a literal string or a
// regex (lines prefixed with "regex:").
type RawRule struct {
	pattern     *regexp.Regexp
	description string
}

// RawPhraseDetector redacts literal strings and regex patterns loaded from a
// plain-text file (one entry per line). Lines starting with '#' are comments.
// Lines prefixed with "regex:" are treated as regular expressions; all other
// non-empty lines are treated as literal strings and matched case-insensitively.
type RawPhraseDetector struct {
	rules []RawRule
}

// LoadRawPhraseDetector reads the file at path and returns a RawPhraseDetector.
// Returns (nil, nil) if path is empty.
func LoadRawPhraseDetector(path string) (*RawPhraseDetector, error) {
	if path == "" {
		return nil, nil
	}
	path = utils.ExpandTilde(path)
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var rules []RawRule
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		var pat *regexp.Regexp
		var desc string

		if after, ok := strings.CutPrefix(line, "regex:"); ok {
			// Explicit regex entry.
			re, err := regexp.Compile(after)
			if err != nil {
				// Skip unparseable patterns rather than failing hard.
				continue
			}
			pat = re
			desc = "raw regex: " + after
		} else {
			// Literal string — escape and match case-insensitively.
			pat = regexp.MustCompile(`(?i)` + regexp.QuoteMeta(line))
			desc = "raw phrase: " + line
		}

		rules = append(rules, RawRule{pattern: pat, description: desc})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return &RawPhraseDetector{rules: rules}, nil
}

func (d *RawPhraseDetector) Type() string { return "raw-phrase" }

// Redact replaces each match with the value returned by callback.
func (d *RawPhraseDetector) Redact(ctx context.Context, content string, callback RedactionCallback) string {
	for _, rule := range d.rules {
		r := rule
		content = r.pattern.ReplaceAllStringFunc(content, func(match string) string {
			return callback(match, "raw-phrase", r.description)
		})
	}
	return content
}
