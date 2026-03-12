package detectors

import (
	"context"
	"math"
	"regexp"
	"strings"

	"github.com/wangyihang/llm-prism/pkg/utils/ctxkeys"
)

type EntropyDetector struct {
	threshold float64
	minLen    int
	regex     *regexp.Regexp
}

func NewEntropyDetector(threshold float64, minLen int) *EntropyDetector {
	return &EntropyDetector{
		threshold: threshold,
		minLen:    minLen,
		// Token pattern: letters, numbers, and common key symbols (excluding = and /)
		regex: regexp.MustCompile(`[a-zA-Z0-9\-_+]{16,}`),
	}
}

var (
	envVarRegex  = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)
	urlPartRegex = regexp.MustCompile(`^.*(\.com|\.org|\.net|\.gov|\.edu|\.io|json-schema|githubusercontent).*$`)
	uuidRegex    = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	hexOnlyRegex = regexp.MustCompile(`(?i)^[0-9a-f]+$`)
)

func (d *EntropyDetector) Type() string {
	return "entropy"
}

func (d *EntropyDetector) Redact(ctx context.Context, content string, callback RedactionCallback) string {
	host := ctxkeys.GetString(ctx, ctxkeys.Host)
	if strings.Contains(host, "googleapis.com") || strings.Contains(host, "cloudaicompanion") || strings.Contains(host, "gemini") {
		return content
	}

	return d.regex.ReplaceAllStringFunc(content, func(match string) string {
		if len(match) < d.minLen {
			return match
		}
		// Skip UUIDs
		if uuidRegex.MatchString(match) {
			return match
		}
		// Skip strings with multiple underscores (likely function/tool names)
		if strings.Count(match, "_") >= 2 {
			return match
		}
		// Skip pure hex strings (likely hashes or IDs, not keys which usually use Base64)
		if hexOnlyRegex.MatchString(match) {
			return match
		}
		// Skip all-uppercase with underscores (likely env vars)
		if envVarRegex.MatchString(match) {
			return match
		}
		// Skip strings that look like part of a common URL or domain
		lowerMatch := strings.ToLower(match)
		if urlPartRegex.MatchString(lowerMatch) {
			return match
		}
		if ShannonEntropy(match) > d.threshold {
			return callback(match, "high-entropy", "High entropy token detected")
		}
		return match
	})
}

func ShannonEntropy(data string) float64 {
	if len(data) == 0 {
		return 0
	}
	counts := make(map[rune]int)
	for _, r := range data {
		counts[r]++
	}
	entropy := 0.0
	for _, count := range counts {
		p := float64(count) / float64(len(data))
		entropy -= p * math.Log2(p)
	}
	return entropy
}
