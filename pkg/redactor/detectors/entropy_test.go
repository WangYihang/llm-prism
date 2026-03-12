package detectors

import (
	"context"
	"strings"
	"testing"

	"github.com/wangyihang/llm-redactor/pkg/utils/ctxkeys"
)

func TestShannonEntropy(t *testing.T) {
	tests := []struct {
		input    string
		expected float64
	}{
		{"", 0},
		{"aaaa", 0},
		{"aabb", 1.0},
		{"abcd", 2.0},
	}
	for _, tt := range tests {
		got := ShannonEntropy(tt.input)
		if got != tt.expected {
			t.Errorf("ShannonEntropy(%q) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}

func TestEntropyDetector(t *testing.T) {
	d := NewEntropyDetector(4.3, 32)
	// Base64 string has higher entropy than Hex
	content := "export SECRET=SG93IGFib3V0IHdlIGFkZCBhIHJlYWxseSBsb25nIGhpZ2ggZW50cm9weSBzdHJpbmcgaGVyZSB0byB0ZXN0"
	redacted := d.Redact(context.Background(), content, func(match, ruleID, description string) string {
		return "REDACTED_SECRET"
	})
	if !strings.Contains(redacted, "REDACTED_SECRET") {
		t.Errorf("Redact() failed to redact high entropy string")
	}
}

func TestEntropyDetectorWhitelist(t *testing.T) {
	d := NewEntropyDetector(4.3, 32)
	content := "export SECRET=SG93IGFib3V0IHdlIGFkZCBhIHJlYWxseSBsb25nIGhpZ2ggZW50cm9weSBzdHJpbmcgaGVyZSB0byB0ZXN0"
	ctx := context.WithValue(context.Background(), ctxkeys.Host, "generativelanguage.googleapis.com")
	redacted := d.Redact(ctx, content, func(match, ruleID, description string) string {
		return "REDACTED_SECRET"
	})
	if strings.Contains(redacted, "REDACTED_SECRET") {
		t.Errorf("Redact() should have skipped redaction for googleapis.com")
	}
}
