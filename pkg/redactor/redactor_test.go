package redactor

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/wangyihang/llm-prism/pkg/utils/ctxkeys"
)

func TestRuleFiltering(t *testing.T) {
	config := `
[[rules]]
id = "go-compatible"
description = "Should be kept"
regex = "sk-[a-zA-Z0-9]{32}"

[[rules]]
id = "incompatible-lookaround"
description = "Should be skipped"
regex = "(?<=secret:)[a-z]+"
`
	tmpFile := "test_rules.toml"
	if err := os.WriteFile(tmpFile, []byte(config), 0644); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile) }()

	r, err := New(tmpFile, zerolog.Nop(), zerolog.Nop())
	if err != nil {
		t.Fatalf("Failed to create redactor: %v", err)
	}

	if len(r.config.Rules) != 2 {
		t.Errorf("Expected 2 rules (1 from config + 1 default DeepSeek), got %d", len(r.config.Rules))
	}
}

func TestRedactRequest(t *testing.T) {
	r := &Redactor{
		config: &Config{
			Rules: []Rule{
				{ID: "test-secret", RawRegex: "SECRET_KEY_[0-9]{5}"},
			},
		},
		logs: zerolog.Nop(),
	}
	if err := r.config.Rules[0].Compile(); err != nil {
		t.Fatalf("Failed to compile rule: %v", err)
	}
	r.detectors = []Detector{NewRegexDetector(r.config.Rules)}

	reqBody := `{"messages": [{"role": "user", "content": "The key is SECRET_KEY_12345"}]}`
	redacted, _ := r.RedactRequest(context.Background(), []byte(reqBody))

	if strings.Contains(string(redacted), "SECRET_KEY_12345") {
		t.Error("Secret not redacted in request")
	}
}

func TestDetectionLogging(t *testing.T) {
	var buf bytes.Buffer
	r := &Redactor{
		config: &Config{
			Rules: []Rule{
				{ID: "log-rule", Description: "Test Desc", RawRegex: "HIT_ME"},
			},
		},
		logs: zerolog.New(&buf),
	}
	if err := r.config.Rules[0].Compile(); err != nil {
		t.Fatalf("Failed to compile rule: %v", err)
	}
	r.detectors = []Detector{NewRegexDetector(r.config.Rules)}

	ctx := context.WithValue(context.Background(), ctxkeys.RequestID, "test-req-id")
	r.RedactContent(ctx, "Text HIT_ME text")

	output := buf.String()
	if !strings.Contains(output, "log-rule") || !strings.Contains(output, "test-req-id") {
		t.Errorf("Audit log incomplete: %s", output)
	}
}

func TestRedactValueRecursively(t *testing.T) {
	r := &Redactor{
		config: &Config{
			Rules: []Rule{
				{ID: "edge-secret", RawRegex: "MY_PASSWORD"},
			},
		},
		logs: zerolog.Nop(),
	}
	_ = r.config.Rules[0].Compile()
	r.detectors = []Detector{NewRegexDetector(r.config.Rules)}

	val := r.RedactValue(context.Background(), []interface{}{"A_MY_PASSWORD_B", map[string]interface{}{"key": "MY_PASSWORD"}})
	valJSON, _ := json.Marshal(val)
	if strings.Contains(string(valJSON), "MY_PASSWORD") {
		t.Errorf("RedactValue failed to redact recursively: %s", string(valJSON))
	}
}

func TestConfigLoadFallback(t *testing.T) {
	jsonConfig := `{"rules": [{"id": "json-rule", "description": "desc", "regex": "JSON_SECRET"}]}`
	tmpFile := "test_rules.json"
	_ = os.WriteFile(tmpFile, []byte(jsonConfig), 0644)
	defer func() { _ = os.Remove(tmpFile) }()
	r2, err := New(tmpFile, zerolog.Nop(), zerolog.Nop())
	if err != nil || len(r2.config.Rules) != 2 {
		t.Errorf("Failed to load JSON config (expected 1 config + 1 default): %v, got count %d", err, len(r2.config.Rules))
	}
}

func TestRedactorMask(t *testing.T) {
	if mask("1234567") != "****" {
		t.Errorf("Short mask failed")
	}
	if mask("123456789") != "1234...6789" {
		t.Errorf("Long mask failed")
	}
}
