package redactor

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/wangyihang/llm-redactor/pkg/redactor/detectors"
	"github.com/wangyihang/llm-redactor/pkg/utils/ctxkeys"
)

// newTestRedactor creates a Redactor with a running background goroutine,
// suitable for tests. Callers must defer r.Close().
func newTestRedactor(rules []Rule, log zerolog.Logger) *Redactor {
	return newTestRedactorWithBuffer(rules, log, eventChannelSize, true)
}

func newTestRedactorWithBuffer(rules []Rule, log zerolog.Logger, buffer int, start bool) *Redactor {
	var regexRules []detectors.RegexRule
	for _, rule := range rules {
		regexRules = append(regexRules, detectors.RegexRule{
			ID:          rule.ID,
			Description: rule.Description,
			Regex:       rule.Regex,
		})
	}
	r := &Redactor{
		config:    &Config{Rules: rules},
		logs:      log,
		detectors: []detectors.Detector{detectors.NewRegexDetector(regexRules)},
		eventCh:   make(chan detectionEvent, buffer),
		done:      make(chan struct{}),
	}
	if start {
		go r.processEvents()
	} else {
		close(r.done)
	}
	return r
}

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
	defer r.Close()

	if len(r.config.Rules) != 1 {
		t.Errorf("Expected 1 rule from config, got %d", len(r.config.Rules))
	}
}

func TestRedactRequest(t *testing.T) {
	rules := []Rule{{ID: "test-secret", RawRegex: "SECRET_KEY_[0-9]{5}"}}
	_ = rules[0].Compile()
	r := newTestRedactor(rules, zerolog.Nop())
	defer r.Close()

	reqBody := `{"messages": [{"role": "user", "content": "The key is SECRET_KEY_12345"}]}`
	redacted, _, _ := r.RedactRequest(context.Background(), []byte(reqBody))

	if strings.Contains(string(redacted), "SECRET_KEY_12345") {
		t.Error("Secret not redacted in request")
	}
}

func TestDetectionLogging(t *testing.T) {
	var buf bytes.Buffer
	rules := []Rule{{ID: "log-rule", Description: "Test Desc", RawRegex: "HIT_ME"}}
	_ = rules[0].Compile()
	r := newTestRedactor(rules, zerolog.New(&buf))

	ctx := context.WithValue(context.Background(), ctxkeys.RequestID, "test-req-id")
	r.RedactContent(ctx, "Text HIT_ME text")

	// Close to flush async events before checking the buffer
	r.Close()

	output := buf.String()
	if !strings.Contains(output, "log-rule") || !strings.Contains(output, "test-req-id") {
		t.Errorf("Audit log incomplete: %s", output)
	}
}

func TestRedactValueRecursively(t *testing.T) {
	rules := []Rule{{ID: "edge-secret", RawRegex: "MY_PASSWORD"}}
	_ = rules[0].Compile()
	r := newTestRedactor(rules, zerolog.Nop())
	defer r.Close()

	val, _ := r.RedactValue(context.Background(), []interface{}{"A_MY_PASSWORD_B", map[string]interface{}{"key": "MY_PASSWORD"}})
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
	if err != nil || len(r2.config.Rules) != 1 {
		t.Errorf("Failed to load JSON config (expected 1 config): %v, got count %d", err, len(r2.config.Rules))
	}
	defer r2.Close()
}

func TestRedactorMask(t *testing.T) {
	if mask("1234567") != "****" {
		t.Errorf("Short mask failed")
	}
	if mask("123456789") != "1234...6789" {
		t.Errorf("Long mask failed")
	}
}

func TestCloseIdempotent(t *testing.T) {
	rules := []Rule{{ID: "test-secret", RawRegex: "SECRET_KEY_[0-9]{5}"}}
	_ = rules[0].Compile()
	r := newTestRedactor(rules, zerolog.Nop())

	r.Close()
	r.Close()
}

func TestRedactAfterCloseDoesNotPanic(t *testing.T) {
	rules := []Rule{{ID: "test-secret", RawRegex: "SECRET_KEY_[0-9]{5}"}}
	_ = rules[0].Compile()
	r := newTestRedactor(rules, zerolog.Nop())
	r.Close()

	_, _ = r.RedactContent(context.Background(), "SECRET_KEY_12345")
	if r.DroppedEvents() == 0 {
		t.Fatal("expected dropped events after close")
	}
}

func TestDroppedEventsOnFullChannel(t *testing.T) {
	rules := []Rule{{ID: "test-secret", RawRegex: "SECRET_KEY_[0-9]{5}"}}
	_ = rules[0].Compile()
	r := newTestRedactorWithBuffer(rules, zerolog.Nop(), 1, false)
	defer r.Close()

	_, _ = r.RedactContent(context.Background(), "SECRET_KEY_12345")
	_, _ = r.RedactContent(context.Background(), "SECRET_KEY_12345")

	if r.DroppedEvents() != 1 {
		t.Fatalf("expected 1 dropped event, got %d", r.DroppedEvents())
	}
}
