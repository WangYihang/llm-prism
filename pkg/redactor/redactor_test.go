package redactor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
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
			ID:            rule.ID,
			Description:   rule.Description,
			Regex:         rule.Regex,
			ReplaceEngine: rule.ReplaceEngine,
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

func TestRedactRequestSkipsIPInsideToolInputSchema(t *testing.T) {
	r, err := New("", zerolog.Nop(), zerolog.Nop())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer r.Close()

	body := []byte(`{"tools":[{"name":"t","custom":{"input_schema":{"type":"object","properties":{"x":{"default":"192.168.1.1"}}}}}}]}`)
	redacted, _, err := r.RedactRequest(context.Background(), body)
	if err != nil {
		t.Fatalf("RedactRequest: %v", err)
	}
	if !strings.Contains(string(redacted), "192.168.1.1") {
		t.Fatalf("IP inside input_schema must not be pseudonymized, got %s", redacted)
	}

	// Use TEST-NET (not RFC1918 private) so default exclude_private_ips does not skip redaction.
	outside := []byte(`{"hint":"connect 203.0.113.44"}`)
	red2, ch, err := r.RedactRequest(context.Background(), outside)
	if err != nil {
		t.Fatalf("RedactRequest: %v", err)
	}
	if !ch || strings.Contains(string(red2), "203.0.113.44") {
		t.Fatalf("IP outside schema should be redacted, changed=%v body=%s", ch, red2)
	}
}

func TestRedactRequestSkipsIPInsideOpenAIParameters(t *testing.T) {
	r, err := New("", zerolog.Nop(), zerolog.Nop())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer r.Close()

	body := []byte(`{"tools":[{"type":"function","function":{"name":"f","parameters":{"type":"object","properties":{"h":{"const":"10.0.0.1"}}}}}}]}`)
	redacted, _, err := r.RedactRequest(context.Background(), body)
	if err != nil {
		t.Fatalf("RedactRequest: %v", err)
	}
	if !strings.Contains(string(redacted), "10.0.0.1") {
		t.Fatalf("IP inside function.parameters must not be pseudonymized, got %s", redacted)
	}
}

func TestRedactRequestSkipsAllDetectorsInsideInputSchema(t *testing.T) {
	r, err := New("", zerolog.Nop(), zerolog.Nop())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer r.Close()

	// Synthetic literals only (not real secrets): email-shaped text and sk-+32hex
	// must survive unchanged or email/DeepSeek rules corrupt const/examples and
	// providers reject the tool JSON Schema.
	body := []byte(`{"tools":[{"custom":{"input_schema":{"examples":["user@example.com"],"properties":{"k":{"const":"sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}}}]}`)
	redacted, _, err := r.RedactRequest(context.Background(), body)
	if err != nil {
		t.Fatalf("RedactRequest: %v", err)
	}
	out := string(redacted)
	if !strings.Contains(out, "user@example.com") || !strings.Contains(out, "sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") {
		t.Fatalf("schema literals must not be redacted, got %s", redacted)
	}

	outside := []byte(`{"note":"contact user@example.com"}`)
	red2, ch, err := r.RedactRequest(context.Background(), outside)
	if err != nil {
		t.Fatalf("RedactRequest: %v", err)
	}
	if !ch || strings.Contains(string(red2), "user@example.com") {
		t.Fatalf("email outside schema should be redacted, changed=%v body=%s", ch, red2)
	}
}

func TestRedactRequestPreservesAnthropicThinkingBlocks(t *testing.T) {
	r, err := New("", zerolog.Nop(), zerolog.Nop())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer r.Close()

	// Signature must stay bit-identical to the thinking payload the API issued.
	body := []byte(`{"messages":[{"role":"assistant","content":[{"type":"thinking","thinking":"notes user@example.com","signature":"pretend-sig"},{"type":"text","text":"footer user@example.com"}]}]}`)
	redacted, _, err := r.RedactRequest(context.Background(), body)
	if err != nil {
		t.Fatalf("RedactRequest: %v", err)
	}
	out := string(redacted)
	if !strings.Contains(out, "pretend-sig") || !strings.Contains(out, `thinking":"notes user@example.com`) {
		t.Fatalf("thinking block must not be modified, got %s", redacted)
	}
	if strings.Contains(out, "footer user@example.com") {
		t.Fatalf("sibling text block should still redact email, got %s", redacted)
	}
}

func TestRedactRequestRedactsThinkingShapedBlocksInUserMessages(t *testing.T) {
	r, err := New("", zerolog.Nop(), zerolog.Nop())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer r.Close()

	body := []byte(`{"messages":[{"role":"user","content":[{"type":"thinking","thinking":"notes user@example.com","signature":"fake"}]}]}`)
	redacted, changed, err := r.RedactRequest(context.Background(), body)
	if err != nil {
		t.Fatalf("RedactRequest: %v", err)
	}
	if !changed {
		t.Fatal("expected redaction in user thinking-shaped block")
	}
	if strings.Contains(string(redacted), "user@example.com") {
		t.Fatalf("user message must not bypass redaction via thinking shape, got %s", redacted)
	}
}

// TestRedactRequest_AnthropicMultiTurn_UserPIINotOnWire verifies that a user
// turn carrying a private email is redacted before the request is sent, while
// a prior assistant extended-thinking block stays bit-stable for API signature
// checks. Assistant "thinking" text is not re-scanned for PII (that would
// break signatures); this fixture keeps thinking free of the user secret so the
// full payload has no plaintext user channel leak.
func TestRedactRequest_AnthropicMultiTurn_UserPIINotOnWire(t *testing.T) {
	r, err := New("", zerolog.Nop(), zerolog.Nop())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer r.Close()

	body := []byte(`{"messages":[
{"role":"user","content":[{"type":"text","text":"Reach me at user@example.com please."}]},
{"role":"assistant","content":[
  {"type":"thinking","thinking":"Plan response; do not repeat contact from user.","signature":"stable-sig-for-test"},
  {"type":"text","text":"Acknowledged."}
]}
]}`)
	redacted, changed, err := r.RedactRequest(context.Background(), body)
	if err != nil {
		t.Fatalf("RedactRequest: %v", err)
	}
	if !changed {
		t.Fatal("expected user email to be redacted")
	}

	var root map[string]interface{}
	if err := json.Unmarshal(redacted, &root); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	msgs, ok := root["messages"].([]interface{})
	if !ok || len(msgs) != 2 {
		t.Fatalf("messages: %v", root["messages"])
	}

	userMsg, ok := msgs[0].(map[string]interface{})
	if !ok || userMsg["role"] != "user" {
		t.Fatalf("first message: %#v", msgs[0])
	}
	userBlocks, ok := userMsg["content"].([]interface{})
	if !ok || len(userBlocks) != 1 {
		t.Fatalf("user content: %#v", userMsg["content"])
	}
	userText, ok := userBlocks[0].(map[string]interface{})["text"].(string)
	if !ok {
		t.Fatalf("user text block: %#v", userBlocks[0])
	}
	if strings.Contains(userText, "user@example.com") {
		t.Fatalf("user text must be redacted, got %q", userText)
	}

	asstMsg, ok := msgs[1].(map[string]interface{})
	if !ok || asstMsg["role"] != "assistant" {
		t.Fatalf("second message: %#v", msgs[1])
	}
	asstBlocks, ok := asstMsg["content"].([]interface{})
	if !ok || len(asstBlocks) != 2 {
		t.Fatalf("assistant content: %#v", asstMsg["content"])
	}
	th, ok := asstBlocks[0].(map[string]interface{})
	if !ok || th["type"] != "thinking" {
		t.Fatalf("thinking block: %#v", asstBlocks[0])
	}
	if got, want := th["signature"], "stable-sig-for-test"; got != want {
		t.Fatalf("signature: got %v want %v", got, want)
	}
	wantThink := "Plan response; do not repeat contact from user."
	if got, ok := th["thinking"].(string); !ok || got != wantThink {
		t.Fatalf("thinking: got %q want %q", got, wantThink)
	}

	if strings.Contains(string(redacted), "user@example.com") {
		t.Fatalf("email must not appear anywhere in redacted body, got %s", redacted)
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

// streamSplitRoundTrip is a table-driven helper that:
//  1. Redacts `real` using the supplied redactor to discover the fake token.
//  2. Builds a payload "prefix-<fakeToken>-suffix".
//  3. Feeds the payload through WrapStreamUnredactor in chunks of every size
//     from 1 up to len(fakeToken)+4, verifying the original is fully restored.
func streamSplitRoundTrip(t *testing.T, r *Redactor, real string) {
	t.Helper()

	redacted, changed := r.RedactContent(context.Background(), real)
	if !changed {
		t.Fatalf("expected redaction for %q, got unchanged", real)
	}
	if redacted == real {
		t.Fatalf("expected fake token for %q, got original back", real)
	}

	payload := "prefix-" + redacted + "-suffix"
	want := "prefix-" + real + "-suffix"

	for chunkSize := 1; chunkSize <= len(redacted)+4; chunkSize++ {
		t.Run(fmt.Sprintf("chunk%d", chunkSize), func(t *testing.T) {
			var chunks [][]byte
			for i := 0; i < len(payload); i += chunkSize {
				end := i + chunkSize
				if end > len(payload) {
					end = len(payload)
				}
				chunks = append(chunks, []byte(payload[i:end]))
			}

			sr := r.WrapStreamUnredactor(io.NopCloser(&multiChunkReader{chunks: chunks}))
			out, err := io.ReadAll(sr)
			if err != nil {
				t.Fatalf("read error: %v", err)
			}
			if string(out) != want {
				t.Fatalf("wrong output (chunkSize=%d)\ngot:  %q\nwant: %q", chunkSize, out, want)
			}
		})
	}
}

// TestStreamUnredactReaderTokenSplitAcrossChunks verifies that fake tokens
// whose bytes are split exactly across two Read calls are still restored,
// for every detector type that implements Unredactor.
func TestStreamUnredactReaderTokenSplitAcrossChunks(t *testing.T) {
	t.Run("IPv6", func(t *testing.T) {
		r := &Redactor{
			config:    &Config{},
			logs:      zerolog.Nop(),
			detectors: []detectors.Detector{detectors.NewIPDetector(false)},
			eventCh:   make(chan detectionEvent, eventChannelSize),
			done:      make(chan struct{}),
		}
		go r.processEvents()
		defer r.Close()
		// Full-form IPv6 so the boundary check doesn't see an alphanumeric char
		// adjacent to the match start.
		streamSplitRoundTrip(t, r, "2001:0db9:0000:0000:0000:0000:0000:0001")
	})

	t.Run("Email", func(t *testing.T) {
		r := &Redactor{
			config:    &Config{},
			logs:      zerolog.Nop(),
			detectors: []detectors.Detector{detectors.NewEmailDetector()},
			eventCh:   make(chan detectionEvent, eventChannelSize),
			done:      make(chan struct{}),
		}
		go r.processEvents()
		defer r.Close()
		streamSplitRoundTrip(t, r, "alice.smith@private-corp.internal")
	})

	t.Run("GitURL", func(t *testing.T) {
		r := &Redactor{
			config:    &Config{},
			logs:      zerolog.Nop(),
			detectors: []detectors.Detector{detectors.NewGitProjectDetector()},
			eventCh:   make(chan detectionEvent, eventChannelSize),
			done:      make(chan struct{}),
		}
		go r.processEvents()
		defer r.Close()
		// A self-hosted git URL (not a well-known host) so it gets pseudonymized.
		streamSplitRoundTrip(t, r, "https://gitlab.internal.mycompany.com/myorg/myrepo\n")
	})

	t.Run("CompanyInURL", func(t *testing.T) {
		rules := []Rule{{
			ID:            "co",
			Description:   "company name in URL-like text",
			RawRegex:      `(?i)\bacme corp\b`,
			ReplaceEngine: "company",
		}}
		if err := rules[0].Compile(); err != nil {
			t.Fatal(err)
		}
		r := newTestRedactor(rules, zerolog.Nop())
		defer r.Close()
		// Space in path: internal wikis / ticket titles pasted into URLs.
		streamSplitRoundTrip(t, r, `https://wiki.internal.example/Acme Corp/Playbook`)
	})
}

// multiChunkReader returns one fixed chunk per Read call, then EOF.
type multiChunkReader struct {
	chunks [][]byte
	pos    int
}

func (m *multiChunkReader) Read(p []byte) (int, error) {
	if m.pos >= len(m.chunks) {
		return 0, io.EOF
	}
	chunk := m.chunks[m.pos]
	m.pos++
	n := copy(p, chunk)
	return n, nil
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
