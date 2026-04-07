package redactor

import (
	"context"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	gitleaksconfig "github.com/zricethezav/gitleaks/v8/config"

	"github.com/coder/websocket"
	"github.com/goccy/go-json"
	"github.com/pelletier/go-toml/v2"
	"github.com/rs/zerolog"
	"github.com/wangyihang/llm-redactor/pkg/redactor/detectors"
	"github.com/wangyihang/llm-redactor/pkg/utils"
	"github.com/wangyihang/llm-redactor/pkg/utils/ctxkeys"
)

const (
	RedactedPlaceholder = "REDACTED_SECRET"
	eventChannelSize    = 1024
)

// schemaSubtreeEntry reports whether descending into mapKey starts a JSON Schema
// payload (tool definitions, Responses API blocks, OpenAI function parameters).
// All redaction must be skipped for string values inside this subtree: not only
// IPs but Gitleaks/regex, email and URL pseudonyms, and same-length secret masks
// can change const/enum/pattern/$ref text and make draft 2020-12 validation fail.
func schemaSubtreeEntry(path []string, mapKey string) bool {
	switch mapKey {
	case "input_schema", "json_schema", "output_schema":
		return true
	case "parameters":
		for i := len(path) - 1; i >= 0; i-- {
			if path[i] == "function" {
				return true
			}
		}
	}
	return false
}

// anthropicSignedThinkingBlock reports whether m is a Claude Messages API
// content block whose signature is bound to the entire block. Redacting any
// field (thinking text, signature, etc.) causes "Invalid `signature` in
// `thinking` block" from the API. We only skip redaction when this block sits
// under role=assistant (see redactValueJSON); user-supplied thinking-shaped
// JSON is still redacted so PII cannot be smuggled in fake blocks.
func anthropicSignedThinkingBlock(m map[string]interface{}) bool {
	t, ok := m["type"].(string)
	if !ok {
		return false
	}
	switch t {
	case "thinking", "redacted_thinking":
		return true
	default:
		return false
	}
}

func isMessagesArrayElementPath(path []string) bool {
	n := len(path)
	return n >= 2 && path[n-2] == "messages" && path[n-1] == "*"
}

func messageHasAssistantRole(m map[string]interface{}) bool {
	r, ok := m["role"].(string)
	return ok && r == "assistant"
}

// detectionEvent captures all info needed to log a single detection asynchronously.
type detectionEvent struct {
	DetectorType string
	RuleID       string
	Description  string
	Match        string
	RequestID    string
	Source       string
	Host         string
	Path         string
	Method       string
}

type DetectionDetail struct {
	RequestID     string
	DetectorType  string
	RuleID        string
	MaskedContent string
}

type Redactor struct {
	config           *Config
	logs             zerolog.Logger
	detectors        []detectors.Detector
	stats            sync.Map // detector_type -> *int64
	details          []DetectionDetail
	mu               sync.Mutex
	eventCh          chan detectionEvent
	done             chan struct{}
	closeOnce        sync.Once
	closed           atomic.Bool
	droppedEvents    atomic.Int64
	appLogPath       string
	trafficLogPath   string
	detectionLogPath string
}

func (r *Redactor) SetLogPaths(app, traffic, detection string) {
	r.appLogPath = app
	r.trafficLogPath = traffic
	r.detectionLogPath = detection
}

func New(configPath string, sysLog, detectionLog zerolog.Logger) (*Redactor, error) {
	var data []byte
	var err error

	if configPath != "" {
		configPath = utils.ExpandTilde(configPath)
		data, err = os.ReadFile(configPath)
		if err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to read config: %w", err)
		}
	}

	if len(data) == 0 {
		sysLog.Debug().Msg("using built-in gitleaks default rules")
		data = []byte(gitleaksconfig.DefaultConfig)
	}

	var config Config
	// Try TOML first (Gitleaks official format)
	if err := toml.Unmarshal(data, &config); err != nil {
		// Fallback to JSON
		if err := json.Unmarshal(data, &config); err != nil {
			return nil, fmt.Errorf("failed to unmarshal config (tried TOML and JSON): %w", err)
		}
	}

	var compatibleRules []Rule
	for _, rule := range config.Rules {
		// Skip rules without regex (e.g., path-only rules from Gitleaks)
		if rule.RawRegex == "" {
			continue
		}
		// Go's regexp engine doesn't support lookaround (?!, ?=, ?<)
		if strings.Contains(rule.RawRegex, "?<") || strings.Contains(rule.RawRegex, "?=") || strings.Contains(rule.RawRegex, "?!") {
			continue
		}
		if err := rule.Compile(); err != nil {
			// Skip invalid/unsupported regex
			continue
		}
		compatibleRules = append(compatibleRules, rule)
	}
	config.Rules = compatibleRules
	gitleaksCount := len(config.Rules)

	sysLog.Info().
		Int("gitleaks", gitleaksCount).
		Int("total", len(config.Rules)).
		Msg("redaction rules loaded")

	var regexRules []detectors.RegexRule
	for _, rule := range config.Rules {
		regexRules = append(regexRules, detectors.RegexRule{
			ID:            rule.ID,
			Description:   rule.Description,
			Regex:         rule.Regex,
			ReplaceEngine: rule.ReplaceEngine,
		})
	}

	gitleaksDetector, err := detectors.NewGitleaksDetector()
	if err != nil {
		sysLog.Warn().Err(err).Msg("failed to initialise gitleaks native detector; skipping")
	}

	detectorsList := []detectors.Detector{
		detectors.NewRegexDetector(regexRules),
		detectors.NewDeepSeekDetector(),
		detectors.NewIPDetector(config.ExcludePrivateIPsOrDefault()),
		detectors.NewEmailDetector(),
		detectors.NewGitProjectDetector(),
		// Default threshold 4.3 to skip hex-only strings (max entropy 4.0)
		// detectors.NewEntropyDetector(4.3, 32),
	}
	if gitleaksDetector != nil {
		detectorsList = append(detectorsList, gitleaksDetector)
	}

	r := &Redactor{
		config:    &config,
		logs:      detectionLog,
		detectors: detectorsList,
		eventCh:   make(chan detectionEvent, eventChannelSize),
		done:      make(chan struct{}),
	}
	go r.processEvents()
	return r, nil
}

func mask(s string) string {
	if len(s) <= 8 {
		return "****"
	}
	return s[:4] + "..." + s[len(s)-4:]
}

// processEvents runs in a background goroutine, consuming detection events
// from the channel and performing logging, stats, and dedup off the hot path.
func (r *Redactor) processEvents() {
	defer close(r.done)
	for evt := range r.eventCh {
		// Log detection
		logEvt := r.logs.Info().
			Str("detector_type", evt.DetectorType).
			Str("rule_id", evt.RuleID).
			Str("description", evt.Description).
			Str("masked_content", mask(evt.Match)).
			Int("match_length", len(evt.Match))

		if evt.RequestID != "" {
			logEvt.Str("request_id", evt.RequestID)
		}
		if evt.Source != "" {
			logEvt.Str("source", evt.Source)
		}
		if evt.Host != "" {
			logEvt.Str("host", evt.Host)
		}
		if evt.Path != "" {
			logEvt.Str("path", evt.Path)
		}
		if evt.Method != "" {
			logEvt.Str("method", evt.Method)
		}

		logEvt.Msg("secret detected")

		// Update stats
		actual, _ := r.stats.LoadOrStore(evt.DetectorType, new(int64))
		atomic.AddInt64(actual.(*int64), 1)

		// Record details (de-duplicated)
		masked := mask(evt.Match)
		r.mu.Lock()
		found := false
		for _, d := range r.details {
			if d.RequestID == evt.RequestID && d.DetectorType == evt.DetectorType && d.RuleID == evt.RuleID && d.MaskedContent == masked {
				found = true
				break
			}
		}
		if !found {
			r.details = append(r.details, DetectionDetail{
				RequestID:     evt.RequestID,
				DetectorType:  evt.DetectorType,
				RuleID:        evt.RuleID,
				MaskedContent: masked,
			})
		}
		r.mu.Unlock()
	}
}

// Close shuts down the background event processor and waits for all
// pending detection events to be flushed.
func (r *Redactor) Close() {
	r.closeOnce.Do(func() {
		r.closed.Store(true)
		close(r.eventCh)
		<-r.done
	})
}

// RedactContent redacts a single string content and sends detections
// to the background processor asynchronously.
// Returns the redacted content and a boolean indicating if any redaction occurred.
func (r *Redactor) RedactContent(ctx context.Context, content string) (string, bool) {
	return r.redactContent(ctx, content, false)
}

func (r *Redactor) redactContent(ctx context.Context, content string, preserveLiterals bool) (string, bool) {
	if preserveLiterals {
		return content, false
	}
	anyRedacted := false
	for _, detector := range r.detectors {
		content = detector.Redact(ctx, content, func(match, ruleID, description string) string {
			anyRedacted = true
			// Check global allow list (must stay synchronous — affects return value)
			for _, allow := range r.config.AllowList {
				if match == allow {
					anyRedacted = false
					return match
				}
			}

			var replacement string
			if len(match) > len(RedactedPlaceholder) {
				replacement = RedactedPlaceholder + strings.Repeat("*", len(match)-len(RedactedPlaceholder))
			} else {
				replacement = RedactedPlaceholder[:len(match)]
			}

			// Send detection event to background processor non-blocking
			r.enqueueEvent(detectionEvent{
				DetectorType: detector.Type(),
				RuleID:       ruleID,
				Description:  description,
				Match:        match,
				RequestID:    ctxkeys.GetString(ctx, ctxkeys.RequestID),
				Source:       ctxkeys.GetString(ctx, ctxkeys.Source),
				Host:         ctxkeys.GetString(ctx, ctxkeys.Host),
				Path:         ctxkeys.GetString(ctx, ctxkeys.Path),
				Method:       ctxkeys.GetString(ctx, ctxkeys.Method),
			})

			return replacement
		})
	}
	return content, anyRedacted
}

func (r *Redactor) enqueueEvent(evt detectionEvent) {
	if r == nil || r.closed.Load() {
		if r != nil {
			r.droppedEvents.Add(1)
		}
		return
	}
	defer func() {
		if rec := recover(); rec != nil {
			r.droppedEvents.Add(1)
			r.logs.Warn().Msg("Detection event channel closed, dropping detection metric.")
		}
	}()
	select {
	case r.eventCh <- evt:
	default:
		// Channel is full, effectively dropping the event metric to prioritize proxy stability
		r.droppedEvents.Add(1)
		r.logs.Warn().Msg("Detection event channel full, dropping detection metric.")
	}
}

func (r *Redactor) DroppedEvents() int64 {
	if r == nil {
		return 0
	}
	return r.droppedEvents.Load()
}

func (r *Redactor) GetStats() map[string]int64 {
	res := make(map[string]int64)
	r.stats.Range(func(key, value interface{}) bool {
		res[key.(string)] = atomic.LoadInt64(value.(*int64))
		return true
	})
	return res
}

// Removed Summary func, now handled in summary.go

// RedactValue recursively traverses a JSON-compatible structure and redacts all string values.
// Returns the redacted value and a boolean indicating if any redaction occurred.
func (r *Redactor) RedactValue(ctx context.Context, v interface{}) (interface{}, bool) {
	return r.redactValueJSON(ctx, v, false, false, false, nil)
}

func (r *Redactor) redactValueJSON(ctx context.Context, v interface{}, inJSONSchema, inAnthropicThinking, inAssistantMessage bool, path []string) (interface{}, bool) {
	anyRedacted := false
	switch val := v.(type) {
	case string:
		preserve := inJSONSchema || (inAnthropicThinking && inAssistantMessage)
		return r.redactContent(ctx, val, preserve)
	case map[string]interface{}:
		inAsst := inAssistantMessage
		if isMessagesArrayElementPath(path) {
			if messageHasAssistantRole(val) {
				inAsst = true
			} else {
				inAsst = false
			}
		}
		thinkingHere := anthropicSignedThinkingBlock(val)
		for k, child := range val {
			nextSchema := inJSONSchema || schemaSubtreeEntry(path, k)
			nextThinking := inAnthropicThinking || thinkingHere
			childPath := append(slices.Clone(path), k)
			redacted, changed := r.redactValueJSON(ctx, child, nextSchema, nextThinking, inAsst, childPath)
			if changed {
				val[k] = redacted
				anyRedacted = true
			}
		}
		return val, anyRedacted
	case []interface{}:
		arrPath := append(slices.Clone(path), "*")
		for i, child := range val {
			redacted, changed := r.redactValueJSON(ctx, child, inJSONSchema, inAnthropicThinking, inAssistantMessage, arrPath)
			if changed {
				val[i] = redacted
				anyRedacted = true
			}
		}
		return val, anyRedacted
	default:
		return v, false
	}
}

// RedactRequest redacts all string values in a JSON request body.
// Returns the original body if no secrets were detected, preserving formatting and signatures.
// Returns (redactedBody, changed, error).
func (r *Redactor) RedactRequest(ctx context.Context, body []byte) ([]byte, bool, error) {
	if !json.Valid(body) {
		return body, false, nil
	}

	var data interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return body, false, err
	}

	redactedData, changed := r.RedactValue(ctx, data)
	if !changed {
		return body, false, nil
	}
	res, err := json.Marshal(redactedData)
	return res, true, err
}

// UnredactContent restores previously pseudonymized values (e.g. fake IPs back
// to real IPs) in a single string. Only detectors that implement the
// Unredactor interface participate.
func (r *Redactor) UnredactContent(content string) string {
	for _, d := range r.detectors {
		if u, ok := d.(detectors.Unredactor); ok {
			content = u.Unredact(content)
		}
	}
	return content
}

// UnredactResponse restores pseudonymized values in a JSON response body.
// Returns the restored body (and true) only when at least one substitution
// was made; otherwise returns the original body unchanged.
func (r *Redactor) UnredactResponse(body []byte) ([]byte, bool, error) {
	if len(body) == 0 {
		return body, false, nil
	}

	restored := r.UnredactContent(string(body))
	if restored == string(body) {
		return body, false, nil
	}
	return []byte(restored), true, nil
}

// RedactWebSocket redacts WebSocket messages.
func (r *Redactor) RedactWebSocket(ctx context.Context, messageType websocket.MessageType, data []byte) ([]byte, bool, error) {
	if messageType != websocket.MessageText {
		return data, false, nil
	}
	// Try to treat it as JSON if possible, otherwise as plain text
	if json.Valid(data) {
		redacted, changed, err := r.RedactRequest(ctx, data)
		if err == nil {
			return redacted, changed, nil
		}
	}
	redacted, changed := r.redactContent(ctx, string(data), false)
	return []byte(redacted), changed, nil
}

// streamUnredactReader wraps an io.ReadCloser and restores pseudonymized
// values (e.g. fake IPs → real IPs) in each chunk as it is read.
//
// Token-split safety: the longest fake token the redactor emits is a fully-
// expanded RFC 3849 IPv6 address ("2001:db8:0:0:0:0:0:ff" ≈ 22 bytes). To
// prevent a token from being split across two consecutive Read calls and
// therefore going unrestored, we retain up to maxTokenLen bytes at the tail of
// each chunk as a "seam" that is prepended to the next chunk before running
// UnredactContent. Only bytes before the seam are returned to the caller.
// On EOF the seam is flushed without trimming.
type streamUnredactReader struct {
	r        io.ReadCloser
	unredact func(string) string
	seam     []byte // tail of the previous chunk, held back to cover split tokens
	overflow []byte // restored bytes that exceed the caller's buffer
}

// maxTokenLen is the upper bound on the byte length of any fake token the
// redactor can emit across all detectors:
//
//   - IPv6 (fully expanded RFC 3849): "2001:db8:0:0:0:0:0:ff"       ≈  22 bytes
//   - Email (faker generated):        "name.surname@sub.example.org" ≈  60 bytes
//   - Git URL (faker generated):      "https://sub.host.tld/user/word.git" ≈ 80 bytes
//
// 256 is a round, conservative ceiling that covers all of the above and leaves
// ample room for future detectors, while remaining negligible compared to a
// typical SSE chunk (usually 100–4000 bytes).
const maxTokenLen = 256

func (s *streamUnredactReader) Read(p []byte) (int, error) {
	// Drain overflow from a previous over-large restored chunk first.
	if len(s.overflow) > 0 {
		n := copy(p, s.overflow)
		s.overflow = s.overflow[n:]
		return n, nil
	}

	n, err := s.r.Read(p)
	if n == 0 && err != nil {
		// EOF (or error): flush the seam if any.
		if len(s.seam) == 0 {
			return 0, err
		}
		restored := []byte(s.unredact(string(s.seam)))
		s.seam = s.seam[:0]
		if len(restored) <= len(p) {
			copy(p, restored)
			return len(restored), err
		}
		copy(p, restored[:len(p)])
		s.overflow = append(s.overflow[:0], restored[len(p):]...)
		return len(p), err
	}

	// Combine previous seam with new chunk and unredact together.
	combined := append(s.seam, p[:n]...)

	// Hold back the last maxTokenLen bytes as the new seam (unless this is
	// the final read, signalled by err != nil).  When combined is shorter
	// than maxTokenLen we keep everything in the seam and return nothing —
	// the seam will be flushed when the underlying reader signals EOF.
	var toProcess []byte
	if err != nil {
		// Final read: flush everything.
		toProcess = combined
		s.seam = s.seam[:0]
	} else if len(combined) > maxTokenLen {
		seamStart := len(combined) - maxTokenLen
		toProcess = combined[:seamStart]
		s.seam = append(s.seam[:0], combined[seamStart:]...)
	} else {
		// Not enough data to safely process yet; keep accumulating.
		s.seam = append(s.seam[:0], combined...)
		return 0, nil
	}

	if len(toProcess) == 0 {
		return 0, nil
	}

	restored := []byte(s.unredact(string(toProcess)))
	if len(restored) <= len(p) {
		copy(p, restored)
		return len(restored), nil
	}

	// Restored content is larger than the caller's buffer.
	copy(p, restored[:len(p)])
	s.overflow = append(s.overflow[:0], restored[len(p):]...)
	return len(p), nil
}

func (s *streamUnredactReader) Close() error {
	return s.r.Close()
}

// WrapStreamUnredactor wraps body so that pseudonymized values are restored
// as the stream is consumed. Safe to call with a nil body (returns nil).
func (r *Redactor) WrapStreamUnredactor(body io.ReadCloser) io.ReadCloser {
	if body == nil {
		return nil
	}
	return &streamUnredactReader{
		r:        body,
		unredact: r.UnredactContent,
	}
}
