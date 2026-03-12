package redactor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/pelletier/go-toml/v2"
	"github.com/rs/zerolog"
	"github.com/wangyihang/llm-prism/pkg/utils"
	"io"
	"net/http"
)

const (
	RedactedPlaceholder = "[REDACTED_SECRET]"
	DefaultRulesURL     = "https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml"
)

type DetectionDetail struct {
	RequestID     string
	DetectorType  string
	RuleID        string
	MaskedContent string
}

type Redactor struct {
	config           *Config
	logs             zerolog.Logger
	detectors        []Detector
	stats            sync.Map // detector_type -> *int64
	details          []DetectionDetail
	mu               sync.Mutex
	appLogPath       string
	trafficLogPath   string
	detectionLogPath string
}

func (r *Redactor) SetLogPaths(app, traffic, detection string) {
	r.appLogPath = app
	r.trafficLogPath = traffic
	r.detectionLogPath = detection
}

func DownloadRules(path string, url string, logs zerolog.Logger) error {
	if url == "" {
		url = DefaultRulesURL
	}
	path = utils.ExpandTilde(path)
	logs.Info().Str("url", url).Str("path", path).Msg("downloading redaction rules")

	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download rules: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to save rules: %w", err)
	}
	return nil
}

func New(configPath string, logs zerolog.Logger) (*Redactor, error) {
	configPath = utils.ExpandTilde(configPath)
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			logs.Warn().Msg("redaction rules not found, attempting automatic download")
			if err := DownloadRules(configPath, "", logs); err != nil {
				return nil, fmt.Errorf("failed to automatically download rules: %w", err)
			}
			// Re-read after download
			data, err = os.ReadFile(configPath)
			if err != nil {
				return nil, fmt.Errorf("failed to read downloaded rules: %w", err)
			}
		} else {
			return nil, fmt.Errorf("failed to read config: %w", err)
		}
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

	detectors := []Detector{
		NewRegexDetector(config.Rules),
		// Default threshold 3.5 for hex-like keys, 24 min length to avoid common variable names
		NewEntropyDetector(3.5, 24),
	}

	return &Redactor{
		config:    &config,
		logs:      logs,
		detectors: detectors,
	}, nil
}

func mask(s string) string {
	if len(s) <= 8 {
		return "****"
	}
	return s[:4] + "..." + s[len(s)-4:]
}

// RedactContent redacts a single string content and logs detections
func (r *Redactor) RedactContent(content string, context map[string]string) string {
	for _, detector := range r.detectors {
		content = detector.Redact(content, func(match, ruleID, description string) string {
			// Check global allow list
			for _, allow := range r.config.AllowList {
				if match == allow {
					return match
				}
			}

			// LOG DETECTION
			evt := r.logs.Info().
				Str("detector_type", detector.Type()).
				Str("rule_id", ruleID).
				Str("description", description).
				Str("masked_content", mask(match)).
				Int("match_length", len(match))

			for k, v := range context {
				evt.Str(k, v)
			}
			evt.Msg("secret detected")

			// Update stats
			actual, _ := r.stats.LoadOrStore(detector.Type(), new(int64))
			atomic.AddInt64(actual.(*int64), 1)

			// Record details (de-duplicated by RequestID, DetectorType, RuleID, MaskedContent)
			r.mu.Lock()
			found := false
			reqID := context["request_id"]
			masked := mask(match)
			for _, d := range r.details {
				if d.RequestID == reqID && d.DetectorType == detector.Type() && d.RuleID == ruleID && d.MaskedContent == masked {
					found = true
					break
				}
			}
			if !found {
				r.details = append(r.details, DetectionDetail{
					RequestID:     reqID,
					DetectorType:  detector.Type(),
					RuleID:        ruleID,
					MaskedContent: masked,
				})
			}
			r.mu.Unlock()

			return RedactedPlaceholder
		})
	}
	return content
}

func (r *Redactor) GetStats() map[string]int64 {
	res := make(map[string]int64)
	r.stats.Range(func(key, value interface{}) bool {
		res[key.(string)] = atomic.LoadInt64(value.(*int64))
		return true
	})
	return res
}

func (r *Redactor) Summary() string {
	stats := r.GetStats()
	var sb strings.Builder

	sb.WriteString("\n[Log File Locations]\n")
	sb.WriteString(fmt.Sprintf("- App Log:       %s\n", r.appLogPath))
	sb.WriteString(fmt.Sprintf("- Traffic Log:   %s\n", r.trafficLogPath))
	sb.WriteString(fmt.Sprintf("- Detection Log: %s\n", r.detectionLogPath))

	if len(stats) == 0 {
		sb.WriteString("\n[Summary] No secrets detected. Your data is clean!\n")
		return sb.String()
	}

	sb.WriteString("\n[Redactor Stats Summary]\n")
	sb.WriteString("+-----------------------+---------------+\n")
	sb.WriteString("| Detector Type         | Total Matches |\n")
	sb.WriteString("+-----------------------+---------------+\n")

	var total int64
	for k, v := range stats {
		sb.WriteString(fmt.Sprintf("| %-21s | %-13d |\n", k, v))
		total += v
	}

	sb.WriteString("+-----------------------+---------------+\n")
	sb.WriteString(fmt.Sprintf("| %-21s | %-13d |\n", "TOTAL PROTECTED", total))
	sb.WriteString("+-----------------------+---------------+\n")

	sb.WriteString("\n[Redactor Detection Details]\n")
	sb.WriteString("+------------------+----------+-----------------------+---------------+\n")
	sb.WriteString("| Request ID       | Detector | Rule ID               | Masked Value  |\n")
	sb.WriteString("+------------------+----------+-----------------------+---------------+\n")
	r.mu.Lock()
	for _, d := range r.details {
		reqIDShort := d.RequestID
		if len(reqIDShort) > 16 {
			reqIDShort = reqIDShort[:16]
		}
		sb.WriteString(fmt.Sprintf("| %-16s | %-8s | %-21s | %-13s |\n", reqIDShort, d.DetectorType, d.RuleID, d.MaskedContent))
	}
	r.mu.Unlock()
	sb.WriteString("+------------------+----------+-----------------------+---------------+\n")

	return sb.String()
}

// RedactValue recursively traverses a JSON-compatible structure and redacts all string values
func (r *Redactor) RedactValue(v interface{}, context map[string]string) interface{} {
	switch val := v.(type) {
	case string:
		return r.RedactContent(val, context)
	case map[string]interface{}:
		for k, v := range val {
			val[k] = r.RedactValue(v, context)
		}
		return val
	case []interface{}:
		for i, v := range val {
			val[i] = r.RedactValue(v, context)
		}
		return val
	default:
		return v
	}
}

// RedactRequest redacts all string values in a JSON request body
func (r *Redactor) RedactRequest(body []byte, context map[string]string) ([]byte, error) {
	if !json.Valid(body) {
		return body, nil
	}

	var data interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return body, err
	}

	redactedData := r.RedactValue(data, context)
	return json.Marshal(redactedData)
}

// StreamRedactor implements a sliding window redactor for SSE streams
type StreamRedactor struct {
	r             *Redactor
	maxLen        int
	context       map[string]string
	buffer        string
	templateEvent map[string]interface{}
}

func NewStreamRedactor(r *Redactor, windowSize int, context map[string]string) *StreamRedactor {
	if windowSize <= 0 {
		windowSize = 100
	}
	return &StreamRedactor{
		r:       r,
		maxLen:  windowSize,
		context: context,
	}
}

func (sr *StreamRedactor) extractAndClearContent(v interface{}) string {
	switch val := v.(type) {
	case string:
		return val
	case map[string]interface{}:
		var fullContent string
		for k, v := range val {
			if k == "content" || k == "text" || k == "thinking" {
				if s, ok := v.(string); ok {
					fullContent += s
					val[k] = "" // clear it to use as template
				} else {
					fullContent += sr.extractAndClearContent(v)
				}
			} else {
				fullContent += sr.extractAndClearContent(v)
			}
		}
		return fullContent
	case []interface{}:
		var fullContent string
		for _, v := range val {
			fullContent += sr.extractAndClearContent(v)
		}
		return fullContent
	}
	return ""
}

func (sr *StreamRedactor) setContent(v interface{}, text string) bool {
	switch val := v.(type) {
	case map[string]interface{}:
		for k, v := range val {
			if k == "content" || k == "text" || k == "thinking" {
				if _, ok := v.(string); ok {
					val[k] = text
					return true
				}
			}
			if sr.setContent(v, text) {
				return true
			}
		}
	case []interface{}:
		for _, v := range val {
			if sr.setContent(v, text) {
				return true
			}
		}
	}
	return false
}

func (sr *StreamRedactor) emitTemplate(text string) []byte {
	if sr.templateEvent == nil {
		return nil
	}
	sr.setContent(sr.templateEvent, text)
	sr.r.RedactValue(sr.templateEvent, sr.context)
	newRaw, _ := json.Marshal(sr.templateEvent)
	return append([]byte("data: "), newRaw...)
}

// RedactSSELine processes a single "data: ..." line
func (sr *StreamRedactor) RedactSSELine(line []byte) []byte {
	hasNewline := bytes.HasSuffix(line, []byte("\n"))
	cleanLine := bytes.TrimSpace(line)

	if !bytes.HasPrefix(cleanLine, []byte("data: ")) {
		return line
	}

	rawData := bytes.TrimPrefix(cleanLine, []byte("data: "))
	if string(rawData) == "[DONE]" {
		flushed := sr.Flush()
		if len(flushed) > 0 {
			if hasNewline {
				flushed = append(flushed, '\n')
			}
			return append(flushed, line...)
		}
		return line
	}

	var data map[string]interface{}
	if err := json.Unmarshal(rawData, &data); err != nil {
		return line
	}

	content := sr.extractAndClearContent(data)

	if content == "" {
		flushed := sr.Flush()
		sr.r.RedactValue(data, sr.context)
		newRaw, _ := json.Marshal(data)
		out := append([]byte("data: "), newRaw...)
		if hasNewline {
			out = append(out, '\n')
		}
		if len(flushed) > 0 {
			if hasNewline {
				flushed = append(flushed, '\n')
			}
			return append(flushed, out...)
		}
		return out
	}

	sr.buffer += content
	if sr.templateEvent == nil {
		sr.templateEvent = data
	}

	redacted := sr.r.RedactContent(sr.buffer, sr.context)
	if redacted != sr.buffer {
		out := sr.emitTemplate(redacted)
		sr.buffer = ""
		sr.templateEvent = nil
		if hasNewline {
			out = append(out, '\n')
		}
		return out
	}

	if len(sr.buffer) > sr.maxLen {
		safeLen := len(sr.buffer) - sr.maxLen
		safeText := sr.buffer[:safeLen]
		sr.buffer = sr.buffer[safeLen:]
		out := sr.emitTemplate(safeText)
		// Use the latest data structure as the new template for accurate outer fields (e.g. usage stats if any)
		sr.templateEvent = data
		if hasNewline {
			out = append(out, '\n')
		}
		return out
	}

	return nil
}

func (sr *StreamRedactor) Flush() []byte {
	if sr.buffer == "" {
		return nil
	}
	redacted := sr.r.RedactContent(sr.buffer, sr.context)
	out := sr.emitTemplate(redacted)
	sr.buffer = ""
	sr.templateEvent = nil
	return out
}
