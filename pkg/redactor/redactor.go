package redactor

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	gitleaksconfig "github.com/zricethezav/gitleaks/v8/config"

	"github.com/goccy/go-json"
	"github.com/pelletier/go-toml/v2"
	"github.com/rs/zerolog"
	"github.com/wangyihang/llm-prism/pkg/redactor/detectors"
	"github.com/wangyihang/llm-prism/pkg/utils"
	"github.com/wangyihang/llm-prism/pkg/utils/ctxkeys"
)

const (
	RedactedPlaceholder = "REDACTED_SECRET"
	eventChannelSize    = 1024
)

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
			ID:          rule.ID,
			Description: rule.Description,
			Regex:       rule.Regex,
		})
	}

	detectorsList := []detectors.Detector{
		detectors.NewRegexDetector(regexRules),
		detectors.NewDeepSeekDetector(),
		// Default threshold 4.3 to skip hex-only strings (max entropy 4.0)
		detectors.NewEntropyDetector(4.3, 32),
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
	close(r.eventCh)
	<-r.done
}

// RedactContent redacts a single string content and sends detections
// to the background processor asynchronously.
func (r *Redactor) RedactContent(ctx context.Context, content string) string {
	for _, detector := range r.detectors {
		content = detector.Redact(content, func(match, ruleID, description string) string {
			// Check global allow list (must stay synchronous — affects return value)
			for _, allow := range r.config.AllowList {
				if match == allow {
					return match
				}
			}

			// Send detection event to background processor non-blocking
			select {
			case r.eventCh <- detectionEvent{
				DetectorType: detector.Type(),
				RuleID:       ruleID,
				Description:  description,
				Match:        match,
				RequestID:    ctxkeys.GetString(ctx, ctxkeys.RequestID),
				Source:       ctxkeys.GetString(ctx, ctxkeys.Source),
				Host:         ctxkeys.GetString(ctx, ctxkeys.Host),
				Path:         ctxkeys.GetString(ctx, ctxkeys.Path),
				Method:       ctxkeys.GetString(ctx, ctxkeys.Method),
			}:
			default:
				// Channel is full, effectively dropping the event metric to prioritize proxy stability
				r.logs.Warn().Msg("Detection event channel full, dropping detection metric.")
			}

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

// Removed Summary func, now handled in summary.go

// RedactValue recursively traverses a JSON-compatible structure and redacts all string values
func (r *Redactor) RedactValue(ctx context.Context, v interface{}) interface{} {
	switch val := v.(type) {
	case string:
		return r.RedactContent(ctx, val)
	case map[string]interface{}:
		for k, v := range val {
			val[k] = r.RedactValue(ctx, v)
		}
		return val
	case []interface{}:
		for i, v := range val {
			val[i] = r.RedactValue(ctx, v)
		}
		return val
	default:
		return v
	}
}

// RedactRequest redacts all string values in a JSON request body
func (r *Redactor) RedactRequest(ctx context.Context, body []byte) ([]byte, error) {
	if !json.Valid(body) {
		return body, nil
	}

	var data interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return body, err
	}

	redactedData := r.RedactValue(ctx, data)
	return json.Marshal(redactedData)
}

// StreamRedactor implements a sliding window redactor for SSE streams
