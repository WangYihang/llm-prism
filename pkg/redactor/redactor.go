package redactor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/pelletier/go-toml/v2"
	"github.com/rs/zerolog"
	"github.com/wangyihang/llm-prism/pkg/utils"
	"github.com/wangyihang/llm-prism/pkg/utils/ctxkeys"
)

const (
	RedactedPlaceholder = "REDACTED_SECRET"
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

	// Add DeepSeek specific rule as it is often missing from Gitleaks
	deepseekRegex := regexp.MustCompile(`sk-[a-f0-9]{32}`)
	config.Rules = append(config.Rules, Rule{
		ID:          "deepseek-api-key",
		Description: "DeepSeek API Key",
		Regex:       deepseekRegex,
		RawRegex:    deepseekRegex.String(),
	})

	detectors := []Detector{
		NewRegexDetector(config.Rules),
		// Default threshold 4.3 to skip hex-only strings (max entropy 4.0)
		NewEntropyDetector(4.3, 32),
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
func (r *Redactor) RedactContent(ctx context.Context, content string) string {
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

			if reqID := ctxkeys.GetString(ctx, ctxkeys.RequestID); reqID != "" {
				evt.Str("request_id", reqID)
			}
			if source := ctxkeys.GetString(ctx, ctxkeys.Source); source != "" {
				evt.Str("source", source)
			}
			if host := ctxkeys.GetString(ctx, ctxkeys.Host); host != "" {
				evt.Str("host", host)
			}
			if path := ctxkeys.GetString(ctx, ctxkeys.Path); path != "" {
				evt.Str("path", path)
			}
			if method := ctxkeys.GetString(ctx, ctxkeys.Method); method != "" {
				evt.Str("method", method)
			}

			evt.Msg("secret detected")

			// Update stats
			actual, _ := r.stats.LoadOrStore(detector.Type(), new(int64))
			atomic.AddInt64(actual.(*int64), 1)

			// Record details (de-duplicated by RequestID, DetectorType, RuleID, MaskedContent)
			r.mu.Lock()
			found := false
			reqID := ctxkeys.GetString(ctx, ctxkeys.RequestID)
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
