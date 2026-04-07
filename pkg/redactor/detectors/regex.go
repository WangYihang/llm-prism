package detectors

import (
	"context"
	"regexp"
	"sort"
	"strings"
)

type RegexRule struct {
	ID            string
	Description   string
	Regex         *regexp.Regexp
	ReplaceEngine string
}

type RegexDetector struct {
	rules          []RegexRule
	pseudonymizers map[string]*ReplaceEnginePseudonymizer // keyed by replace_engine (e.g. "company")
}

func NewRegexDetector(rules []RegexRule) *RegexDetector {
	// One pseudonymizer per replace_engine for the detector lifetime (session):
	// the same real string always maps to the same fake across all rules using
	// that engine, and Unredact sees a single fake→real table per engine.
	pseudonymizers := make(map[string]*ReplaceEnginePseudonymizer)
	for _, rule := range rules {
		if rule.ReplaceEngine == "" {
			continue
		}
		if _, exists := pseudonymizers[rule.ReplaceEngine]; !exists {
			pseudonymizers[rule.ReplaceEngine] = NewReplaceEnginePseudonymizer(rule.ReplaceEngine)
		}
	}
	return &RegexDetector{rules: rules, pseudonymizers: pseudonymizers}
}

func (d *RegexDetector) Type() string {
	return "regex"
}

func (d *RegexDetector) Redact(ctx context.Context, content string, callback RedactionCallback) string {
	for _, rule := range d.rules {
		rule := rule // capture for closure
		if rule.ReplaceEngine != "" {
			ps := d.pseudonymizers[rule.ReplaceEngine]
			content = rule.Regex.ReplaceAllStringFunc(content, func(match string) string {
				if len(match) == 0 {
					return match
				}
				fake := ps.GetOrCreate(match)
				callback(match, rule.ID, rule.Description)
				return fake
			})
		} else {
			content = rule.Regex.ReplaceAllStringFunc(content, func(match string) string {
				if len(match) == 0 {
					return match
				}
				return callback(match, rule.ID, rule.Description)
			})
		}
	}
	return content
}

// Unredact restores pseudonymized values produced by replace_engine rules.
func (d *RegexDetector) Unredact(content string) string {
	if len(d.pseudonymizers) == 0 {
		return content
	}
	engines := make([]string, 0, len(d.pseudonymizers))
	for e := range d.pseudonymizers {
		engines = append(engines, e)
	}
	sort.Strings(engines)
	for _, e := range engines {
		ps := d.pseudonymizers[e]
		ps.mu.RLock()
		pairs := make([]struct {
			fake, real string
		}, 0, len(ps.fakeToReal))
		for fake, real := range ps.fakeToReal {
			pairs = append(pairs, struct {
				fake, real string
			}{fake, real})
		}
		ps.mu.RUnlock()
		// Longest fake first so a shorter token cannot truncate a longer fake
		// (e.g. paths or URLs where one pseudonym is a substring of another).
		sort.Slice(pairs, func(i, j int) bool {
			return len(pairs[i].fake) > len(pairs[j].fake)
		})
		for _, p := range pairs {
			content = strings.ReplaceAll(content, p.fake, p.real)
		}
	}
	return content
}
