package detectors

import (
	"context"
	"strings"

	gitleaksconfig "github.com/zricethezav/gitleaks/v8/config"
	"github.com/spf13/viper"
)

// GitleaksDetector uses the native gitleaks config rules (including
// SecretGroup extraction) to find and permanently redact secrets.
// It uses only the gitleaks config package to avoid heavy transitive
// dependencies introduced by the detect package.
type GitleaksDetector struct {
	rules []gitleaksconfig.Rule
}

// NewGitleaksDetector initialises a GitleaksDetector with the built-in
// gitleaks default ruleset.
func NewGitleaksDetector() (*GitleaksDetector, error) {
	v := viper.New()
	v.SetConfigType("toml")
	if err := v.ReadConfig(strings.NewReader(gitleaksconfig.DefaultConfig)); err != nil {
		return nil, err
	}
	var vc gitleaksconfig.ViperConfig
	if err := v.Unmarshal(&vc); err != nil {
		return nil, err
	}
	cfg, err := vc.Translate()
	if err != nil {
		return nil, err
	}

	rules := make([]gitleaksconfig.Rule, 0, len(cfg.Rules))
	for _, r := range cfg.Rules {
		if r.Regex == nil {
			continue
		}
		rules = append(rules, r)
	}
	return &GitleaksDetector{rules: rules}, nil
}

// Type returns the detector identifier.
func (g *GitleaksDetector) Type() string {
	return "gitleaks"
}

// Redact runs the gitleaks rules against content and replaces each
// detected secret with the value returned by callback. When a rule
// defines a SecretGroup the capture group is used as the secret value;
// otherwise the full match is used.
func (g *GitleaksDetector) Redact(ctx context.Context, content string, callback RedactionCallback) string {
	for _, rule := range g.rules {
		r := rule // capture
		content = r.Regex.ReplaceAllStringFunc(content, func(match string) string {
			if match == "" {
				return match
			}
			secret := match
			if r.SecretGroup > 0 {
				submatches := r.Regex.FindStringSubmatch(match)
				if len(submatches) > r.SecretGroup {
					secret = submatches[r.SecretGroup]
				}
			}
			if secret == "" {
				return match
			}
			replacement := callback(secret, r.RuleID, r.Description)
			// If only a sub-group is the secret, splice it back into the match.
			if secret != match {
				return strings.Replace(match, secret, replacement, 1)
			}
			return replacement
		})
	}
	return content
}
