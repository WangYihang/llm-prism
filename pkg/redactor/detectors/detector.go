package detectors

import "context"

type RedactionCallback func(match, ruleID, description string) string

type Detector interface {
	Redact(ctx context.Context, content string, callback RedactionCallback) string
	Type() string
}

// Unredactor is implemented by detectors that support reversible substitution
// (e.g. IP pseudonymization). UnredactContent restores previously substituted
// values in a string.
type Unredactor interface {
	Unredact(content string) string
}
