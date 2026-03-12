package detectors

import "context"

type RedactionCallback func(match, ruleID, description string) string

type Detector interface {
	Redact(ctx context.Context, content string, callback RedactionCallback) string
	Type() string
}
