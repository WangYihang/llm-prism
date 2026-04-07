package detectors

import (
	"context"
	"regexp"
	"strings"
	"testing"
)

// nopCallback is a no-op RedactionCallback that returns a placeholder.
func nopCallback(match, _, _ string) string { return "[REDACTED]" }

// --- ReplaceEnginePseudonymizer ---

func TestReplaceEnginePseudonymizerStableMapping(t *testing.T) {
	for _, engine := range []string{"company", "name", "email"} {
		p := NewReplaceEnginePseudonymizer(engine)
		first := p.GetOrCreate("Acme Corp")
		second := p.GetOrCreate("Acme Corp")
		if first != second {
			t.Errorf("engine=%s: expected stable mapping, got %q then %q", engine, first, second)
		}
	}
}

func TestReplaceEnginePseudonymizerDistinctInputsDistinctFakes(t *testing.T) {
	for _, engine := range []string{"company", "name", "email"} {
		p := NewReplaceEnginePseudonymizer(engine)
		a := p.GetOrCreate("Alice")
		b := p.GetOrCreate("Bob")
		if a == b {
			t.Errorf("engine=%s: different inputs produced identical fake %q", engine, a)
		}
	}
}

func TestReplaceEnginePseudonymizerRestore(t *testing.T) {
	for _, engine := range []string{"company", "name", "email"} {
		p := NewReplaceEnginePseudonymizer(engine)
		fake := p.GetOrCreate("Acme Corp")
		real, ok := p.Restore(fake)
		if !ok {
			t.Errorf("engine=%s: Restore returned ok=false", engine)
		}
		if real != "Acme Corp" {
			t.Errorf("engine=%s: Restore got %q, want %q", engine, real, "Acme Corp")
		}
	}
}

func TestReplaceEnginePseudonymizerRestoreUnknownReturnsFalse(t *testing.T) {
	p := NewReplaceEnginePseudonymizer("name")
	_, ok := p.Restore("NoSuchFake Person")
	if ok {
		t.Error("expected ok=false for unknown fake value")
	}
}

func TestReplaceEngineCompanyNotEmpty(t *testing.T) {
	p := NewReplaceEnginePseudonymizer("company")
	fake := p.GetOrCreate("Acme Corp")
	if strings.TrimSpace(fake) == "" {
		t.Error("company engine returned empty string")
	}
}

func TestReplaceEngineEmailContainsAt(t *testing.T) {
	p := NewReplaceEnginePseudonymizer("email")
	fake := p.GetOrCreate("john@acme.com")
	if !strings.Contains(fake, "@") {
		t.Errorf("email engine returned non-email-like value: %q", fake)
	}
}

// --- RegexDetector with replace_engine ---

func makeRule(id, pattern, engine string) RegexRule {
	return RegexRule{
		ID:            id,
		Description:   id,
		Regex:         regexp.MustCompile(pattern),
		ReplaceEngine: engine,
	}
}

func TestRegexDetectorReplaceEngineCompanyRedactsMatch(t *testing.T) {
	d := NewRegexDetector([]RegexRule{makeRule("co", `(?i)\bacme corp\b`, "company")})
	out := d.Redact(context.Background(), "We work at Acme Corp today.", nopCallback)
	if strings.Contains(out, "Acme Corp") || strings.Contains(out, "acme corp") {
		t.Errorf("original value still present: %q", out)
	}
}

func TestRegexDetectorReplaceEngineNameRedactsMatch(t *testing.T) {
	d := NewRegexDetector([]RegexRule{makeRule("person", `(?i)\bjohn doe\b`, "name")})
	out := d.Redact(context.Background(), "Contact John Doe.", nopCallback)
	if strings.Contains(out, "John Doe") || strings.Contains(out, "john doe") {
		t.Errorf("original value still present: %q", out)
	}
}

func TestRegexDetectorReplaceEngineEmailRedactsMatch(t *testing.T) {
	d := NewRegexDetector([]RegexRule{makeRule("em", `john@acme\.com`, "email")})
	out := d.Redact(context.Background(), "Email john@acme.com here.", nopCallback)
	if strings.Contains(out, "john@acme.com") {
		t.Errorf("original value still present: %q", out)
	}
}

func TestRegexDetectorReplaceEngineStableWithinSession(t *testing.T) {
	d := NewRegexDetector([]RegexRule{makeRule("co", `(?i)\bacme corp\b`, "company")})
	ctx := context.Background()
	out1 := d.Redact(ctx, "Acme Corp", nopCallback)
	out2 := d.Redact(ctx, "Acme Corp", nopCallback)
	if out1 != out2 {
		t.Errorf("unstable mapping: first=%q second=%q", out1, out2)
	}
}

func TestRegexDetectorReplaceEngineCallbackInvokedForLogging(t *testing.T) {
	d := NewRegexDetector([]RegexRule{makeRule("co", `(?i)\bacme corp\b`, "company")})
	var hits int
	d.Redact(context.Background(), "Acme Corp is great.", func(match, ruleID, _ string) string {
		hits++
		if match == "" {
			t.Error("callback received empty match")
		}
		if ruleID != "co" {
			t.Errorf("unexpected ruleID %q", ruleID)
		}
		return "[REDACTED]"
	})
	if hits != 1 {
		t.Errorf("expected 1 callback, got %d", hits)
	}
}

func TestRegexDetectorReplaceEngineUnredact(t *testing.T) {
	d := NewRegexDetector([]RegexRule{makeRule("co", `(?i)\bacme corp\b`, "company")})
	ctx := context.Background()
	redacted := d.Redact(ctx, "Work at Acme Corp.", nopCallback)
	restored := d.Unredact(redacted)
	if !strings.Contains(restored, "Acme Corp") {
		t.Errorf("Unredact failed: got %q", restored)
	}
}

func TestRegexDetectorNoReplaceEngineUsesCallback(t *testing.T) {
	d := NewRegexDetector([]RegexRule{makeRule("secret", `SECRET_KEY`, "")})
	out := d.Redact(context.Background(), "SECRET_KEY found", func(match, _, _ string) string {
		return "[GONE]"
	})
	if strings.Contains(out, "SECRET_KEY") {
		t.Errorf("expected callback replacement, got: %q", out)
	}
	if !strings.Contains(out, "[GONE]") {
		t.Errorf("expected callback value [GONE] in output, got: %q", out)
	}
}

func TestRegexDetectorReplaceEngineRoundTripMultipleValues(t *testing.T) {
	d := NewRegexDetector([]RegexRule{makeRule("co", `(?i)\bacme corp\b|\bfoo inc\b`, "company")})
	ctx := context.Background()
	in := "Acme Corp and Foo Inc are partners."
	redacted := d.Redact(ctx, in, nopCallback)
	if strings.Contains(redacted, "Acme Corp") || strings.Contains(redacted, "Foo Inc") {
		t.Errorf("original values present after redact: %q", redacted)
	}
	restored := d.Unredact(redacted)
	if !strings.Contains(restored, "Acme Corp") || !strings.Contains(restored, "Foo Inc") {
		t.Errorf("round-trip failed: got %q", restored)
	}
}

// URL-shaped and log-shaped payloads: company regex must not break on slashes,
// hyphens, or JSON delimiters, and Unredact (substring replace) must restore
// the real name inside the original URL/text.
func TestRegexDetectorReplaceEngineCompanyInURLPathRoundTrip(t *testing.T) {
	d := NewRegexDetector([]RegexRule{makeRule("co", `(?i)\bacme corp\b`, "company")})
	ctx := context.Background()
	in := `https://confluence.internal.example/display/Acme Corp/Runbook`
	redacted := d.Redact(ctx, in, nopCallback)
	if strings.Contains(redacted, "Acme Corp") || strings.Contains(redacted, "acme corp") {
		t.Fatalf("expected redaction, got %q", redacted)
	}
	restored := d.Unredact(redacted)
	if restored != in {
		t.Fatalf("round-trip: got %q want %q", restored, in)
	}
}

func TestRegexDetectorReplaceEngineCompanyHyphenWrappedInURLLikeLineRoundTrip(t *testing.T) {
	d := NewRegexDetector([]RegexRule{makeRule("co", `(?i)\bacme corp\b`, "company")})
	ctx := context.Background()
	in := `GET https://jira.example/browse/prefix-Acme Corp-suffix HTTP/1.1`
	redacted := d.Redact(ctx, in, nopCallback)
	restored := d.Unredact(redacted)
	if restored != in {
		t.Fatalf("round-trip: got %q want %q", restored, in)
	}
}

func TestRegexDetectorReplaceEngineCompanyInJSONURLValueRoundTrip(t *testing.T) {
	d := NewRegexDetector([]RegexRule{makeRule("co", `(?i)\bacme corp\b`, "company")})
	ctx := context.Background()
	in := `{"wiki":"https://wiki.internal/space/Acme Corp/home","ok":true}`
	redacted := d.Redact(ctx, in, nopCallback)
	restored := d.Unredact(redacted)
	if restored != in {
		t.Fatalf("round-trip: got %q want %q", restored, in)
	}
}

// Regression: Unredact must replace longer fakes before shorter ones. Map iteration
// order is random; without a deterministic order, restoring "ab" can corrupt a
// neighboring fake "abc" in paths, URLs, or tool/edit output that contains both.
func TestRegexDetectorUnredactLongestFakeFirst(t *testing.T) {
	d := NewRegexDetector([]RegexRule{makeRule("co", `_nomatch_`, "company")})
	ps := d.pseudonymizers["company"]
	ps.mu.Lock()
	ps.fakeToReal["ab"] = "REAL_SHORT"
	ps.fakeToReal["abc"] = "REAL_LONG"
	ps.realToFake["REAL_SHORT"] = "ab"
	ps.realToFake["REAL_LONG"] = "abc"
	ps.mu.Unlock()

	in := `file:///tmp/ab/abc/final`
	want := `file:///tmp/REAL_SHORT/REAL_LONG/final`
	if got := d.Unredact(in); got != want {
		t.Fatalf("Unredact: got %q want %q", got, want)
	}
}

func TestRegexDetectorSharedSessionMapPerReplaceEngine(t *testing.T) {
	d := NewRegexDetector([]RegexRule{
		makeRule("vendor-rule", `(?i)\bacme corp\b`, "company"),
		makeRule("contract-rule", `(?i)\bfoo inc\b`, "company"),
	})
	if len(d.pseudonymizers) != 1 {
		t.Fatalf("expected one session pseudonymizer for all company rules, got %d", len(d.pseudonymizers))
	}
	ps := d.pseudonymizers["company"]
	if ps == nil {
		t.Fatal("missing company pseudonymizer")
	}

	fakeAcme := ps.GetOrCreate("Acme Corp")
	if again := ps.GetOrCreate("Acme Corp"); again != fakeAcme {
		t.Fatalf("same real must reuse session fake: got %q want %q", again, fakeAcme)
	}
	if fakeFoo := ps.GetOrCreate("Foo Inc"); fakeFoo == fakeAcme {
		t.Fatal("different companies should not collide on the same fake")
	}

	ctx := context.Background()
	in := "Acme Corp licenses to Foo Inc."
	redacted := d.Redact(ctx, in, nopCallback)
	if strings.Contains(redacted, "Acme Corp") || strings.Contains(redacted, "Foo Inc") {
		t.Fatalf("expected both redacted: %q", redacted)
	}

	restored := d.Unredact(redacted)
	if restored != in {
		t.Fatalf("round-trip: got %q want %q", restored, in)
	}
}
