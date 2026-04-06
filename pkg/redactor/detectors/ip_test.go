package detectors

import (
	"context"
	"strings"
	"testing"
)

func TestIPDetectorIPv6DoubleColonNotInsideIdentifiers(t *testing.T) {
	d := NewIPDetector(false)
	ctx := context.Background()
	for _, in := range []string{
		"namespace::func",
		"foo::bar",
		"myns::dead:beef", // "::dead:beef" is IPv6-shaped inside a longer token
	} {
		t.Run(in, func(t *testing.T) {
			out := d.Redact(ctx, in, func(match, _, _ string) string {
				t.Fatalf("should not redact C++/Rust scope syntax, hit %q in %q", match, in)
				return ""
			})
			if out != in {
				t.Fatalf("expected unchanged %q, got %q", in, out)
			}
		})
	}
}

func TestIPDetectorIPv6BracketedAndSpacedStillRedacted(t *testing.T) {
	d := NewIPDetector(false)
	ctx := context.Background()
	for _, in := range []string{"[::1]", "addr ::1 tail", "\t::1\n"} {
		var hits int
		out := d.Redact(ctx, in, func(_, _, _ string) string {
			hits++
			return ""
		})
		if hits != 1 {
			t.Fatalf("%q: expected 1 redaction hit, got %d", in, hits)
		}
		if strings.Contains(out, "::1") {
			t.Fatalf("%q: expected ::1 replaced, got %q", in, out)
		}
	}
}

func TestIPDetectorIPv6BareDoubleColonNotMatched(t *testing.T) {
	d := NewIPDetector(false)
	ctx := context.Background()
	out := d.Redact(ctx, "addr is :: port 443", func(_, _, _ string) string {
		t.Fatal("callback should not run for bare ::")
		return ""
	})
	if out != "addr is :: port 443" {
		t.Fatalf("bare :: should be unchanged, got %q", out)
	}
}

func TestIPDetectorIPv6LoopbackMatched(t *testing.T) {
	d := NewIPDetector(false)
	var hits int
	out := d.Redact(context.Background(), "::1", func(_, _, _ string) string {
		hits++
		return ""
	})
	if hits != 1 {
		t.Fatalf("expected 1 hit, got %d", hits)
	}
	if out == "::1" {
		t.Fatal("::1 should be redacted")
	}
	if !strings.HasPrefix(out, "2001:db8:0:0:0:0:0:") {
		t.Fatalf("expected RFC 3849 expanded fake, got %q", out)
	}
}

func TestIPDetectorIPv4MappedIPv6BeforeIPv4(t *testing.T) {
	d := NewIPDetector(false)
	in := "::ffff:192.0.2.1"
	out := d.Redact(context.Background(), in, func(_, _, _ string) string { return "" })
	if strings.Contains(out, "192.0.2.1") {
		t.Fatalf("IPv4 tail should not remain after redact: %q", out)
	}
	restored := d.Unredact(out)
	if restored != in {
		t.Fatalf("round-trip: got %q want %q", restored, in)
	}
}

func TestIPDetectorRFC3849DocumentationUnchanged(t *testing.T) {
	d := NewIPDetector(false)
	in := "doc 2001:db8::1 and 2001:0db8::42"
	out := d.Redact(context.Background(), in, func(_, _, _ string) string {
		t.Fatal("RFC 3849 doc addresses should not be redacted")
		return ""
	})
	if out != in {
		t.Fatalf("expected unchanged, got %q", out)
	}
}

func TestIPPseudonymizerGetOrCreatePreservesCIDR(t *testing.T) {
	p := NewIPPseudonymizer()
	a := p.GetOrCreate("10.0.0.0/8", false)
	if !strings.Contains(a, "/8") {
		t.Fatalf("CIDR suffix missing: %q", a)
	}
}

func TestIPDetectorSkipsPrivateWhenConfigured(t *testing.T) {
	d := NewIPDetector(true)
	ctx := context.Background()
	in := "http://127.0.0.1:8080 and 192.168.0.10 and 10.0.0.1"
	var hits int
	out := d.Redact(ctx, in, func(_, _, _ string) string {
		hits++
		return ""
	})
	if hits != 0 {
		t.Fatalf("expected no redaction callbacks for private/loopback, got %d", hits)
	}
	if out != in {
		t.Fatalf("expected unchanged, got %q", out)
	}
}

func TestIPDetectorStillRedactsPublicWhenExcludingPrivate(t *testing.T) {
	d := NewIPDetector(true)
	in := "peer 203.0.113.44"
	out := d.Redact(context.Background(), in, func(_, _, _ string) string { return "" })
	if strings.Contains(out, "203.0.113.44") {
		t.Fatalf("public/doc-range IP should be pseudonymized, got %q", out)
	}
}
