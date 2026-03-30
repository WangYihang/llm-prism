package detectors

import (
	"context"
	"fmt"
	"regexp"
	"sync"
)

// IPPseudonymizer maintains a bidirectional mapping between real and fake IPs.
// Fake IPs are drawn from RFC 5737 TEST-NET ranges (192.0.2.0/24,
// 198.51.100.0/24, 203.0.113.0/24) which are reserved for documentation and
// will never appear in real traffic.
type IPPseudonymizer struct {
	mu         sync.RWMutex
	realToFake map[string]string
	fakeToReal map[string]string
	ipv4Count  int
	ipv6Count  int
}

// fakeIPv4Pools lists the three RFC 5737 TEST-NET ranges used for substitution.
var fakeIPv4Pools = []string{
	"192.0.2.%d",    // TEST-NET-1
	"198.51.100.%d", // TEST-NET-2
	"203.0.113.%d",  // TEST-NET-3
}

func NewIPPseudonymizer() *IPPseudonymizer {
	return &IPPseudonymizer{
		realToFake: make(map[string]string),
		fakeToReal: make(map[string]string),
	}
}

func (p *IPPseudonymizer) nextFakeIPv4() string {
	p.ipv4Count++
	pool := (p.ipv4Count - 1) / 254
	host := (p.ipv4Count-1)%254 + 1
	if pool >= len(fakeIPv4Pools) {
		pool = pool % len(fakeIPv4Pools)
	}
	return fmt.Sprintf(fakeIPv4Pools[pool], host)
}

func (p *IPPseudonymizer) nextFakeIPv6() string {
	p.ipv6Count++
	// RFC 3849 documentation range: 2001:db8::/32
	return fmt.Sprintf("2001:db8::%x", p.ipv6Count)
}

// GetOrCreate returns the fake IP for a given real IP, creating one if needed.
// The token may include a CIDR suffix (e.g. "10.0.0.0/8"); the suffix is
// preserved on the fake side.
func (p *IPPseudonymizer) GetOrCreate(realToken string, isIPv6 bool) string {
	p.mu.RLock()
	if fake, ok := p.realToFake[realToken]; ok {
		p.mu.RUnlock()
		return fake
	}
	p.mu.RUnlock()

	p.mu.Lock()
	defer p.mu.Unlock()
	if fake, ok := p.realToFake[realToken]; ok {
		return fake
	}

	var fakeBase string
	if isIPv6 {
		fakeBase = p.nextFakeIPv6()
	} else {
		fakeBase = p.nextFakeIPv4()
	}

	// Preserve CIDR prefix if present
	cidr := ""
	ipPart := realToken
	if idx := cidrSuffixIndex(realToken); idx != -1 {
		cidr = realToken[idx:]
		ipPart = realToken[:idx]
		_ = ipPart
	}
	fake := fakeBase + cidr

	p.realToFake[realToken] = fake
	p.fakeToReal[fake] = realToken
	return fake
}

// Restore returns the real IP for a given fake IP, if known.
func (p *IPPseudonymizer) Restore(fakeToken string) (string, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	real, ok := p.fakeToReal[fakeToken]
	return real, ok
}

// cidrSuffixIndex returns the index of the '/' in a CIDR string, or -1.
func cidrSuffixIndex(s string) int {
	for i, c := range s {
		if c == '/' {
			return i
		}
	}
	return -1
}

type IPDetector struct {
	ipv4          *regexp.Regexp
	ipv6          *regexp.Regexp
	pseudonymizer *IPPseudonymizer
}

func NewIPDetector() *IPDetector {
	return &IPDetector{
		// Matches IPv4 addresses with optional CIDR suffix (/0–/32).
		ipv4: regexp.MustCompile(
			`\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\.){3}` +
				`(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)` +
				`(?:/(?:3[0-2]|[12]?\d))?\b`,
		),
		// Matches IPv6 in full and compressed forms (RFC 4291).
		ipv6: regexp.MustCompile(`(?i)(?:` +
			`[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){7}` + // full 8 groups
			`|(?:[0-9a-f]{1,4}:){1,7}:` + // trailing ::
			`|::(?:[0-9a-f]{1,4}:){0,6}[0-9a-f]{1,4}` + // leading ::
			`|(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}` + // one compressed group
			`|(?:[0-9a-f]{1,4}:){1,5}(?::[0-9a-f]{1,4}){1,2}` +
			`|(?:[0-9a-f]{1,4}:){1,4}(?::[0-9a-f]{1,4}){1,3}` +
			`|(?:[0-9a-f]{1,4}:){1,3}(?::[0-9a-f]{1,4}){1,4}` +
			`|(?:[0-9a-f]{1,4}:){1,2}(?::[0-9a-f]{1,4}){1,5}` +
			`|[0-9a-f]{1,4}:(?::[0-9a-f]{1,4}){1,6}` +
			`|::` + // loopback / unspecified
			`)`),
		pseudonymizer: NewIPPseudonymizer(),
	}
}

func (d *IPDetector) Type() string { return "ip" }

// Redact replaces each detected IP with a stable fake IP from the TEST-NET
// ranges and invokes callback for logging/stats (passing the real IP).
func (d *IPDetector) Redact(ctx context.Context, content string, callback RedactionCallback) string {
	content = d.ipv4.ReplaceAllStringFunc(content, func(match string) string {
		fake := d.pseudonymizer.GetOrCreate(match, false)
		callback(match, "ipv4-address", "IPv4 Address")
		return fake
	})
	content = d.ipv6.ReplaceAllStringFunc(content, func(match string) string {
		fake := d.pseudonymizer.GetOrCreate(match, true)
		callback(match, "ipv6-address", "IPv6 Address")
		return fake
	})
	return content
}

// Unredact replaces any fake IPs in content with the original real IPs.
func (d *IPDetector) Unredact(content string) string {
	content = d.ipv4.ReplaceAllStringFunc(content, func(match string) string {
		if real, ok := d.pseudonymizer.Restore(match); ok {
			return real
		}
		return match
	})
	content = d.ipv6.ReplaceAllStringFunc(content, func(match string) string {
		if real, ok := d.pseudonymizer.Restore(match); ok {
			return real
		}
		return match
	})
	return content
}
