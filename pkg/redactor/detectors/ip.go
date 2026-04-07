package detectors

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
)

// ipv4AddrCore matches a dotted IPv4 address (no CIDR). Used by IPv4 and
// IPv4-embedded-in-IPv6 patterns so they stay in sync.
const ipv4AddrCore = `(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)`

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
	// RFC 3849 documentation range (2001:db8::/32), fully expanded so fakes never
	// contain a "::…" substring that the IPv6 regex would match inside Unredact.
	return fmt.Sprintf("2001:db8:0:0:0:0:0:%x", p.ipv6Count+1)
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

	cidr := ""
	if idx := cidrSuffixIndex(realToken); idx != -1 {
		cidr = realToken[idx:]
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

// ipv6MatchHasTokenBoundaries rejects IPv6-shaped substrings embedded in identifiers
// (for example "namespace::func" → "::f", or "foo::bar" → "::ba") while keeping
// real addresses delimited by punctuation, brackets, or whitespace.
func ipv6MatchHasTokenBoundaries(s string, start, end int) bool {
	if start > 0 {
		c := s[start-1]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			return false
		}
	}
	if end < len(s) {
		c := s[end]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			return false
		}
	}
	return true
}

// isRFC3849DocumentationIPv6 reports whether addr is in 2001:db8::/32 (RFC 3849).
func isRFC3849DocumentationIPv6(match string) bool {
	addr := match
	if i := cidrSuffixIndex(match); i >= 0 {
		addr = match[:i]
	}
	ip := net.ParseIP(addr)
	if ip == nil || ip.To4() != nil {
		return false
	}
	ip = ip.To16()
	return len(ip) == net.IPv6len && ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0x0d && ip[3] == 0xb8
}

type IPDetector struct {
	ipv4                   *regexp.Regexp
	ipv6                   *regexp.Regexp
	pseudonymizer          *IPPseudonymizer
	excludePrivateLoopback bool
}

// NewIPDetector builds an IP pseudonymizer. When excludePrivateLoopback is true,
// addresses for which net.IP reports IsPrivate or IsLoopback are not replaced
// (useful for Docker Compose and other local routing).
func NewIPDetector(excludePrivateLoopback bool) *IPDetector {
	ipv4 := regexp.MustCompile(
		`\b` + ipv4AddrCore + `(?:/(?:3[0-2]|[12]?\d))?\b`,
	)
	// IPv6 full/compressed (RFC 4291), plus IPv4-mapped (::ffff:x.x.x.x) and
	// IPv4-compatible tails (::x.x.x.x). Does not match a bare "::".
	ipv6 := regexp.MustCompile(`(?i)(?:` +
		`(?:::ffff:)` + ipv4AddrCore +
		`|::` + ipv4AddrCore +
		`|[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){7}` +
		`|(?:[0-9a-f]{1,4}:){1,7}:` +
		`|::(?:[0-9a-f]{1,4}:){0,6}[0-9a-f]{1,4}` +
		`|(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}` +
		`|(?:[0-9a-f]{1,4}:){1,5}(?::[0-9a-f]{1,4}){1,2}` +
		`|(?:[0-9a-f]{1,4}:){1,4}(?::[0-9a-f]{1,4}){1,3}` +
		`|(?:[0-9a-f]{1,4}:){1,3}(?::[0-9a-f]{1,4}){1,4}` +
		`|(?:[0-9a-f]{1,4}:){1,2}(?::[0-9a-f]{1,4}){1,5}` +
		`|[0-9a-f]{1,4}:(?::[0-9a-f]{1,4}){1,6}` +
		`)`,
	)
	return &IPDetector{
		ipv4:                   ipv4,
		ipv6:                   ipv6,
		pseudonymizer:          NewIPPseudonymizer(),
		excludePrivateLoopback: excludePrivateLoopback,
	}
}

// ipMatchIsPrivateOrLoopback reports whether match is an IP (optional CIDR) that
// should be left unchanged when excludePrivateLoopback is enabled.
func ipMatchIsPrivateOrLoopback(match string) bool {
	addr := match
	if i := cidrSuffixIndex(match); i >= 0 {
		addr = match[:i]
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback()
}

func (d *IPDetector) Type() string { return "ip" }

// Redact replaces each detected IP with a stable fake IP from the TEST-NET
// ranges and invokes callback for logging/stats (passing the real IP).
func (d *IPDetector) Redact(ctx context.Context, content string, callback RedactionCallback) string {
	// IPv6 first so IPv4 substrings inside IPv4-mapped addresses are not torn apart.
	content = d.redactIPv6WithBoundaries(content, callback)
	content = d.ipv4.ReplaceAllStringFunc(content, func(match string) string {
		if d.excludePrivateLoopback && ipMatchIsPrivateOrLoopback(match) {
			return match
		}
		fake := d.pseudonymizer.GetOrCreate(match, false)
		callback(match, "ipv4-address", "IPv4 Address")
		return fake
	})
	return content
}

func (d *IPDetector) redactIPv6WithBoundaries(content string, callback RedactionCallback) string {
	indices := d.ipv6.FindAllStringIndex(content, -1)
	if len(indices) == 0 {
		return content
	}
	var b strings.Builder
	b.Grow(len(content) + 64)
	last := 0
	for _, loc := range indices {
		start, end := loc[0], loc[1]
		b.WriteString(content[last:start])
		match := content[start:end]
		if !ipv6MatchHasTokenBoundaries(content, start, end) {
			b.WriteString(match)
			last = end
			continue
		}
		if isRFC3849DocumentationIPv6(match) {
			b.WriteString(match)
			last = end
			continue
		}
		if d.excludePrivateLoopback && ipMatchIsPrivateOrLoopback(match) {
			b.WriteString(match)
			last = end
			continue
		}
		fake := d.pseudonymizer.GetOrCreate(match, true)
		callback(match, "ipv6-address", "IPv6 Address")
		b.WriteString(fake)
		last = end
	}
	b.WriteString(content[last:])
	return b.String()
}

// Unredact replaces any fake IPs in content with the original real IPs.
func (d *IPDetector) Unredact(content string) string {
	content = d.unredactIPv6WithBoundaries(content)
	content = d.ipv4.ReplaceAllStringFunc(content, func(match string) string {
		if real, ok := d.pseudonymizer.Restore(match); ok {
			return real
		}
		return match
	})
	return content
}

func (d *IPDetector) unredactIPv6WithBoundaries(content string) string {
	indices := d.ipv6.FindAllStringIndex(content, -1)
	if len(indices) == 0 {
		return content
	}
	var b strings.Builder
	b.Grow(len(content))
	last := 0
	for _, loc := range indices {
		start, end := loc[0], loc[1]
		b.WriteString(content[last:start])
		key := content[start:end]
		if !ipv6MatchHasTokenBoundaries(content, start, end) {
			b.WriteString(key)
			last = end
			continue
		}
		if real, ok := d.pseudonymizer.Restore(key); ok {
			b.WriteString(real)
		} else {
			b.WriteString(key)
		}
		last = end
	}
	b.WriteString(content[last:])
	return b.String()
}
