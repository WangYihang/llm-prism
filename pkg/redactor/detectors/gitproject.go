package detectors

import (
	"context"
	"regexp"
	"strings"
	"sync"

	"github.com/go-faker/faker/v4"
)

// wellKnownGitHosts lists public open-source hosting domains that should not
// be pseudonymized.
var wellKnownGitHosts = map[string]bool{
	"github.com":      true,
	"gitlab.com":      true,
	"bitbucket.org":   true,
	"codeberg.org":    true,
	"sourceforge.net": true,
}

// GitProjectPseudonymizer maintains bidirectional mappings for Git hostnames
// and path segments (org/repo). All maps are keyed by the real value and
// produce stable fake replacements within a session.
type GitProjectPseudonymizer struct {
	mu             sync.RWMutex
	hostRealToFake map[string]string
	hostFakeToReal map[string]string
	segRealToFake  map[string]string
	segFakeToReal  map[string]string
}

func NewGitProjectPseudonymizer() *GitProjectPseudonymizer {
	return &GitProjectPseudonymizer{
		hostRealToFake: make(map[string]string),
		hostFakeToReal: make(map[string]string),
		segRealToFake:  make(map[string]string),
		segFakeToReal:  make(map[string]string),
	}
}

func (p *GitProjectPseudonymizer) getFakeHost(real string) string {
	p.mu.RLock()
	if v, ok := p.hostRealToFake[real]; ok {
		p.mu.RUnlock()
		return v
	}
	p.mu.RUnlock()

	p.mu.Lock()
	defer p.mu.Unlock()
	if v, ok := p.hostRealToFake[real]; ok {
		return v
	}
	fake := faker.DomainName()
	for _, exists := p.hostFakeToReal[fake]; exists; _, exists = p.hostFakeToReal[fake] {
		fake = faker.DomainName()
	}
	p.hostRealToFake[real] = fake
	p.hostFakeToReal[fake] = real
	return fake
}

func (p *GitProjectPseudonymizer) restoreHost(fake string) (string, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	v, ok := p.hostFakeToReal[fake]
	return v, ok
}

// getFakeSeg returns a stable fake for a single path segment (org or repo name).
// isOrg controls whether faker.Username or faker.Word is used for generation.
func (p *GitProjectPseudonymizer) getFakeSeg(real string, isOrg bool) string {
	p.mu.RLock()
	if v, ok := p.segRealToFake[real]; ok {
		p.mu.RUnlock()
		return v
	}
	p.mu.RUnlock()

	p.mu.Lock()
	defer p.mu.Unlock()
	if v, ok := p.segRealToFake[real]; ok {
		return v
	}
	var fake string
	if isOrg {
		fake = strings.ToLower(faker.Username())
	} else {
		fake = strings.ToLower(faker.Word())
	}
	for _, exists := p.segFakeToReal[fake]; exists; _, exists = p.segFakeToReal[fake] {
		if isOrg {
			fake = strings.ToLower(faker.Username())
		} else {
			fake = strings.ToLower(faker.Word())
		}
	}
	p.segRealToFake[real] = fake
	p.segFakeToReal[fake] = real
	return fake
}

func (p *GitProjectPseudonymizer) restoreSeg(fake string) (string, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	v, ok := p.segFakeToReal[fake]
	return v, ok
}

// GitProjectDetector detects self-hosted GitLab/Bitbucket repository URLs
// (HTTPS and SSH forms) and pseudonymizes the hostname and path segments.
type GitProjectDetector struct {
	httpsRe       *regexp.Regexp
	sshRe         *regexp.Regexp
	pseudonymizer *GitProjectPseudonymizer
}

func NewGitProjectDetector() *GitProjectDetector {
	return &GitProjectDetector{
		// Matches HTTPS git URLs:
		//   https://hostname[:port]/org/repo[.git]
		// Group 1: hostname[:port], Group 2: org, Group 3: repo (without .git)
		httpsRe: regexp.MustCompile(
			`(?i)\bhttps?://([a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?)+(?::\d+)?)` +
				`/([a-zA-Z0-9_.\-]+)/([a-zA-Z0-9_.\-]+?)(?:\.git)?(?:[/?#\s]|$)`,
		),
		// Matches SSH git URLs:
		//   git@hostname:org/repo[.git]
		// Group 1: hostname, Group 2: org, Group 3: repo (without .git)
		sshRe: regexp.MustCompile(
			`\bgit@([a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?)+)` +
				`:([a-zA-Z0-9_.\-]+)/([a-zA-Z0-9_.\-]+?)(?:\.git)?(?:[\s"']|$)`,
		),
		pseudonymizer: NewGitProjectPseudonymizer(),
	}
}

func (d *GitProjectDetector) Type() string { return "git-project" }

// hostOnly strips a port suffix from a host:port string to get just the hostname.
func hostOnly(hostport string) string {
	if idx := strings.LastIndex(hostport, ":"); idx != -1 {
		// Only strip if after the colon is numeric (port)
		candidate := hostport[idx+1:]
		allDigits := len(candidate) > 0
		for _, c := range candidate {
			if c < '0' || c > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			return hostport[:idx]
		}
	}
	return hostport
}

func (d *GitProjectDetector) redactMatch(match string, re *regexp.Regexp, ssh bool, callback RedactionCallback) string {
	return re.ReplaceAllStringFunc(match, func(m string) string {
		subs := re.FindStringSubmatch(m)
		if subs == nil {
			return m
		}
		hostport := subs[1]
		org := subs[2]
		repo := subs[3]

		// Determine the bare hostname (without port) for the allowlist check.
		bare := hostOnly(hostport)
		if wellKnownGitHosts[strings.ToLower(bare)] {
			return m
		}

		fakeHostport := d.pseudonymizer.getFakeHost(hostport)
		fakeOrg := d.pseudonymizer.getFakeSeg(org, true)
		fakeRepo := d.pseudonymizer.getFakeSeg(repo, false)

		// Preserve .git suffix if it was present in the original match.
		gitSuffix := ""
		// Check if the original had .git before the terminator.
		inner := m
		if idx := strings.Index(inner, hostport); idx != -1 {
			rest := inner[idx+len(hostport):]
			if ssh {
				// rest starts with ":org/repo[.git]..."
				rest = strings.TrimPrefix(rest, ":"+org+"/"+repo)
			} else {
				// rest starts with "/org/repo[.git]..."
				rest = strings.TrimPrefix(rest, "/"+org+"/"+repo)
			}
			if strings.HasPrefix(rest, ".git") {
				gitSuffix = ".git"
			}
		}

		var fake string
		if ssh {
			fake = "git@" + fakeHostport + ":" + fakeOrg + "/" + fakeRepo + gitSuffix
		} else {
			// Preserve scheme
			scheme := "https"
			if strings.HasPrefix(strings.ToLower(m), "http://") {
				scheme = "http"
			}
			fake = scheme + "://" + fakeHostport + "/" + fakeOrg + "/" + fakeRepo + gitSuffix
		}

		// Preserve trailing terminator character (space, newline, etc.)
		// The regex captured it implicitly via the trailing group — restore it.
		orig := m
		if len(orig) > 0 {
			last := orig[len(orig)-1]
			if last == ' ' || last == '\t' || last == '\n' || last == '\r' ||
				last == '"' || last == '\'' || last == '/' || last == '?' || last == '#' {
				fake += string(last)
			}
		}

		callback(orig, "git-project-url", "Git Repository URL")
		return fake
	})
}

// Redact replaces self-hosted git URLs with pseudonymized equivalents.
func (d *GitProjectDetector) Redact(ctx context.Context, content string, callback RedactionCallback) string {
	content = d.redactMatch(content, d.httpsRe, false, callback)
	content = d.redactMatch(content, d.sshRe, true, callback)
	return content
}

// Unredact restores previously pseudonymized git URLs to their originals.
func (d *GitProjectDetector) Unredact(content string) string {
	restore := func(m string, re *regexp.Regexp, ssh bool) string {
		return re.ReplaceAllStringFunc(m, func(orig string) string {
			subs := re.FindStringSubmatch(orig)
			if subs == nil {
				return orig
			}
			fakeHostport := subs[1]
			fakeOrg := subs[2]
			fakeRepo := subs[3]

			realHost, hostOk := d.pseudonymizer.restoreHost(fakeHostport)
			realOrg, orgOk := d.pseudonymizer.restoreSeg(fakeOrg)
			realRepo, repoOk := d.pseudonymizer.restoreSeg(fakeRepo)

			if !hostOk && !orgOk && !repoOk {
				return orig
			}
			if !hostOk {
				realHost = fakeHostport
			}
			if !orgOk {
				realOrg = fakeOrg
			}
			if !repoOk {
				realRepo = fakeRepo
			}

			// Preserve .git suffix
			gitSuffix := ""
			inner := orig
			if idx := strings.Index(inner, fakeHostport); idx != -1 {
				rest := inner[idx+len(fakeHostport):]
				if ssh {
					rest = strings.TrimPrefix(rest, ":"+fakeOrg+"/"+fakeRepo)
				} else {
					rest = strings.TrimPrefix(rest, "/"+fakeOrg+"/"+fakeRepo)
				}
				if strings.HasPrefix(rest, ".git") {
					gitSuffix = ".git"
				}
			}

			var real string
			if ssh {
				real = "git@" + realHost + ":" + realOrg + "/" + realRepo + gitSuffix
			} else {
				scheme := "https"
				if strings.HasPrefix(strings.ToLower(orig), "http://") {
					scheme = "http"
				}
				real = scheme + "://" + realHost + "/" + realOrg + "/" + realRepo + gitSuffix
			}

			// Preserve trailing terminator
			if len(orig) > 0 {
				last := orig[len(orig)-1]
				if last == ' ' || last == '\t' || last == '\n' || last == '\r' ||
					last == '"' || last == '\'' || last == '/' || last == '?' || last == '#' {
					real += string(last)
				}
			}

			return real
		})
	}

	content = restore(content, d.httpsRe, false)
	content = restore(content, d.sshRe, true)
	return content
}
