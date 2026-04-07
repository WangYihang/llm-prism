package redactor

import (
	"regexp"
)

// Rule matches the Gitleaks official TOML structure
type Rule struct {
	ID            string         `toml:"id" json:"id"`
	Description   string         `toml:"description" json:"description"`
	Regex         *regexp.Regexp `toml:"-" json:"-"`
	RawRegex      string         `toml:"regex" json:"regex"`
	ReplaceEngine string         `toml:"replace_engine" json:"replace_engine"`
}

type Config struct {
	Rules     []Rule   `toml:"rules" json:"rules"`
	AllowList []string `toml:"allow_list" json:"allow_list"`
	// ExcludePrivateIPs skips pseudonymizing addresses where net.IP IsPrivate or IsLoopback
	// (RFC 1918 / unique local IPv6, 127.0.0.0/8, ::1, etc.). Nil means true (default),
	// so Docker Compose and local service URLs usually keep working without config.
	ExcludePrivateIPs *bool `toml:"exclude_private_ips" json:"exclude_private_ips"`
}

// ExcludePrivateIPsOrDefault returns whether local/private IPs should be left unchanged.
// The default is true when the config field is omitted.
func (c *Config) ExcludePrivateIPsOrDefault() bool {
	if c == nil || c.ExcludePrivateIPs == nil {
		return true
	}
	return *c.ExcludePrivateIPs
}

func (r *Rule) Compile() error {
	re, err := regexp.Compile(r.RawRegex)
	if err != nil {
		return err
	}
	r.Regex = re
	return nil
}
