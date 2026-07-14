package cidr

import (
	"net"
	"strings"
)

type Rule struct {
	Domain string
	Nets   []*net.IPNet
}

func (r Rule) Allows(ip net.IP) bool {
	for _, n := range r.Nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

type Matcher struct {
	exact    map[string]Rule
	wildcard map[string]Rule
}

func NewMatcher(rules []Rule) *Matcher {
	m := &Matcher{
		exact:    make(map[string]Rule),
		wildcard: make(map[string]Rule),
	}
	for _, r := range rules {
		domain := NormalizeDomain(r.Domain)
		if IsWildcard(domain) {
			m.wildcard[strings.TrimPrefix(domain, "*.")] = r
		} else {
			m.exact[domain] = r
		}
	}
	return m
}

func (m *Matcher) Match(hostname string) (Rule, bool) {
	h := NormalizeDomain(hostname)
	if r, ok := m.exact[h]; ok {
		return r, true
	}
	labels := strings.Split(h, ".")
	for i := 1; i < len(labels); i++ {
		base := strings.Join(labels[i:], ".")
		if r, ok := m.wildcard[base]; ok {
			return r, true
		}
	}
	return Rule{}, false
}

func NormalizeDomain(domain string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
}

func IsWildcard(domain string) bool {
	return strings.HasPrefix(domain, "*.")
}

func WildcardBase(domain string) (string, bool) {
	d := NormalizeDomain(domain)
	if !IsWildcard(d) {
		return "", false
	}
	return strings.TrimPrefix(d, "*."), true
}
