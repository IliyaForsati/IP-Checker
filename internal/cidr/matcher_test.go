package cidr

import (
	"net"
	"testing"
)

func mustNet(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("ParseCIDR(%q): %v", s, err)
	}
	return n
}

func TestMatcherExact(t *testing.T) {
	m := NewMatcher([]Rule{
		{Domain: "claude.ai", Nets: []*net.IPNet{mustNet(t, "104.16.0.0/13")}},
	})

	if _, ok := m.Match("claude.ai"); !ok {
		t.Fatalf("expected exact match for claude.ai")
	}
	if _, ok := m.Match("Claude.AI"); !ok {
		t.Fatalf("expected case-insensitive match")
	}
	if _, ok := m.Match("claude.ai."); !ok {
		t.Fatalf("expected match with trailing dot stripped")
	}
	if _, ok := m.Match("api.claude.ai"); ok {
		t.Fatalf("did not expect subdomain match on an exact rule")
	}
	if _, ok := m.Match("notclaude.ai"); ok {
		t.Fatalf("did not expect unrelated domain to match")
	}
}

func TestMatcherWildcard(t *testing.T) {
	m := NewMatcher([]Rule{
		{Domain: "*.anthropic.com", Nets: []*net.IPNet{mustNet(t, "104.16.0.0/13")}},
	})

	cases := []struct {
		host string
		want bool
	}{
		{"api.anthropic.com", true},
		{"deep.sub.anthropic.com", true},
		{"anthropic.com", false},
		{"notanthropic.com", false},
		{"anthropic.com.evil.example", false},
	}
	for _, c := range cases {
		_, got := m.Match(c.host)
		if got != c.want {
			t.Errorf("Match(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

func TestMatcherPicksMostSpecificExactOverWildcard(t *testing.T) {
	m := NewMatcher([]Rule{
		{Domain: "api.anthropic.com", Nets: []*net.IPNet{mustNet(t, "1.1.1.0/24")}},
		{Domain: "*.anthropic.com", Nets: []*net.IPNet{mustNet(t, "104.16.0.0/13")}},
	})

	rule, ok := m.Match("api.anthropic.com")
	if !ok {
		t.Fatalf("expected a match")
	}
	if rule.Domain != "api.anthropic.com" {
		t.Fatalf("expected exact rule to win, got %q", rule.Domain)
	}
}

func TestRuleAllows(t *testing.T) {
	r := Rule{Nets: []*net.IPNet{mustNet(t, "104.16.0.0/13")}}

	if !r.Allows(net.ParseIP("104.16.0.1")) {
		t.Errorf("expected 104.16.0.1 to be allowed (range start)")
	}
	if !r.Allows(net.ParseIP("104.23.255.254")) {
		t.Errorf("expected 104.23.255.254 to be allowed (range end)")
	}
	if r.Allows(net.ParseIP("104.24.0.0")) {
		t.Errorf("expected 104.24.0.0 to be rejected (just past range end)")
	}
	if r.Allows(net.ParseIP("8.8.8.8")) {
		t.Errorf("expected 8.8.8.8 to be rejected")
	}
}

func TestRuleAllowsNoNets(t *testing.T) {
	r := Rule{}
	if r.Allows(net.ParseIP("1.2.3.4")) {
		t.Errorf("expected no allowed IPs when rule has zero nets")
	}
}
