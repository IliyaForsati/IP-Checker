package config

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func writeConfig(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return path
}

func TestLoadValidConfig(t *testing.T) {
	path := writeConfig(t, `{
		"cidr_sets": {
			"cloudflare": ["104.16.0.0/13", "172.64.0.0/13"]
		},
		"domains": [
			{"domain": "claude.ai", "cidr_sets": ["cloudflare"]},
			{"domain": "*.anthropic.com", "cidr_sets": ["cloudflare"], "cidrs": ["1.1.1.0/24"]}
		]
	}`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.EnforcementMode != EnforcementModeEnforce {
		t.Errorf("expected default enforcement_mode enforce, got %q", cfg.EnforcementMode)
	}
	if cfg.Log.Level != "warn" {
		t.Errorf("expected default log level warn, got %q", cfg.Log.Level)
	}
	if cfg.NFQueue.DNSQueueNum != defaultDNSQueueNum || cfg.NFQueue.TLSQueueNum != defaultTLSQueueNum {
		t.Errorf("expected default queue numbers, got dns=%d tls=%d", cfg.NFQueue.DNSQueueNum, cfg.NFQueue.TLSQueueNum)
	}
	if len(cfg.Domains) != 2 {
		t.Fatalf("expected 2 domain rules, got %d", len(cfg.Domains))
	}

	matcher, err := cfg.BuildMatcher()
	if err != nil {
		t.Fatalf("BuildMatcher: %v", err)
	}
	rule, ok := matcher.Match("claude.ai")
	if !ok {
		t.Fatalf("expected claude.ai to match")
	}
	if !rule.Allows(net.ParseIP("104.16.1.1")) {
		t.Errorf("expected claude.ai rule to allow an IP inside cloudflare set")
	}

	rule, ok = matcher.Match("api.anthropic.com")
	if !ok {
		t.Fatalf("expected api.anthropic.com to match wildcard rule")
	}
	if !rule.Allows(net.ParseIP("1.1.1.5")) {
		t.Errorf("expected inline CIDR 1.1.1.0/24 to be honored")
	}
}

func TestLoadRejectsInvalidJSON(t *testing.T) {
	path := writeConfig(t, `{not valid json`)
	if _, err := Load(path); err == nil {
		t.Fatalf("expected error for invalid JSON")
	}
}

func TestLoadRejectsBadCIDR(t *testing.T) {
	path := writeConfig(t, `{
		"domains": [{"domain": "example.com", "cidrs": ["not-a-cidr"]}]
	}`)
	if _, err := Load(path); err == nil {
		t.Fatalf("expected error for invalid CIDR")
	}
}

func TestLoadRejectsDanglingCIDRSetReference(t *testing.T) {
	path := writeConfig(t, `{
		"domains": [{"domain": "example.com", "cidr_sets": ["does-not-exist"]}]
	}`)
	if _, err := Load(path); err == nil {
		t.Fatalf("expected error for dangling cidr_sets reference")
	}
}

func TestLoadRejectsDuplicateDomain(t *testing.T) {
	path := writeConfig(t, `{
		"domains": [
			{"domain": "example.com", "cidrs": ["1.1.1.0/24"]},
			{"domain": "Example.com.", "cidrs": ["1.1.1.0/24"]}
		]
	}`)
	if _, err := Load(path); err == nil {
		t.Fatalf("expected error for duplicate (normalized) domain")
	}
}

func TestLoadRejectsZeroCIDRDomain(t *testing.T) {
	path := writeConfig(t, `{
		"domains": [{"domain": "example.com"}]
	}`)
	if _, err := Load(path); err == nil {
		t.Fatalf("expected error for domain with zero resolvable CIDRs")
	}
}

func TestLoadRejectsSameQueueNumbers(t *testing.T) {
	path := writeConfig(t, `{
		"nfqueue": {"dns_queue_num": 5, "tls_queue_num": 5},
		"domains": [{"domain": "example.com", "cidrs": ["1.1.1.0/24"]}]
	}`)
	if _, err := Load(path); err == nil {
		t.Fatalf("expected error when dns and tls queue numbers match")
	}
}

func TestLoadRejectsInvalidEnforcementMode(t *testing.T) {
	path := writeConfig(t, `{
		"enforcement_mode": "yolo",
		"domains": [{"domain": "example.com", "cidrs": ["1.1.1.0/24"]}]
	}`)
	if _, err := Load(path); err == nil {
		t.Fatalf("expected error for invalid enforcement_mode")
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load("/nonexistent/path/config.json"); err == nil {
		t.Fatalf("expected error for missing file")
	}
}
