package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"

	"github.com/IliyaForsati/IP-Checker/internal/cidr"
)

const (
	EnforcementModeMonitor = "monitor"
	EnforcementModeEnforce = "enforce"

	defaultDNSQueueNum              = 100
	defaultTLSQueueNum              = 101
	defaultDNSCorrelationTTLSeconds = 300
	defaultFlowVerdictTTLSeconds    = 600
	defaultLogLevel                 = "warn"
	defaultLogPath                  = "stdout"
)

var validLogLevels = map[string]bool{
	"debug": true,
	"info":  true,
	"warn":  true,
	"error": true,
}

type Config struct {
	Log                      LogConfig           `json:"log"`
	NFQueue                  NFQueueConfig       `json:"nfqueue"`
	EnforcementMode          string              `json:"enforcement_mode"`
	DNSCorrelationTTLSeconds int                 `json:"dns_correlation_ttl_seconds"`
	FlowVerdictTTLSeconds    int                 `json:"flow_verdict_ttl_seconds"`
	CIDRSets                 map[string][]string `json:"cidr_sets"`
	Domains                  []DomainRule        `json:"domains"`
}

type LogConfig struct {
	Level string `json:"level"`
	Path  string `json:"path"`
}

type NFQueueConfig struct {
	DNSQueueNum uint16 `json:"dns_queue_num"`
	TLSQueueNum uint16 `json:"tls_queue_num"`
}

type DomainRule struct {
	Domain   string   `json:"domain"`
	CIDRSets []string `json:"cidr_sets,omitempty"`
	CIDRs    []string `json:"cidrs,omitempty"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}

	applyDefaults(&cfg)

	if err := Validate(&cfg); err != nil {
		return nil, fmt.Errorf("invalid config %s: %w", path, err)
	}

	return &cfg, nil
}

func applyDefaults(cfg *Config) {
	if cfg.EnforcementMode == "" {
		cfg.EnforcementMode = EnforcementModeEnforce
	}
	if cfg.Log.Level == "" {
		cfg.Log.Level = defaultLogLevel
	}
	if cfg.Log.Path == "" {
		cfg.Log.Path = defaultLogPath
	}
	if cfg.NFQueue.DNSQueueNum == 0 {
		cfg.NFQueue.DNSQueueNum = defaultDNSQueueNum
	}
	if cfg.NFQueue.TLSQueueNum == 0 {
		cfg.NFQueue.TLSQueueNum = defaultTLSQueueNum
	}
	if cfg.DNSCorrelationTTLSeconds == 0 {
		cfg.DNSCorrelationTTLSeconds = defaultDNSCorrelationTTLSeconds
	}
	if cfg.FlowVerdictTTLSeconds == 0 {
		cfg.FlowVerdictTTLSeconds = defaultFlowVerdictTTLSeconds
	}
}

func Validate(cfg *Config) error {
	if cfg.EnforcementMode != EnforcementModeMonitor && cfg.EnforcementMode != EnforcementModeEnforce {
		return fmt.Errorf("enforcement_mode must be %q or %q, got %q", EnforcementModeMonitor, EnforcementModeEnforce, cfg.EnforcementMode)
	}

	if !validLogLevels[cfg.Log.Level] {
		return fmt.Errorf("log.level must be one of debug/info/warn/error, got %q", cfg.Log.Level)
	}

	if cfg.NFQueue.DNSQueueNum == cfg.NFQueue.TLSQueueNum {
		return fmt.Errorf("nfqueue.dns_queue_num and nfqueue.tls_queue_num must differ, both are %d", cfg.NFQueue.DNSQueueNum)
	}

	for name, cidrs := range cfg.CIDRSets {
		if name == "" {
			return fmt.Errorf("cidr_sets contains an empty set name")
		}
		for _, c := range cidrs {
			if _, _, err := net.ParseCIDR(c); err != nil {
				return fmt.Errorf("cidr_sets[%s]: invalid CIDR %q: %w", name, c, err)
			}
		}
	}

	seenDomains := make(map[string]bool)
	for i, d := range cfg.Domains {
		if d.Domain == "" {
			return fmt.Errorf("domains[%d]: domain must not be empty", i)
		}

		normalized := cidr.NormalizeDomain(d.Domain)
		if seenDomains[normalized] {
			return fmt.Errorf("domains[%d]: duplicate domain %q", i, d.Domain)
		}
		seenDomains[normalized] = true

		for _, setName := range d.CIDRSets {
			if _, ok := cfg.CIDRSets[setName]; !ok {
				return fmt.Errorf("domains[%d] (%s): references unknown cidr_sets entry %q", i, d.Domain, setName)
			}
		}

		for _, c := range d.CIDRs {
			if _, _, err := net.ParseCIDR(c); err != nil {
				return fmt.Errorf("domains[%d] (%s): invalid CIDR %q: %w", i, d.Domain, c, err)
			}
		}

		total := len(d.CIDRs)
		for _, setName := range d.CIDRSets {
			total += len(cfg.CIDRSets[setName])
		}
		if total == 0 {
			return fmt.Errorf("domains[%d] (%s): resolves to zero CIDRs, this would block all traffic to this domain", i, d.Domain)
		}
	}

	return nil
}

func (cfg *Config) BuildMatcher() (*cidr.Matcher, error) {
	rules := make([]cidr.Rule, 0, len(cfg.Domains))
	for _, d := range cfg.Domains {
		seen := make(map[string]bool)
		var nets []*net.IPNet

		addCIDR := func(s string) error {
			_, n, err := net.ParseCIDR(s)
			if err != nil {
				return fmt.Errorf("domain %s: invalid CIDR %q: %w", d.Domain, s, err)
			}
			key := n.String()
			if seen[key] {
				return nil
			}
			seen[key] = true
			nets = append(nets, n)
			return nil
		}

		var setNames []string
		setNames = append(setNames, d.CIDRSets...)
		sort.Strings(setNames)
		for _, setName := range setNames {
			for _, c := range cfg.CIDRSets[setName] {
				if err := addCIDR(c); err != nil {
					return nil, err
				}
			}
		}
		for _, c := range d.CIDRs {
			if err := addCIDR(c); err != nil {
				return nil, err
			}
		}

		rules = append(rules, cidr.Rule{Domain: d.Domain, Nets: nets})
	}

	return cidr.NewMatcher(rules), nil
}
