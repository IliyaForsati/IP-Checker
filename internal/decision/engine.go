package decision

import (
	"log/slog"
	"net"

	"github.com/IliyaForsati/IP-Checker/internal/cidr"
)

type Verdict int

const (
	VerdictAccept Verdict = iota
	VerdictDrop
)

func (v Verdict) String() string {
	if v == VerdictDrop {
		return "drop"
	}
	return "accept"
}

type Engine struct {
	matcher     *cidr.Matcher
	logger      *slog.Logger
	monitorOnly bool
}

func NewEngine(matcher *cidr.Matcher, logger *slog.Logger, monitorOnly bool) *Engine {
	return &Engine{matcher: matcher, logger: logger, monitorOnly: monitorOnly}
}

func (e *Engine) EvaluateSNI(dstIP net.IP, dstPort uint16, sni string) Verdict {
	if sni == "" {
		e.logger.Debug("no SNI observed, cannot determine domain",
			"event", "no_sni", "dst_ip", dstIP.String(), "dst_port", dstPort)
		return VerdictAccept
	}

	rule, matched := e.matcher.Match(sni)
	if !matched {
		e.logger.Warn("passthrough: domain not present in config, unmonitored",
			"event", "passthrough_unmonitored", "domain", sni, "dst_ip", dstIP.String(), "dst_port", dstPort)
		return VerdictAccept
	}

	if rule.Allows(dstIP) {
		e.logger.Info("allow: destination within allowed CIDRs",
			"event", "allow", "domain", sni, "matched_rule", rule.Domain, "dst_ip", dstIP.String(), "dst_port", dstPort)
		return VerdictAccept
	}

	e.logger.Warn("blocked connection: destination IP outside allowed range",
		"event", "block", "domain", sni, "matched_rule", rule.Domain,
		"dst_ip", dstIP.String(), "dst_port", dstPort, "reason", "ip_not_in_allowed_cidrs",
		"monitor_only", e.monitorOnly)

	if e.monitorOnly {
		return VerdictAccept
	}
	return VerdictDrop
}
