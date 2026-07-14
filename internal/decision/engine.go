package decision

import (
	"log/slog"
	"net"
	"sync/atomic"

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

type engineState struct {
	matcher     *cidr.Matcher
	monitorOnly bool
}

type Engine struct {
	logger *slog.Logger
	state  atomic.Pointer[engineState]
}

func NewEngine(matcher *cidr.Matcher, logger *slog.Logger, monitorOnly bool) *Engine {
	e := &Engine{logger: logger}
	e.SetState(matcher, monitorOnly)
	return e
}

func (e *Engine) SetState(matcher *cidr.Matcher, monitorOnly bool) {
	e.state.Store(&engineState{matcher: matcher, monitorOnly: monitorOnly})
}

func (e *Engine) EvaluateSNI(dstIP net.IP, dstPort uint16, sni string) Verdict {
	if sni == "" {
		e.logger.Debug("no SNI observed, cannot determine domain",
			"event", "no_sni", "dst_ip", dstIP.String(), "dst_port", dstPort)
		return VerdictAccept
	}

	state := e.state.Load()
	rule, matched := state.matcher.Match(sni)
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
		"monitor_only", state.monitorOnly)

	if state.monitorOnly {
		return VerdictAccept
	}
	return VerdictDrop
}

func (e *Engine) EvaluateDNSAnswer(domain string, ip net.IP) {
	state := e.state.Load()
	rule, matched := state.matcher.Match(domain)
	if !matched {
		return
	}
	if rule.Allows(ip) {
		return
	}
	e.logger.Warn("dns pre-check: configured domain resolved outside allowed CIDRs",
		"event", "dns_resolution_outside_allowed", "domain", domain, "matched_rule", rule.Domain, "resolved_ip", ip.String())
}

func (e *Engine) EvaluateNewSYN(dstIP net.IP, dstPort uint16, domain string) Verdict {
	state := e.state.Load()
	rule, matched := state.matcher.Match(domain)
	if !matched {
		return VerdictAccept
	}
	if rule.Allows(dstIP) {
		return VerdictAccept
	}

	e.logger.Warn("blocked SYN preemptively via DNS correlation",
		"event", "block_syn_preemptive", "domain", domain, "matched_rule", rule.Domain,
		"dst_ip", dstIP.String(), "dst_port", dstPort, "reason", "ip_not_in_allowed_cidrs",
		"monitor_only", state.monitorOnly)

	if state.monitorOnly {
		return VerdictAccept
	}
	return VerdictDrop
}
