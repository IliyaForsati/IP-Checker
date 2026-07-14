package sniobserver

import (
	"github.com/IliyaForsati/IP-Checker/internal/decision"
	"github.com/IliyaForsati/IP-Checker/internal/packet"
)

type Pipeline struct {
	engine      *decision.Engine
	flows       *decision.FlowTable
	reassembler *Reassembler
}

func NewPipeline(engine *decision.Engine, flows *decision.FlowTable) *Pipeline {
	return &Pipeline{
		engine:      engine,
		flows:       flows,
		reassembler: NewReassembler(),
	}
}

func (p *Pipeline) HandleIPv4(ip *packet.IPv4) decision.Verdict {
	seg, err := packet.ParseTCP(ip.Payload)
	if err != nil {
		return decision.VerdictAccept
	}

	key := packet.NewFlowKey(ip.SrcIP, ip.DstIP, seg.SrcPort, seg.DstPort)

	if verdict, ok := p.flows.Get(key); ok {
		return verdict
	}

	if seg.HasFlag(packet.TCPFlagFIN) || seg.HasFlag(packet.TCPFlagRST) {
		p.reassembler.Evict(key)
		return decision.VerdictAccept
	}

	if len(seg.Payload) == 0 {
		return decision.VerdictAccept
	}

	buf, overflowed := p.reassembler.Feed(key, seg.Payload)
	if overflowed {
		return decision.VerdictAccept
	}

	hostname, complete, err := ExtractSNI(buf)
	if err != nil {
		p.reassembler.Evict(key)
		return decision.VerdictAccept
	}
	if !complete {
		return decision.VerdictAccept
	}

	p.reassembler.Evict(key)
	verdict := p.engine.EvaluateSNI(ip.DstIP, seg.DstPort, hostname)
	p.flows.Set(key, verdict)
	return verdict
}
