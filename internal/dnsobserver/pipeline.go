package dnsobserver

import (
	"github.com/IliyaForsati/IP-Checker/internal/decision"
	"github.com/IliyaForsati/IP-Checker/internal/packet"
)

type Pipeline struct {
	table  *Table
	engine *decision.Engine
}

func NewPipeline(table *Table, engine *decision.Engine) *Pipeline {
	return &Pipeline{table: table, engine: engine}
}

func (p *Pipeline) HandleIPv4(ip *packet.IPv4) {
	var (
		answers []Answer
		err     error
	)

	switch ip.Protocol {
	case packet.ProtocolUDP:
		dgram, perr := packet.ParseUDP(ip.Payload)
		if perr != nil {
			return
		}
		answers, err = ParseAnswers(dgram.Payload)
	case packet.ProtocolTCP:
		seg, perr := packet.ParseTCP(ip.Payload)
		if perr != nil || len(seg.Payload) == 0 {
			return
		}
		answers, err = ParseAnswersTCP(seg.Payload)
	default:
		return
	}

	if err != nil {
		return
	}

	for _, a := range answers {
		p.table.Record(a.Name, a.IP, a.TTL)
		p.engine.EvaluateDNSAnswer(a.Name, a.IP)
	}
}
