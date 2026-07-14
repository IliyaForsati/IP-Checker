package dnsobserver

import (
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/IliyaForsati/IP-Checker/internal/cidr"
	"github.com/IliyaForsati/IP-Checker/internal/decision"
	"github.com/IliyaForsati/IP-Checker/internal/packet"
)

func buildIPv4Header(protocol uint8, src, dst net.IP, payloadLen int) []byte {
	h := make([]byte, 20)
	h[0] = 0x45
	binary.BigEndian.PutUint16(h[2:4], uint16(20+payloadLen))
	h[8] = 64
	h[9] = protocol
	copy(h[12:16], src.To4())
	copy(h[16:20], dst.To4())
	return h
}

func buildUDPDatagram(srcPort, dstPort uint16, payload []byte) []byte {
	h := make([]byte, 8)
	binary.BigEndian.PutUint16(h[0:2], srcPort)
	binary.BigEndian.PutUint16(h[2:4], dstPort)
	binary.BigEndian.PutUint16(h[4:6], uint16(8+len(payload)))
	return append(h, payload...)
}

func TestPipeline_RecordsUDPAnswers(t *testing.T) {
	msg := buildDNSResponse(t, "claude.ai", []net.IP{net.ParseIP("104.16.1.1")}, 300)
	udp := buildUDPDatagram(53, 53211, msg)
	src := net.ParseIP("1.1.1.1")
	dst := net.ParseIP("10.0.0.5")
	raw := append(buildIPv4Header(packet.ProtocolUDP, src, dst, len(udp)), udp...)

	ip, err := packet.ParseIPv4(raw)
	if err != nil {
		t.Fatalf("ParseIPv4: %v", err)
	}

	table := NewTable(time.Minute)
	matcher := cidr.NewMatcher(nil)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	engine := decision.NewEngine(matcher, logger, false)
	p := NewPipeline(table, engine)

	p.HandleIPv4(ip)

	domain, ok := table.Lookup(net.ParseIP("104.16.1.1"))
	if !ok || domain != "claude.ai" {
		t.Fatalf("expected correlation table to record claude.ai -> 104.16.1.1, got domain=%q ok=%v", domain, ok)
	}
}

func TestPipeline_IgnoresNonDNSPayload(t *testing.T) {
	udp := buildUDPDatagram(53, 53211, []byte("not-a-dns-message"))
	src := net.ParseIP("1.1.1.1")
	dst := net.ParseIP("10.0.0.5")
	raw := append(buildIPv4Header(packet.ProtocolUDP, src, dst, len(udp)), udp...)

	ip, err := packet.ParseIPv4(raw)
	if err != nil {
		t.Fatalf("ParseIPv4: %v", err)
	}

	table := NewTable(time.Minute)
	matcher := cidr.NewMatcher(nil)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	engine := decision.NewEngine(matcher, logger, false)
	p := NewPipeline(table, engine)

	p.HandleIPv4(ip)

	if table.Len() != 0 {
		t.Fatalf("expected no correlation entries from garbage payload, len=%d", table.Len())
	}
}
