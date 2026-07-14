package sniobserver

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

func buildTCPSegment(srcPort, dstPort uint16, seq uint32, flags uint8, payload []byte) []byte {
	h := make([]byte, 20)
	binary.BigEndian.PutUint16(h[0:2], srcPort)
	binary.BigEndian.PutUint16(h[2:4], dstPort)
	binary.BigEndian.PutUint32(h[4:8], seq)
	h[12] = 5 << 4
	h[13] = flags
	return append(h, payload...)
}

func buildIPv4TCPPacket(t *testing.T, src, dst net.IP, srcPort, dstPort uint16, seq uint32, flags uint8, payload []byte) *packet.IPv4 {
	t.Helper()
	tcp := buildTCPSegment(srcPort, dstPort, seq, flags, payload)
	raw := append(buildIPv4Header(packet.ProtocolTCP, src, dst, len(tcp)), tcp...)
	ip, err := packet.ParseIPv4(raw)
	if err != nil {
		t.Fatalf("ParseIPv4: %v", err)
	}
	return ip
}

func testPipeline(t *testing.T, allowedCIDR, domain string, monitorOnly bool) *Pipeline {
	t.Helper()
	_, allowedNet, err := net.ParseCIDR(allowedCIDR)
	if err != nil {
		t.Fatalf("ParseCIDR: %v", err)
	}
	matcher := cidr.NewMatcher([]cidr.Rule{{Domain: domain, Nets: []*net.IPNet{allowedNet}}})
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	engine := decision.NewEngine(matcher, logger, monitorOnly)
	flows := decision.NewFlowTable(time.Minute)
	return NewPipeline(engine, flows)
}

func TestPipeline_AllowsConfiguredDomainWithAllowedIP(t *testing.T) {
	clientHello := captureRealClientHello(t, "claude.ai")
	p := testPipeline(t, "104.16.0.0/13", "claude.ai", false)

	ip := buildIPv4TCPPacket(t, net.ParseIP("10.0.0.5"), net.ParseIP("104.16.1.1"), 51000, 443, 1, packet.TCPFlagACK, clientHello)

	if v := p.HandleIPv4(ip); v != decision.VerdictAccept {
		t.Fatalf("expected Accept, got %v", v)
	}
}

func TestPipeline_BlocksConfiguredDomainWithDisallowedIP(t *testing.T) {
	clientHello := captureRealClientHello(t, "claude.ai")
	p := testPipeline(t, "104.16.0.0/13", "claude.ai", false)

	ip := buildIPv4TCPPacket(t, net.ParseIP("10.0.0.5"), net.ParseIP("8.8.8.8"), 51000, 443, 1, packet.TCPFlagACK, clientHello)

	if v := p.HandleIPv4(ip); v != decision.VerdictDrop {
		t.Fatalf("expected Drop, got %v", v)
	}
}

func TestPipeline_CachesVerdictForSubsequentPackets(t *testing.T) {
	clientHello := captureRealClientHello(t, "claude.ai")
	p := testPipeline(t, "104.16.0.0/13", "claude.ai", false)

	src := net.ParseIP("10.0.0.5")
	dst := net.ParseIP("8.8.8.8")

	first := buildIPv4TCPPacket(t, src, dst, 51000, 443, 1, packet.TCPFlagACK, clientHello)
	if v := p.HandleIPv4(first); v != decision.VerdictDrop {
		t.Fatalf("expected Drop on first packet, got %v", v)
	}

	second := buildIPv4TCPPacket(t, src, dst, 51000, 443, 2, packet.TCPFlagACK, []byte("irrelevant-followup-bytes"))
	if v := p.HandleIPv4(second); v != decision.VerdictDrop {
		t.Fatalf("expected cached Drop verdict on second packet, got %v", v)
	}
}

func TestPipeline_PassesThroughUnconfiguredDomain(t *testing.T) {
	clientHello := captureRealClientHello(t, "example.org")
	p := testPipeline(t, "104.16.0.0/13", "claude.ai", false)

	ip := buildIPv4TCPPacket(t, net.ParseIP("10.0.0.5"), net.ParseIP("93.184.216.34"), 51000, 443, 1, packet.TCPFlagACK, clientHello)

	if v := p.HandleIPv4(ip); v != decision.VerdictAccept {
		t.Fatalf("expected Accept for unconfigured domain, got %v", v)
	}
}

func TestPipeline_AcceptsBareSYNWithoutPayload(t *testing.T) {
	p := testPipeline(t, "104.16.0.0/13", "claude.ai", false)
	ip := buildIPv4TCPPacket(t, net.ParseIP("10.0.0.5"), net.ParseIP("8.8.8.8"), 51000, 443, 1, packet.TCPFlagSYN, nil)

	if v := p.HandleIPv4(ip); v != decision.VerdictAccept {
		t.Fatalf("expected Accept for bare SYN with no payload yet, got %v", v)
	}
}

func TestPipeline_BuffersAcrossSegmentsThenBlocks(t *testing.T) {
	clientHello := captureRealClientHello(t, "claude.ai")
	p := testPipeline(t, "104.16.0.0/13", "claude.ai", false)

	src := net.ParseIP("10.0.0.5")
	dst := net.ParseIP("8.8.8.8")
	mid := len(clientHello) / 2

	first := buildIPv4TCPPacket(t, src, dst, 51000, 443, 1, packet.TCPFlagACK, clientHello[:mid])
	if v := p.HandleIPv4(first); v != decision.VerdictAccept {
		t.Fatalf("expected Accept while still buffering, got %v", v)
	}

	second := buildIPv4TCPPacket(t, src, dst, 51000, 443, 2, packet.TCPFlagACK, clientHello[mid:])
	if v := p.HandleIPv4(second); v != decision.VerdictDrop {
		t.Fatalf("expected Drop once ClientHello completes, got %v", v)
	}
}
