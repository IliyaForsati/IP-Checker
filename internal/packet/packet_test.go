package packet

import (
	"encoding/binary"
	"net"
	"testing"
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

func buildUDPDatagram(srcPort, dstPort uint16, payload []byte) []byte {
	h := make([]byte, 8)
	binary.BigEndian.PutUint16(h[0:2], srcPort)
	binary.BigEndian.PutUint16(h[2:4], dstPort)
	binary.BigEndian.PutUint16(h[4:6], uint16(8+len(payload)))
	return append(h, payload...)
}

func TestParseIPv4TCP(t *testing.T) {
	tcp := buildTCPSegment(51422, 443, 1000, TCPFlagSYN, nil)
	src := net.ParseIP("10.0.0.5")
	dst := net.ParseIP("104.16.1.1")
	raw := append(buildIPv4Header(ProtocolTCP, src, dst, len(tcp)), tcp...)

	ip, err := ParseIPv4(raw)
	if err != nil {
		t.Fatalf("ParseIPv4: %v", err)
	}
	if !ip.SrcIP.Equal(src) || !ip.DstIP.Equal(dst) {
		t.Fatalf("unexpected src/dst: %v -> %v", ip.SrcIP, ip.DstIP)
	}
	if ip.Protocol != ProtocolTCP {
		t.Fatalf("expected protocol TCP, got %d", ip.Protocol)
	}

	seg, err := ParseTCP(ip.Payload)
	if err != nil {
		t.Fatalf("ParseTCP: %v", err)
	}
	if seg.SrcPort != 51422 || seg.DstPort != 443 {
		t.Fatalf("unexpected ports: %d -> %d", seg.SrcPort, seg.DstPort)
	}
	if !seg.HasFlag(TCPFlagSYN) {
		t.Fatalf("expected SYN flag set")
	}
	if seg.HasFlag(TCPFlagACK) {
		t.Fatalf("did not expect ACK flag set")
	}
}

func TestParseIPv4UDP(t *testing.T) {
	payload := []byte("dns-query")
	udp := buildUDPDatagram(53211, 53, payload)
	src := net.ParseIP("10.0.0.5")
	dst := net.ParseIP("1.1.1.1")
	raw := append(buildIPv4Header(ProtocolUDP, src, dst, len(udp)), udp...)

	ip, err := ParseIPv4(raw)
	if err != nil {
		t.Fatalf("ParseIPv4: %v", err)
	}

	dgram, err := ParseUDP(ip.Payload)
	if err != nil {
		t.Fatalf("ParseUDP: %v", err)
	}
	if dgram.SrcPort != 53211 || dgram.DstPort != 53 {
		t.Fatalf("unexpected ports: %d -> %d", dgram.SrcPort, dgram.DstPort)
	}
	if string(dgram.Payload) != string(payload) {
		t.Fatalf("unexpected payload: %q", dgram.Payload)
	}
}

func TestParseIPv4RejectsNonIPv4(t *testing.T) {
	raw := []byte{0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	if _, err := ParseIPv4(raw); err != ErrNotIPv4 {
		t.Fatalf("expected ErrNotIPv4, got %v", err)
	}
}

func TestParseIPv4RejectsShort(t *testing.T) {
	if _, err := ParseIPv4([]byte{0x45, 0, 0}); err != ErrNotIPv4 {
		t.Fatalf("expected ErrNotIPv4 for short buffer, got %v", err)
	}
}

func TestParseTCPRejectsShort(t *testing.T) {
	if _, err := ParseTCP([]byte{1, 2, 3}); err != ErrShortTCP {
		t.Fatalf("expected ErrShortTCP, got %v", err)
	}
}

func TestParseUDPRejectsShort(t *testing.T) {
	if _, err := ParseUDP([]byte{1, 2, 3}); err != ErrShortUDP {
		t.Fatalf("expected ErrShortUDP, got %v", err)
	}
}
