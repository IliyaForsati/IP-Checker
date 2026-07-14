package dnsobserver

import (
	"net"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func buildDNSResponse(t *testing.T, name string, ips []net.IP, ttl uint32) []byte {
	t.Helper()

	dnsName, err := dnsmessage.NewName(name + ".")
	if err != nil {
		t.Fatalf("NewName: %v", err)
	}

	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true})
	builder.EnableCompression()

	if err := builder.StartQuestions(); err != nil {
		t.Fatalf("StartQuestions: %v", err)
	}
	if err := builder.Question(dnsmessage.Question{
		Name:  dnsName,
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	}); err != nil {
		t.Fatalf("Question: %v", err)
	}

	if err := builder.StartAnswers(); err != nil {
		t.Fatalf("StartAnswers: %v", err)
	}
	for _, ip := range ips {
		var addr [4]byte
		copy(addr[:], ip.To4())
		if err := builder.AResource(
			dnsmessage.ResourceHeader{Name: dnsName, Class: dnsmessage.ClassINET, TTL: ttl},
			dnsmessage.AResource{A: addr},
		); err != nil {
			t.Fatalf("AResource: %v", err)
		}
	}

	buf, err := builder.Finish()
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	return buf
}

func TestParseAnswers(t *testing.T) {
	msg := buildDNSResponse(t, "claude.ai", []net.IP{net.ParseIP("104.16.1.1"), net.ParseIP("104.16.1.2")}, 300)

	answers, err := ParseAnswers(msg)
	if err != nil {
		t.Fatalf("ParseAnswers: %v", err)
	}
	if len(answers) != 2 {
		t.Fatalf("expected 2 answers, got %d", len(answers))
	}
	for _, a := range answers {
		if a.Name != "claude.ai" {
			t.Errorf("expected name claude.ai, got %q", a.Name)
		}
		if a.TTL.Seconds() != 300 {
			t.Errorf("expected TTL 300s, got %v", a.TTL)
		}
	}
	if !answers[0].IP.Equal(net.ParseIP("104.16.1.1")) {
		t.Errorf("unexpected first IP: %v", answers[0].IP)
	}
}

func TestParseAnswersTCP(t *testing.T) {
	msg := buildDNSResponse(t, "claude.ai", []net.IP{net.ParseIP("104.16.1.1")}, 60)
	framed := make([]byte, 2+len(msg))
	framed[0] = byte(len(msg) >> 8)
	framed[1] = byte(len(msg))
	copy(framed[2:], msg)

	answers, err := ParseAnswersTCP(framed)
	if err != nil {
		t.Fatalf("ParseAnswersTCP: %v", err)
	}
	if len(answers) != 1 || !answers[0].IP.Equal(net.ParseIP("104.16.1.1")) {
		t.Fatalf("unexpected answers: %+v", answers)
	}
}

func TestParseAnswersTCPTruncated(t *testing.T) {
	if _, err := ParseAnswersTCP([]byte{0, 10, 1, 2}); err != ErrTruncatedTCPMessage {
		t.Fatalf("expected ErrTruncatedTCPMessage, got %v", err)
	}
}

func TestParseAnswersInvalid(t *testing.T) {
	if _, err := ParseAnswers([]byte{1, 2, 3}); err == nil {
		t.Fatalf("expected error for garbage input")
	}
}
