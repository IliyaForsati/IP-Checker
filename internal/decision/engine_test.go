package decision

import (
	"io"
	"log/slog"
	"net"
	"testing"

	"github.com/IliyaForsati/IP-Checker/internal/cidr"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func testMatcher() *cidr.Matcher {
	_, allowedNet, _ := net.ParseCIDR("104.16.0.0/13")
	return cidr.NewMatcher([]cidr.Rule{
		{Domain: "claude.ai", Nets: []*net.IPNet{allowedNet}},
	})
}

func TestEvaluateSNI_DomainNotConfigured(t *testing.T) {
	engine := NewEngine(testMatcher(), testLogger(), false)
	verdict := engine.EvaluateSNI(net.ParseIP("8.8.8.8"), 443, "example.org")
	if verdict != VerdictAccept {
		t.Fatalf("expected Accept for unconfigured domain, got %v", verdict)
	}
}

func TestEvaluateSNI_AllowedIP(t *testing.T) {
	engine := NewEngine(testMatcher(), testLogger(), false)
	verdict := engine.EvaluateSNI(net.ParseIP("104.16.1.1"), 443, "claude.ai")
	if verdict != VerdictAccept {
		t.Fatalf("expected Accept for allowed IP, got %v", verdict)
	}
}

func TestEvaluateSNI_DisallowedIP(t *testing.T) {
	engine := NewEngine(testMatcher(), testLogger(), false)
	verdict := engine.EvaluateSNI(net.ParseIP("8.8.8.8"), 443, "claude.ai")
	if verdict != VerdictDrop {
		t.Fatalf("expected Drop for disallowed IP, got %v", verdict)
	}
}

func TestEvaluateSNI_MonitorModeNeverDrops(t *testing.T) {
	engine := NewEngine(testMatcher(), testLogger(), true)
	verdict := engine.EvaluateSNI(net.ParseIP("8.8.8.8"), 443, "claude.ai")
	if verdict != VerdictAccept {
		t.Fatalf("expected Accept in monitor mode even for disallowed IP, got %v", verdict)
	}
}

func TestEvaluateSNI_EmptySNI(t *testing.T) {
	engine := NewEngine(testMatcher(), testLogger(), false)
	verdict := engine.EvaluateSNI(net.ParseIP("8.8.8.8"), 443, "")
	if verdict != VerdictAccept {
		t.Fatalf("expected Accept when no SNI observed, got %v", verdict)
	}
}
