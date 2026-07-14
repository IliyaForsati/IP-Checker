package decision

import (
	"testing"
	"time"

	"github.com/IliyaForsati/IP-Checker/internal/packet"
)

func TestFlowTable_SetGet(t *testing.T) {
	ft := NewFlowTable(time.Minute)
	key := packet.FlowKey{SrcPort: 1234, DstPort: 443}

	if _, ok := ft.Get(key); ok {
		t.Fatalf("expected no entry before Set")
	}

	ft.Set(key, VerdictDrop)
	verdict, ok := ft.Get(key)
	if !ok {
		t.Fatalf("expected entry after Set")
	}
	if verdict != VerdictDrop {
		t.Fatalf("expected VerdictDrop, got %v", verdict)
	}
}

func TestFlowTable_TTLExpiry(t *testing.T) {
	ft := NewFlowTable(time.Minute)
	key := packet.FlowKey{SrcPort: 1234, DstPort: 443}

	now := time.Now()
	ft.now = func() time.Time { return now }
	ft.Set(key, VerdictDrop)

	ft.now = func() time.Time { return now.Add(2 * time.Minute) }
	if _, ok := ft.Get(key); ok {
		t.Fatalf("expected entry to have expired")
	}
}

func TestFlowTable_Sweep(t *testing.T) {
	ft := NewFlowTable(time.Minute)
	key := packet.FlowKey{SrcPort: 1234, DstPort: 443}

	now := time.Now()
	ft.now = func() time.Time { return now }
	ft.Set(key, VerdictAccept)

	ft.Sweep(now.Add(2 * time.Minute))
	if ft.Len() != 0 {
		t.Fatalf("expected expired entry to be swept, len=%d", ft.Len())
	}
}
