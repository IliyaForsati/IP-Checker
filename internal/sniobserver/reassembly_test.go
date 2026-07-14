package sniobserver

import (
	"bytes"
	"testing"

	"github.com/IliyaForsati/IP-Checker/internal/packet"
)

func TestReassemblerAccumulatesInOrder(t *testing.T) {
	r := NewReassembler()
	key := packet.FlowKey{SrcPort: 1, DstPort: 443}

	buf, overflowed := r.Feed(key, []byte("abc"))
	if overflowed {
		t.Fatalf("did not expect overflow")
	}
	if !bytes.Equal(buf, []byte("abc")) {
		t.Fatalf("unexpected buf: %q", buf)
	}

	buf, overflowed = r.Feed(key, []byte("def"))
	if overflowed {
		t.Fatalf("did not expect overflow")
	}
	if !bytes.Equal(buf, []byte("abcdef")) {
		t.Fatalf("unexpected buf: %q", buf)
	}
}

func TestReassemblerEvict(t *testing.T) {
	r := NewReassembler()
	key := packet.FlowKey{SrcPort: 1, DstPort: 443}

	r.Feed(key, []byte("abc"))
	r.Evict(key)

	buf, _ := r.Feed(key, []byte("xyz"))
	if !bytes.Equal(buf, []byte("xyz")) {
		t.Fatalf("expected fresh buffer after evict, got %q", buf)
	}
}

func TestReassemblerOverflow(t *testing.T) {
	r := NewReassembler()
	key := packet.FlowKey{SrcPort: 1, DstPort: 443}

	big := make([]byte, MaxBufferedBytes+1)
	_, overflowed := r.Feed(key, big)
	if !overflowed {
		t.Fatalf("expected overflow for payload exceeding MaxBufferedBytes")
	}

	buf, overflowed := r.Feed(key, []byte("x"))
	if overflowed {
		t.Fatalf("did not expect overflow after eviction")
	}
	if !bytes.Equal(buf, []byte("x")) {
		t.Fatalf("expected fresh buffer after overflow eviction, got len=%d", len(buf))
	}
}
