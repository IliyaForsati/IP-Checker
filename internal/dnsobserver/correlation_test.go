package dnsobserver

import (
	"net"
	"testing"
	"time"
)

func TestTableRecordAndLookup(t *testing.T) {
	table := NewTable(5 * time.Minute)
	table.Record("claude.ai", net.ParseIP("104.16.1.1"), time.Minute)

	domain, ok := table.Lookup(net.ParseIP("104.16.1.1"))
	if !ok {
		t.Fatalf("expected lookup to succeed")
	}
	if domain != "claude.ai" {
		t.Fatalf("expected claude.ai, got %q", domain)
	}

	if _, ok := table.Lookup(net.ParseIP("8.8.8.8")); ok {
		t.Fatalf("did not expect a match for an unrecorded IP")
	}
}

func TestTableExpiry(t *testing.T) {
	table := NewTable(5 * time.Minute)
	now := time.Now()
	table.now = func() time.Time { return now }

	table.Record("claude.ai", net.ParseIP("104.16.1.1"), time.Minute)

	table.now = func() time.Time { return now.Add(2 * time.Minute) }
	if _, ok := table.Lookup(net.ParseIP("104.16.1.1")); ok {
		t.Fatalf("expected entry to have expired")
	}
}

func TestTableClampsTTLToConfiguredMax(t *testing.T) {
	table := NewTable(time.Minute)
	now := time.Now()
	table.now = func() time.Time { return now }

	table.Record("claude.ai", net.ParseIP("104.16.1.1"), time.Hour)

	table.now = func() time.Time { return now.Add(90 * time.Second) }
	if _, ok := table.Lookup(net.ParseIP("104.16.1.1")); ok {
		t.Fatalf("expected DNS TTL to be clamped to the configured table TTL")
	}
}

func TestTableSweep(t *testing.T) {
	table := NewTable(time.Minute)
	now := time.Now()
	table.now = func() time.Time { return now }

	table.Record("claude.ai", net.ParseIP("104.16.1.1"), time.Minute)
	table.Sweep(now.Add(2 * time.Minute))

	if table.Len() != 0 {
		t.Fatalf("expected expired entry to be swept, len=%d", table.Len())
	}
}

func TestTableIgnoresIPv6(t *testing.T) {
	table := NewTable(time.Minute)
	table.Record("claude.ai", net.ParseIP("2606:4700::1"), time.Minute)
	if table.Len() != 0 {
		t.Fatalf("expected IPv6 addresses to be ignored in v1, len=%d", table.Len())
	}
}
