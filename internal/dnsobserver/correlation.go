package dnsobserver

import (
	"net"
	"sync"
	"time"
)

type correlationEntry struct {
	domain    string
	expiresAt time.Time
}

type Table struct {
	mu      sync.RWMutex
	entries map[[4]byte]correlationEntry
	ttl     time.Duration
	now     func() time.Time
}

func NewTable(ttl time.Duration) *Table {
	return &Table{
		entries: make(map[[4]byte]correlationEntry),
		ttl:     ttl,
		now:     time.Now,
	}
}

func (t *Table) Record(domain string, ip net.IP, ttl time.Duration) {
	key, ok := ipKey(ip)
	if !ok {
		return
	}
	effectiveTTL := ttl
	if effectiveTTL <= 0 || effectiveTTL > t.ttl {
		effectiveTTL = t.ttl
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	t.entries[key] = correlationEntry{domain: domain, expiresAt: t.now().Add(effectiveTTL)}
}

func (t *Table) Lookup(ip net.IP) (string, bool) {
	key, ok := ipKey(ip)
	if !ok {
		return "", false
	}

	t.mu.RLock()
	defer t.mu.RUnlock()
	entry, ok := t.entries[key]
	if !ok || t.now().After(entry.expiresAt) {
		return "", false
	}
	return entry.domain, true
}

func (t *Table) Sweep(now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, e := range t.entries {
		if now.After(e.expiresAt) {
			delete(t.entries, k)
		}
	}
}

func (t *Table) Len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.entries)
}

func ipKey(ip net.IP) ([4]byte, bool) {
	v4 := ip.To4()
	if v4 == nil {
		return [4]byte{}, false
	}
	var key [4]byte
	copy(key[:], v4)
	return key, true
}
