package decision

import (
	"sync"
	"time"

	"github.com/IliyaForsati/IP-Checker/internal/packet"
)

type flowEntry struct {
	verdict   Verdict
	expiresAt time.Time
}

type FlowTable struct {
	mu    sync.RWMutex
	flows map[packet.FlowKey]flowEntry
	ttl   time.Duration
	now   func() time.Time
}

func NewFlowTable(ttl time.Duration) *FlowTable {
	return &FlowTable{
		flows: make(map[packet.FlowKey]flowEntry),
		ttl:   ttl,
		now:   time.Now,
	}
}

func (t *FlowTable) Get(key packet.FlowKey) (Verdict, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	entry, ok := t.flows[key]
	if !ok || t.now().After(entry.expiresAt) {
		return VerdictAccept, false
	}
	return entry.verdict, true
}

func (t *FlowTable) Set(key packet.FlowKey, verdict Verdict) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.flows[key] = flowEntry{verdict: verdict, expiresAt: t.now().Add(t.ttl)}
}

func (t *FlowTable) Sweep(now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, e := range t.flows {
		if now.After(e.expiresAt) {
			delete(t.flows, k)
		}
	}
}

func (t *FlowTable) Len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.flows)
}
