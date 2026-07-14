package sniobserver

import (
	"sync"

	"github.com/IliyaForsati/IP-Checker/internal/packet"
)

const MaxBufferedBytes = 16 * 1024

type Reassembler struct {
	mu   sync.Mutex
	bufs map[packet.FlowKey][]byte
}

func NewReassembler() *Reassembler {
	return &Reassembler{bufs: make(map[packet.FlowKey][]byte)}
}

func (r *Reassembler) Feed(key packet.FlowKey, payload []byte) (buf []byte, overflowed bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	next := append(r.bufs[key], payload...)
	if len(next) > MaxBufferedBytes {
		delete(r.bufs, key)
		return nil, true
	}
	r.bufs[key] = next
	return next, false
}

func (r *Reassembler) Evict(key packet.FlowKey) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.bufs, key)
}
