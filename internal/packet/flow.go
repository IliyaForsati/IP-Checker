package packet

import "net"

type FlowKey struct {
	SrcIP   [4]byte
	DstIP   [4]byte
	SrcPort uint16
	DstPort uint16
}

func NewFlowKey(srcIP, dstIP net.IP, srcPort, dstPort uint16) FlowKey {
	var key FlowKey
	copy(key.SrcIP[:], srcIP.To4())
	copy(key.DstIP[:], dstIP.To4())
	key.SrcPort = srcPort
	key.DstPort = dstPort
	return key
}
