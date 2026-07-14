package packet

import (
	"encoding/binary"
	"errors"
	"net"
)

var (
	ErrNotIPv4  = errors.New("packet: not an IPv4 packet")
	ErrShortTCP = errors.New("packet: TCP header too short")
	ErrShortUDP = errors.New("packet: UDP header too short")
)

const (
	ProtocolTCP = 6
	ProtocolUDP = 17
)

const (
	TCPFlagFIN = 1 << 0
	TCPFlagSYN = 1 << 1
	TCPFlagRST = 1 << 2
	TCPFlagACK = 1 << 4
)

type IPv4 struct {
	SrcIP    net.IP
	DstIP    net.IP
	Protocol uint8
	Payload  []byte
}

func ParseIPv4(raw []byte) (*IPv4, error) {
	if len(raw) < 20 {
		return nil, ErrNotIPv4
	}
	if raw[0]>>4 != 4 {
		return nil, ErrNotIPv4
	}
	ihl := int(raw[0]&0x0F) * 4
	if ihl < 20 || len(raw) < ihl {
		return nil, ErrNotIPv4
	}
	return &IPv4{
		SrcIP:    net.IP(append([]byte(nil), raw[12:16]...)),
		DstIP:    net.IP(append([]byte(nil), raw[16:20]...)),
		Protocol: raw[9],
		Payload:  raw[ihl:],
	}, nil
}

type TCP struct {
	SrcPort uint16
	DstPort uint16
	Seq     uint32
	Flags   uint8
	Payload []byte
}

func ParseTCP(l4 []byte) (*TCP, error) {
	if len(l4) < 20 {
		return nil, ErrShortTCP
	}
	dataOff := int(l4[12]>>4) * 4
	if dataOff < 20 || len(l4) < dataOff {
		return nil, ErrShortTCP
	}
	return &TCP{
		SrcPort: binary.BigEndian.Uint16(l4[0:2]),
		DstPort: binary.BigEndian.Uint16(l4[2:4]),
		Seq:     binary.BigEndian.Uint32(l4[4:8]),
		Flags:   l4[13],
		Payload: l4[dataOff:],
	}, nil
}

func (t *TCP) HasFlag(flag uint8) bool {
	return t.Flags&flag != 0
}

type UDP struct {
	SrcPort uint16
	DstPort uint16
	Payload []byte
}

func ParseUDP(l4 []byte) (*UDP, error) {
	if len(l4) < 8 {
		return nil, ErrShortUDP
	}
	return &UDP{
		SrcPort: binary.BigEndian.Uint16(l4[0:2]),
		DstPort: binary.BigEndian.Uint16(l4[2:4]),
		Payload: l4[8:],
	}, nil
}
