package sniobserver

import (
	"encoding/binary"
	"errors"
	"strings"
)

var ErrNotHandshake = errors.New("sniobserver: not a TLS handshake record")

const (
	recordTypeHandshake      = 0x16
	handshakeTypeClientHello = 0x01
	extensionServerName      = 0x0000
	serverNameTypeHostName   = 0x00
)

func ExtractSNI(buf []byte) (hostname string, complete bool, err error) {
	if len(buf) < 1 {
		return "", false, nil
	}
	if buf[0] != recordTypeHandshake {
		return "", false, ErrNotHandshake
	}
	if len(buf) < 5 {
		return "", false, nil
	}
	recordLen := int(binary.BigEndian.Uint16(buf[3:5]))
	if len(buf) < 5+recordLen {
		return "", false, nil
	}

	body := buf[5:]
	if len(body) < 1 {
		return "", false, nil
	}
	if body[0] != handshakeTypeClientHello {
		return "", false, ErrNotHandshake
	}
	if len(body) < 4 {
		return "", false, nil
	}
	handshakeLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	if len(body) < 4+handshakeLen {
		return "", false, nil
	}

	ch := body[4 : 4+handshakeLen]
	offset := 0

	if len(ch) < offset+2 {
		return "", true, nil
	}
	offset += 2

	if len(ch) < offset+32 {
		return "", true, nil
	}
	offset += 32

	if len(ch) < offset+1 {
		return "", true, nil
	}
	sessionIDLen := int(ch[offset])
	offset++
	if len(ch) < offset+sessionIDLen {
		return "", true, nil
	}
	offset += sessionIDLen

	if len(ch) < offset+2 {
		return "", true, nil
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(ch[offset : offset+2]))
	offset += 2
	if len(ch) < offset+cipherSuitesLen {
		return "", true, nil
	}
	offset += cipherSuitesLen

	if len(ch) < offset+1 {
		return "", true, nil
	}
	compressionMethodsLen := int(ch[offset])
	offset++
	if len(ch) < offset+compressionMethodsLen {
		return "", true, nil
	}
	offset += compressionMethodsLen

	if len(ch) < offset+2 {
		return "", true, nil
	}
	extensionsLen := int(binary.BigEndian.Uint16(ch[offset : offset+2]))
	offset += 2
	if len(ch) < offset+extensionsLen {
		return "", true, nil
	}
	extensions := ch[offset : offset+extensionsLen]

	pos := 0
	for pos+4 <= len(extensions) {
		extType := binary.BigEndian.Uint16(extensions[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(extensions[pos+2 : pos+4]))
		pos += 4
		if pos+extLen > len(extensions) {
			break
		}
		extData := extensions[pos : pos+extLen]
		pos += extLen

		if extType == extensionServerName {
			if name, ok := parseServerNameExtension(extData); ok {
				return strings.ToLower(name), true, nil
			}
		}
	}

	return "", true, nil
}

func parseServerNameExtension(data []byte) (string, bool) {
	if len(data) < 2 {
		return "", false
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	if len(data) < 2+listLen {
		return "", false
	}
	list := data[2 : 2+listLen]

	pos := 0
	for pos+3 <= len(list) {
		nameType := list[pos]
		nameLen := int(binary.BigEndian.Uint16(list[pos+1 : pos+3]))
		pos += 3
		if pos+nameLen > len(list) {
			return "", false
		}
		if nameType == serverNameTypeHostName {
			return string(list[pos : pos+nameLen]), true
		}
		pos += nameLen
	}
	return "", false
}
