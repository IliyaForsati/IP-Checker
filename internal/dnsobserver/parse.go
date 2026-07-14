package dnsobserver

import (
	"errors"
	"net"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

var ErrTruncatedTCPMessage = errors.New("dnsobserver: truncated TCP DNS message")

type Answer struct {
	Name string
	IP   net.IP
	TTL  time.Duration
}

func ParseAnswers(payload []byte) ([]Answer, error) {
	var parser dnsmessage.Parser
	if _, err := parser.Start(payload); err != nil {
		return nil, err
	}
	if err := parser.SkipAllQuestions(); err != nil {
		return nil, err
	}

	var answers []Answer
	for {
		header, err := parser.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return answers, err
		}
		if header.Type != dnsmessage.TypeA {
			if err := parser.SkipAnswer(); err != nil {
				return answers, err
			}
			continue
		}
		resource, err := parser.AResource()
		if err != nil {
			return answers, err
		}
		answers = append(answers, Answer{
			Name: strings.TrimSuffix(header.Name.String(), "."),
			IP:   net.IP(resource.A[:]),
			TTL:  time.Duration(header.TTL) * time.Second,
		})
	}
	return answers, nil
}

func ParseAnswersTCP(payload []byte) ([]Answer, error) {
	if len(payload) < 2 {
		return nil, ErrTruncatedTCPMessage
	}
	msgLen := int(payload[0])<<8 | int(payload[1])
	if len(payload) < 2+msgLen {
		return nil, ErrTruncatedTCPMessage
	}
	return ParseAnswers(payload[2 : 2+msgLen])
}
