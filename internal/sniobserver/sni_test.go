package sniobserver

import (
	"crypto/tls"
	"net"
	"testing"
	"time"
)

func captureRealClientHello(t *testing.T, serverName string) []byte {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	captured := make(chan []byte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			captured <- nil
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 8192)
		n, _ := conn.Read(buf)
		captured <- buf[:n]
	}()

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer clientConn.Close()

	tlsConn := tls.Client(clientConn, &tls.Config{ServerName: serverName, InsecureSkipVerify: true})
	_ = tlsConn.SetDeadline(time.Now().Add(3 * time.Second))
	_ = tlsConn.Handshake()

	buf := <-captured
	if len(buf) == 0 {
		t.Fatalf("did not capture any ClientHello bytes")
	}
	return buf
}

func TestExtractSNI_RealClientHello(t *testing.T) {
	clientHello := captureRealClientHello(t, "claude.ai")

	hostname, complete, err := ExtractSNI(clientHello)
	if err != nil {
		t.Fatalf("ExtractSNI: %v", err)
	}
	if !complete {
		t.Fatalf("expected complete=true for a full ClientHello")
	}
	if hostname != "claude.ai" {
		t.Fatalf("expected hostname claude.ai, got %q", hostname)
	}
}

func TestExtractSNI_PartialBuffering(t *testing.T) {
	clientHello := captureRealClientHello(t, "anthropic.com")

	for cut := 0; cut < 5; cut++ {
		_, complete, err := ExtractSNI(clientHello[:cut])
		if err != nil {
			t.Fatalf("unexpected error at cut=%d: %v", cut, err)
		}
		if complete {
			t.Fatalf("expected complete=false at cut=%d (only %d bytes)", cut, cut)
		}
	}

	hostname, complete, err := ExtractSNI(clientHello)
	if err != nil {
		t.Fatalf("ExtractSNI on full buffer: %v", err)
	}
	if !complete || hostname != "anthropic.com" {
		t.Fatalf("expected complete hostname anthropic.com, got complete=%v hostname=%q", complete, hostname)
	}
}

func TestExtractSNI_NotHandshake(t *testing.T) {
	httpRequest := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	_, _, err := ExtractSNI(httpRequest)
	if err != ErrNotHandshake {
		t.Fatalf("expected ErrNotHandshake, got %v", err)
	}
}

func TestExtractSNI_EmptyBuffer(t *testing.T) {
	_, complete, err := ExtractSNI(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if complete {
		t.Fatalf("expected complete=false for empty buffer")
	}
}
