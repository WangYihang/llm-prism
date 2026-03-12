package commands

import (
	"net"
	"testing"
	"time"
)

func TestWaitForProxySuccess(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("failed to split host/port: %v", err)
	}

	if err := waitForProxy("127.0.0.1", port, 500*time.Millisecond); err != nil {
		t.Fatalf("expected proxy to be ready: %v", err)
	}
}

func TestWaitForProxyTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("failed to split host/port: %v", err)
	}

	if err := waitForProxy("127.0.0.1", port, 200*time.Millisecond); err == nil {
		t.Fatal("expected timeout error")
	}
}
