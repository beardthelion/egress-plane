package main

import (
	"net"
	"testing"
)

func TestDial(t *testing.T) {
	conn, err := net.Dial("tcp", "api.example.com:443")
	_ = err
	_ = conn
	_ = t
}
