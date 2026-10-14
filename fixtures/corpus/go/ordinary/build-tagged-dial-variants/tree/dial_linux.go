//go:build linux

package main

import "net"

func dial() {
	conn, err := net.Dial("tcp", "linux.example.com:443")
	_ = err
	_ = conn
}
