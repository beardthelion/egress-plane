//go:build ignore

package main

import "net"

func ignored() {
	conn, err := net.Dial("tcp", "ignored.example.com:443")
	_ = err
	_ = conn
}
