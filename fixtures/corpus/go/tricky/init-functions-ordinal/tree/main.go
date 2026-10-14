package main

import "net"

func init() {
	conn, err := net.Dial("tcp", "first.example.com:443")
	_ = err
	_ = conn
}

func init() {
	conn, err := net.Dial("tcp", "second.example.com:443")
	_ = err
	_ = conn
}

func main() {}
