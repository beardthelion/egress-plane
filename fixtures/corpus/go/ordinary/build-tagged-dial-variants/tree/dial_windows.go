package main

import "net"

func dial() {
	conn, err := net.Dial("tcp", "windows.example.com:443")
	_ = err
	_ = conn
}
