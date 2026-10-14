package main

import "net"

func main() {
	conn, err := net.Dial("tcp", "api.example.com:443")
	_ = err
	_ = conn
}
