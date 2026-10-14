package main

import "net"

func main() {
	a, b := net.Pipe()
	var buf net.Buffers
	_, _, _ = a, b, buf
}
