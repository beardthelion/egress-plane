package main

import "net"

func main() {
	l, err := net.Listen("tcp", "0.0.0.0:9090")
	_ = err
	_ = l
}
