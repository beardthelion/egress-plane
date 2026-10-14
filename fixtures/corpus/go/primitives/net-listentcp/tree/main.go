package main

import "net"

func main() {
	l, err := net.ListenTCP("tcp", nil)
	_ = err
	_ = l
}
