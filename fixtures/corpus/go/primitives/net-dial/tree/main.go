package main

import "net"

func main() {
	c, err := net.Dial("tcp", "dial.example.com:443")
	_ = err
	_ = c
}
