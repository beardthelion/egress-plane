package main

import "net"

func main() {
	addrs, err := net.LookupHost("example.com")
	_ = err
	_ = addrs
}
