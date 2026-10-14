package main

import "net"

func main() {
	names, err := net.LookupAddr("8.8.8.8")
	_ = err
	_ = names
}
