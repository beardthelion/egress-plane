package main

import "net"

func main() {
	var c net.TCPConn
	rc, err := c.SyscallConn()
	_ = err
	_ = rc
}
