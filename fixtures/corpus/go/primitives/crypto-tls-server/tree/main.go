package main

import (
	"crypto/tls"
	"net"
)

func main() {
	var c net.Conn
	s := tls.Server(c, nil)
	_ = s
}
