package main

import "crypto/tls"

func main() {
	l, err := tls.Listen("tcp", "0.0.0.0:443", nil)
	_ = err
	_ = l
}
