package main

import "crypto/tls"

func main() {
	c, err := tls.Dial("tcp", "tls.example.com:443", nil)
	_ = err
	_ = c
}
