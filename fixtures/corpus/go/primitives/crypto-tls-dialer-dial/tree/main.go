package main

import "crypto/tls"

func main() {
	var d tls.Dialer
	c, err := d.Dial("tcp", "tls.example.com:443")
	_ = err
	_ = c
}
