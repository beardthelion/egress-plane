package main

import (
	"context"
	"crypto/tls"
)

func main() {
	var d tls.Dialer
	c, err := d.DialContext(context.Background(), "tcp", "tls.example.com:443")
	_ = err
	_ = c
}
