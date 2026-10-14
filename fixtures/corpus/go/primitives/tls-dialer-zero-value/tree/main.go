package main

import (
	"context"
	"crypto/tls"
)

func main() {
	var d tls.Dialer
	d.Dial(context.Background(), "tcp", "tls.example.com:443")
	d2 := tls.Dialer{}
	d2.Dial(context.Background(), "tcp", "tls.example.org:443")
}
