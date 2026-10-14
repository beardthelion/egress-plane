package main

import (
	"context"
	"net"
)

func main() {
	var d net.Dialer
	c, err := d.DialContext(context.Background(), "tcp", "api.example.com:443")
	_ = err
	_ = c
}
