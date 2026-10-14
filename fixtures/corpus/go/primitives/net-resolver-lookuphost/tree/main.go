package main

import (
	"context"
	"net"
)

func main() {
	var r net.Resolver
	addrs, err := r.LookupHost(context.Background(), "api.example.com")
	_ = err
	_ = addrs
}
