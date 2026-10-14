package main

import (
	"context"
	"net"
)

func main() {
	var r net.Resolver
	r.LookupHost(context.Background(), "example.com")
	s := net.Resolver{}
	s.LookupHost(context.Background(), "example.org")
}
