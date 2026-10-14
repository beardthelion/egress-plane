package main

import (
	"context"
	"net"
)

func main() {
	var lc net.ListenConfig
	lc.Listen(context.Background(), "tcp", "0.0.0.0:9090")
	lc2 := net.ListenConfig{}
	lc2.Listen(context.Background(), "tcp", "0.0.0.0:9091")
}
