package main

import (
	"net"
	"time"
)

func main() {
	c, err := net.DialTimeout("tcp", "api.example.com:443", time.Second)
	_ = err
	_ = c
}
