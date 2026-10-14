package main

import "net/rpc"

func main() {
	c, err := rpc.Dial("tcp", "rpc.example.com:1234")
	_ = err
	_ = c
}
