package main

import "net/rpc/jsonrpc"

func main() {
	c, err := jsonrpc.Dial("tcp", "rpc.example.com:8080")
	_ = err
	_ = c
}
