package main

import "net/rpc"

func main() {
	c, err := rpc.DialHTTP("tcp", "rpc.example.com:80")
	_ = err
	_ = c
}
