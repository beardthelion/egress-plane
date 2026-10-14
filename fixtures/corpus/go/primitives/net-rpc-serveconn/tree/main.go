package main

import (
	"io"
	"net/rpc"
)

func main() {
	var c io.ReadWriteCloser
	rpc.ServeConn(c)
}
