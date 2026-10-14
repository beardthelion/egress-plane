package main

import "net/rpc"

func main() {
	var c rpc.Client
	c.Call("Svc.M", nil, nil)
	c2 := rpc.Client{}
	c2.Call("Svc.M2", nil, nil)
}
