package main

import "net/rpc/jsonrpc"

// The unexported clientCodec and serverCodec members stay inert.
func main() {
	_ = jsonrpc.clientCodec.WriteRequest
	_ = jsonrpc.serverCodec.ReadRequestHeader
}
