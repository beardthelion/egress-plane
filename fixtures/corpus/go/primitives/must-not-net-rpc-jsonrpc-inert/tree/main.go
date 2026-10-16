package main

import pkg "net/rpc/jsonrpc"

func main() {
    _ = pkg.clientCodec.Example
    _ = pkg.serverCodec.Example
}
