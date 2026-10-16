package main

import pkg "net/rpc/jsonrpc"

func probe() {
    pkg.NewClientCodec()
}
