package main

import pkg "net/rpc"

func probe() {
    var v pkg.Server
    v.ServeCodec()
}
