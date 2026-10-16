package main

import pkg "net/rpc"

func probe() {
    var v pkg.Client
    v.Go()
}
