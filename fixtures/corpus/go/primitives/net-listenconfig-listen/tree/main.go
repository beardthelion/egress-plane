package main

import pkg "net"

func probe() {
    var v pkg.ListenConfig
    v.Listen("x", "x", "x.example:443")
}
