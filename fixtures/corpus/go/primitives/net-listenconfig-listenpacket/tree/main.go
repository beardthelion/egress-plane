package main

import pkg "net"

func probe() {
    var v pkg.ListenConfig
    v.ListenPacket("x", "x", "x.example:443")
}
