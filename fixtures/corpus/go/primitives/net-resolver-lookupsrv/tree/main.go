package main

import pkg "net"

func probe() {
    var v pkg.Resolver
    v.LookupSRV("x", "x", "x", "https://x.example/")
}
