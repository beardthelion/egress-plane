package main

import pkg "net"

func probe() {
    var v pkg.Resolver
    v.LookupPort("x", "x", "https://x.example/")
}
