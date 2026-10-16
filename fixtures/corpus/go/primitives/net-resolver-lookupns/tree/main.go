package main

import pkg "net"

func probe() {
    var v pkg.Resolver
    v.LookupNS("x", "https://x.example/")
}
