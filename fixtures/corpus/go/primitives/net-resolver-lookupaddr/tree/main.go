package main

import pkg "net"

func probe() {
    var v pkg.Resolver
    v.LookupAddr("x", "https://x.example/")
}
