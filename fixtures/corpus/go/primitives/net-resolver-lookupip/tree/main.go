package main

import pkg "net"

func probe() {
    var v pkg.Resolver
    v.LookupIP("x", "x", "https://x.example/")
}
