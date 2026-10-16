package main

import pkg "net"

func probe() {
    var v pkg.Resolver
    v.LookupNetIP("x", "x", "https://x.example/")
}
