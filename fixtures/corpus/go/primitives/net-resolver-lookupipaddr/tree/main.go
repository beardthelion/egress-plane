package main

import pkg "net"

func probe() {
    var v pkg.Resolver
    v.LookupIPAddr("x", "https://x.example/")
}
