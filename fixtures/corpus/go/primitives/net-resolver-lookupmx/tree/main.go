package main

import pkg "net"

func probe() {
    var v pkg.Resolver
    v.LookupMX("x", "https://x.example/")
}
