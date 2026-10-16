package main

import pkg "net"

func probe() {
    var v pkg.Resolver
    v.LookupCNAME("x", "https://x.example/")
}
