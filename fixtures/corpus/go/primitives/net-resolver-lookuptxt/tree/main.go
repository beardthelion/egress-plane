package main

import pkg "net"

func probe() {
    var v pkg.Resolver
    v.LookupTXT("x", "https://x.example/")
}
