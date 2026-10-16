package main

import pkg "net"

func probe() {
    pkg.LookupPort("x", "https://x.example/")
}
