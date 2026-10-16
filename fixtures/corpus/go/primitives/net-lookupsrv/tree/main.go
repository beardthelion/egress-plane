package main

import pkg "net"

func probe() {
    pkg.LookupSRV("x", "x", "https://x.example/")
}
