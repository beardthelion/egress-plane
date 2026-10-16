package main

import pkg "net"

func probe() {
    pkg.LookupIP("x", "https://x.example/")
}
