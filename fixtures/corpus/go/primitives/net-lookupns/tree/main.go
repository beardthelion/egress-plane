package main

import pkg "net"

func probe() {
    pkg.LookupNS("https://x.example/")
}
