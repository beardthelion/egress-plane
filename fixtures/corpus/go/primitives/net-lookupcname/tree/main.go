package main

import pkg "net"

func probe() {
    pkg.LookupCNAME("https://x.example/")
}
