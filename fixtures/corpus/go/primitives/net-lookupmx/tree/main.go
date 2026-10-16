package main

import pkg "net"

func probe() {
    pkg.LookupMX("https://x.example/")
}
