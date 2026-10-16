package main

import pkg "net"

func probe() {
    pkg.LookupTXT("https://x.example/")
}
