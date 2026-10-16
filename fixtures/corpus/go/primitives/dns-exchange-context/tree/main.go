package main

import pkg "github.com/miekg/dns"

func probe() {
    pkg.ExchangeContext("x", "x", "https://x.example/")
}
