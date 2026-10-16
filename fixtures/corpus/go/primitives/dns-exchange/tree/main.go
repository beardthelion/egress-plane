package main

import pkg "github.com/miekg/dns"

func probe() {
    pkg.Exchange("x", "https://x.example/")
}
