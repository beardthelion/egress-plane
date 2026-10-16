package main

import pkg "github.com/miekg/dns"

func probe() {
    pkg.Dial("x", "x.example:443")
}
