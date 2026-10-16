package main

import pkg "github.com/miekg/dns"

func probe() {
    pkg.ListenAndServe("x.example:443")
}
