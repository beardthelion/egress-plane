package main

import pkg "github.com/miekg/dns"

func probe() {
    var v pkg.Server
    v.ListenAndServe()
}
