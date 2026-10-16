package main

import pkg "net/http"

func probe() {
    var v pkg.DefaultTransport
    v.RoundTrip()
}
