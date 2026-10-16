package main

import pkg "golang.org/x/net/http2"

func probe() {
    var v pkg.Transport
    v.RoundTrip()
}
