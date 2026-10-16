package main

import pkg "net/http/httputil"

func probe() {
    var v pkg.ProxyRequest
    v.SetURL("https://x.example/")
}
