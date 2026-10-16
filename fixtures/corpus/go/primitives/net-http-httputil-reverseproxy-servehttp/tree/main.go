package main

import pkg "net/http/httputil"

func probe() {
    var v pkg.ReverseProxy
    v.ServeHTTP()
}
