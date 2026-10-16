package main

import pkg "github.com/valyala/fasthttp"

func probe() {
    var v pkg.Server
    v.ListenAndServeUNIX()
}
