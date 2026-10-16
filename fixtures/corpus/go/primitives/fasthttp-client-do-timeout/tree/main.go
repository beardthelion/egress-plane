package main

import pkg "github.com/valyala/fasthttp"

func probe() {
    var v pkg.Client
    v.DoTimeout()
}
