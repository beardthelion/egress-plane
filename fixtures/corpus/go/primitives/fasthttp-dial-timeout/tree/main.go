package main

import pkg "github.com/valyala/fasthttp"

func probe() {
    pkg.DialTimeout("x.example:443")
}
