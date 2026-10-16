package main

import pkg "github.com/valyala/fasthttp"

func probe() {
    pkg.DialDualStack("x.example:443")
}
