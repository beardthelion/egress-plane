package main

import pkg "github.com/valyala/fasthttp"

func probe() {
    pkg.Dial("x.example:443")
}
