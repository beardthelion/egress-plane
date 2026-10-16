package main

import pkg "github.com/valyala/fasthttp"

func probe() {
    pkg.ListenAndServeUNIX("x.example:443")
}
