package main

import pkg "github.com/valyala/fasthttp"

func probe() {
    pkg.ListenAndServe("x.example:443")
}
