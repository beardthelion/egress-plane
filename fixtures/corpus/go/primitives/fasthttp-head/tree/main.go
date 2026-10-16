package main

import pkg "github.com/valyala/fasthttp"

func probe() {
    pkg.Head("x", "https://x.example/")
}
