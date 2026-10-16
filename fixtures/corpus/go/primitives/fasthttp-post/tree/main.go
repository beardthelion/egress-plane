package main

import pkg "github.com/valyala/fasthttp"

func probe() {
    pkg.Post("x", "https://x.example/")
}
