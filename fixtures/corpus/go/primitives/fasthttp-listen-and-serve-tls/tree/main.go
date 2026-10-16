package main

import pkg "github.com/valyala/fasthttp"

func probe() {
    pkg.ListenAndServeTLS("x.example:443")
}
