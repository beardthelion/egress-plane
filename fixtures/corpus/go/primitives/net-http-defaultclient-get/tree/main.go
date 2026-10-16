package main

import pkg "net/http"

func probe() {
    var v pkg.DefaultClient
    v.Get("https://x.example/")
}
