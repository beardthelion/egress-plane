package main

import pkg "github.com/go-resty/resty/v2"

func probe() {
    var v pkg.Request
    v.Get("https://x.example/")
}
