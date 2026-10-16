package main

import pkg "net/http"

func probe() {
    var v pkg.DefaultClient
    v.Do("https://x.example/")
}
