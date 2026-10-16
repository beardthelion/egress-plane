package main

import pkg "net/http"

func probe() {
    var v pkg.DefaultClient
    v.Head("https://x.example/")
}
